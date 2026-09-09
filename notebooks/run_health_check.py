# Databricks notebook source
# MAGIC %md
# MAGIC # Databricks Workspace Health Check
# MAGIC
# MAGIC Runs a technical health check against **this workspace** and produces a single
# MAGIC self-contained HTML report covering Security & IAM, Compute & Cost Hygiene,
# MAGIC Data Governance (Unity Catalog) and Jobs/Workflows/DevOps.
# MAGIC
# MAGIC **How to run this:**
# MAGIC 1. Make sure this notebook is opened from a **Databricks Repo** synced from the
# MAGIC    `databricks-health-check` Azure DevOps repo (so `../src/health_check` sits
# MAGIC    next to this notebook -- see `docs/deployment_guide.md`).
# MAGIC 2. Attach this notebook to any cluster (small, single-node is fine -- this is
# MAGIC    a metadata/API-driven check, not a data processing job).
# MAGIC 3. Fill in the widgets above (environment, optional SQL warehouse for the
# MAGIC    Delta table health sample, output location) and **Run All**.
# MAGIC 4. The report renders inline below and is also saved to `output_path` for
# MAGIC    download / sharing.
# MAGIC
# MAGIC **Permissions:** a baseline run works with whatever identity opened the
# MAGIC notebook. For full coverage (token inventory, org-wide token policy), run
# MAGIC as a **workspace admin** -- checks that need admin rights degrade to an
# MAGIC informational "could not evaluate" finding rather than failing the run.

# COMMAND ----------

# MAGIC %md ### Widgets

# COMMAND ----------

dbutils.widgets.dropdown("environment", "dev", ["dev", "test", "preprod", "prod"], "Environment")
dbutils.widgets.text("workspace_display_name", "", "Workspace display name (optional, for the report header)")
dbutils.widgets.text("sql_warehouse_id", "", "SQL Warehouse ID (optional, enables the Delta table health sample)")
dbutils.widgets.text("output_path", "/dbfs/FileStore/health_check_reports", "Output folder (DBFS/Workspace path)")
dbutils.widgets.text("repo_root_override", "", "Repo root override (leave blank to auto-detect)")

environment = dbutils.widgets.get("environment").strip().lower()
workspace_display_name = dbutils.widgets.get("workspace_display_name").strip()
sql_warehouse_id = dbutils.widgets.get("sql_warehouse_id").strip() or None
output_path = dbutils.widgets.get("output_path").strip().rstrip("/")
repo_root_override = dbutils.widgets.get("repo_root_override").strip() or None

# COMMAND ----------

# MAGIC %md ### Locate the package (`src/health_check`) relative to this notebook

# COMMAND ----------

import os
import sys


def _notebook_path() -> str:
    return dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()


def _resolve_repo_root() -> str:
    if repo_root_override:
        if os.path.isdir(os.path.join(repo_root_override, "src", "health_check")):
            return repo_root_override
        raise RuntimeError(
            f"repo_root_override='{repo_root_override}' does not contain src/health_check -- check the path."
        )

    notebook_path = _notebook_path()
    notebooks_dir = os.path.dirname(notebook_path)
    repo_root_ws_style = os.path.dirname(notebooks_dir)  # .../databricks-health-check

    candidates = [repo_root_ws_style]
    if not repo_root_ws_style.startswith("/Workspace"):
        candidates.append("/Workspace" + repo_root_ws_style)

    for candidate in candidates:
        if os.path.isdir(os.path.join(candidate, "src", "health_check")):
            return candidate

    raise RuntimeError(
        "Could not auto-detect the repo root from this notebook's path "
        f"({notebook_path}). Tried: {candidates}. "
        "Set the 'repo_root_override' widget to the repo's absolute path, e.g. "
        "'/Workspace/Repos/<you>/databricks-health-check'."
    )


REPO_ROOT = _resolve_repo_root()
SRC_PATH = os.path.join(REPO_ROOT, "src")
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

print(f"Repo root:   {REPO_ROOT}")
print(f"Source path: {SRC_PATH}")

# COMMAND ----------

# MAGIC %md ### Dependencies
# MAGIC
# MAGIC `pyyaml` and `requests` ship with every standard Databricks Runtime, so this
# MAGIC install is normally a fast no-op. It's kept as its own cell because `%pip`
# MAGIC must run unconditionally at the top level (it can't be wrapped in `try/if`).

# COMMAND ----------

# MAGIC %pip install pyyaml requests --quiet

# COMMAND ----------

import requests  # noqa: F401
import yaml  # noqa: F401

# COMMAND ----------

# MAGIC %md ### Load configuration & build the API client

# COMMAND ----------

import datetime as dt
import json

import yaml

from health_check.api_client import client_from_notebook_context
from health_check.checks import security_iam, compute_cost, data_governance, jobs_devops
from health_check.scoring import build_scorecard
from health_check.report import render_html_report
from health_check import __version__ as PACKAGE_VERSION

CONFIG_PATH = os.path.join(REPO_ROOT, "config", "health_check_config.yaml")
with open(CONFIG_PATH) as f:
    cfg = yaml.safe_load(f)

profile = cfg.get("environment_profiles", {}).get(environment, cfg.get("environment_profiles", {}).get("default", {}))
is_prod_like = bool(profile.get("is_production_like", False))

client = client_from_notebook_context(dbutils)
whoami = client.whoami()
is_admin = client.is_admin()

workspace_name = workspace_display_name or client.host.split("//")[-1].split(".")[0]

print(f"Environment:        {environment} (production-like: {is_prod_like})")
print(f"Workspace host:     {client.host}")
print(f"Running as:         {whoami.get('userName') or whoami.get('displayName') or 'unknown'}")
print(f"Admin-scope token:  {is_admin}")
print(f"SQL warehouse for Delta health sample: {sql_warehouse_id or '(not supplied -- that check will be skipped)'}")

# COMMAND ----------

# MAGIC %md ### Run all checks

# COMMAND ----------

from health_check.utils import Finding, Status, Severity


def _run_category(module_run_fn, label: str):
    try:
        return module_run_fn()
    except Exception as exc:  # noqa: BLE001 - a whole-category failure still shouldn't kill the run
        return [
            Finding(
                category=label,
                check_id="CATEGORY-ERROR",
                title=f"{label} checks did not complete",
                status=Status.ERROR,
                severity=Severity.INFO,
                detail=f"Unexpected error running this category's checks: {exc!r}",
                recommendation="See the notebook run log for the full traceback and re-run.",
            )
        ]


categories_cfg = cfg.get("categories", {})

findings_by_category = {
    "security_iam": {
        "label": categories_cfg.get("security_iam", {}).get("label", "Security & IAM"),
        "weight": categories_cfg.get("security_iam", {}).get("weight", 0.25),
        "findings": _run_category(lambda: security_iam.run(client, cfg, is_prod_like), "Security & IAM"),
    },
    "compute_cost": {
        "label": categories_cfg.get("compute_cost", {}).get("label", "Compute & Cost Hygiene"),
        "weight": categories_cfg.get("compute_cost", {}).get("weight", 0.25),
        "findings": _run_category(lambda: compute_cost.run(client, cfg, is_prod_like), "Compute & Cost Hygiene"),
    },
    "data_governance": {
        "label": categories_cfg.get("data_governance", {}).get("label", "Data Governance"),
        "weight": categories_cfg.get("data_governance", {}).get("weight", 0.25),
        "findings": _run_category(
            lambda: data_governance.run(client, cfg, is_prod_like, warehouse_id=sql_warehouse_id),
            "Data Governance",
        ),
    },
    "jobs_devops": {
        "label": categories_cfg.get("jobs_devops", {}).get("label", "Jobs, Workflows & DevOps"),
        "weight": categories_cfg.get("jobs_devops", {}).get("weight", 0.25),
        "findings": _run_category(lambda: jobs_devops.run(client, cfg, is_prod_like), "Jobs, Workflows & DevOps"),
    },
}

total_findings = sum(len(v["findings"]) for v in findings_by_category.values())
print(f"Collected {total_findings} findings across {len(findings_by_category)} categories.")

# COMMAND ----------

# MAGIC %md ### Score & render the report

# COMMAND ----------

grade_bands = [(b["min"], b["label"]) for b in cfg.get("grade_bands", [])] or None
generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

scorecard = build_scorecard(
    workspace_name=workspace_name,
    environment=environment,
    findings_by_category=findings_by_category,
    generated_at=generated_at,
    grade_bands=grade_bands,
)

html_report = render_html_report(
    scorecard,
    subtitle=f"Account host: {client.host}",
    package_version=PACKAGE_VERSION,
)

print(f"Overall score: {scorecard.overall_score:.1f}/100 ({scorecard.overall_grade})")
for c in scorecard.categories:
    print(f"  {c.label:35s} {c.score:5.1f}/100  ({c.passed} pass / {c.warned} warn / {c.failed} fail / {c.errored} n/a)")

# COMMAND ----------

# MAGIC %md ### Save the report

# COMMAND ----------

timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
safe_workspace_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in workspace_name)
base_filename = f"{safe_workspace_name}_{environment}_{timestamp}"

os.makedirs(output_path, exist_ok=True)
html_out_path = os.path.join(output_path, f"{base_filename}.html")
json_out_path = os.path.join(output_path, f"{base_filename}.json")

with open(html_out_path, "w") as f:
    f.write(html_report)

with open(json_out_path, "w") as f:
    json.dump(scorecard.to_dict(), f, indent=2, default=str)

print(f"Saved HTML report: {html_out_path}")
print(f"Saved JSON scorecard: {json_out_path}")

if output_path.startswith("/dbfs/FileStore"):
    workspace_host = client.host
    file_url_path = html_out_path.replace("/dbfs/FileStore", "/files", 1)
    print(f"Downloadable link (open while authenticated to the workspace): {workspace_host}{file_url_path}")

# COMMAND ----------

# MAGIC %md ### Report

# COMMAND ----------

displayHTML(html_report)
