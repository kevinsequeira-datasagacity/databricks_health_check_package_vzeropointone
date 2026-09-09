"""
End-to-end verification of the check-module *logic* (not the real SDK)
against a MockWorkspaceClient loaded with realistic synthetic data. Also
doubles as the sample-report generator -- see `if __name__ == "__main__"`
at the bottom, which writes docs/sample_report.html.

See the README's "A note on verification" for what this does and doesn't
prove.
"""
import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import yaml  # noqa: E402

from mock_workspace_client import MockWorkspaceClient  # noqa: E402

from health_check_sdk.checks import security_iam, compute, jobs_cicd, unity_catalog  # noqa: E402
from health_check_sdk.scoring import build_scorecard  # noqa: E402
from health_check_sdk.report import render_html_report  # noqa: E402
from health_check_sdk import __version__ as PACKAGE_VERSION  # noqa: E402

PKG_ROOT = Path(__file__).resolve().parents[1]

GROUPS_LIST = [
    {"id": "g1", "display_name": "Databricks-Workspace-Admins", "external_id": "ext-1"},
    {"id": "g2", "display_name": "Databricks-Data-Engineers", "external_id": "ext-2"},
    {"id": "g3", "display_name": "Databricks-Analysts", "external_id": "ext-3"},
    {"id": "g4", "display_name": "users"},
    {"id": "g5", "display_name": "break-glass-admins"},
]
ADMINS_GROUP_DETAIL = {
    "id": "g0",
    "display_name": "admins",
    "members": [
        {"user_name": "old.contractor@acme.com", "$ref": "Users/1"},
        {"user_name": "jane.analyst@acme.com", "$ref": "Users/2"},
        {"user_name": "kevin.sequeira@datasagacity.com.au", "$ref": "Users/3"},
        {"user_name": "another.admin@acme.com", "$ref": "Users/4"},
    ],
}

_now = dt.datetime.now(dt.timezone.utc)
TOKENS = [
    {"comment": "ci-deploy", "creation_time": int((_now - dt.timedelta(days=10)).timestamp() * 1000), "expiry_time": -1},
    {"comment": "adhoc-analyst", "creation_time": int((_now - dt.timedelta(days=200)).timestamp() * 1000), "expiry_time": int((_now + dt.timedelta(days=200)).timestamp() * 1000)},
]

SCOPES = [
    {"name": "kv-prod-scope", "backend_type": "AZURE_KEYVAULT"},
    {"name": "legacy-scope", "backend_type": "DATABRICKS"},
]
ACLS_BY_SCOPE = {
    "legacy-scope": [{"principal": "users", "permission": "MANAGE"}],
    "kv-prod-scope": [{"principal": "data-eng-group", "permission": "READ"}],
}

CLUSTERS = [
    {"cluster_name": "shared-allpurpose", "cluster_source": "UI", "spark_version": "11.3.x-scala2.12", "autotermination_minutes": 0, "policy_id": None, "custom_tags": {}},
    {"cluster_name": "etl-job-cluster", "cluster_source": "JOB", "spark_version": "14.3.x-scala2.12", "autotermination_minutes": 0, "policy_id": "pol-1", "custom_tags": {"environment": "prod", "cost-center": "cc-100"}},
    {"cluster_name": "analyst-interactive", "cluster_source": "UI", "spark_version": "14.3.x-scala2.12", "autotermination_minutes": 30, "policy_id": "pol-1", "custom_tags": {"environment": "prod", "cost-center": "cc-200"}},
]
POOLS = [{"instance_pool_name": "warm-pool", "min_idle_instances": 8, "max_capacity": 10}]
WAREHOUSES = [{"name": "analytics-wh", "auto_stop_mins": 120, "enable_serverless_compute": False}]

JOBS = [
    {
        "job_id": 101,
        "settings": {
            "name": "bronze_ingest_daily",
            "git_source": {"git_url": "https://dev.azure.com/acme/data/_git/etl", "git_branch": "release/v3"},
            "run_as": {"service_principal_name": "sp-etl-prod"},
            "email_notifications": {"on_failure": ["data-eng@acme.com"]},
            "timeout_seconds": 3600,
            "max_retries": 2,
            "tasks": [{"task_key": "ingest", "new_cluster": {}, "timeout_seconds": 3600, "max_retries": 2}],
        },
    },
    {
        "job_id": 102,
        "settings": {
            "name": "adhoc_report_refresh",
            "run_as": {"user_name": "jane.analyst@acme.com"},
            "tasks": [{"task_key": "refresh", "existing_cluster_id": "0101-shared-allpurpose"}],
        },
    },
    {
        "job_id": 103,
        "settings": {
            "name": "legacy_notebook_job",
            "existing_cluster_id": "0101-shared-allpurpose",
            "run_as": {"user_name": "old.contractor@acme.com"},
        },
    },
]
RUNS = (
    [{"job_id": 101, "run_name": "bronze_ingest_daily", "state": {"result_state": "SUCCESS"}} for _ in range(18)]
    + [{"job_id": 101, "run_name": "bronze_ingest_daily", "state": {"result_state": "FAILED"}} for _ in range(2)]
    + [{"job_id": 102, "run_name": "adhoc_report_refresh", "state": {"result_state": "SUCCESS"}} for _ in range(2)]
    + [{"job_id": 102, "run_name": "adhoc_report_refresh", "state": {"result_state": "FAILED"}} for _ in range(3)]
)
REPOS = [
    {"path": "/Repos/svc/etl", "provider": "azureDevOpsServices", "branch": "main"},
    {"path": "/Repos/svc/ml-models", "provider": "gitHub", "tag": "v2.0.0"},
]

CATALOGS = [
    {"name": "prod_gold", "isolation_mode": "ISOLATED"},
    {"name": "prod_silver", "isolation_mode": "OPEN"},
]
GRANTS_BY_CATALOG = {
    "prod_gold": {"privilege_assignments": [{"principal": "account users", "privileges": ["ALL_PRIVILEGES"]}]},
    "prod_silver": {"privilege_assignments": [{"principal": "data-eng-group", "privileges": ["SELECT", "USE_SCHEMA"]}]},
}
EXT_LOCATIONS = [
    {"name": "raw-landing", "credential_name": "cred-raw", "read_only": False},
    {"name": "curated", "credential_name": "cred-curated", "read_only": True},
]
STORAGE_CREDS = [{"name": "cred-raw"}, {"name": "cred-curated"}, {"name": "cred-orphaned-legacy"}]
SCHEMAS_BY_CATALOG = {
    "system": [{"name": n} for n in ("access", "billing", "compute", "query", "marketplace")],
}


def _build_mock_client() -> MockWorkspaceClient:
    services = {
        "groups": {
            "list": lambda filter=None, **kw: [{"id": "g0", "display_name": "admins"}] if filter else GROUPS_LIST,
            "get": lambda id, **kw: ADMINS_GROUP_DETAIL,
        },
        "token_management": {
            "list": lambda **kw: TOKENS,
            "get_token_policy": lambda **kw: {"token_policy": {}},
        },
        "secrets": {
            "list_scopes": lambda **kw: SCOPES,
            "list_acls": lambda scope=None, **kw: ACLS_BY_SCOPE.get(scope, []),
        },
        "ip_access_lists": {"list": lambda **kw: []},
        "cluster_policies": {"list": lambda **kw: [{"policy_id": "pol-1", "name": "standard-etl-policy"}]},
        "clusters": {"list": lambda **kw: CLUSTERS},
        "instance_pools": {"list": lambda **kw: POOLS},
        "warehouses": {"list": lambda **kw: WAREHOUSES},
        "jobs": {
            "list": lambda expand_tasks=None, **kw: JOBS,
            "list_runs": lambda **kw: RUNS,
        },
        "repos": {"list": lambda **kw: REPOS},
        "catalogs": {"list": lambda **kw: CATALOGS},
        "grants": {"get": lambda securable_type=None, full_name=None, **kw: GRANTS_BY_CATALOG.get(full_name, {"privilege_assignments": []})},
        "external_locations": {"list": lambda **kw: EXT_LOCATIONS},
        "storage_credentials": {"list": lambda **kw: STORAGE_CREDS},
        "schemas": {"list": lambda catalog_name=None, **kw: SCHEMAS_BY_CATALOG.get(catalog_name, [])},
        "tables": {"list": lambda catalog_name=None, schema_name=None, **kw: []},
        "statement_execution": {},
        "current_user": {"me": lambda **kw: {"user_name": "kevin.sequeira@datasagacity.com.au"}},
    }
    return MockWorkspaceClient(services)


def _run_all(w, cfg, is_prod_like=True, is_admin=True):
    categories_cfg = cfg["categories"]
    return {
        "security_iam": {**categories_cfg["security_iam"], "findings": security_iam.run(w, cfg, is_prod_like, is_admin)},
        "compute": {**categories_cfg["compute"], "findings": compute.run(w, cfg, is_prod_like)},
        "unity_catalog": {**categories_cfg["unity_catalog"], "findings": unity_catalog.run(w, cfg, is_prod_like, warehouse_id=None)},
        "jobs_cicd": {**categories_cfg["jobs_cicd"], "findings": jobs_cicd.run(w, cfg, is_prod_like)},
    }


def test_all_categories_run_without_raising_and_produce_findings():
    with open(PKG_ROOT / "config" / "health_check_config.yaml") as f:
        cfg = yaml.safe_load(f)
    w = _build_mock_client()

    findings_by_category = _run_all(w, cfg)

    for key, spec in findings_by_category.items():
        assert len(spec["findings"]) > 0, f"{key} produced no findings at all"
        # every check should either be a real judgement or a clearly-marked
        # ERROR/INFO/N-A -- never silently empty or malformed
        for f in spec["findings"]:
            assert f.check_id
            assert f.title
            assert f.status is not None

    scorecard = build_scorecard(
        workspace_name="Acme-Corp-PROD",
        environment="prod",
        findings_by_category=findings_by_category,
        generated_at="2026-09-09 00:00 UTC",
    )
    assert 0.0 <= scorecard.overall_score <= 100.0

    # Known-bad synthetic data should actually surface as findings, proving
    # the checks aren't just rubber-stamping everything PASS.
    all_findings = [f for cat in scorecard.categories for f in cat.findings]
    check_ids_with_issues = {f.check_id for f in all_findings if f.status.value in ("WARN", "FAIL")}
    assert "SEC-002" in check_ids_with_issues  # 4 direct admins, no nested group
    assert "UC-002" in check_ids_with_issues  # ALL_PRIVILEGES to account users


def test_report_renders_from_mock_data():
    with open(PKG_ROOT / "config" / "health_check_config.yaml") as f:
        cfg = yaml.safe_load(f)
    w = _build_mock_client()
    findings_by_category = _run_all(w, cfg)

    scorecard = build_scorecard(
        workspace_name="Acme-Corp-PROD",
        environment="prod",
        findings_by_category=findings_by_category,
        generated_at="2026-09-09 00:00 UTC",
        grade_bands=[(b["min"], b["label"]) for b in cfg.get("grade_bands", [])],
    )
    html = render_html_report(scorecard, subtitle="Account host: https://adb-1234567890123456.7.azuredatabricks.net (SAMPLE DATA)", package_version=PACKAGE_VERSION)
    assert html.startswith("<!DOCTYPE html>")
    assert "Acme-Corp-PROD" in html


if __name__ == "__main__":
    with open(PKG_ROOT / "config" / "health_check_config.yaml") as f:
        cfg = yaml.safe_load(f)
    w = _build_mock_client()
    findings_by_category = _run_all(w, cfg)

    for key, spec in findings_by_category.items():
        print(f"\n=== {spec['label']} ({len(spec['findings'])} findings) ===")
        for f in spec["findings"]:
            print(f"  [{f.status.value:5s}] {f.check_id:10s} {f.title}")

    grade_bands = [(b["min"], b["label"]) for b in cfg.get("grade_bands", [])]
    scorecard = build_scorecard(
        workspace_name="Acme-Corp-PROD",
        environment="prod",
        findings_by_category=findings_by_category,
        generated_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        grade_bands=grade_bands,
    )
    print(f"\nOverall score: {scorecard.overall_score:.1f}/100 ({scorecard.overall_grade})")
    for c in scorecard.categories:
        print(f"  {c.label:20s} {c.score:5.1f}/100  ({c.passed} pass / {c.warned} warn / {c.failed} fail / {c.errored} n/a)")

    html = render_html_report(scorecard, subtitle="Account host: https://adb-1234567890123456.7.azuredatabricks.net (SAMPLE DATA)", package_version=PACKAGE_VERSION)
    out_html = PKG_ROOT / "docs" / "sample_report.html"
    out_html.write_text(html)
    print(f"\nWrote sample report: {out_html}")
