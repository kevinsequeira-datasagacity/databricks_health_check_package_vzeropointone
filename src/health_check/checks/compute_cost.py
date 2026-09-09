"""
Compute & cost hygiene checks.

  COST-001  Interactive cluster autotermination is configured
  COST-002  Cluster runtime (DBR) version currency
  COST-003  Cluster policy attachment rate
  COST-004  Required cost-allocation tags present on clusters
  COST-005  Instance pool idle-capacity sizing
  COST-006  SQL warehouse auto-stop & sizing
  COST-007  Jobs running on all-purpose clusters instead of job clusters
"""
from __future__ import annotations

import re

from ..api_client import DatabricksClient
from ..utils import Finding, Severity, Status, run_check

CATEGORY = "compute_cost"
CATEGORY_LABEL = "Compute & Cost Hygiene"


def _parse_dbr(spark_version: str):
    """'13.3.x-scala2.12' / '13.3.x-photon-scala2.12' -> (13, 3)"""
    m = re.match(r"^(\d+)\.(\d+)", spark_version or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _is_job_cluster(cluster: dict) -> bool:
    return cluster.get("cluster_source") in ("JOB",)


def _cost001_autotermination(client: DatabricksClient, cfg: dict, limits: dict) -> list:
    max_minutes = cfg.get("thresholds", {}).get("clusters", {}).get("max_autotermination_minutes", 120)
    clusters = client.get("/api/2.0/clusters/list").get("clusters", []) or []
    clusters = clusters[: limits.get("max_clusters_to_inspect", 500)]
    interactive = [c for c in clusters if not _is_job_cluster(c)]

    if not interactive:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="COST-001",
                title="Interactive cluster autotermination",
                status=Status.INFO,
                detail="No interactive (all-purpose) clusters found.",
            )
        ]

    offenders = [
        c for c in interactive
        if not c.get("autotermination_minutes") or c.get("autotermination_minutes", 0) > max_minutes
    ]
    if offenders:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="COST-001",
                title="Interactive cluster autotermination",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=(
                    f"{len(offenders)} of {len(interactive)} all-purpose cluster(s) have no "
                    f"autotermination set, or it exceeds {max_minutes} minutes: "
                    + ", ".join(c.get("cluster_name", "?") for c in offenders[:10])
                ),
                recommendation=f"Set autotermination_minutes <= {max_minutes} on interactive clusters, or enforce it via cluster policy.",
                evidence={"offenders": [c.get("cluster_name") for c in offenders]},
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="COST-001",
            title="Interactive cluster autotermination",
            status=Status.PASS,
            detail=f"All {len(interactive)} all-purpose cluster(s) autoterminate within {max_minutes} minutes.",
        )
    ]


def _cost002_dbr_currency(client: DatabricksClient, cfg: dict, limits: dict) -> list:
    min_lts = cfg.get("thresholds", {}).get("clusters", {}).get("min_dbr_lts_major_minor", "13.3")
    min_major, min_minor = (int(x) for x in min_lts.split("."))
    clusters = client.get("/api/2.0/clusters/list").get("clusters", []) or []
    clusters = clusters[: limits.get("max_clusters_to_inspect", 500)]

    stale = []
    for c in clusters:
        parsed = _parse_dbr(c.get("spark_version", ""))
        if parsed and parsed < (min_major, min_minor):
            stale.append(c)

    if stale:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="COST-002",
                title="Cluster runtime (DBR) version currency",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=(
                    f"{len(stale)} of {len(clusters)} cluster(s) run a DBR version older than "
                    f"the {min_lts} LTS baseline: "
                    + ", ".join(f"{c.get('cluster_name', '?')} ({c.get('spark_version')})" for c in stale[:10])
                ),
                recommendation="Upgrade to a current LTS Databricks Runtime for security patches and performance improvements.",
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="COST-002",
            title="Cluster runtime (DBR) version currency",
            status=Status.PASS,
            detail=f"All {len(clusters)} cluster(s) are on DBR {min_lts}+ or newer.",
        )
    ]


def _cost003_policy_attachment(client: DatabricksClient, cfg: dict, is_prod_like: bool, limits: dict) -> list:
    clusters = client.get("/api/2.0/clusters/list").get("clusters", []) or []
    clusters = clusters[: limits.get("max_clusters_to_inspect", 500)]
    interactive = [c for c in clusters if not _is_job_cluster(c)]
    if not interactive:
        return [
            Finding(category=CATEGORY_LABEL, check_id="COST-003", title="Cluster policy attachment", status=Status.INFO, detail="No interactive clusters found.")
        ]

    with_policy = [c for c in interactive if c.get("policy_id")]
    ratio = len(with_policy) / len(interactive)
    require = cfg.get("thresholds", {}).get("clusters", {}).get("require_cluster_policy_in_prod", True)

    if is_prod_like and require and ratio < 1.0:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="COST-003",
                title="Cluster policy attachment",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=f"Only {len(with_policy)}/{len(interactive)} ({ratio:.0%}) interactive clusters are attached to a cluster policy.",
                recommendation="Require a cluster policy for all interactive cluster creation in production-like environments.",
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="COST-003",
            title="Cluster policy attachment",
            status=Status.PASS if ratio > 0.8 else Status.INFO,
            detail=f"{len(with_policy)}/{len(interactive)} ({ratio:.0%}) interactive clusters use a cluster policy.",
        )
    ]


def _cost004_tagging(client: DatabricksClient, cfg: dict, limits: dict) -> list:
    required_tags = cfg.get("thresholds", {}).get("clusters", {}).get("require_tags", []) or []
    if not required_tags:
        return [Finding(category=CATEGORY_LABEL, check_id="COST-004", title="Cost-allocation tagging", status=Status.NOT_APPLICABLE, detail="No required tags configured.")]

    clusters = client.get("/api/2.0/clusters/list").get("clusters", []) or []
    clusters = clusters[: limits.get("max_clusters_to_inspect", 500)]
    interactive = [c for c in clusters if not _is_job_cluster(c)]
    if not interactive:
        return [Finding(category=CATEGORY_LABEL, check_id="COST-004", title="Cost-allocation tagging", status=Status.INFO, detail="No interactive clusters found.")]

    missing = []
    for c in interactive:
        tags = c.get("custom_tags", {}) or {}
        missing_tags = [t for t in required_tags if t not in tags]
        if missing_tags:
            missing.append((c.get("cluster_name", "?"), missing_tags))

    if missing:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="COST-004",
                title="Cost-allocation tagging",
                status=Status.WARN,
                severity=Severity.LOW,
                detail=f"{len(missing)}/{len(interactive)} cluster(s) are missing one or more required tags ({', '.join(required_tags)}).",
                recommendation="Enforce required tags via cluster policy so cost/usage can be attributed by environment and cost center.",
                evidence={"examples": [f"{name}: missing {tags}" for name, tags in missing[:10]]},
            )
        ]
    return [
        Finding(category=CATEGORY_LABEL, check_id="COST-004", title="Cost-allocation tagging", status=Status.PASS, detail=f"All {len(interactive)} cluster(s) carry the required tags.")
    ]


def _cost005_instance_pools(client: DatabricksClient, cfg: dict) -> list:
    pools = client.get("/api/2.0/instance-pools/list").get("instance_pools", []) or []
    if not pools:
        return [Finding(category=CATEGORY_LABEL, check_id="COST-005", title="Instance pool sizing", status=Status.INFO, detail="No instance pools defined.")]

    overprovisioned = []
    for p in pools:
        min_idle = p.get("min_idle_instances", 0) or 0
        max_cap = p.get("max_capacity")
        if max_cap and min_idle > 0 and (min_idle / max_cap) > 0.5:
            overprovisioned.append(p.get("instance_pool_name", "?"))

    findings = []
    if overprovisioned:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="COST-005",
                title="Instance pool sizing",
                status=Status.WARN,
                severity=Severity.LOW,
                detail=f"{len(overprovisioned)} pool(s) keep more than half their max capacity idle at all times: {', '.join(overprovisioned)}",
                recommendation="Reduce min_idle_instances unless the workload genuinely needs instant warm-start capacity for most of the day.",
            )
        )
    else:
        findings.append(Finding(category=CATEGORY_LABEL, check_id="COST-005", title="Instance pool sizing", status=Status.PASS, detail=f"{len(pools)} pool(s) checked; idle sizing looks reasonable."))
    return findings


def _cost006_sql_warehouses(client: DatabricksClient, cfg: dict) -> list:
    max_auto_stop = cfg.get("thresholds", {}).get("sql_warehouses", {}).get("max_auto_stop_minutes", 30)
    warehouses = client.get("/api/2.0/sql/warehouses").get("warehouses", []) or []
    if not warehouses:
        return [Finding(category=CATEGORY_LABEL, check_id="COST-006", title="SQL warehouse auto-stop", status=Status.INFO, detail="No SQL warehouses defined.")]

    offenders = [w for w in warehouses if not w.get("enable_serverless_compute") and (w.get("auto_stop_mins", 0) or 0) > max_auto_stop]
    if offenders:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="COST-006",
                title="SQL warehouse auto-stop",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=(
                    f"{len(offenders)} classic/pro warehouse(s) have auto-stop above {max_auto_stop} minutes: "
                    + ", ".join(f"{w.get('name', '?')} ({w.get('auto_stop_mins')}m)" for w in offenders[:10])
                ),
                recommendation=f"Lower auto-stop to <= {max_auto_stop} minutes, or move to serverless SQL warehouses where available.",
            )
        ]
    return [Finding(category=CATEGORY_LABEL, check_id="COST-006", title="SQL warehouse auto-stop", status=Status.PASS, detail=f"All {len(warehouses)} warehouse(s) auto-stop promptly or run serverless.")]


def _cost007_job_cluster_ratio(client: DatabricksClient, cfg: dict, limits: dict) -> list:
    max_ratio = cfg.get("thresholds", {}).get("jobs_compute", {}).get("max_all_purpose_job_ratio", 0.20)
    jobs = list(client.get_pages("/api/2.1/jobs/list", {"expand_tasks": "true"}, items_key="jobs"))
    jobs = jobs[: limits.get("max_jobs_to_inspect", 500)]
    if not jobs:
        return [Finding(category=CATEGORY_LABEL, check_id="COST-007", title="Job cluster vs. all-purpose usage", status=Status.INFO, detail="No jobs defined.")]

    total_tasks = 0
    on_all_purpose = 0
    offending_jobs = set()
    for job in jobs:
        settings = job.get("settings", {}) or {}
        # Multi-task jobs (Jobs API 2.1) list their tasks explicitly; legacy
        # single-task jobs carry existing_cluster_id/new_cluster at the top
        # level instead, so synthesize a single pseudo-task for those.
        tasks = settings.get("tasks") or []
        if not tasks:
            if settings.get("existing_cluster_id"):
                tasks = [{"existing_cluster_id": settings.get("existing_cluster_id")}]
            elif settings.get("new_cluster"):
                tasks = [{"new_cluster": True}]
        for t in tasks:
            total_tasks += 1
            if t.get("existing_cluster_id"):
                on_all_purpose += 1
                offending_jobs.add(settings.get("name", str(job.get("job_id"))))

    if total_tasks == 0:
        return [Finding(category=CATEGORY_LABEL, check_id="COST-007", title="Job cluster vs. all-purpose usage", status=Status.INFO, detail="Could not determine cluster usage for any job task.")]

    ratio = on_all_purpose / total_tasks
    if ratio > max_ratio:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="COST-007",
                title="Job cluster vs. all-purpose usage",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=(
                    f"{on_all_purpose}/{total_tasks} ({ratio:.0%}) job tasks run on a shared all-purpose "
                    f"cluster rather than a dedicated job cluster, above the {max_ratio:.0%} guideline. "
                    f"Affected jobs include: {', '.join(list(offending_jobs)[:10])}"
                ),
                recommendation=(
                    "Switch scheduled jobs to job clusters (new_cluster) sized for the workload. "
                    "All-purpose clusters cost more per DBU and mix workloads' compute together, "
                    "making cost attribution and isolation harder."
                ),
            )
        ]
    return [Finding(category=CATEGORY_LABEL, check_id="COST-007", title="Job cluster vs. all-purpose usage", status=Status.PASS, detail=f"Only {ratio:.0%} of job tasks run on all-purpose clusters.")]


def run(client: DatabricksClient, cfg: dict, is_prod_like: bool) -> list:
    limits = cfg.get("limits", {})
    findings: list = []
    findings += run_check(lambda: _cost001_autotermination(client, cfg, limits), category=CATEGORY_LABEL, check_id="COST-001", title="Interactive cluster autotermination")
    findings += run_check(lambda: _cost002_dbr_currency(client, cfg, limits), category=CATEGORY_LABEL, check_id="COST-002", title="Cluster runtime (DBR) version currency")
    findings += run_check(lambda: _cost003_policy_attachment(client, cfg, is_prod_like, limits), category=CATEGORY_LABEL, check_id="COST-003", title="Cluster policy attachment")
    findings += run_check(lambda: _cost004_tagging(client, cfg, limits), category=CATEGORY_LABEL, check_id="COST-004", title="Cost-allocation tagging")
    findings += run_check(lambda: _cost005_instance_pools(client, cfg), category=CATEGORY_LABEL, check_id="COST-005", title="Instance pool sizing")
    findings += run_check(lambda: _cost006_sql_warehouses(client, cfg), category=CATEGORY_LABEL, check_id="COST-006", title="SQL warehouse auto-stop")
    findings += run_check(lambda: _cost007_job_cluster_ratio(client, cfg, limits), category=CATEGORY_LABEL, check_id="COST-007", title="Job cluster vs. all-purpose usage")
    return findings
