"""
Jobs, workflows & Azure DevOps integration checks.

  JOB-001  Retry & timeout hygiene per job/task
  JOB-002  Failure notifications configured
  JOB-003  Jobs deployed from git (Azure DevOps) vs. ad-hoc notebook paths
  JOB-004  Jobs run as a service principal (not an individual user) in prod-like envs
  JOB-005  Job run failure rate over the lookback window
  JOB-006  Databricks Repos -> Azure DevOps linkage & ref pinning
"""
from __future__ import annotations

from ..api_client import DatabricksClient
from ..utils import Finding, Severity, Status, safe_get, run_check

CATEGORY = "jobs_devops"
CATEGORY_LABEL = "Jobs, Workflows & DevOps"


def _iter_tasks(settings: dict):
    tasks = settings.get("tasks")
    if tasks:
        return tasks
    # legacy single-task job shape
    return [settings]


def _job001_retry_timeout(client: DatabricksClient, limits: dict) -> list:
    jobs = list(client.get_pages("/api/2.1/jobs/list", {"expand_tasks": "true"}, items_key="jobs"))[: limits.get("max_jobs_to_inspect", 500)]
    if not jobs:
        return [Finding(category=CATEGORY_LABEL, check_id="JOB-001", title="Retry & timeout hygiene", status=Status.INFO, detail="No jobs defined.")]

    offenders = []
    for job in jobs:
        settings = job.get("settings", {}) or {}
        name = settings.get("name", str(job.get("job_id")))
        job_timeout = settings.get("timeout_seconds", 0)
        for task in _iter_tasks(settings):
            timeout = task.get("timeout_seconds", 0) or job_timeout
            retries = task.get("max_retries", 0) or settings.get("max_retries", 0)
            if not timeout and not retries:
                offenders.append(name)
                break

    if offenders:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="JOB-001",
                title="Retry & timeout hygiene",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=f"{len(offenders)}/{len(jobs)} job(s) have neither a timeout nor a retry policy set: {', '.join(offenders[:10])}",
                recommendation="Set timeout_seconds and max_retries (with min_retry_interval_millis) so a hung or transient failure doesn't run indefinitely or fail silently.",
                evidence={"offenders": offenders},
            )
        ]
    return [Finding(category=CATEGORY_LABEL, check_id="JOB-001", title="Retry & timeout hygiene", status=Status.PASS, detail=f"All {len(jobs)} job(s) have a timeout and/or retry policy.")]


def _job002_notifications(client: DatabricksClient, limits: dict, is_prod_like: bool) -> list:
    jobs = list(client.get_pages("/api/2.1/jobs/list", {"expand_tasks": "true"}, items_key="jobs"))[: limits.get("max_jobs_to_inspect", 500)]
    if not jobs:
        return [Finding(category=CATEGORY_LABEL, check_id="JOB-002", title="Failure notifications", status=Status.INFO, detail="No jobs defined.")]

    offenders = []
    for job in jobs:
        settings = job.get("settings", {}) or {}
        name = settings.get("name", str(job.get("job_id")))
        email_on_failure = safe_get(settings, "email_notifications", "on_failure") or []
        webhook_on_failure = safe_get(settings, "webhook_notifications", "on_failure") or []
        task_level_alerts = any(
            (safe_get(t, "email_notifications", "on_failure") or safe_get(t, "webhook_notifications", "on_failure"))
            for t in _iter_tasks(settings)
        )
        if not email_on_failure and not webhook_on_failure and not task_level_alerts:
            offenders.append(name)

    if offenders:
        severity = Severity.HIGH if is_prod_like else Severity.MEDIUM
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="JOB-002",
                title="Failure notifications",
                status=Status.WARN,
                severity=severity,
                detail=f"{len(offenders)}/{len(jobs)} job(s) have no on_failure email or webhook notification configured: {', '.join(offenders[:10])}",
                recommendation="Add on_failure email or webhook (Slack/Teams/PagerDuty) notifications, especially for scheduled production jobs.",
                evidence={"offenders": offenders},
            )
        ]
    return [Finding(category=CATEGORY_LABEL, check_id="JOB-002", title="Failure notifications", status=Status.PASS, detail=f"All {len(jobs)} job(s) have failure notifications configured.")]


def _job003_git_source(client: DatabricksClient, cfg: dict, limits: dict, is_prod_like: bool) -> list:
    require = cfg.get("thresholds", {}).get("jobs", {}).get("require_git_source_in_prod", True)
    jobs = list(client.get_pages("/api/2.1/jobs/list", {"expand_tasks": "true"}, items_key="jobs"))[: limits.get("max_jobs_to_inspect", 500)]
    if not jobs:
        return [Finding(category=CATEGORY_LABEL, check_id="JOB-003", title="CI/CD deployment (git_source)", status=Status.INFO, detail="No jobs defined.")]

    without_git = [
        (job.get("settings", {}) or {}).get("name", str(job.get("job_id")))
        for job in jobs
        if not (job.get("settings", {}) or {}).get("git_source")
    ]

    if without_git and is_prod_like and require:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="JOB-003",
                title="CI/CD deployment (git_source)",
                status=Status.WARN,
                severity=Severity.HIGH,
                detail=(
                    f"{len(without_git)}/{len(jobs)} job(s) are defined against workspace-local "
                    f"notebook paths rather than a git_source: {', '.join(without_git[:10])}"
                ),
                recommendation=(
                    "Deploy production jobs from the Azure DevOps repo via a Databricks Asset Bundle "
                    "(or job git_source pointing at a tagged commit) so job definitions are versioned, "
                    "reviewed via PR, and reproducible from source control."
                ),
                evidence={"jobs_without_git_source": without_git},
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="JOB-003",
            title="CI/CD deployment (git_source)",
            status=Status.PASS if not without_git else Status.INFO,
            detail=(
                f"{len(jobs) - len(without_git)}/{len(jobs)} job(s) are deployed from a git source."
                if without_git else f"All {len(jobs)} job(s) are deployed from a git source."
            ),
        )
    ]


def _job004_run_as(client: DatabricksClient, cfg: dict, limits: dict, is_prod_like: bool) -> list:
    require = cfg.get("thresholds", {}).get("jobs", {}).get("require_service_principal_run_as_in_prod", True)
    if not (is_prod_like and require):
        return [Finding(category=CATEGORY_LABEL, check_id="JOB-004", title="Job run-as identity", status=Status.NOT_APPLICABLE, detail="Only enforced in production-like environments.")]

    jobs = list(client.get_pages("/api/2.1/jobs/list", {"expand_tasks": "true"}, items_key="jobs"))[: limits.get("max_jobs_to_inspect", 500)]
    if not jobs:
        return [Finding(category=CATEGORY_LABEL, check_id="JOB-004", title="Job run-as identity", status=Status.INFO, detail="No jobs defined.")]

    user_run_as = []
    for job in jobs:
        settings = job.get("settings", {}) or {}
        run_as = settings.get("run_as", {}) or {}
        if run_as.get("user_name"):
            user_run_as.append(settings.get("name", str(job.get("job_id"))))

    if user_run_as:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="JOB-004",
                title="Job run-as identity",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=f"{len(user_run_as)}/{len(jobs)} job(s) run as an individual user rather than a service principal: {', '.join(user_run_as[:10])}",
                recommendation="Set run_as to a dedicated service principal for production jobs, so runs don't break when the owning individual leaves or loses access.",
                evidence={"jobs": user_run_as},
            )
        ]
    return [Finding(category=CATEGORY_LABEL, check_id="JOB-004", title="Job run-as identity", status=Status.PASS, detail=f"All {len(jobs)} job(s) run as a service principal.")]


def _job005_failure_rate(client: DatabricksClient, cfg: dict, limits: dict) -> list:
    import datetime as dt

    lookback_days = cfg.get("thresholds", {}).get("jobs", {}).get("lookback_days", 30)
    max_failure_rate = cfg.get("thresholds", {}).get("jobs", {}).get("max_failure_rate", 0.15)
    start_ms = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=lookback_days)).timestamp() * 1000)

    runs = list(
        client.get_pages(
            "/api/2.1/jobs/runs/list",
            {"start_time_from": start_ms, "completed_only": "true", "limit": 25},
            items_key="runs",
        )
    )
    runs = runs[: limits.get("max_jobs_to_inspect", 500) * 5]
    if not runs:
        return [Finding(category=CATEGORY_LABEL, check_id="JOB-005", title="Job run failure rate", status=Status.INFO, detail=f"No completed job runs in the last {lookback_days} days.")]

    by_job: dict = {}
    for r in runs:
        job_id = r.get("job_id")
        name = safe_get(r, "run_name") or str(job_id)
        result_state = safe_get(r, "state", "result_state") or safe_get(r, "status", "termination_details", "code")
        entry = by_job.setdefault(job_id, {"name": name, "total": 0, "failed": 0})
        entry["total"] += 1
        if result_state in ("FAILED", "TIMEDOUT", "ERROR", "INTERNAL_ERROR"):
            entry["failed"] += 1

    offenders = []
    for job_id, stats in by_job.items():
        if stats["total"] >= 3:
            rate = stats["failed"] / stats["total"]
            if rate > max_failure_rate:
                offenders.append((stats["name"], stats["failed"], stats["total"], rate))

    if offenders:
        offenders.sort(key=lambda x: -x[3])
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="JOB-005",
                title="Job run failure rate",
                status=Status.WARN,
                severity=Severity.HIGH,
                detail=(
                    f"{len(offenders)} job(s) exceed a {max_failure_rate:.0%} failure rate over the last "
                    f"{lookback_days} days: "
                    + "; ".join(f"{n} ({f}/{t} = {r:.0%})" for n, f, t, r in offenders[:10])
                ),
                recommendation="Investigate root cause (data issues, capacity, upstream dependency) for the flagged jobs; consider tightening retry/backoff or alerting sooner.",
                evidence={"offenders": [f"{n}:{f}/{t}" for n, f, t, r in offenders]},
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="JOB-005",
            title="Job run failure rate",
            status=Status.PASS,
            detail=f"No job exceeded a {max_failure_rate:.0%} failure rate across {len(by_job)} job(s) with runs in the last {lookback_days} days.",
        )
    ]


def _job006_repos_linkage(client: DatabricksClient, cfg: dict, is_prod_like: bool) -> list:
    expected_provider = cfg.get("thresholds", {}).get("repos", {}).get("expected_git_provider", "azureDevOpsServices")
    require_pinned = cfg.get("thresholds", {}).get("repos", {}).get("require_pinned_ref_in_prod", True)

    repos = list(client.get_pages("/api/2.0/repos", {}, items_key="repos"))
    if not repos:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="JOB-006",
                title="Databricks Repos <-> Azure DevOps linkage",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail="No Databricks Repos are checked out in this workspace.",
                recommendation="Use Databricks Repos (synced from Azure DevOps) for all deployed code rather than notebooks edited directly in the workspace.",
            )
        ]

    wrong_provider = [r for r in repos if r.get("provider") != expected_provider]
    unpinned_prod = [r for r in repos if r.get("branch") and not r.get("tag")] if is_prod_like and require_pinned else []

    findings = []
    if wrong_provider:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="JOB-006",
                title="Repo provider mismatch",
                status=Status.INFO,
                severity=Severity.LOW,
                detail=f"{len(wrong_provider)} repo(s) use a provider other than {expected_provider}: " + ", ".join(f"{r.get('path')} ({r.get('provider')})" for r in wrong_provider[:10]),
                recommendation="Confirm this is intentional if the client uses multiple git platforms.",
            )
        )
    if unpinned_prod:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="JOB-006b",
                title="Production Repos tracking a mutable branch",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=f"{len(unpinned_prod)} repo(s) in this production-like workspace track a branch rather than a pinned tag/release commit: " + ", ".join(r.get("path", "?") for r in unpinned_prod[:10]),
                recommendation="Pin production Repos checkouts to a release tag (or use a Databricks Asset Bundle deployment) so PROD code changes only on an explicit, reviewed release.",
            )
        )
    if not findings:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="JOB-006",
                title="Databricks Repos <-> Azure DevOps linkage",
                status=Status.PASS,
                detail=f"{len(repos)} repo(s) checked out, all via {expected_provider}" + (", pinned appropriately for this environment." if is_prod_like else "."),
            )
        )
    return findings


def run(client: DatabricksClient, cfg: dict, is_prod_like: bool) -> list:
    limits = cfg.get("limits", {})
    findings: list = []
    findings += run_check(lambda: _job001_retry_timeout(client, limits), category=CATEGORY_LABEL, check_id="JOB-001", title="Retry & timeout hygiene")
    findings += run_check(lambda: _job002_notifications(client, limits, is_prod_like), category=CATEGORY_LABEL, check_id="JOB-002", title="Failure notifications")
    findings += run_check(lambda: _job003_git_source(client, cfg, limits, is_prod_like), category=CATEGORY_LABEL, check_id="JOB-003", title="CI/CD deployment (git_source)")
    findings += run_check(lambda: _job004_run_as(client, cfg, limits, is_prod_like), category=CATEGORY_LABEL, check_id="JOB-004", title="Job run-as identity")
    findings += run_check(lambda: _job005_failure_rate(client, cfg, limits), category=CATEGORY_LABEL, check_id="JOB-005", title="Job run failure rate")
    findings += run_check(lambda: _job006_repos_linkage(client, cfg, is_prod_like), category=CATEGORY_LABEL, check_id="JOB-006", title="Databricks Repos <-> Azure DevOps linkage")
    return findings
