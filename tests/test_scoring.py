import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from health_check.utils import Finding, Status, Severity
from health_check.scoring import build_scorecard, grade_for, DEFAULT_GRADE_BANDS


def _findings_by_category(**overrides):
    base = {
        "security_iam": {"label": "Security & IAM", "weight": 0.3, "findings": []},
        "compute_cost": {"label": "Compute & Cost Hygiene", "weight": 0.25, "findings": []},
        "data_governance": {"label": "Data Governance", "weight": 0.25, "findings": []},
        "jobs_devops": {"label": "Jobs, Workflows & DevOps", "weight": 0.2, "findings": []},
    }
    for key, findings in overrides.items():
        base[key]["findings"] = findings
    return base


def test_all_pass_scores_100():
    findings = [
        Finding(category="Security & IAM", check_id="SEC-001", title="t1", status=Status.PASS),
        Finding(category="Security & IAM", check_id="SEC-002", title="t2", status=Status.PASS),
    ]
    scorecard = build_scorecard(
        workspace_name="ws",
        environment="dev",
        findings_by_category=_findings_by_category(security_iam=findings),
        generated_at="now",
    )
    sec = next(c for c in scorecard.categories if c.key == "security_iam")
    assert sec.score == 100.0
    assert scorecard.overall_score == 100.0
    assert scorecard.overall_grade == grade_for(100.0)


def test_critical_fail_tanks_category_score():
    findings = [
        Finding(category="Security & IAM", check_id="SEC-001", title="t1", status=Status.FAIL, severity=Severity.CRITICAL),
    ]
    scorecard = build_scorecard(
        workspace_name="ws",
        environment="prod",
        findings_by_category=_findings_by_category(security_iam=findings),
        generated_at="now",
    )
    sec = next(c for c in scorecard.categories if c.key == "security_iam")
    assert sec.score == 0.0
    assert sec.failed == 1
    assert sec.grade == "F - Critical issues"


def test_info_and_error_findings_do_not_affect_score():
    findings = [
        Finding(category="Security & IAM", check_id="SEC-001", title="t1", status=Status.PASS),
        Finding(category="Security & IAM", check_id="SEC-002", title="t2", status=Status.INFO),
        Finding(category="Security & IAM", check_id="SEC-003", title="t3", status=Status.ERROR),
        Finding(category="Security & IAM", check_id="SEC-004", title="t4", status=Status.NOT_APPLICABLE),
    ]
    scorecard = build_scorecard(
        workspace_name="ws",
        environment="dev",
        findings_by_category=_findings_by_category(security_iam=findings),
        generated_at="now",
    )
    sec = next(c for c in scorecard.categories if c.key == "security_iam")
    assert sec.score == 100.0  # only the single PASS is scorable, and it costs nothing
    assert sec.errored == 1


def test_warn_costs_less_than_fail_at_same_severity():
    warn_findings = [Finding(category="c", check_id="X-1", title="t", status=Status.WARN, severity=Severity.HIGH)]
    fail_findings = [Finding(category="c", check_id="X-1", title="t", status=Status.FAIL, severity=Severity.HIGH)]

    warn_card = build_scorecard(
        workspace_name="ws", environment="dev",
        findings_by_category=_findings_by_category(security_iam=warn_findings), generated_at="now",
    )
    fail_card = build_scorecard(
        workspace_name="ws", environment="dev",
        findings_by_category=_findings_by_category(security_iam=fail_findings), generated_at="now",
    )
    warn_score = next(c for c in warn_card.categories if c.key == "security_iam").score
    fail_score = next(c for c in fail_card.categories if c.key == "security_iam").score
    assert warn_score > fail_score


def test_overall_score_is_weighted_average():
    # security_iam weight 0.3 at score 0, everything else empty (=100).
    findings = [Finding(category="c", check_id="X", title="t", status=Status.FAIL, severity=Severity.CRITICAL)]
    scorecard = build_scorecard(
        workspace_name="ws", environment="dev",
        findings_by_category=_findings_by_category(security_iam=findings),
        generated_at="now",
    )
    # 0*0.3 + 100*0.25 + 100*0.25 + 100*0.2 = 70
    assert abs(scorecard.overall_score - 70.0) < 1e-9


def test_grade_bands_are_monotonic_and_cover_zero_to_hundred():
    thresholds = sorted((t for t, _ in DEFAULT_GRADE_BANDS), reverse=True)
    assert thresholds[-1] == 0
    for score in (0, 39, 40, 59, 60, 74, 75, 89, 90, 100):
        # should never raise / should always resolve to a label
        assert grade_for(score)
