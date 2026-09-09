import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from health_check_sdk.utils import Finding, Status, Severity
from health_check_sdk.scoring import build_scorecard
from health_check_sdk.report import render_html_report


def _demo_scorecard():
    findings_by_category = {
        "security_iam": {
            "label": "Security & IAM",
            "weight": 0.3,
            "findings": [
                Finding(category="Security & IAM", check_id="SEC-001", title="Entra ID / SCIM group sync", status=Status.PASS, detail="ok"),
                Finding(category="Security & IAM", check_id="SEC-003", title="Personal access token hygiene", status=Status.FAIL, severity=Severity.HIGH, detail="tokens never expire", recommendation="rotate them"),
            ],
        },
        "compute": {
            "label": "Compute",
            "weight": 0.25,
            "findings": [
                Finding(category="Compute", check_id="CMP-001", title="Autotermination", status=Status.WARN, severity=Severity.MEDIUM, detail="some clusters idle forever", recommendation="set autotermination"),
            ],
        },
        "unity_catalog": {"label": "Unity Catalog", "weight": 0.25, "findings": []},
        "jobs_cicd": {"label": "Jobs & CI/CD", "weight": 0.2, "findings": []},
    }
    return build_scorecard(
        workspace_name="Acme-PROD",
        environment="prod",
        findings_by_category=findings_by_category,
        generated_at="2026-09-09 00:00 UTC",
    )


def test_report_renders_without_error_and_contains_key_content():
    scorecard = _demo_scorecard()
    html = render_html_report(scorecard, subtitle="Account host: https://adb-123.7.azuredatabricks.net")

    assert html.startswith("<!DOCTYPE html>")
    assert "Acme-PROD" in html
    assert "SEC-003" in html
    assert "rotate them" in html
    assert f"{scorecard.overall_score:.0f}" in html


def test_report_escapes_html_in_findings():
    findings_by_category = {
        "security_iam": {
            "label": "Security & IAM",
            "weight": 1.0,
            "findings": [
                Finding(
                    category="Security & IAM",
                    check_id="SEC-999",
                    title="<script>alert(1)</script>",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    detail="<img src=x onerror=alert(1)>",
                ),
            ],
        },
    }
    scorecard = build_scorecard(
        workspace_name="ws", environment="dev", findings_by_category=findings_by_category, generated_at="now",
    )
    html = render_html_report(scorecard)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
