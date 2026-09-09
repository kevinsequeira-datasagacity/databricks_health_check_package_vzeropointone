"""
Turns a flat list of Finding objects into per-category and overall workspace
scores. The model is deliberately simple so a client can sanity-check it by
hand:

  * Every *scorable* finding (PASS / WARN / FAIL -- see utils.Finding) starts
    at 100 points and loses points according to severity: a CRITICAL FAIL
    costs it all, a LOW WARN costs relatively little.
  * A category's score is the mean of its findings' scores.
  * The overall score is the weighted mean of category scores, using the
    weights in config/health_check_config.yaml (so a client can decide that,
    say, Security matters more than cost hygiene without touching code).
  * INFO / N/A / ERROR findings never move the score -- they're evidence,
    not judgements -- but ERROR findings are surfaced separately so a
    reader knows a category's score may be based on partial coverage.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .utils import Finding, Status

DEFAULT_GRADE_BANDS = [
    (90, "A - Healthy"),
    (75, "B - Minor issues"),
    (60, "C - Needs attention"),
    (40, "D - At risk"),
    (0, "F - Critical issues"),
]


def grade_for(score: float, bands=None) -> str:
    for threshold, label in bands or DEFAULT_GRADE_BANDS:
        if score >= threshold:
            return label
    return (bands or DEFAULT_GRADE_BANDS)[-1][1]


@dataclass
class CategoryScore:
    key: str
    label: str
    weight: float
    score: float
    grade: str
    total_checks: int
    passed: int
    warned: int
    failed: int
    errored: int
    findings: list = field(default_factory=list)


@dataclass
class WorkspaceScorecard:
    workspace_name: str
    environment: str
    overall_score: float
    overall_grade: str
    categories: list  # list[CategoryScore]
    generated_at: str
    coverage_notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "workspace_name": self.workspace_name,
            "environment": self.environment,
            "overall_score": round(self.overall_score, 1),
            "overall_grade": self.overall_grade,
            "generated_at": self.generated_at,
            "coverage_notes": self.coverage_notes,
            "categories": [
                {
                    "key": c.key,
                    "label": c.label,
                    "weight": c.weight,
                    "score": round(c.score, 1),
                    "grade": c.grade,
                    "total_checks": c.total_checks,
                    "passed": c.passed,
                    "warned": c.warned,
                    "failed": c.failed,
                    "errored": c.errored,
                    "findings": [f.to_dict() for f in c.findings],
                }
                for c in self.categories
            ],
        }


def _score_category(findings: list) -> float:
    scorable = [f for f in findings if f.is_scorable()]
    if not scorable:
        return 100.0
    total_penalty = sum(f.penalty() for f in scorable)
    avg_penalty = total_penalty / len(scorable)
    return max(0.0, min(100.0, 100.0 * (1.0 - avg_penalty)))


def build_scorecard(
    *,
    workspace_name: str,
    environment: str,
    findings_by_category: dict,   # {category_key: {"label": str, "weight": float, "findings": [Finding, ...]}}
    generated_at: str,
    grade_bands=None,
) -> WorkspaceScorecard:
    categories: list[CategoryScore] = []
    coverage_notes: list[str] = []

    for key, spec in findings_by_category.items():
        findings = spec["findings"]
        label = spec.get("label", key)
        weight = spec.get("weight", 0.0)

        passed = sum(1 for f in findings if f.status == Status.PASS)
        warned = sum(1 for f in findings if f.status == Status.WARN)
        failed = sum(1 for f in findings if f.status == Status.FAIL)
        errored = sum(1 for f in findings if f.status == Status.ERROR)

        score = _score_category(findings)
        cat = CategoryScore(
            key=key,
            label=label,
            weight=weight,
            score=score,
            grade=grade_for(score, grade_bands),
            total_checks=passed + warned + failed,
            passed=passed,
            warned=warned,
            failed=failed,
            errored=errored,
            findings=findings,
        )
        categories.append(cat)

        if errored:
            coverage_notes.append(
                f"{label}: {errored} check(s) could not be evaluated (see ERROR findings) "
                "-- this category's score may not reflect full coverage."
            )

    total_weight = sum(c.weight for c in categories) or 1.0
    overall = sum(c.score * c.weight for c in categories) / total_weight

    return WorkspaceScorecard(
        workspace_name=workspace_name,
        environment=environment,
        overall_score=overall,
        overall_grade=grade_for(overall, grade_bands),
        categories=categories,
        generated_at=generated_at,
        coverage_notes=coverage_notes,
    )
