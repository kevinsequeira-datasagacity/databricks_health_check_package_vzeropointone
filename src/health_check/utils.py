"""
Shared primitives used by every check module: the Finding record, status /
severity enums, and small defensive helpers so that one flaky API call never
takes down the whole health check run.
"""
from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger("health_check")


class Status(str, Enum):
    """Outcome of a single check."""
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"          # not a pass/fail judgement, e.g. "here's what we found"
    NOT_APPLICABLE = "N/A"
    ERROR = "ERROR"        # the check itself couldn't run (permissions, API error, etc.)


class Severity(str, Enum):
    """How much a WARN/FAIL should weigh against the score."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Severity is only meaningful for WARN/FAIL; PASS/INFO/N/A/ERROR findings are
# still recorded (for the evidence trail) but don't cost any points.
_SCORABLE_STATUSES = {Status.PASS, Status.WARN, Status.FAIL}

_SEVERITY_PENALTY = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.45,
    Severity.LOW: 0.2,
    Severity.INFO: 0.0,
}


@dataclass
class Finding:
    """One evaluated check result."""
    category: str                  # e.g. "Security & IAM"
    check_id: str                  # stable machine id, e.g. "SEC-004"
    title: str                     # short human title
    status: Status
    severity: Severity = Severity.INFO
    detail: str = ""               # what we found, in plain language
    recommendation: str = ""       # what to do about it (blank for PASS/INFO)
    evidence: dict = field(default_factory=dict)   # raw-ish supporting data, kept small
    resource: Optional[str] = None  # the specific cluster/job/table/etc. this is about

    def is_scorable(self) -> bool:
        return self.status in _SCORABLE_STATUSES

    def penalty(self) -> float:
        """0.0 (no penalty) .. 1.0 (full penalty) for this single finding."""
        if self.status == Status.PASS:
            return 0.0
        if self.status != Status.FAIL and self.status != Status.WARN:
            return 0.0
        base = _SEVERITY_PENALTY.get(self.severity, 0.45)
        # A WARN costs half of what an equivalent-severity FAIL costs.
        return base if self.status == Status.FAIL else base * 0.5

    def to_dict(self) -> dict:
        d = {
            "category": self.category,
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "resource": self.resource,
            "evidence": self.evidence,
        }
        return d


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def parse_epoch_ms(value: Optional[int]) -> Optional[_dt.datetime]:
    if value is None or value in (-1, 0):
        return None
    try:
        return _dt.datetime.fromtimestamp(value / 1000.0, tz=_dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def days_since(dt: Optional[_dt.datetime]) -> Optional[float]:
    if dt is None:
        return None
    return (utcnow() - dt).total_seconds() / 86400.0


def safe_get(d: Optional[dict], *path, default=None):
    """Nested dict.get() that never raises on a missing/None link in the path."""
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def run_check(
    fn: Callable[[], list],
    *,
    category: str,
    check_id: str,
    title: str,
) -> list:
    """
    Execute a single check function, catching anything it raises and turning
    it into an ERROR finding rather than aborting the whole health check.
    Every check module wraps its individual `_checkXXX()` functions with this.
    """
    try:
        result = fn()
        return result or []
    except PermissionError as exc:
        logger.warning("Permission denied for %s (%s): %s", check_id, title, exc)
        return [
            Finding(
                category=category,
                check_id=check_id,
                title=title,
                status=Status.ERROR,
                severity=Severity.INFO,
                detail=(
                    "Could not evaluate this check: the identity running the "
                    f"notebook does not have permission to call the required API. ({exc})"
                ),
                recommendation=(
                    "Re-run this health check as a workspace admin (or an admin "
                    "service principal) to get full coverage of this category."
                ),
            )
        ]
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        logger.exception("Check %s (%s) failed", check_id, title)
        return [
            Finding(
                category=category,
                check_id=check_id,
                title=title,
                status=Status.ERROR,
                severity=Severity.INFO,
                detail=f"Check raised an unexpected error: {exc!r}",
                recommendation="See the notebook run log / driver stderr for the full traceback.",
            )
        ]


def chunked(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i : i + size]
