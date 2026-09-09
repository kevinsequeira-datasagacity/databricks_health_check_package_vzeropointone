"""
Renders a WorkspaceScorecard (see scoring.py) into a single self-contained
HTML report: no external CSS/JS/fonts, safe to open offline, safe to embed
with Databricks' `displayHTML()`, and safe to email or hand to a client.

Color usage follows a fixed status palette (never re-themed): green = good,
amber = warning, orange = serious, red = critical -- and every status is
always paired with an icon + text label, never color alone, per
accessibility guidance. Category bars use the categorical palette in a
fixed hue order (Security=blue, Compute=orange, Data=aqua, Jobs=yellow) so
the same category is always the same color across a report.
"""
from __future__ import annotations

import html as _html

from .scoring import WorkspaceScorecard, CategoryScore
from .utils import Status, Severity, Finding

# ---- palette (validated defaults; see the package's dataviz reference) ----

_STATUS_COLOR = {
    Status.PASS: "#0ca30c",
    Status.WARN: "#fab219",
    Status.FAIL: "#d03b3b",
    Status.ERROR: "#898781",
    Status.INFO: "#2a78d6",
    Status.NOT_APPLICABLE: "#898781",
}
_STATUS_ICON = {
    Status.PASS: "✓",       # check
    Status.WARN: "⚠",       # warning triangle
    Status.FAIL: "✕",       # x
    Status.ERROR: "ⓘ",      # (i) circled
    Status.INFO: "ℹ",       # info
    Status.NOT_APPLICABLE: "–",  # en-dash
}
_STATUS_ORDER = [Status.FAIL, Status.WARN, Status.ERROR, Status.INFO, Status.PASS, Status.NOT_APPLICABLE]

_SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}

# Fixed categorical order -- one hue per category key, stable across runs.
_CATEGORY_HUE = {
    "security_iam": ("#2a78d6", "#3987e5"),      # blue
    "compute": ("#eb6834", "#d95926"),           # orange
    "unity_catalog": ("#1baf7a", "#199e70"),     # aqua
    "jobs_cicd": ("#eda100", "#c98500"),         # yellow
}
_DEFAULT_HUE = ("#4a3aa7", "#9085e9")  # violet, for any category outside the fixed four


def _e(s) -> str:
    return _html.escape("" if s is None else str(s))


def _score_status_color(score: float) -> str:
    if score >= 85:
        return "#0ca30c"
    if score >= 70:
        return "#fab219"
    if score >= 50:
        return "#ec835a"
    return "#d03b3b"


CSS = r"""
<style>
  .hc-root {
    color-scheme: light;
    --surface-1:   #fcfcfb;
    --surface-2:   #f9f9f7;
    --text-1:      #0b0b0b;
    --text-2:      #52514e;
    --text-muted:  #898781;
    --grid:        #e1e0d9;
    --baseline:    #c3c2b7;
    --border:      rgba(11,11,11,0.10);
    --card-bg:     #ffffff;
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    background: var(--surface-2);
    color: var(--text-1);
    padding: 32px 16px 64px;
    line-height: 1.45;
  }
  @media (prefers-color-scheme: dark) {
    .hc-root { color-scheme: dark;
      --surface-1: #1a1a19; --surface-2: #0d0d0d; --text-1: #ffffff;
      --text-2: #c3c2b7; --text-muted: #898781; --grid: #2c2c2a;
      --baseline: #383835; --border: rgba(255,255,255,0.10); --card-bg: #202020;
    }
  }
  .hc-root * { box-sizing: border-box; }
  .hc-wrap { max-width: 1080px; margin: 0 auto; }
  .hc-header { display:flex; justify-content:space-between; align-items:flex-end; flex-wrap:wrap; gap:12px; margin-bottom:24px; }
  .hc-header h1 { font-size: 22px; margin: 0 0 4px; }
  .hc-header .sub { color: var(--text-2); font-size: 13px; }
  .hc-badge { display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; background: var(--surface-1); border:1px solid var(--border); color: var(--text-2); }
  .hc-card { background: var(--card-bg); border:1px solid var(--border); border-radius:12px; padding:20px 24px; margin-bottom:20px; }
  .hc-hero { display:flex; gap:32px; align-items:center; flex-wrap:wrap; }
  .hc-score { font-size:56px; font-weight:700; font-variant-numeric: tabular-nums; line-height:1; }
  .hc-grade { font-size:15px; font-weight:600; margin-top:6px; }
  .hc-hero-meta { color: var(--text-2); font-size: 13px; max-width: 480px; }
  .hc-cat-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(230px,1fr)); gap:16px; margin-top: 8px; }
  .hc-cat { }
  .hc-cat-top { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:6px; }
  .hc-cat-label { font-size:13px; font-weight:600; color: var(--text-1); }
  .hc-cat-score { font-size:13px; font-variant-numeric: tabular-nums; color: var(--text-2); }
  .hc-bar-track { height:8px; border-radius:4px; background: var(--grid); overflow:hidden; }
  .hc-bar-fill { height:100%; border-radius:4px; }
  .hc-cat-counts { margin-top:6px; font-size:11.5px; color: var(--text-muted); }
  .hc-section-title { font-size:16px; font-weight:700; margin: 32px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--grid); }
  table.hc-findings { width:100%; border-collapse: collapse; font-size: 13px; }
  table.hc-findings th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.03em; color: var(--text-muted); font-weight:600; padding: 6px 10px; border-bottom:1px solid var(--grid); }
  table.hc-findings td { padding: 10px; border-bottom:1px solid var(--grid); vertical-align: top; }
  table.hc-findings tr:last-child td { border-bottom:none; }
  .hc-status-chip { display:inline-flex; align-items:center; gap:5px; font-size:11.5px; font-weight:700; padding:2px 8px; border-radius:6px; white-space:nowrap; }
  .hc-sev { font-size:11px; color: var(--text-muted); }
  .hc-check-id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:11px; color: var(--text-muted); }
  .hc-title-cell { font-weight:600; }
  .hc-detail { color: var(--text-2); margin-top:2px; }
  .hc-reco { margin-top:4px; font-size:12.5px; }
  .hc-reco b { color: var(--text-1); }
  details.hc-collapse summary { cursor:pointer; font-size:13px; color: var(--text-2); padding: 8px 0; }
  .hc-notes { font-size:12.5px; color: var(--text-2); background: var(--surface-1); border:1px solid var(--border); border-radius:8px; padding:12px 16px; margin-top:10px; }
  .hc-reco-list { list-style:none; margin:0; padding:0; }
  .hc-reco-list li { padding:10px 0; border-bottom:1px solid var(--grid); font-size:13px; }
  .hc-reco-list li:last-child { border-bottom:none; }
  .hc-footer { margin-top:40px; font-size:11.5px; color: var(--text-muted); text-align:center; }
</style>
"""


def _status_chip(status: Status) -> str:
    # Text stays in the primary-ink token for legibility (some status hues,
    # e.g. warning amber, are intentionally low-contrast as *text* per the
    # palette spec); the status hue carries identity via the icon glyph and
    # the tinted background instead, per "never color alone".
    color = _STATUS_COLOR.get(status, "#898781")
    icon = _STATUS_ICON.get(status, "")
    return (
        f'<span class="hc-status-chip" style="background:{color}26; color:var(--text-1);">'
        f'<span style="color:{color};">{icon}</span> {_e(status.value)}</span>'
    )


def _finding_row(f: Finding) -> str:
    sev = f"<span class='hc-sev'>{_e(_SEVERITY_LABEL.get(f.severity, f.severity.value))}</span>" if f.status in (Status.WARN, Status.FAIL) else ""
    reco = f'<div class="hc-reco"><b>Recommendation:</b> {_e(f.recommendation)}</div>' if f.recommendation else ""
    resource = f' <span class="hc-check-id">[{_e(f.resource)}]</span>' if f.resource else ""
    return f"""
      <tr>
        <td>{_status_chip(f.status)}<br/>{sev}</td>
        <td class="hc-check-id">{_e(f.check_id)}</td>
        <td>
          <div class="hc-title-cell">{_e(f.title)}{resource}</div>
          <div class="hc-detail">{_e(f.detail)}</div>
          {reco}
        </td>
      </tr>
    """


def _category_findings_table(cat: CategoryScore) -> str:
    by_status = {s: [] for s in _STATUS_ORDER}
    for f in cat.findings:
        by_status.setdefault(f.status, []).append(f)

    actionable = [f for f in cat.findings if f.status in (Status.FAIL, Status.WARN)]
    other = [f for f in cat.findings if f.status not in (Status.FAIL, Status.WARN, Status.PASS)]
    passed = [f for f in cat.findings if f.status == Status.PASS]

    rows_actionable = "".join(_finding_row(f) for f in sorted(actionable, key=lambda x: _STATUS_ORDER.index(x.status)))
    rows_other = "".join(_finding_row(f) for f in other)
    rows_passed = "".join(_finding_row(f) for f in passed)

    table_head = """
      <table class="hc-findings">
        <thead><tr><th style="width:110px">Status</th><th style="width:80px">Check</th><th>Finding</th></tr></thead>
        <tbody>
    """
    parts = [f'<div class="hc-section-title">{_e(cat.label)}</div>']
    if rows_actionable:
        parts.append(table_head + rows_actionable + "</tbody></table>")
    if rows_other:
        parts.append(
            "<details class='hc-collapse'><summary>"
            f"{len(other)} informational note(s)</summary>"
            + table_head + rows_other + "</tbody></table></details>"
        )
    if rows_passed:
        parts.append(
            "<details class='hc-collapse'><summary>"
            f"{len(passed)} passing check(s)</summary>"
            + table_head + rows_passed + "</tbody></table></details>"
        )
    if not actionable and not other and not passed:
        parts.append("<p style='color:var(--text-muted); font-size:13px;'>No findings recorded for this category.</p>")
    return "".join(parts)


def _category_card_block(cat: CategoryScore) -> str:
    hue = _CATEGORY_HUE.get(cat.key, _DEFAULT_HUE)[0]
    pct = max(0, min(100, cat.score))
    return f"""
      <div class="hc-cat">
        <div class="hc-cat-top">
          <span class="hc-cat-label">{_e(cat.label)}</span>
          <span class="hc-cat-score">{cat.score:.0f}/100 &middot; {_e(cat.grade)}</span>
        </div>
        <div class="hc-bar-track"><div class="hc-bar-fill" style="width:{pct:.0f}%; background:{hue};"></div></div>
        <div class="hc-cat-counts">
          {cat.passed} passed &middot; {cat.warned} warnings &middot; {cat.failed} failed
          {f" &middot; {cat.errored} not evaluated" if cat.errored else ""}
        </div>
      </div>
    """


def _priority_actions(scorecard: WorkspaceScorecard, limit: int = 12) -> str:
    all_findings = []
    for cat in scorecard.categories:
        all_findings.extend(cat.findings)
    actionable = [f for f in all_findings if f.status in (Status.FAIL, Status.WARN)]

    sev_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    status_rank = {Status.FAIL: 0, Status.WARN: 1}
    actionable.sort(key=lambda f: (status_rank.get(f.status, 9), sev_rank.get(f.severity, 9)))

    if not actionable:
        return "<p style='color:var(--text-muted); font-size:13px;'>No FAIL or WARN findings -- nothing to prioritise.</p>"

    items = []
    for f in actionable[:limit]:
        items.append(
            f"""<li>
              {_status_chip(f.status)} <span class="hc-sev">{_e(_SEVERITY_LABEL.get(f.severity, ''))}</span>
              &middot; <span class="hc-check-id">{_e(f.check_id)}</span> &middot; <b>{_e(f.category)}</b><br/>
              <div class="hc-title-cell" style="margin-top:2px;">{_e(f.title)}</div>
              <div class="hc-detail">{_e(f.detail)}</div>
              {f'<div class="hc-reco"><b>Recommendation:</b> {_e(f.recommendation)}</div>' if f.recommendation else ''}
            </li>"""
        )
    more = len(actionable) - limit
    tail = f"<p style='color:var(--text-muted); font-size:12.5px; margin-top:8px;'>+ {more} more finding(s) below, by category.</p>" if more > 0 else ""
    return f"<ul class='hc-reco-list'>{''.join(items)}</ul>{tail}"


def _grade_badge(score: float, grade: str) -> str:
    # Same "tint background + colored icon, primary-ink text" pattern as
    # _status_chip, so the grade badge stays legible even where the status
    # hue itself (e.g. warning amber) is low-contrast as text.
    color = _score_status_color(score)
    return (
        f'<span class="hc-status-chip" style="background:{color}26; color:var(--text-1); '
        f'font-size:13px; padding:4px 12px;"><span style="color:{color};">&#9679;</span> {_e(grade)}</span>'
    )


def render_html_report(scorecard: WorkspaceScorecard, *, subtitle: str = "", package_version: str = "1.0.0") -> str:
    coverage_html = ""
    if scorecard.coverage_notes:
        coverage_html = (
            "<div class='hc-notes'><b>Coverage notes:</b><ul style='margin:6px 0 0 18px; padding:0;'>"
            + "".join(f"<li>{_e(n)}</li>" for n in scorecard.coverage_notes)
            + "</ul></div>"
        )

    cat_cards = "".join(_category_card_block(c) for c in scorecard.categories)
    cat_findings = "".join(_category_findings_table(c) for c in scorecard.categories)
    priority = _priority_actions(scorecard)

    body = f"""
    <div class="hc-root">
      <div class="hc-wrap">
        <div class="hc-header">
          <div>
            <h1>Databricks Workspace Health Check</h1>
            <div class="sub">{_e(scorecard.workspace_name)}{(' &middot; ' + _e(subtitle)) if subtitle else ''}</div>
          </div>
          <div style="text-align:right;">
            <span class="hc-badge">{_e(scorecard.environment.upper())}</span>
            <div class="sub" style="margin-top:6px;">Generated {_e(scorecard.generated_at)}</div>
          </div>
        </div>

        <div class="hc-card">
          <div class="hc-hero">
            <div>
              <div class="hc-score">{scorecard.overall_score:.0f}<span style="font-size:20px; color:var(--text-muted); font-weight:500;">/100</span></div>
              <div class="hc-grade">{_grade_badge(scorecard.overall_score, scorecard.overall_grade)}</div>
            </div>
            <div class="hc-hero-meta">
              Overall score is the weighted average of the category scores below, using the
              category weights configured for this health check. A category with checks that
              could not be evaluated (see coverage notes) may not reflect full coverage.
            </div>
          </div>
          <div class="hc-cat-grid">{cat_cards}</div>
          {coverage_html}
        </div>

        <div class="hc-card">
          <div class="hc-section-title" style="margin-top:0;">Priority actions</div>
          {priority}
        </div>

        <div class="hc-card">
          {cat_findings}
        </div>

        <div class="hc-footer">
          Databricks Workspace Health Check package v{_e(package_version)} &middot;
          Generated for internal review -- verify high-impact findings before acting on them.
        </div>
      </div>
    </div>
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Databricks Health Check - {_e(scorecard.workspace_name)}</title>
{CSS}
</head>
<body style="margin:0;">
{body}
</body>
</html>
"""
