# Databricks Workspace Health Check (SDK edition)

A technical health check for a single Azure Databricks workspace, built on
the official [`databricks-sdk`](https://pypi.org/project/databricks-sdk/)
`WorkspaceClient` rather than raw REST calls. Runs entirely inside the
Databricks UI: import the notebook, attach a cluster, fill in a few widgets,
**Run All**. No PAT to provision for a baseline run -- `WorkspaceClient()`
auto-detects the notebook's own identity.

See `docs/sample_report.html` for what the generated report looks like
(rendered from synthetic data, not a real workspace).

## What it checks

| Category | Weight (default) | Examples |
|---|---|---|
| Security & IAM | 30% | Entra ID/SCIM group sync, admin group membership, PAT lifetime, secret scope backing/ACLs, IP access lists, cluster policy enforcement, org-wide token policy |
| Compute | 25% | Cluster autotermination, DBR version currency, cluster policy attachment rate, cost-allocation tagging, instance pool sizing, SQL warehouse auto-stop, job-cluster vs. all-purpose usage |
| Unity Catalog | 25% | Catalog inventory & isolation, broad catalog-level grants, external location/storage credential hygiene, Delta table small-file sampling, system schema enablement |
| Jobs & CI/CD | 20% | Retry/timeout hygiene, failure notifications, git-source (Azure DevOps / GitHub) deployment, run-as identity, job failure rate, Databricks Repos linkage & ref pinning |

Every individual check is documented in the corresponding module under
`src/health_check_sdk/checks/` -- read the docstring at the top of each file
for the full list and rationale. Weights and thresholds live in
`config/health_check_config.yaml` and can be tuned per client without
touching code.

## Quick start

1. Push this repo to your git platform (Azure DevOps and/or GitHub -- see
   `docs/deployment_guide.md`).
2. In the workspace: **Repos -> Add Repo**, point it at the repo.
3. Open `notebooks/run_health_check.py` from the checked-out repo, attach any
   cluster, set the `environment` widget (`dev`/`test`/`preprod`/`prod`) and
   **Run All**.
4. The report renders inline in the notebook and is saved as an `.html`
   (plus a machine-readable `.json`) under the `output_path` widget's
   location.

Full deployment options are in `docs/deployment_guide.md`.

## Relationship to the REST-based `databricks-health-check` package

This is a **separate, sibling package**, not a replacement. Both cover the
same ground (Security & IAM, Compute, Jobs/CI-CD, Unity Catalog) and share
the same scoring model and HTML report design; they differ only in how they
talk to the workspace:

- `databricks-health-check` calls the REST API directly via `requests`, with
  a small hand-rolled client (`api_client.py`).
- `databricks-health-check-sdk` (this package) goes through the official
  `databricks-sdk` `WorkspaceClient` for every call, and immediately
  normalizes each typed response to a plain dict with `utils.to_dict()` so
  the check logic itself reads almost identically to the REST version.

Pick whichever fits the client's constraints: the SDK edition is more
idiomatic and gets you typed objects, built-in retries/pagination, and the
SDK's broader auth resolution (config profiles, Azure CLI, OAuth, etc.) for
free; the REST edition has one fewer dependency (`requests` ships with every
Databricks Runtime, `databricks-sdk` needs an install on some older
runtimes) and is easier to read line-by-line if you want to see exactly
which endpoint is being called.

## A note on verification

This package's check *logic* is verified end-to-end against a mock
`WorkspaceClient` (see `tests/mock_workspace_client.py` and
`docs/sample_report.html`, generated from that mock) -- the scoring, report
rendering, and each check's decision logic all run and produce sane output.
What that mock **cannot** verify is that every SDK method name and field
name used below (e.g. `w.groups.list()`, `w.token_management.get_token_policy()`,
a `Group`'s `external_id` attribute) exactly matches the installed
`databricks-sdk` version's real API surface -- that needs a live workspace
and an installed SDK to smoke-test, which wasn't available while building
this. Field names were chosen to match `databricks-sdk`'s well-documented,
stable public API as of early 2026 (SDK dataclasses generally mirror the
REST API's JSON field names via `.as_dict()`), and every check is wrapped in
`utils.run_check()` so a wrong method/field name degrades to a single
`ERROR` finding rather than crashing the notebook -- but **please run this
against a real workspace and skim the printed output / any `ERROR` findings
before relying on it for a client engagement**, and open the specific check
module if one needs a small field-name fix.

## Design notes

- **Auth**: `health_check_sdk.client.get_workspace_client()` returns a
  `WorkspaceClient()` with no arguments -- inside a Databricks notebook this
  uses the SDK's native-auth detection (the identity of whoever runs the
  notebook). A handful of checks (PAT inventory, org-wide token policy) need
  workspace admin rights; without them, those checks report `ERROR` with a
  clear "re-run as admin" recommendation rather than failing the whole run.
- **Normalization**: every SDK return value is passed through
  `utils.to_dict()` before the check logic touches it, so checks work with
  plain dicts (`.get()`, no attribute-access surprises) regardless of which
  SDK dataclass produced the value.
- **Resilience**: every individual check is wrapped so a single failing API
  call (permissions, transient error, unexpected response shape, or a wrong
  method/field name -- see "A note on verification" above) turns into one
  `ERROR` finding, not a crashed notebook. See `utils.run_check`.
- **Scoring**: identical model to the REST-based package -- each finding
  starts at 100 points and loses points by severity; a category's score is
  the mean of its findings; the overall score is the weighted mean of
  category scores. See `config/health_check_config.yaml`.
- **Environments**: `environment_profiles` in the config decides which
  checks are held to production-grade expectations (IP access lists,
  git-source deployment, run-as service principal, ...). PRE-PROD and PROD
  are `is_production_like: true` by default.
- **Git providers**: `JOB-003`/`JOB-006` accept both Azure DevOps and GitHub
  out of the box (`thresholds.repos.expected_git_providers` in the config) --
  add another platform there (and to `_PROVIDER_LABELS` in
  `checks/jobs_cicd.py` for friendly naming) if needed.
- **Report**: `report.render_html_report()` produces one self-contained HTML
  file (inline CSS, no external requests), safe to open offline, embed via
  `displayHTML()`, or email to a client.

## Repo layout

```
databricks-health-check-sdk/
├── notebooks/
│   └── run_health_check.py       # the entry point -- run this in the Databricks UI
├── src/health_check_sdk/
│   ├── client.py                  # WorkspaceClient helpers (get_workspace_client, is_admin_scope, ...)
│   ├── scoring.py                 # findings -> category/overall scores
│   ├── report.py                  # HTML report renderer
│   ├── utils.py                   # Finding/Status/Severity, to_dict() normalizer, run_check() resilience wrapper
│   └── checks/
│       ├── security_iam.py
│       ├── compute.py
│       ├── jobs_cicd.py
│       └── unity_catalog.py
├── config/
│   └── health_check_config.yaml  # weights, thresholds, per-environment profiles
├── tests/                          # unit tests + a MockWorkspaceClient -- run locally/CI, not in Databricks
├── docs/
│   ├── deployment_guide.md
│   └── sample_report.html
└── azure-pipelines.yml            # lint + unit tests on PR (does not deploy/run the health check)
```

## Extending it

To add a new check: add a `_XXX_your_check(w, cfg, ...)` function to the
relevant module in `src/health_check_sdk/checks/`, call the SDK method(s)
you need and pass each result through `to_dict()`, return a list of
`Finding` objects, and register it in that module's `run()` wrapped in
`utils.run_check(...)`. No changes needed elsewhere -- the scoring and
report layers work off the generic `Finding` list.

## Limitations

- The Delta table health check (`UC-004`) requires a running SQL warehouse
  and only samples a bounded number of tables per schema for runtime reasons
  -- treat it as directional, not exhaustive.
- Account-level checks (true SCIM provisioning status, account-wide system
  schema enablement) need an account-admin identity against the accounts API
  host, which is out of scope for a workspace-scoped `WorkspaceClient`; those
  checks report what's visible from the workspace and note where an
  account-level follow-up is needed.
- This reads metadata (configs, permissions, job/run history) only -- it
  never reads table contents.
- See "A note on verification" above -- smoke-test against a real workspace
  before a client engagement.
