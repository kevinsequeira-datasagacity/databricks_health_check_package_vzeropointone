# Databricks Workspace Health Check

A self-contained package that runs a technical health check against a single
Azure Databricks workspace and produces a scored HTML report. Built for a
client with four workspaces (DEV / TEST / PRE-PROD / PROD) under one Azure
Databricks account, Entra ID -> SCIM group sync for IAM, and Azure DevOps as
the git platform -- but the checks are generic enough to reuse elsewhere.

Runs entirely inside the Databricks UI: import the notebook, attach a
cluster, fill in a few widgets, **Run All**. No external server, no PAT to
provision for a baseline run (it authenticates as whoever runs the notebook).

## What it checks

| Category | Weight (default) | Examples |
|---|---|---|
| Security & IAM | 30% | Entra ID/SCIM group sync, admin group membership, PAT lifetime, secret scope backing/ACLs, IP access lists, cluster policy enforcement, org-wide token policy |
| Compute & Cost Hygiene | 25% | Cluster autotermination, DBR version currency, cluster policy attachment rate, cost-allocation tagging, instance pool sizing, SQL warehouse auto-stop, job-cluster vs. all-purpose usage |
| Data Governance (Unity Catalog) | 25% | Catalog inventory & isolation, broad catalog-level grants, external location/storage credential hygiene, Delta table small-file sampling, system schema enablement |
| Jobs, Workflows & DevOps | 20% | Retry/timeout hygiene, failure notifications, git-source (CI/CD) deployment, run-as identity, job failure rate, Databricks Repos <-> Azure DevOps linkage & ref pinning |

Every individual check is documented in the corresponding module under
`src/health_check/checks/` -- read the docstring at the top of each file for
the full list and rationale. Weights and thresholds live in
`config/health_check_config.yaml` and can be tuned per client without
touching code.

See `docs/sample_report.html` for what the generated report looks like
(rendered from synthetic data, not a real workspace).

## Quick start (per workspace)

1. Push this repo to Azure DevOps (see `docs/deployment_guide.md` for the
   one-time setup).
2. In each of the 4 workspaces: **Repos -> Add Repo**, point it at the Azure
   DevOps repo, and check out the branch/tag you want that workspace to run.
3. Open `notebooks/run_health_check.py` from the checked-out repo, attach any
   cluster, set the `environment` widget (`dev`/`test`/`preprod`/`prod`) and
   **Run All**.
4. The report renders inline in the notebook and is saved as an `.html` (plus
   a machine-readable `.json`) under the `output_path` widget's location.

Full deployment options (manual Repos, scheduled Job, Asset Bundle via CI/CD)
are in `docs/deployment_guide.md`.

## Design notes

- **Auth**: `health_check.api_client.client_from_notebook_context()` uses the
  notebook's own execution token -- the same permissions as whoever runs it.
  A handful of checks (PAT inventory, org-wide token policy) need workspace
  admin rights; without them, those checks report `ERROR` with a clear
  "re-run as admin" recommendation rather than failing the whole run.
- **Resilience**: every individual check is wrapped so a single failing API
  call (permissions, transient error, unexpected response shape) turns into
  one `ERROR` finding, not a crashed notebook. See `utils.run_check`.
- **Scoring**: each finding starts at 100 points and loses points by
  severity (`utils.Finding.penalty`); a category's score is the mean of its
  findings, and the overall score is the weighted mean of category scores
  (`scoring.build_scorecard`). See `config/health_check_config.yaml` for the
  weights and grade bands.
- **Environments**: `config/health_check_config.yaml`'s `environment_profiles`
  map decides which checks are held to production-grade expectations (e.g.
  IP access lists, git-source deployment, run-as service principal). PRE-PROD
  and PROD are `is_production_like: true` by default.
- **Report**: `report.render_html_report()` produces one self-contained HTML
  file (inline CSS, no external requests), safe to open offline, embed via
  `displayHTML()`, or email to a client.

## Repo layout

```
databricks-health-check/
├── notebooks/
│   └── run_health_check.py      # the entry point -- run this in the Databricks UI
├── src/health_check/
│   ├── api_client.py             # thin Databricks REST client (notebook-context auth)
│   ├── scoring.py                 # findings -> category/overall scores
│   ├── report.py                  # HTML report renderer
│   ├── utils.py                   # Finding/Status/Severity + run_check() resilience wrapper
│   └── checks/
│       ├── security_iam.py
│       ├── compute_cost.py
│       ├── data_governance.py
│       └── jobs_devops.py
├── config/
│   └── health_check_config.yaml  # weights, thresholds, per-environment profiles
├── tests/                          # unit tests (scoring math, report rendering) -- run locally/CI, not in Databricks
├── docs/
│   └── deployment_guide.md
└── azure-pipelines.yml            # lint + unit tests on PR (does not deploy/run the health check)
```

## Extending it

To add a new check: add a `_XXX_your_check(client, cfg, ...)` function to the
relevant module in `src/health_check/checks/`, return a list of `Finding`
objects (see `utils.Finding`), and register it in that module's `run()`
wrapped in `utils.run_check(...)`. No changes needed elsewhere -- the
scoring and report layers work off the generic `Finding` list.

To add a whole new category: add a module under `checks/`, register its
`run()` in `notebooks/run_health_check.py`'s `findings_by_category` dict, and
add a matching entry (label + weight) under `categories:` in
`config/health_check_config.yaml`.

## Limitations

- The Delta table health check (`DG-004`) requires a running SQL warehouse
  and only samples a bounded number of tables per schema for runtime reasons
  -- treat it as directional, not exhaustive.
- Account-level checks (true SCIM provisioning status, account-wide system
  schema enablement) need an account-admin identity against the accounts API
  host, which is out of scope for a workspace-scoped notebook token; those
  checks report what's visible from the workspace and note where an
  account-level follow-up is needed.
- This reads metadata (configs, permissions, job/run history) only -- it
  never reads table contents.
