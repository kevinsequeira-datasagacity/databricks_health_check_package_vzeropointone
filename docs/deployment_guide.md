# Deployment guide

How to get this package into a workspace via Databricks Repos, and how to
run it. Written for the same 4-workspace (DEV/TEST/PRE-PROD/PROD) setup as
the sibling REST-based package, but works for a single workspace just as
well.

## 1. One-time: push the package to your git platform

Either Azure DevOps or GitHub (both are approved providers by default -- see
`thresholds.repos.expected_git_providers` in `config/health_check_config.yaml`):

```bash
cd databricks-health-check-sdk
git init
git remote add origin <your-azure-devops-or-github-clone-url>
git add .
git commit -m "Initial import: Databricks workspace health check (SDK edition)"
git push -u origin main
```

Tag a release once you're happy with it (e.g. `v1.0.0`) -- PRE-PROD/PROD
Repos should track a tag, not `main` (see `JOB-006` in the report, which
flags this on the client's own repos, and the same principle applies here).

## 2. Per workspace: add the Databricks Repo

1. In the workspace, go to **Repos** (left sidebar) -> **Add Repo**.
2. Git provider: **Azure DevOps Services** or **GitHub**, matching where you
   pushed it. You'll need a Git integration credential configured once per
   workspace under **Settings -> Linked accounts**.
3. Repository URL: the clone URL from step 1.
4. DEV/TEST: check out `main`. PRE-PROD/PROD: check out a specific **tag**
   (e.g. `v1.0.0`), not a branch.
5. The notebook auto-detects `src/health_check_sdk` next to it from its own
   notebook path -- you shouldn't need to configure anything else here.

## 3. Run it

1. Open `notebooks/run_health_check.py` from the checked-out repo.
2. Attach any cluster (a small single-node cluster is plenty).
3. Set the widgets at the top:
   - `environment`: `dev` / `test` / `preprod` / `prod`.
   - `workspace_display_name`: optional, shown in the report header.
   - `sql_warehouse_id`: optional. Supply a running SQL warehouse's ID to
     include the Unity Catalog Delta table health sample (`UC-004`); leave
     blank to skip it (all other checks still run).
   - `output_path`: where the `.html`/`.json` report is written. Defaults to
     `/dbfs/FileStore/health_check_reports`.
4. **Run All**. The report renders inline and is saved to `output_path`.
5. For the fullest Security & IAM coverage (PAT inventory, org-wide token
   policy -- `SEC-003`/`SEC-007`), run this as a **workspace admin**.

No PAT or secret scope setup is needed for a baseline run -- `WorkspaceClient()`
auto-detects the notebook's own identity. This is a change from older
`databrickscfg`-profile-based scripts you may have used before: there's
nothing to configure here for the common case.

## 4. Before trusting it in a client engagement

This package's check logic was verified against a mock `WorkspaceClient`
(see the README's "A note on verification"), not a live workspace, while it
was built. **The first run against a real workspace is your smoke test**:

- Skim the printed summary at the bottom of the run for any `ERROR`
  findings -- those point at a specific check whose SDK method/field name
  needs a small fix for your installed `databricks-sdk` version.
- If a check reports `ERROR` with an unexpected-error message rather than a
  permissions message, open that check's module (named in the printed
  category/check_id), find the failing SDK call, and adjust the method or
  field name to match what your `databricks-sdk` version actually returns
  (`print(to_dict(...))` on the raw SDK object is the fastest way to see the
  real field names).

## 5. Optional: run it on a schedule instead of manually

Same pattern as the REST-based package: wrap `notebooks/run_health_check.py`
in a Databricks Job (widget values as job `base_parameters`) and schedule
it, or deploy it as part of a Databricks Asset Bundle through your CI/CD
pipeline. Keep the schedule light (weekly is usually plenty).

## 6. Reading the output with the client

- The **overall score and grade** is a weighted roll-up; the **Priority
  actions** section (FAIL/WARN findings, sorted by severity) is the actual
  punch list for a health-check engagement.
- **Coverage notes** (if present) mean some checks in a category couldn't be
  evaluated -- usually a permissions issue, occasionally an SDK
  method/field mismatch (see section 4). Re-run as admin, or investigate the
  specific check if the message doesn't look permissions-related.
- Findings carry a `check_id` (e.g. `SEC-004`, `CMP-001`, `UC-002`) that maps
  directly to a function in the corresponding `checks/*.py` module.
