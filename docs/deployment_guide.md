# Deployment guide

How to get this package into all four workspaces (DEV / TEST / PRE-PROD /
PROD) via Azure DevOps + Databricks Repos, and how to run it.

## 1. One-time: push the package to Azure DevOps

1. Create a new Azure DevOps repo (e.g. `databricks-health-check`) in the
   client's project.
2. Push this package to it as-is:

   ```bash
   cd databricks-health-check
   git init
   git remote add origin https://dev.azure.com/<org>/<project>/_git/databricks-health-check
   git add .
   git commit -m "Initial import: Databricks workspace health check package"
   git push -u origin main
   ```
3. Tag a release once you're happy with it, e.g. `v1.0.0` -- PRE-PROD/PROD
   Repos should track a tag, not `main` (see step 3 below and check `JOB-006`
   in the report, which flags this).
4. (Optional but recommended) Set up branch policies on `main` requiring a
   PR + the `azure-pipelines.yml` build to pass, so changes to the checks
   themselves go through review before reaching any workspace.

## 2. Per workspace: add the Databricks Repo

Repeat for each of the 4 workspaces (DEV, TEST, PRE-PROD, PROD):

1. In the workspace, go to **Repos** (left sidebar) -> **Add Repo**.
2. Git provider: **Azure DevOps Services**. You'll need a Git integration
   token/credential configured once per workspace under
   **Settings -> Linked accounts** (a PAT from Azure DevOps with `Code (Read)`
   scope is enough for read-only sync).
3. Repository URL: the Azure DevOps clone URL from step 1.
4. For DEV/TEST: check out `main` (so they get the latest checks
   automatically).
   For PRE-PROD/PROD: check out a specific **tag** (e.g. `v1.0.0`), not a
   branch -- this is what `JOB-006` in the report checks for on *your
   client's own* jobs/repos, and the same principle applies to this package.
5. Confirm the resulting path so the notebook can find `src/` next to it,
   e.g. `/Workspace/Repos/<you>/databricks-health-check` or a Git folder
   path if your workspace uses the newer "Git folders" UI. You generally
   don't need to do anything else here -- `notebooks/run_health_check.py`
   auto-detects this from its own notebook path.

## 3. Run it

1. Open `notebooks/run_health_check.py` from the checked-out repo.
2. Attach any cluster (a small single-node cluster is plenty -- this reads
   metadata via REST/SQL, it doesn't process data).
3. Set the widgets at the top:
   - `environment`: `dev` / `test` / `preprod` / `prod` -- this drives which
     checks are held to production-grade thresholds (see
     `config/health_check_config.yaml` -> `environment_profiles`).
   - `workspace_display_name`: optional, shown in the report header (e.g.
     `Acme Corp - PROD`). Defaults to a name derived from the workspace URL.
   - `sql_warehouse_id`: optional. Supply a running SQL warehouse's ID to
     include the Delta table health sample (`DG-004`); leave blank to skip
     it (all other checks still run).
   - `output_path`: where the `.html`/`.json` report is written. Defaults to
     `/dbfs/FileStore/health_check_reports` (gives you a workspace URL you
     can open in a browser -- see the notebook's printed output for the
     exact link). Point it at a Unity Catalog Volume path instead if you
     want the report governed alongside your other UC-managed assets.
4. **Run All**. The report renders inline and is saved to `output_path`.
5. For the fullest Security & IAM coverage (PAT inventory, org-wide token
   policy -- `SEC-003`/`SEC-007`), run this as a **workspace admin**. Run as
   any other identity and those two checks report `ERROR` with a note to
   re-run as admin, rather than failing the whole notebook.

Repeat in each workspace. Each run is independent and produces its own
report -- this package intentionally checks "an entire workspace at a time"
rather than trying to aggregate across all four in one run.

## 4. Optional: run it on a schedule instead of manually

If you want a recurring automated health check rather than running it
manually before a client review:

1. **Databricks Job**: create a Job in each workspace with a single
   Notebook task pointing at `notebooks/run_health_check.py` **from the
   Repo path**, with the widget values above set as job parameters
   (`base_parameters`). Schedule it (e.g. weekly). Point the job's failure
   notification at your own inbox/Slack, not the client's, since a WARN/FAIL
   finding is expected output, not a job failure.
2. **Databricks Asset Bundle**: if the client already deploys via Bundles,
   wrap the same Job definition in a `databricks.yml` bundle and deploy it
   through the `azure-pipelines.yml` CI/CD pipeline (add a `databricks
   bundle deploy` stage) so the scheduled health check job itself is
   versioned and deployed the same way as the client's other production
   jobs -- which also means it will show up clean in `JOB-003`/`JOB-006`.

Either way, keep the schedule light (weekly is usually plenty) -- several of
the checks (job run history, Delta table sampling) scale with workspace
size and there's no benefit to running this more often than the environment
actually changes.

## 5. Reading the output with the client

- The **overall score and grade** (top of the report) is a weighted roll-up
  -- useful as a single number to track over time, but the **Priority
  actions** section (FAIL/WARN findings, sorted by severity) is the actual
  punch list for a health-check engagement.
- **Coverage notes** (if present) mean some checks in a category couldn't be
  evaluated -- usually a permissions issue. Re-run as admin, or note the gap
  explicitly in your findings if admin access isn't available for this
  engagement.
- Findings carry a `check_id` (e.g. `SEC-004`, `COST-001`) that maps
  directly to a function in the corresponding `checks/*.py` module, so you
  can always go read exactly what was queried and how the verdict was
  reached -- useful when a client asks "how did you determine this?".
