"""
Databricks Workspace Health Check (SDK edition)
================================================

A technical health check for a single Azure Databricks workspace, built on
the official `databricks-sdk` `WorkspaceClient` rather than raw REST calls.
Covers:

  * Security & IAM (Entra ID / SCIM, tokens, secrets, network, policies)
  * Compute (clusters, pools, SQL warehouses, tagging)
  * Jobs & CI/CD (job hygiene, Azure DevOps / GitHub / Repos integration)
  * Unity Catalog (catalogs, grants, external locations, Delta health)

See notebooks/run_health_check.py for the entry point, and
docs/deployment_guide.md for rolling this out across workspaces via
Databricks Repos.

This is a sibling package to `databricks-health-check` (the REST/requests
-based version) -- same checks in spirit, reimplemented against the SDK.
See docs/deployment_guide.md's "Relationship to the REST-based package"
section for when to use which.
"""

__version__ = "1.0.0"
