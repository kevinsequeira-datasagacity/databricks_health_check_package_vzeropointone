"""
Databricks Workspace Health Check
=================================

A self-contained package for running a technical health check against a
single Azure Databricks workspace, covering:

  * Security & Identity (Entra ID / SCIM, tokens, secrets, network, policies)
  * Compute & cost hygiene (clusters, pools, SQL warehouses, tagging)
  * Data governance (Unity Catalog: catalogs, grants, external locations, Delta health)
  * Jobs, workflows & DevOps (job hygiene, Azure DevOps / Repos integration)

See notebooks/run_health_check.py for the entry point, and
docs/deployment_guide.md for how to roll this out across DEV / TEST /
PRE-PROD / PROD workspaces via Databricks Repos synced from Azure DevOps.
"""

__version__ = "1.0.0"
