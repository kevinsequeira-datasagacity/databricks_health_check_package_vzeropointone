"""
Thin helpers around `databricks.sdk.WorkspaceClient`.

Design goals:
  * Zero extra config to run inside a Databricks notebook: `WorkspaceClient()`
    with no arguments auto-detects the notebook's own native auth (the
    "Databricks native authentication" flow the SDK resolves automatically
    when code runs on a Databricks cluster) -- nothing to paste into the
    notebook or a secret scope for a baseline run. Outside Databricks (local
    dev, CI, `pytest`), the SDK falls back to its standard resolution order
    (DATABRICKS_HOST/DATABRICKS_TOKEN env vars, a ~/.databrickscfg profile,
    Azure CLI, etc.) -- see WorkspaceClient(profile="...") if you need to
    point this at a specific workspace explicitly for local testing.
  * `is_admin_scope()` lets checks that need workspace-admin rights (token
    inventory, org-wide token policy) degrade to an informational finding
    instead of crashing, exactly like the REST-based sibling package.
"""
from __future__ import annotations

from databricks.sdk import WorkspaceClient

from .utils import DatabricksError, PermissionDenied


def get_workspace_client(profile: str | None = None) -> WorkspaceClient:
    """
    Returns a WorkspaceClient. Inside a Databricks notebook, call this with
    no arguments. `profile` is only for running the package outside
    Databricks (local dev against a ~/.databrickscfg profile).
    """
    if profile:
        return WorkspaceClient(profile=profile)
    return WorkspaceClient()


def is_admin_scope(w: WorkspaceClient) -> bool:
    """Best-effort: can we call an admin-only endpoint with this identity?"""
    try:
        next(iter(w.token_management.list()), None)
        return True
    except PermissionDenied:
        return False
    except DatabricksError:
        # Unexpected but non-auth error -- don't assume either way, but
        # don't block the caller either.
        return False


def whoami(w: WorkspaceClient) -> dict:
    from .utils import to_dict

    try:
        return to_dict(w.current_user.me())
    except DatabricksError:
        return {}


def workspace_host(w: WorkspaceClient) -> str:
    host = getattr(w.config, "host", None) or ""
    return host.rstrip("/")
