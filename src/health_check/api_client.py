"""
Minimal Databricks REST API client used by every check module.

Design goals:
  * Zero extra secrets to manage: by default it authenticates using the
    *notebook's own execution context* (the same token the notebook already
    has as the user/service-principal who ran it), obtained via
    `dbutils.notebook.entry_point.getDbutils().notebook().getContext()`.
    Nothing needs to be pasted into the notebook or a secret scope for a
    baseline run.
  * A handful of checks (token-management, account-level SCIM) require a
    workspace-admin PAT rather than the ambient notebook token. The client
    exposes `is_admin_scope` so those checks can degrade gracefully instead
    of crashing when run by a non-admin.
  * Every call goes through `get`, which turns 401/403 into PermissionError
    (caught by utils.run_check) and retries transient 429/5xx a few times.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

import requests


class DatabricksApiError(RuntimeError):
    pass


@dataclass
class DatabricksClient:
    host: str            # e.g. "https://adb-1234567890123456.7.azuredatabricks.net"
    token: str
    timeout: int = 30
    max_retries: int = 3

    def __post_init__(self):
        self.host = self.host.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "databricks-health-check/1.0",
            }
        )
        self._admin_scope: Optional[bool] = None

    # -- low level -----------------------------------------------------

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.host}{path}"
        last_exc = None
        for attempt in range(self.max_retries):
            try:
                resp = self._session.request(method, url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(min(2**attempt, 8))
                continue

            if resp.status_code in (401, 403):
                raise PermissionError(
                    f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:300]}"
                )
            if resp.status_code == 429 or resp.status_code >= 500:
                last_exc = DatabricksApiError(f"HTTP {resp.status_code}: {resp.text[:300]}")
                time.sleep(min(2**attempt, 8))
                continue
            if resp.status_code >= 400:
                raise DatabricksApiError(
                    f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:500]}"
                )
            return resp
        raise DatabricksApiError(f"{method} {path} failed after {self.max_retries} attempts: {last_exc}")

    def get(self, path: str, params: Optional[dict] = None) -> dict:
        resp = self._request("GET", path, params=params or {})
        if not resp.content:
            return {}
        return resp.json()

    def post(self, path: str, json: Optional[dict] = None) -> dict:
        resp = self._request("POST", path, json=json or {})
        if not resp.content:
            return {}
        return resp.json()

    def get_pages(self, path: str, params: Optional[dict], items_key: str, token_key: str = "next_page_token"):
        """Generic pagination helper for the newer 2.1-style list APIs."""
        params = dict(params or {})
        while True:
            page = self.get(path, params=params)
            for item in page.get(items_key, []) or []:
                yield item
            token = page.get(token_key)
            if not token:
                break
            params["page_token"] = token

    # -- convenience wrappers used across check modules -----------------

    def whoami(self) -> dict:
        return self.get("/api/2.0/preview/scim/v2/Me")

    def is_admin(self) -> bool:
        """Best-effort: can we call an admin-only endpoint? Cached per client."""
        if self._admin_scope is not None:
            return self._admin_scope
        try:
            self.get("/api/2.0/token-management/tokens", params={"count": 1})
            self._admin_scope = True
        except PermissionError:
            self._admin_scope = False
        except DatabricksApiError:
            # Unexpected but non-auth error -- don't assume either way, but
            # don't block the caller either.
            self._admin_scope = False
        return self._admin_scope


def client_from_notebook_context(dbutils, timeout: int = 30) -> DatabricksClient:
    """
    Build a DatabricksClient using the ambient auth of the notebook that is
    currently executing, i.e. no PAT or secret scope required. Call this
    from *inside* a Databricks notebook and pass it its own `dbutils`:

        from health_check.api_client import client_from_notebook_context
        client = client_from_notebook_context(dbutils)
    """
    ctx = dbutils.notebook.entry_point.getDbutils().notebook().getContext()
    host = ctx.apiUrl().get()
    token = ctx.apiToken().get()
    if not token:
        raise DatabricksApiError(
            "Could not obtain a notebook execution token. If credential "
            "passthrough / token access is disabled for this workspace, "
            "supply an explicit PAT via client_from_token() instead."
        )
    return DatabricksClient(host=host, token=token, timeout=timeout)


def client_from_token(host: str, token: str, timeout: int = 30) -> DatabricksClient:
    """Build a client from an explicit host + PAT, e.g. one stored in a secret scope."""
    return DatabricksClient(host=host, token=token, timeout=timeout)
