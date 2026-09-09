"""
A minimal stand-in for `databricks.sdk.WorkspaceClient`, used by the unit
tests (and the sample-report generator) to exercise the real check-module
logic without needing a live workspace or the `databricks-sdk` package
installed.

Design: every sub-service method returns plain dicts (or lists of plain
dicts) rather than typed SDK dataclasses. `health_check_sdk.utils.to_dict()`
passes an already-a-dict value straight through, so the check modules run
identically against this mock as they would against `to_dict()`-normalized
real SDK objects -- this mock verifies the check *logic*, not the exact
shape of the installed SDK's dataclasses (see the README's "A note on
verification").

Usage:
    responses = {"/groups.list": [...], ...}   # see individual _Service classes
    w = MockWorkspaceClient(responses)
    security_iam.run(w, cfg, is_prod_like=True, is_admin=True)
"""
from __future__ import annotations


class _Service:
    """A generic callable-attribute bag: service.list() / .get() etc. return
    whatever was registered under that method name in `handlers`."""

    def __init__(self, handlers: dict):
        self._handlers = handlers

    def __getattr__(self, name):
        if name not in self._handlers:
            raise AttributeError(f"MockWorkspaceClient: no handler registered for method '{name}'")
        return self._handlers[name]


class _Config:
    def __init__(self, host: str):
        self.host = host


class MockWorkspaceClient:
    """
    `services` maps a WorkspaceClient attribute name (e.g. "groups",
    "clusters") to a dict of {method_name: callable}. Each callable takes
    whatever kwargs the real SDK method would and returns a plain dict (for
    a `.get()`-style call) or a list of plain dicts (for a `.list()`-style
    call, which the real SDK returns as an iterator -- lists work fine
    since check modules always wrap calls in `list(...)` or a comprehension).
    """

    def __init__(self, services: dict, host: str = "https://adb-1234567890123456.7.azuredatabricks.net"):
        for name, handlers in services.items():
            setattr(self, name, _Service(handlers))
        self.config = _Config(host)
