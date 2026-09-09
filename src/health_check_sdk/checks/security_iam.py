"""
Security & IAM checks, built on databricks-sdk's WorkspaceClient.

Assumes Entra ID -> SCIM group sync into the workspace and evaluates:

  SEC-001  Entra/SCIM group sync is actually populating workspace groups
  SEC-002  Workspace admin rights are granted via group, not individual users
  SEC-003  Personal access token hygiene (lifetime, ownership)
  SEC-004  Secret scope backing + ACL breadth
  SEC-005  IP access lists (expected in production-like environments)
  SEC-006  Cluster policy enforcement exists
  SEC-007  Org-wide max token lifetime policy is set

Every SDK call is immediately normalized with `utils.to_dict()` so the check
logic below works off plain dicts with the same field names as the REST
API's JSON (which is what `.as_dict()` serializes back to) -- this keeps the
logic identical in spirit to the REST-based sibling package while still
going through the official, typed WorkspaceClient for every call.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..utils import DatabricksError, Finding, PermissionDenied, Severity, Status, parse_epoch_ms, run_check, safe_get, to_dict

if TYPE_CHECKING:
    from databricks.sdk import WorkspaceClient

CATEGORY = "security_iam"
CATEGORY_LABEL = "Security & IAM"


def _sec001_scim_group_sync(w: "WorkspaceClient", cfg: dict) -> list:
    resources = [to_dict(g) for g in w.groups.list()]
    if not resources:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-001",
                title="Entra ID / SCIM group sync",
                status=Status.FAIL,
                severity=Severity.HIGH,
                detail="No groups were found in this workspace at all.",
                recommendation=(
                    "Confirm the Entra ID enterprise application's SCIM provisioning "
                    "is configured and has run at least once for this workspace."
                ),
            )
        ]

    synced = [g for g in resources if g.get("external_id")]
    local_only = [g for g in resources if not g.get("external_id") and g.get("display_name") not in ("admins", "users")]

    findings = []
    if not synced:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-001",
                title="Entra ID / SCIM group sync",
                status=Status.WARN,
                severity=Severity.HIGH,
                detail=(
                    f"Found {len(resources)} group(s) in the workspace, but none carry an "
                    "external_id, which is how SCIM-provisioned groups are normally tagged. "
                    "Group membership may be managed manually instead of synced from Entra ID."
                ),
                recommendation=(
                    "Verify the Entra ID enterprise application's provisioning job status "
                    "(Entra admin center -> Enterprise applications -> Databricks -> Provisioning)."
                ),
                evidence={"total_groups": len(resources)},
            )
        )
    else:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-001",
                title="Entra ID / SCIM group sync",
                status=Status.PASS,
                detail=f"{len(synced)} of {len(resources)} group(s) are SCIM-provisioned (carry an external_id).",
                evidence={"synced_groups": len(synced), "total_groups": len(resources)},
            )
        )

    if local_only:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-001b",
                title="Locally-managed (non-synced) groups present",
                status=Status.INFO,
                severity=Severity.LOW,
                detail=(
                    f"{len(local_only)} group(s) appear to be workspace-local rather than "
                    "synced from Entra ID: " + ", ".join(g.get("display_name", "?") for g in local_only[:10])
                    + ("..." if len(local_only) > 10 else "")
                ),
                recommendation=(
                    "If these are intentional (e.g. break-glass groups), document them; "
                    "otherwise migrate their membership into Entra ID for a single source of truth."
                ),
                evidence={"groups": [g.get("display_name") for g in local_only]},
            )
        )
    return findings


def _sec002_admin_membership(w: "WorkspaceClient", cfg: dict) -> list:
    matches = [to_dict(g) for g in w.groups.list(filter='displayName eq "admins"')]
    if not matches:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-002",
                title="Workspace admin membership",
                status=Status.ERROR,
                detail="Could not locate the built-in 'admins' group via the Groups API.",
            )
        ]

    admins_group_id = matches[0].get("id")
    detail = to_dict(w.groups.get(id=admins_group_id))
    members = detail.get("members", []) or []

    def _ref(m: dict) -> str:
        return (m.get("$ref") or m.get("ref") or "") or ""

    direct_users = [m for m in members if _ref(m).startswith("Users/") or "user_name" in m]
    nested_groups = [m for m in members if _ref(m).startswith("Groups/")]

    expected_groups = set(cfg.get("thresholds", {}).get("admin_group", {}).get("expected_admin_group_names", []))
    nested_names = {m.get("display") for m in nested_groups}

    if len(direct_users) > 3 and not nested_groups:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-002",
                title="Workspace admin membership",
                status=Status.WARN,
                severity=Severity.HIGH,
                detail=(
                    f"{len(direct_users)} individual user(s) are directly assigned workspace "
                    "admin, with no admin group nested in. This is hard to audit centrally "
                    "from Entra ID and tends to drift over time."
                ),
                recommendation=(
                    "Grant admin via an Entra ID group synced into Databricks "
                    f"(e.g. {', '.join(expected_groups) or 'a dedicated *-Workspace-Admins group'}) "
                    "instead of assigning individuals directly."
                ),
                evidence={"direct_admin_count": len(direct_users)},
            )
        ]

    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="SEC-002",
            title="Workspace admin membership",
            status=Status.PASS,
            detail=(
                f"{len(direct_users)} direct user admin(s), {len(nested_groups)} nested admin group(s)"
                + (f" ({', '.join(sorted(n for n in nested_names if n))})" if nested_names else "")
                + "."
            ),
            evidence={"direct_admin_count": len(direct_users), "nested_groups": list(nested_names)},
        )
    ]


def _sec003_token_hygiene(w: "WorkspaceClient", cfg: dict, is_admin: bool) -> list:
    if not is_admin:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-003",
                title="Personal access token hygiene",
                status=Status.ERROR,
                detail="Requires an admin identity to list all workspace tokens (token-management API).",
                recommendation="Re-run as a workspace admin / admin service principal for full token coverage.",
            )
        ]

    max_days = cfg.get("thresholds", {}).get("tokens", {}).get("max_lifetime_days", 90)
    tokens = [to_dict(t) for t in w.token_management.list()]

    if not tokens:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-003",
                title="Personal access token hygiene",
                status=Status.PASS,
                detail="No personal access tokens are currently issued in this workspace.",
            )
        ]

    no_expiry = []
    long_lived = []
    for t in tokens:
        expiry = t.get("expiry_time", -1)
        if expiry in (-1, None):
            no_expiry.append(t)
            continue
        expires_at = parse_epoch_ms(expiry)
        created_at = parse_epoch_ms(t.get("creation_time"))
        if created_at and expires_at:
            lifetime_days = (expires_at - created_at).total_seconds() / 86400.0
            if lifetime_days > max_days:
                long_lived.append(t)

    findings = []
    if no_expiry:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-003",
                title="Tokens with no expiration",
                status=Status.FAIL,
                severity=Severity.HIGH,
                detail=f"{len(no_expiry)} of {len(tokens)} token(s) never expire.",
                recommendation="Rotate these to expiring tokens and set an org-wide maximum token lifetime (see SEC-007).",
                evidence={"comment_samples": [t.get("comment") for t in no_expiry[:10]]},
            )
        )
    if long_lived:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-003b",
                title="Long-lived tokens",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=f"{len(long_lived)} token(s) have a lifetime greater than {max_days} days.",
                recommendation=f"Reissue with a lifetime under {max_days} days where practical.",
            )
        )
    if not no_expiry and not long_lived:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-003",
                title="Personal access token hygiene",
                status=Status.PASS,
                detail=f"All {len(tokens)} token(s) expire within the {max_days}-day policy window.",
            )
        )
    return findings


def _sec004_secret_scopes(w: "WorkspaceClient", cfg: dict, is_prod_like: bool) -> list:
    scopes = [to_dict(s) for s in w.secrets.list_scopes()]
    if not scopes:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-004",
                title="Secret scope backing & ACLs",
                status=Status.INFO,
                detail="No secret scopes are defined in this workspace.",
            )
        ]

    findings = []
    databricks_backed_in_prod = []
    broad_acls = []
    for scope in scopes:
        name = scope.get("name")
        backend = scope.get("backend_type", "DATABRICKS")
        if is_prod_like and backend == "DATABRICKS":
            databricks_backed_in_prod.append(name)
        try:
            acls = [to_dict(a) for a in w.secrets.list_acls(scope=name)]
        except (PermissionDenied, DatabricksError):
            acls = []
        for acl in acls:
            if acl.get("principal") in ("users", "account users") and acl.get("permission") in ("MANAGE", "WRITE"):
                broad_acls.append((name, acl.get("principal"), acl.get("permission")))

    if databricks_backed_in_prod:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-004",
                title="Secret scopes backed by Databricks (not Key Vault) in a production-like environment",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=(
                    f"{len(databricks_backed_in_prod)} scope(s) use native Databricks-backed "
                    f"storage rather than Azure Key Vault: {', '.join(databricks_backed_in_prod)}"
                ),
                recommendation=(
                    "Back production secret scopes with Azure Key Vault so secret access, "
                    "rotation and audit live in the same place as the rest of your Azure RBAC."
                ),
            )
        )
    if broad_acls:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-004b",
                title="Broad secret scope ACLs",
                status=Status.WARN,
                severity=Severity.HIGH,
                detail=(
                    f"{len(broad_acls)} scope ACL(s) grant WRITE/MANAGE to a broad principal, e.g. "
                    + "; ".join(f"{n} -> {p}:{perm}" for n, p, perm in broad_acls[:5])
                ),
                recommendation="Scope MANAGE/WRITE ACLs to specific admin groups or service principals, not all users.",
                evidence={"broad_acls": [f"{n}:{p}:{perm}" for n, p, perm in broad_acls]},
            )
        )
    if not findings:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-004",
                title="Secret scope backing & ACLs",
                status=Status.PASS,
                detail=f"Checked {len(scopes)} secret scope(s); no backing or ACL breadth issues found.",
            )
        )
    return findings


def _sec005_ip_access_lists(w: "WorkspaceClient", cfg: dict, is_prod_like: bool) -> list:
    require = cfg.get("thresholds", {}).get("ip_access_lists", {}).get("require_in_production_like", True)
    lists_ = [to_dict(l) for l in w.ip_access_lists.list()]
    enabled = [l for l in lists_ if l.get("enabled")]

    if is_prod_like and require and not enabled:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-005",
                title="IP access lists",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail="No enabled IP access list restricts access to this production-like workspace.",
                recommendation=(
                    "Configure an IP access list (or route through Azure Private Link / a "
                    "corporate egress range) to restrict workspace access to known networks."
                ),
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="SEC-005",
            title="IP access lists",
            status=Status.PASS if enabled else Status.INFO,
            detail=f"{len(enabled)} enabled IP access list(s) out of {len(lists_)} defined.",
        )
    ]


def _sec006_cluster_policies(w: "WorkspaceClient", cfg: dict, is_prod_like: bool) -> list:
    require = cfg.get("thresholds", {}).get("clusters", {}).get("require_cluster_policy_in_prod", True)
    policies = [to_dict(p) for p in w.cluster_policies.list()]
    if not policies:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-006",
                title="Cluster policy enforcement",
                status=Status.WARN if (is_prod_like and require) else Status.INFO,
                severity=Severity.MEDIUM,
                detail="No cluster policies are defined in this workspace.",
                recommendation=(
                    "Define at least one cluster policy restricting instance types, "
                    "autotermination and tagging, and require non-admins to use it."
                ),
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="SEC-006",
            title="Cluster policy enforcement",
            status=Status.PASS,
            detail=f"{len(policies)} cluster polic(y/ies) defined: " + ", ".join(p.get("name", "?") for p in policies[:10]),
        )
    ]


def _sec007_token_policy(w: "WorkspaceClient", cfg: dict, is_admin: bool) -> list:
    if not is_admin:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-007",
                title="Org-wide maximum token lifetime policy",
                status=Status.ERROR,
                detail="Requires an admin identity to read the workspace token policy.",
            )
        ]

    get_policy = getattr(w.token_management, "get_token_policy", None)
    if not callable(get_policy):
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-007",
                title="Org-wide maximum token lifetime policy",
                status=Status.INFO,
                detail=(
                    "This installed databricks-sdk version doesn't expose a token-policy call; "
                    "check the admin console manually (Settings -> Admin Console -> Workspace "
                    "settings -> Personal access tokens)."
                ),
            )
        ]

    try:
        policy = to_dict(get_policy())
    except (PermissionDenied, DatabricksError):
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-007",
                title="Org-wide maximum token lifetime policy",
                status=Status.INFO,
                detail="Could not read the token policy with this identity/SDK version; check the admin console manually.",
            )
        ]

    max_lifetime = safe_get(policy, "token_policy", "max_token_lifetime_days") or policy.get("max_token_lifetime_days")
    if not max_lifetime:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-007",
                title="Org-wide maximum token lifetime policy",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail="No org-wide maximum token lifetime is configured; individual tokens may be issued without expiry.",
                recommendation="Set a maximum token lifetime in Admin Console -> Workspace settings -> Personal access tokens.",
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="SEC-007",
            title="Org-wide maximum token lifetime policy",
            status=Status.PASS,
            detail=f"Maximum token lifetime enforced at {max_lifetime} days.",
        )
    ]


def run(w: "WorkspaceClient", cfg: dict, is_prod_like: bool, is_admin: bool) -> list:
    findings: list = []
    findings += run_check(lambda: _sec001_scim_group_sync(w, cfg), category=CATEGORY_LABEL, check_id="SEC-001", title="Entra ID / SCIM group sync")
    findings += run_check(lambda: _sec002_admin_membership(w, cfg), category=CATEGORY_LABEL, check_id="SEC-002", title="Workspace admin membership")
    findings += run_check(lambda: _sec003_token_hygiene(w, cfg, is_admin), category=CATEGORY_LABEL, check_id="SEC-003", title="Personal access token hygiene")
    findings += run_check(lambda: _sec004_secret_scopes(w, cfg, is_prod_like), category=CATEGORY_LABEL, check_id="SEC-004", title="Secret scope backing & ACLs")
    findings += run_check(lambda: _sec005_ip_access_lists(w, cfg, is_prod_like), category=CATEGORY_LABEL, check_id="SEC-005", title="IP access lists")
    findings += run_check(lambda: _sec006_cluster_policies(w, cfg, is_prod_like), category=CATEGORY_LABEL, check_id="SEC-006", title="Cluster policy enforcement")
    findings += run_check(lambda: _sec007_token_policy(w, cfg, is_admin), category=CATEGORY_LABEL, check_id="SEC-007", title="Org-wide maximum token lifetime policy")
    return findings
