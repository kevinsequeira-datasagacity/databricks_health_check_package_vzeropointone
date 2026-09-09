"""
Security & IAM checks.

Assumes Entra ID -> SCIM group sync into the workspace (per the client's
stated setup) and evaluates:

  SEC-001  Entra/SCIM group sync is actually populating workspace groups
  SEC-002  Workspace admin rights are granted via group, not individual users
  SEC-003  Personal access token hygiene (lifetime, ownership)
  SEC-004  Secret scope backing + ACL breadth
  SEC-005  IP access lists (expected in production-like environments)
  SEC-006  Cluster policy enforcement exists
  SEC-007  Org-wide max token lifetime policy is set
"""
from __future__ import annotations

from ..api_client import DatabricksClient
from ..utils import Finding, Severity, Status, parse_epoch_ms, safe_get, run_check

CATEGORY = "security_iam"
CATEGORY_LABEL = "Security & IAM"


def _sec001_scim_group_sync(client: DatabricksClient, cfg: dict) -> list:
    groups = client.get("/api/2.0/preview/scim/v2/Groups", params={"count": 200})
    resources = groups.get("Resources", []) or []
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

    synced = [g for g in resources if g.get("externalId")]
    local_only = [g for g in resources if not g.get("externalId") and g.get("displayName") not in ("admins", "users")]

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
                    "externalId, which is how SCIM-provisioned groups are normally tagged. "
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
                detail=f"{len(synced)} of {len(resources)} group(s) are SCIM-provisioned (carry an externalId).",
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
                    "synced from Entra ID: " + ", ".join(g.get("displayName", "?") for g in local_only[:10])
                    + ("..." if len(local_only) > 10 else "")
                ),
                recommendation=(
                    "If these are intentional (e.g. break-glass groups), document them; "
                    "otherwise migrate their membership into Entra ID for a single source of truth."
                ),
                evidence={"groups": [g.get("displayName") for g in local_only]},
            )
        )
    return findings


def _sec002_admin_membership(client: DatabricksClient, cfg: dict) -> list:
    groups = client.get("/api/2.0/preview/scim/v2/Groups", params={"filter": 'displayName eq "admins"'})
    resources = groups.get("Resources", []) or []
    if not resources:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-002",
                title="Workspace admin membership",
                status=Status.ERROR,
                detail="Could not locate the built-in 'admins' group via SCIM.",
            )
        ]

    admins_group = resources[0]
    group_id = admins_group.get("id")
    detail = client.get(f"/api/2.0/preview/scim/v2/Groups/{group_id}")
    members = detail.get("members", []) or []

    direct_users = [m for m in members if (m.get("$ref", "") or "").startswith("Users/") or "userName" in m]
    nested_groups = [m for m in members if (m.get("$ref", "") or "").startswith("Groups/")]

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


def _sec003_token_hygiene(client: DatabricksClient, cfg: dict) -> list:
    if not client.is_admin():
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
    resp = client.get("/api/2.0/token-management/tokens")
    tokens = resp.get("token_infos", []) or []

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


def _sec004_secret_scopes(client: DatabricksClient, cfg: dict, is_prod_like: bool) -> list:
    scopes = client.get("/api/2.0/secrets/scopes/list").get("scopes", []) or []
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
            acls = client.get("/api/2.0/secrets/acls/list", params={"scope": name}).get("items", []) or []
        except PermissionError:
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


def _sec005_ip_access_lists(client: DatabricksClient, cfg: dict, is_prod_like: bool) -> list:
    require = cfg.get("thresholds", {}).get("ip_access_lists", {}).get("require_in_production_like", True)
    resp = client.get("/api/2.0/ip-access-lists")
    lists_ = resp.get("ip_access_lists", []) or []
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


def _sec006_cluster_policies(client: DatabricksClient, cfg: dict, is_prod_like: bool) -> list:
    require = cfg.get("thresholds", {}).get("clusters", {}).get("require_cluster_policy_in_prod", True)
    policies = client.get("/api/2.0/policies/clusters/list").get("policies", []) or []
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


def _sec007_token_policy(client: DatabricksClient, cfg: dict) -> list:
    if not client.is_admin():
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-007",
                title="Org-wide maximum token lifetime policy",
                status=Status.ERROR,
                detail="Requires an admin identity to read the workspace token policy.",
            )
        ]
    try:
        policy = client.get("/api/2.0/token-management/token-policy")
    except Exception:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="SEC-007",
                title="Org-wide maximum token lifetime policy",
                status=Status.INFO,
                detail="This workspace/API version does not expose a token-policy endpoint; check the admin console manually (Settings -> Admin Console -> Workspace settings -> Personal access tokens).",
            )
        ]
    max_lifetime = safe_get(policy, "token_policy", "max_token_lifetime_days")
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


def run(client: DatabricksClient, cfg: dict, is_prod_like: bool) -> list:
    findings: list = []
    findings += run_check(lambda: _sec001_scim_group_sync(client, cfg), category=CATEGORY_LABEL, check_id="SEC-001", title="Entra ID / SCIM group sync")
    findings += run_check(lambda: _sec002_admin_membership(client, cfg), category=CATEGORY_LABEL, check_id="SEC-002", title="Workspace admin membership")
    findings += run_check(lambda: _sec003_token_hygiene(client, cfg), category=CATEGORY_LABEL, check_id="SEC-003", title="Personal access token hygiene")
    findings += run_check(lambda: _sec004_secret_scopes(client, cfg, is_prod_like), category=CATEGORY_LABEL, check_id="SEC-004", title="Secret scope backing & ACLs")
    findings += run_check(lambda: _sec005_ip_access_lists(client, cfg, is_prod_like), category=CATEGORY_LABEL, check_id="SEC-005", title="IP access lists")
    findings += run_check(lambda: _sec006_cluster_policies(client, cfg, is_prod_like), category=CATEGORY_LABEL, check_id="SEC-006", title="Cluster policy enforcement")
    findings += run_check(lambda: _sec007_token_policy(client, cfg), category=CATEGORY_LABEL, check_id="SEC-007", title="Org-wide maximum token lifetime policy")
    return findings
