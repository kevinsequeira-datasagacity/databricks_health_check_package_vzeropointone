"""
Data governance checks, assuming Unity Catalog is fully enabled across all
four workspaces (per the client's stated setup):

  DG-001  Catalog inventory & workspace isolation/binding
  DG-002  Broad (account-users-style) grants at catalog level
  DG-003  External locations & storage credential hygiene
  DG-004  Delta table health sample (small-file ratio) via a SQL warehouse
  DG-005  System schema (system.access / system.billing / ...) visibility

DG-004 is the only check here that needs a running SQL warehouse (to run
DESCRIBE DETAIL); it degrades to an INFO finding if no warehouse_id is
supplied, rather than failing the whole run.
"""
from __future__ import annotations

import time

from ..api_client import DatabricksClient
from ..utils import Finding, Severity, Status, run_check

CATEGORY = "data_governance"
CATEGORY_LABEL = "Data Governance (Unity Catalog)"

_SYSTEM_SCHEMAS_OF_INTEREST = ["access", "billing", "compute", "lineage", "query", "marketplace"]


def _dg001_catalog_inventory(client: DatabricksClient) -> list:
    catalogs = list(client.get_pages("/api/2.1/unity-catalog/catalogs", {}, items_key="catalogs"))
    catalogs = [c for c in catalogs if c.get("name") not in ("system", "samples")]

    if not catalogs:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-001",
                title="Catalog inventory",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail="No user-defined catalogs were found via Unity Catalog in this workspace.",
                recommendation="Confirm the workspace is correctly bound to the expected Unity Catalog metastore.",
            )
        ]

    open_isolation = [c for c in catalogs if c.get("isolation_mode", "OPEN") == "OPEN"]
    findings = [
        Finding(
            category=CATEGORY_LABEL,
            check_id="DG-001",
            title="Catalog inventory",
            status=Status.PASS,
            detail=f"{len(catalogs)} catalog(s) visible: " + ", ".join(c.get("name", "?") for c in catalogs[:15]),
            evidence={"catalogs": [c.get("name") for c in catalogs]},
        )
    ]
    if open_isolation:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-001b",
                title="Catalogs with open workspace binding",
                status=Status.INFO,
                severity=Severity.LOW,
                detail=(
                    f"{len(open_isolation)} catalog(s) are bound to ALL workspaces on the metastore "
                    f"(isolation_mode=OPEN): {', '.join(c.get('name') for c in open_isolation[:10])}"
                ),
                recommendation=(
                    "If DEV/TEST should not see PROD catalogs (or vice versa), set isolation_mode=ISOLATED "
                    "and explicitly bind each catalog to the workspaces that should access it."
                ),
            )
        )
    return findings


def _dg002_broad_grants(client: DatabricksClient, cfg: dict, is_prod_like: bool) -> list:
    broad_privs = set(cfg.get("thresholds", {}).get("unity_catalog", {}).get("broad_privileges", ["ALL PRIVILEGES"]))
    catalogs = list(client.get_pages("/api/2.1/unity-catalog/catalogs", {}, items_key="catalogs"))
    catalogs = [c for c in catalogs if c.get("name") not in ("system", "samples")]

    offenders = []
    for c in catalogs:
        name = c.get("name")
        try:
            perms = client.get(f"/api/2.1/unity-catalog/permissions/catalog/{name}")
        except PermissionError:
            continue
        for grant in perms.get("privilege_assignments", []) or []:
            principal = grant.get("principal", "")
            privileges = set(grant.get("privileges", []) or [])
            if principal.lower() in ("account users", "users") and (privileges & broad_privs):
                offenders.append((name, principal, sorted(privileges & broad_privs)))

    if offenders:
        severity = Severity.CRITICAL if is_prod_like else Severity.HIGH
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-002",
                title="Broad catalog-level grants",
                status=Status.FAIL,
                severity=severity,
                detail=(
                    f"{len(offenders)} catalog(s) grant broad privileges to a workspace-wide principal: "
                    + "; ".join(f"{cat} -> {who}: {privs}" for cat, who, privs in offenders[:10])
                ),
                recommendation=(
                    "Replace catalog-wide grants to 'account users'/'users' with least-privilege grants "
                    "to specific Entra ID groups (e.g. read-only analyst groups, per-domain owner groups)."
                ),
                evidence={"offenders": [f"{cat}:{who}:{privs}" for cat, who, privs in offenders]},
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="DG-002",
            title="Broad catalog-level grants",
            status=Status.PASS,
            detail=f"No catalog-wide broad grants found across {len(catalogs)} catalog(s).",
        )
    ]


def _dg003_external_locations(client: DatabricksClient) -> list:
    ext_locations = list(client.get_pages("/api/2.1/unity-catalog/external-locations", {}, items_key="external_locations"))
    storage_creds = list(client.get_pages("/api/2.1/unity-catalog/storage-credentials", {}, items_key="storage_credentials"))

    findings = []
    used_cred_names = {loc.get("credential_name") for loc in ext_locations if loc.get("credential_name")}
    orphaned_creds = [c.get("name") for c in storage_creds if c.get("name") not in used_cred_names]
    writable_locations = [loc.get("name") for loc in ext_locations if not loc.get("read_only")]

    findings.append(
        Finding(
            category=CATEGORY_LABEL,
            check_id="DG-003",
            title="External locations & storage credentials",
            status=Status.PASS,
            detail=f"{len(ext_locations)} external location(s), {len(storage_creds)} storage credential(s) registered.",
        )
    )
    if orphaned_creds:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-003b",
                title="Unused storage credentials",
                status=Status.INFO,
                severity=Severity.LOW,
                detail=f"{len(orphaned_creds)} storage credential(s) aren't referenced by any external location: {', '.join(orphaned_creds[:10])}",
                recommendation="Remove unused storage credentials to reduce the standing set of Azure identities with storage access.",
            )
        )
    if writable_locations:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-003c",
                title="Writable external locations",
                status=Status.INFO,
                severity=Severity.LOW,
                detail=f"{len(writable_locations)} external location(s) are read-write: {', '.join(writable_locations[:10])}",
                recommendation="Mark locations read_only=true where write access isn't actually required (e.g. curated/reference data lakes).",
            )
        )
    return findings


def _run_sql_statement(client: DatabricksClient, warehouse_id: str, statement: str, poll_seconds=1.5, max_wait_seconds=60):
    resp = client.post(
        "/api/2.0/sql/statements/",
        json={"warehouse_id": warehouse_id, "statement": statement, "wait_timeout": "0s"},
    )
    statement_id = resp.get("statement_id")
    waited = 0.0
    while resp.get("status", {}).get("state") in ("PENDING", "RUNNING"):
        time.sleep(poll_seconds)
        waited += poll_seconds
        if waited > max_wait_seconds:
            raise TimeoutError(f"Statement {statement_id} did not finish within {max_wait_seconds}s")
        resp = client.get(f"/api/2.0/sql/statements/{statement_id}")
    state = resp.get("status", {}).get("state")
    if state != "SUCCEEDED":
        raise RuntimeError(f"Statement failed ({state}): {resp.get('status', {}).get('error')}")
    columns = [c.get("name") for c in resp.get("manifest", {}).get("schema", {}).get("columns", [])]
    rows = resp.get("result", {}).get("data_array", []) or []
    return [dict(zip(columns, row)) for row in rows]


def _dg004_delta_health(client: DatabricksClient, cfg: dict, limits: dict, warehouse_id: str | None) -> list:
    if not warehouse_id:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-004",
                title="Delta table health sample",
                status=Status.INFO,
                detail="Skipped: no SQL warehouse was supplied to run DESCRIBE DETAIL against a sample of tables.",
                recommendation="Re-run with a `sql_warehouse_id` widget value to include Delta table health (small-file ratio) in this report.",
            )
        ]

    uc_cfg = cfg.get("thresholds", {}).get("unity_catalog", {}).get("delta_health", {})
    sample_n = uc_cfg.get("sample_tables_per_schema", 5)
    max_small_ratio = uc_cfg.get("max_small_file_ratio", 0.30)
    max_schemas = limits.get("max_schemas_to_scan_for_delta_health", 50)

    catalogs = [c for c in client.get_pages("/api/2.1/unity-catalog/catalogs", {}, items_key="catalogs") if c.get("name") not in ("system", "samples")]
    schemas = []
    for c in catalogs:
        schemas.extend(client.get_pages("/api/2.1/unity-catalog/schemas", {"catalog_name": c.get("name")}, items_key="schemas"))
    schemas = [s for s in schemas if s.get("name") != "information_schema"][:max_schemas]

    flagged = []
    inspected = 0
    errors = 0
    for schema in schemas:
        catalog_name, schema_name = schema.get("catalog_name"), schema.get("name")
        tables = list(client.get_pages(
            "/api/2.1/unity-catalog/tables",
            {"catalog_name": catalog_name, "schema_name": schema_name},
            items_key="tables",
        ))[:sample_n]
        for t in tables:
            if t.get("table_type") != "MANAGED" and t.get("data_source_format") != "DELTA":
                continue
            full_name = f"{catalog_name}.{schema_name}.{t.get('name')}"
            try:
                rows = _run_sql_statement(client, warehouse_id, f"DESCRIBE DETAIL {full_name}")
                inspected += 1
            except Exception:
                errors += 1
                continue
            if not rows:
                continue
            detail = rows[0]
            num_files = detail.get("numFiles") or 0
            size_bytes = detail.get("sizeInBytes") or 0
            if num_files and size_bytes:
                avg_file_mb = (size_bytes / num_files) / (1024 * 1024)
                if avg_file_mb < 16:
                    flagged.append((full_name, round(avg_file_mb, 1), num_files))

    findings = []
    if inspected == 0:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-004",
                title="Delta table health sample",
                status=Status.INFO,
                detail=f"Could not inspect any tables (errors: {errors}). Check the supplied SQL warehouse is running and the caller has SELECT on sampled tables.",
            )
        )
        return findings

    if flagged:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-004",
                title="Small-file fragmentation in sampled Delta tables",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                detail=(
                    f"{len(flagged)} of {inspected} sampled table(s) have an average file size under 16MB, "
                    "suggesting they'd benefit from OPTIMIZE: "
                    + "; ".join(f"{n} (~{mb}MB avg, {nf} files)" for n, mb, nf in flagged[:10])
                ),
                recommendation=(
                    "Run OPTIMIZE (and enable auto-compaction / predictive optimization where available) "
                    "on the flagged tables; schedule VACUUM per your retention policy."
                ),
                evidence={"sample_size": inspected, "threshold_used_mb": 16, "config_max_small_file_ratio": max_small_ratio},
            )
        )
    else:
        findings.append(
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-004",
                title="Delta table health sample",
                status=Status.PASS,
                detail=f"Sampled {inspected} table(s) across {len(schemas)} schema(s); no small-file fragmentation found.",
            )
        )
    findings.append(
        Finding(
            category=CATEGORY_LABEL,
            check_id="DG-004b",
            title="Delta health sample coverage",
            status=Status.INFO,
            detail=(
                f"This is a bounded sample ({sample_n} table(s)/schema, {len(schemas)} schema(s) scanned) for "
                "runtime reasons -- treat it as directional, not exhaustive. VACUUM/OPTIMIZE run history "
                "(via DESCRIBE HISTORY) was not evaluated in this automated pass."
            ),
        )
    )
    return findings


def _dg005_system_schemas(client: DatabricksClient) -> list:
    try:
        schemas = list(client.get_pages("/api/2.1/unity-catalog/schemas", {"catalog_name": "system"}, items_key="schemas"))
    except PermissionError:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-005",
                title="System schema (system.*) enablement",
                status=Status.INFO,
                detail="Could not read the `system` catalog with this identity.",
                recommendation="Check system schema enablement via the account console or the accounts-level API (requires account admin).",
            )
        ]

    enabled_names = {s.get("name") for s in schemas}
    missing = [s for s in _SYSTEM_SCHEMAS_OF_INTEREST if s not in enabled_names]

    if missing:
        return [
            Finding(
                category=CATEGORY_LABEL,
                check_id="DG-005",
                title="System schema (system.*) enablement",
                status=Status.WARN,
                severity=Severity.LOW,
                detail=f"System schema(s) not enabled (or not visible to this identity): {', '.join(missing)}.",
                recommendation=(
                    "Enable the missing system schemas at the account level (Account Console -> "
                    "Unity Catalog -> Metastore -> System Schemas, or the systemschemas account API) "
                    "so audit, billing, lineage and compute usage are queryable in-platform."
                ),
            )
        ]
    return [
        Finding(
            category=CATEGORY_LABEL,
            check_id="DG-005",
            title="System schema (system.*) enablement",
            status=Status.PASS,
            detail=f"All checked system schemas are enabled: {', '.join(sorted(enabled_names & set(_SYSTEM_SCHEMAS_OF_INTEREST)))}.",
        )
    ]


def run(client: DatabricksClient, cfg: dict, is_prod_like: bool, warehouse_id: str | None = None) -> list:
    limits = cfg.get("limits", {})
    findings: list = []
    findings += run_check(lambda: _dg001_catalog_inventory(client), category=CATEGORY_LABEL, check_id="DG-001", title="Catalog inventory")
    findings += run_check(lambda: _dg002_broad_grants(client, cfg, is_prod_like), category=CATEGORY_LABEL, check_id="DG-002", title="Broad catalog-level grants")
    findings += run_check(lambda: _dg003_external_locations(client), category=CATEGORY_LABEL, check_id="DG-003", title="External locations & storage credentials")
    findings += run_check(lambda: _dg004_delta_health(client, cfg, limits, warehouse_id), category=CATEGORY_LABEL, check_id="DG-004", title="Delta table health sample")
    findings += run_check(lambda: _dg005_system_schemas(client), category=CATEGORY_LABEL, check_id="DG-005", title="System schema (system.*) enablement")
    return findings
