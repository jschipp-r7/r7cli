"""Matrix command for r7-cli.

Fetches licensed Rapid7 products and renders a NIST CSF × CIS v8 coverage matrix.
"""
from __future__ import annotations

import sys
from typing import Any

import click
from tabulate import tabulate

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import ACCOUNT_BASE, IDR_V1_BASE, IVM_V4_BASE, SC_BASE, APIError, R7Error

# ---------------------------------------------------------------------------
# Static data constants
# ---------------------------------------------------------------------------

PRODUCT_CODE_MAP: dict[str, str] = {
    "SC":   "Surface Command",
    "ICS":  "insightCloudSec",
    "IVM":  "insightVM",
    "IDR":  "insightIDR",
    "OPS":  "insightIDR",
    "ICON": "SOAR",
    "IH":   "DRP",
    "TC":   "DRP",
    "AS":   "insightAppSec",
    "CAS":  "Vector Command",
    "MDR":  "MDR",
    "DSPM": "DSPM",
    "CGRC": "Cyber GRC",
}

NIST_STAGES: list[str] = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]

CIS_ASSET_TYPES: list[str] = ["DEVICES", "SOFTWARE", "NETWORK", "USERS", "DATA", "DOCUMENTATION"]

CELL_MAPPING: dict[tuple[str, str], set[str] | None] = {
    # GOVERN — all cells require Cyber GRC
    ("GOVERN", "DEVICES"):       {"Cyber GRC"},
    ("GOVERN", "SOFTWARE"):      {"Cyber GRC"},
    ("GOVERN", "NETWORK"):       {"Cyber GRC"},
    ("GOVERN", "USERS"):         {"Cyber GRC"},
    ("GOVERN", "DATA"):          {"Cyber GRC"},
    ("GOVERN", "DOCUMENTATION"): {"Cyber GRC"},
    # IDENTIFY
    ("IDENTIFY", "DEVICES"):       {"Surface Command", "insightVM", "insightCloudSec", "insightIDR"},
    ("IDENTIFY", "SOFTWARE"):      {"insightVM", "insightCloudSec", "Surface Command", "insightAppSec"},
    ("IDENTIFY", "NETWORK"):       {"insightVM", "Surface Command"},
    ("IDENTIFY", "USERS"):         {"Surface Command", "insightCloudSec", "insightIDR"},
    ("IDENTIFY", "DATA"):          {"DSPM"},
    ("IDENTIFY", "DOCUMENTATION"): None,
    # PROTECT
    ("PROTECT", "DEVICES"):       {"insightVM", "insightCloudSec"},
    ("PROTECT", "SOFTWARE"):      {"insightVM", "insightAppSec", "insightCloudSec", "Surface Command"},
    ("PROTECT", "NETWORK"):       {"insightVM", "insightCloudSec"},
    ("PROTECT", "USERS"):         {"insightVM", "insightCloudSec", "Surface Command"},
    ("PROTECT", "DATA"):          {"DSPM", "insightCloudSec"},
    ("PROTECT", "DOCUMENTATION"): {"Cyber GRC"},
    # DETECT
    ("DETECT", "DEVICES"):       {"insightIDR", "MDR", "DRP"},
    ("DETECT", "SOFTWARE"):      {"insightIDR", "MDR", "DRP"},
    ("DETECT", "NETWORK"):       {"insightIDR", "MDR", "DRP"},
    ("DETECT", "USERS"):         {"insightIDR", "MDR", "DRP"},
    ("DETECT", "DATA"):          {"insightIDR", "MDR", "DRP"},
    ("DETECT", "DOCUMENTATION"): {"Cyber GRC"},
    # RESPOND
    ("RESPOND", "DEVICES"):       {"insightIDR", "SOAR", "MDR"},
    ("RESPOND", "SOFTWARE"):      {"insightIDR", "SOAR", "MDR"},
    ("RESPOND", "NETWORK"):       {"insightIDR", "SOAR", "MDR", "DRP"},
    ("RESPOND", "USERS"):         {"insightIDR", "SOAR", "MDR"},
    ("RESPOND", "DATA"):          {"insightIDR", "SOAR", "MDR"},
    ("RESPOND", "DOCUMENTATION"): {"Cyber GRC", "SOAR"},
    # RECOVER — all None
    ("RECOVER", "DEVICES"):       None,
    ("RECOVER", "SOFTWARE"):      None,
    ("RECOVER", "NETWORK"):       None,
    ("RECOVER", "USERS"):         None,
    ("RECOVER", "DATA"):          None,
    ("RECOVER", "DOCUMENTATION"): None,
}

# Percentage mapping: each cell maps to a list of (product, percent) tuples.
# Order matters — percentages are summed (capped at 100) for licensed products.
CELL_PERCENT_MAPPING: dict[tuple[str, str], list[tuple[str, int]] | None] = {
    # GOVERN
    ("GOVERN", "DEVICES"):       [("Cyber GRC", 100)],
    ("GOVERN", "SOFTWARE"):      [("Cyber GRC", 100)],
    ("GOVERN", "NETWORK"):       [("Cyber GRC", 100)],
    ("GOVERN", "USERS"):         [("Cyber GRC", 100)],
    ("GOVERN", "DATA"):          [("Cyber GRC", 100)],
    ("GOVERN", "DOCUMENTATION"): [("Cyber GRC", 100)],
    # IDENTIFY
    ("IDENTIFY", "DEVICES"):       [("Surface Command", 100), ("insightVM", 75), ("insightCloudSec", 50), ("insightIDR", 75)],
    ("IDENTIFY", "SOFTWARE"):      [("insightVM", 75), ("insightCloudSec", 50), ("Surface Command", 25), ("insightAppSec", 10)],
    ("IDENTIFY", "NETWORK"):       [("insightVM", 75), ("Surface Command", 50)],
    ("IDENTIFY", "USERS"):         [("Surface Command", 100), ("insightCloudSec", 50), ("insightIDR", 100)],
    ("IDENTIFY", "DATA"):          [("DSPM", 100)],
    ("IDENTIFY", "DOCUMENTATION"): None,
    # PROTECT
    ("PROTECT", "DEVICES"):       [("insightVM", 75), ("insightCloudSec", 25)],
    ("PROTECT", "SOFTWARE"):      [("insightVM", 100), ("insightAppSec", 50), ("insightCloudSec", 100), ("Surface Command", 25)],
    ("PROTECT", "NETWORK"):       [("insightVM", 75), ("insightCloudSec", 50)],
    ("PROTECT", "USERS"):         [("insightVM", 50), ("insightCloudSec", 50), ("Surface Command", 100)],
    ("PROTECT", "DATA"):          [("DSPM", 100), ("insightCloudSec", 25)],
    ("PROTECT", "DOCUMENTATION"): [("Cyber GRC", 100)],
    # DETECT
    ("DETECT", "DEVICES"):       [("insightIDR", 100), ("MDR", 100), ("DRP", 25)],
    ("DETECT", "SOFTWARE"):      [("insightIDR", 100), ("MDR", 100), ("DRP", 25)],
    ("DETECT", "NETWORK"):       [("insightIDR", 100), ("MDR", 100), ("DRP", 25)],
    ("DETECT", "USERS"):         [("insightIDR", 100), ("MDR", 100), ("DRP", 25)],
    ("DETECT", "DATA"):          [("insightIDR", 100), ("MDR", 100), ("DRP", 25)],
    ("DETECT", "DOCUMENTATION"): [("Cyber GRC", 100)],
    # RESPOND
    ("RESPOND", "DEVICES"):       [("insightIDR", 50), ("SOAR", 50), ("MDR", 100)],
    ("RESPOND", "SOFTWARE"):      [("insightIDR", 50), ("SOAR", 50), ("MDR", 100)],
    ("RESPOND", "NETWORK"):       [("insightIDR", 50), ("SOAR", 50), ("MDR", 100), ("DRP", 25)],
    ("RESPOND", "USERS"):         [("insightIDR", 50), ("SOAR", 50), ("MDR", 100)],
    ("RESPOND", "DATA"):          [("insightIDR", 50), ("SOAR", 50), ("MDR", 100)],
    ("RESPOND", "DOCUMENTATION"): [("Cyber GRC", 50), ("SOAR", 50), ("SOAR", 50)],
    # RECOVER — all None
    ("RECOVER", "DEVICES"):       None,
    ("RECOVER", "SOFTWARE"):      None,
    ("RECOVER", "NETWORK"):       None,
    ("RECOVER", "USERS"):         None,
    ("RECOVER", "DATA"):          None,
    ("RECOVER", "DOCUMENTATION"): None,
}

# Reduction rules: (component_key, product, stage_scope, reduction_percent)
REDUCTION_RULES: list[tuple[str, str, str | None, int]] = [
    ("scan_engines",       "insightVM",       None,     25),
    ("collectors",         "insightIDR",      None,     50),
    ("network_sensors",    "insightIDR",      None,     25),
    ("honeypots",          "insightIDR",      None,     10),
    ("orchestrator",       "insightIDR",      "DETECT", 10),
    ("sc_connectors",      "Surface Command", None,     50),
    ("no_event_sources",   "insightIDR",      None,     75),
    ("few_event_sources",  "insightIDR",      None,     50),
    ("no_active_workflows","insightIDR",      "DETECT", 10),
]
# Note: stale_offline_agents is handled dynamically in compute_reductions
# since its reduction scales with the percentage of stale+offline agents.

ACTION_ITEM_MESSAGES: dict[str, str] = {
    "scan_engines":        "Deploy scan engines to increase insightVM coverage by 25%",
    "collectors":          "Deploy collectors to increase insightIDR coverage by 50%",
    "network_sensors":     "Deploy network sensors to increase insightIDR coverage by 25%",
    "honeypots":           "Deploy honeypots to increase insightIDR coverage by 10%",
    "orchestrator":        "Deploy orchestrator to increase insightIDR DETECT coverage by 10%",
    "sc_connectors":       "Deploy at least 5 third-party connectors in Surface Command to increase coverage by 50%",
    "no_event_sources":    "Enable event sources in InsightIDR to increase coverage by 75%",
    "few_event_sources":   "Enable at least 5 event sources in InsightIDR to increase coverage by 50%",
    "stale_offline_agents":"Remediate stale/offline agents to increase insightIDR coverage (10% per 10% of unhealthy agents)",
    "no_active_workflows": "Enable active workflows in InsightConnect to increase insightIDR DETECT coverage by 10%",
}

# Connector names to exclude when counting third-party connectors
_SC_CONNECTOR_EXCLUDE = ("built-in", "rapid7", "easm")
_SC_CONNECTOR_MIN = 5

SCORING_RULES = """\
Scoring Rules for the NIST CSF × CIS v8 Coverage Matrix
========================================================

Matrix Axes:
  X-axis (columns): NIST CSF stages — GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER
  Y-axis (rows):    CIS v8 asset types — DEVICES, SOFTWARE, NETWORK, USERS, DATA, DOCUMENTATION

Cell Scoring:
  Each cell maps to one or more Rapid7 products with a percentage weight.
  If you are licensed for a product, its percentage is added to the cell total (capped at 100%).
  If no products are licensed for a cell, it shows 0%.
  Cells with no product mapping show N/A.

Display Modes:
  Default:    ✅ = at least one product licensed, 🚫 = none licensed, N/A = no mapping
  --percent:  Shows the summed percentage for licensed products in each cell
  --solution: Shows the Rapid7 product names mapped to each cell
  --reality:  Adjusts percentages based on actual deployment state (see below)

Reality / Deployment Adjustments (--reality or --deployment):
  The following reductions are applied when infrastructure components are missing:

  Component          Product Affected   Scope        Reduction
  ─────────────────  ─────────────────  ───────────  ─────────
  Scan engines       insightVM          All cells    -25%
  Collectors         insightIDR         All cells    -50%
  Network sensors    insightIDR         All cells    -25%
  Honeypots          insightIDR         All cells    -10%
  Orchestrator       insightIDR         DETECT only  -10%
  SC connectors <5   Surface Command    All cells    -50%
  No event sources   insightIDR         All cells    -75%
  <5 event sources   insightIDR         All cells    -50%
  Stale/offline      insightIDR         All cells    -10% per 10% unhealthy
  No ICON workflows  insightIDR         DETECT only  -10%

  Reductions stack additively. Product contributions are floored at 0%.
  Cell totals are clamped to [0%, 100%].

Recommendations:
  After the matrix, unlicensed products are ranked by how much they would
  improve your coverage. In percent mode, ranking is by total percentage
  points gained. In default mode, ranking is by number of new cells covered.
"""

# Display strings
_COVERED = "✅"
_NOT_COVERED = "🚫"
_NOT_APPLICABLE = "\033[1;37mN/A\033[0m"


# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def resolve_product_codes(product_records: list[dict]) -> set[str]:
    """Extract product_code from each record and resolve to canonical names."""
    licensed: set[str] = set()
    for record in product_records:
        code = record.get("product_code", "")
        name = PRODUCT_CODE_MAP.get(code)
        if name is not None:
            licensed.add(name)
    return licensed


def evaluate_cell(required: set[str] | None, licensed: set[str]) -> str:
    """Determine coverage status for a single matrix cell."""
    if required is None:
        return "not_applicable"
    if required & licensed:
        return "covered"
    return "not_covered"


def evaluate_cell_percent(
    mapping: list[tuple[str, int]] | None,
    licensed: set[str],
) -> str:
    """Compute the percentage string for a single matrix cell.

    Sums percentages of licensed products, capped at 100.
    Returns 'N/A' when the mapping is None.
    Returns '0%' when products exist but none are licensed.
    """
    if mapping is None:
        return _NOT_APPLICABLE
    total = 0
    for product, pct in mapping:
        if product in licensed:
            total += pct
    return f"{min(total, 100)}%"


def compute_reductions(status: dict[str, bool]) -> list[tuple[str, str | None, int]]:
    """Compute reduction rules from deployment status.

    Returns list of (product_name, nist_stage_or_none, reduction_percent) tuples
    for each component that is missing (False) in *status*.
    """
    reductions: list[tuple[str, str | None, int]] = []
    for component_key, product, stage_scope, reduction in REDUCTION_RULES:
        if not status.get(component_key, False):
            reductions.append((product, stage_scope, reduction))

    # Dynamic rule: stale/offline agents — 10% reduction per 10% of unhealthy agents
    stale_offline_pct = status.get("_stale_offline_pct", 0)
    if isinstance(stale_offline_pct, (int, float)) and stale_offline_pct > 0:
        # For every 10% of stale+offline, reduce insightIDR by 10%
        tiers = int(stale_offline_pct // 10)
        if tiers > 0:
            reductions.append(("insightIDR", None, tiers * 10))

    return reductions


def apply_reductions(
    mapping: dict[tuple[str, str], list[tuple[str, int]] | None],
    reductions: list[tuple[str, str | None, int]],
) -> dict[tuple[str, str], list[tuple[str, int]] | None]:
    """Apply deployment reductions to a cell-percent mapping.

    Returns a new mapping with adjusted percentages.  Product-level
    contributions are floored at 0.
    """
    adjusted: dict[tuple[str, str], list[tuple[str, int]] | None] = {}
    for (stage, asset_type), entries in mapping.items():
        if entries is None:
            adjusted[(stage, asset_type)] = None
            continue
        new_entries: list[tuple[str, int]] = []
        for product, pct in entries:
            total_reduction = 0
            for r_product, r_stage, r_amount in reductions:
                if r_product == product and (r_stage is None or r_stage == stage):
                    total_reduction += r_amount
            new_entries.append((product, max(0, pct - total_reduction)))
        adjusted[(stage, asset_type)] = new_entries
    return adjusted


def build_action_items(status: dict[str, bool]) -> str:
    """Build action items string for missing deployments.

    Returns empty string if all components are deployed.
    """
    lines: list[str] = []
    for component_key in ACTION_ITEM_MESSAGES:
        if not status.get(component_key, False):
            lines.append(ACTION_ITEM_MESSAGES[component_key])

    # Dynamic: stale/offline agents
    stale_offline_pct = status.get("_stale_offline_pct", 0)
    if isinstance(stale_offline_pct, (int, float)) and stale_offline_pct > 0:
        tiers = int(stale_offline_pct // 10)
        if tiers > 0:
            lines.append(
                f"Remediate stale/offline agents ({stale_offline_pct:.0f}% unhealthy) "
                f"to increase insightIDR coverage by {tiers * 10}%"
            )

    if not lines:
        return ""
    return "Action Items to Improve Coverage:\n" + "\n".join(f"  - {line}" for line in lines)


_STATUS_DISPLAY = {
    "covered": _COVERED,
    "not_covered": _NOT_COVERED,
    "not_applicable": _NOT_APPLICABLE,
}


def evaluate_cell_solutions(required: set[str] | None) -> str:
    """Return a comma-separated string of solution names for a cell, or N/A."""
    if required is None:
        return _NOT_APPLICABLE
    return ", ".join(sorted(required))


def build_matrix(licensed: set[str], percent: bool = False, solution: bool = False, adjusted_mapping: dict[tuple[str, str], list[tuple[str, int]] | None] | None = None) -> list[list[str]]:
    """Build the display matrix rows for the coverage grid."""
    rows: list[list[str]] = []
    for asset_type in CIS_ASSET_TYPES:
        row: list[str] = [asset_type]
        for stage in NIST_STAGES:
            if solution:
                required = CELL_MAPPING[(stage, asset_type)]
                row.append(evaluate_cell_solutions(required))
            elif percent:
                pct_mapping = adjusted_mapping if adjusted_mapping is not None else CELL_PERCENT_MAPPING
                row.append(evaluate_cell_percent(
                    pct_mapping[(stage, asset_type)], licensed,
                ))
            else:
                required = CELL_MAPPING[(stage, asset_type)]
                status = evaluate_cell(required, licensed)
                row.append(_STATUS_DISPLAY[status])
        rows.append(row)
    return rows


def render_matrix(rows: list[list[str]]) -> str:
    """Render the coverage matrix as an ASCII grid table."""
    return tabulate(rows, headers=["", *NIST_STAGES], tablefmt="grid")


def build_recommendations(licensed: set[str], percent: bool = False) -> str:
    """Return a recommendation string for unlicensed products that would improve the matrix.

    In default mode, ranks by how many new cells the product would flip from 🚫 to ✅.
    In percent mode, ranks by total percentage points the product would add across all cells.
    Only includes products that would actually improve the score.
    """
    # Collect every product name referenced in the mappings
    all_products: set[str] = set()
    for mapping in CELL_PERCENT_MAPPING.values():
        if mapping is not None:
            for product, _ in mapping:
                all_products.add(product)

    unlicensed = all_products - licensed
    if not unlicensed:
        return "You're fully covered — no additional products to recommend."

    scores: dict[str, int] = {}

    for product in unlicensed:
        score = 0
        for stage in NIST_STAGES:
            for asset_type in CIS_ASSET_TYPES:
                if percent:
                    mapping = CELL_PERCENT_MAPPING.get((stage, asset_type))
                    if mapping is None:
                        continue
                    # Current total
                    current = sum(p for prod, p in mapping if prod in licensed)
                    current = min(current, 100)
                    # Total if this product were added
                    new = sum(p for prod, p in mapping if prod in licensed or prod == product)
                    new = min(new, 100)
                    score += new - current
                else:
                    required = CELL_MAPPING.get((stage, asset_type))
                    if required is None:
                        continue
                    # Only count cells that are currently not covered
                    if not (required & licensed) and product in required:
                        score += 1
        if score > 0:
            scores[product] = score

    if not scores:
        return ""

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    unit = "percentage points" if percent else "cells"
    lines = ["\nRecommended products to improve your coverage:"]
    for product, score in ranked:
        lines.append(f"  + {product:<20s}  (+{score} {unit})")
    return "\n".join(lines)


def check_deployments(client: R7Client, config: Config) -> dict[str, bool]:
    """Query deployment APIs and return presence status for each component.

    Returns dict with keys: 'scan_engines', 'collectors', 'network_sensors',
    'honeypots', 'orchestrator'. Values are True if at least one instance exists.
    """
    status: dict[str, bool] = {
        "scan_engines": False,
        "collectors": False,
        "network_sensors": False,
        "honeypots": False,
        "orchestrator": False,
        "sc_connectors": False,
        "no_event_sources": False,    # True = event sources exist (not a problem)
        "few_event_sources": False,   # True = 5+ event sources (not a problem)
        "stale_offline_agents": True,  # True = healthy (not a problem)
        "no_active_workflows": False,  # True = active workflows exist (not a problem)
    }

    # Scan engines — IVM v4
    try:
        url = IVM_V4_BASE.format(region=config.region) + "/integration/scan/engine"
        resp = client.get(url, solution="vm", subcommand="matrix")
        if isinstance(resp, dict):
            data = resp.get("data", [])
            status["scan_engines"] = len(data) > 0
        elif isinstance(resp, list):
            status["scan_engines"] = len(resp) > 0
    except R7Error as exc:
        print(f"Warning: scan engine check failed: {exc}", file=sys.stderr)

    # IDR health-metrics checks
    idr_components = ["collectors", "network_sensors", "honeypots", "orchestrator"]
    for component in idr_components:
        try:
            url = IDR_V1_BASE.format(region=config.region) + "/health-metrics"
            resp = client.get(url, params={"resourceTypes": component},
                              solution="siem", subcommand="matrix")
            if isinstance(resp, list):
                status[component] = len(resp) > 0
            elif isinstance(resp, dict):
                # Look for any list value with items
                has_items = False
                for val in resp.values():
                    if isinstance(val, list) and len(val) > 0:
                        has_items = True
                        break
                status[component] = has_items
        except R7Error as exc:
            print(f"Warning: {component} check failed: {exc}", file=sys.stderr)

    # Surface Command connectors check
    try:
        base = SC_BASE.format(region=config.region)
        url = f"{base}/graph-api/objects/table"
        resp = client.post(
            url,
            json={"cypher": "MATCH (a:`sys.apps.integration`) RETURN a"},
            params={"format": "json"},
            solution="asm",
            subcommand="matrix-connectors",
        )
        items = resp.get("items", []) if isinstance(resp, dict) else resp if isinstance(resp, list) else []
        # Count third-party connectors (exclude built-in, rapid7, easm)
        count = 0
        for item in items:
            data = item.get("data", []) if isinstance(item, dict) else []
            name = str(data[2]) if len(data) > 2 else ""
            name_lower = name.lower()
            if not any(excl in name_lower for excl in _SC_CONNECTOR_EXCLUDE):
                count += 1
        status["sc_connectors"] = count >= _SC_CONNECTOR_MIN
    except R7Error as exc:
        print(f"Warning: Surface Command connector check failed: {exc}", file=sys.stderr)

    # Event sources check
    try:
        url = IDR_V1_BASE.format(region=config.region) + "/health-metrics"
        resp = client.get(url, params={"resourceTypes": "event_sources"},
                          solution="siem", subcommand="matrix")
        es_count = 0
        if isinstance(resp, list):
            es_count = len(resp)
        elif isinstance(resp, dict):
            for val in resp.values():
                if isinstance(val, list):
                    es_count = max(es_count, len(val))
        status["no_event_sources"] = es_count > 0
        status["few_event_sources"] = es_count >= 5
    except R7Error as exc:
        print(f"Warning: event sources check failed: {exc}", file=sys.stderr)

    # Stale/offline agents check
    try:
        url = IDR_V1_BASE.format(region=config.region) + "/health-metrics"
        resp = client.get(url, solution="siem", subcommand="matrix-agents")
        # Look for the agent status summary in the response
        data_list = resp.get("data", []) if isinstance(resp, dict) else resp if isinstance(resp, list) else []
        for entry in data_list:
            if not isinstance(entry, dict):
                continue
            rrn = entry.get("rrn", "")
            if "status:summary" in str(rrn):
                total = entry.get("total", 0)
                stale = entry.get("stale", 0)
                offline = entry.get("offline", 0)
                if total > 0:
                    unhealthy_pct = ((stale + offline) / total) * 100
                    status["_stale_offline_pct"] = unhealthy_pct
                    status["stale_offline_agents"] = unhealthy_pct < 10
                break
    except R7Error as exc:
        print(f"Warning: agent health check failed: {exc}", file=sys.stderr)

    # Active workflows check (InsightConnect)
    try:
        from r7cli.models import CONNECT_V2_BASE
        url = CONNECT_V2_BASE.format(region=config.region) + "/workflows"
        resp = client.get(url, params={"state": "active", "limit": 1},
                          solution="soar", subcommand="matrix")
        workflows = []
        if isinstance(resp, dict):
            workflows = resp.get("data", {}).get("workflows", [])
            if not workflows:
                # Try flat list
                for val in resp.values():
                    if isinstance(val, list) and val:
                        workflows = val
                        break
        elif isinstance(resp, list):
            workflows = resp
        status["no_active_workflows"] = len(workflows) > 0
    except R7Error as exc:
        print(f"Warning: active workflows check failed: {exc}", file=sys.stderr)

    return status


# ---------------------------------------------------------------------------
# Click commands
# ---------------------------------------------------------------------------

@click.group("matrix")
@click.pass_context
def matrix(ctx: click.Context) -> None:
    """Generate a NIST CSF × CIS v8 defender coverage matrix based on the Rapid7 products you're licensed for."""
    pass


@matrix.command("rapid7")
@click.option("-p", "--percent", is_flag=True, help="Show coverage percentages instead of checkmarks.")
@click.option("--solution", is_flag=True, help="Show Rapid7 solution names mapped to each cell.")
@click.option("--reality/--no-reality", "--deployment/--no-deployment", default=False,
              help="Adjust percentages based on actual deployment state.")
@click.option("--scoring", is_flag=True, help="Print the scoring rules and exit.")
@click.pass_context
def rapid7(ctx: click.Context, percent: bool, solution: bool, reality: bool, scoring: bool) -> None:
    """Display a NIST CSF × CIS v8 product coverage matrix."""
    if scoring:
        click.echo(SCORING_RULES)
        return

    if percent and solution:
        click.echo("Error: --percent and --solution are mutually exclusive.", err=True)
        ctx.exit(1)

    if reality and solution:
        click.echo("Error: --reality and --solution are mutually exclusive.", err=True)
        ctx.exit(1)

    # --reality implies --percent
    if reality and not percent:
        percent = True

    config = ctx.obj["config"]
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/products"

    try:
        data: Any = client.get(url, solution="platform", subcommand="matrix")

        if not isinstance(data, list):
            raise APIError(
                "Unexpected response format from Products API: expected a JSON array.",
                status_code=0,
                body=str(data),
            )

        licensed = resolve_product_codes(data)

        adjusted_mapping = None
        deployment_status = None
        if reality:
            deployment_status = check_deployments(client, config)
            reductions = compute_reductions(deployment_status)
            adjusted_mapping = apply_reductions(CELL_PERCENT_MAPPING, reductions)

        if solution:
            click.echo(
                "Display the Rapid7 solution names mapped to each NIST CSF × CIS v8 cell.",
                err=True,
            )
        elif reality:
            click.echo(
                "Percentages adjusted for deployment state.",
                err=True,
            )
        elif percent:
            click.echo(
                "Display the estimated coverage for the licensed Rapid7 products "
                "that you're authorized for, not authorized for, and the ones that are not applicable.",
                err=True,
            )
        else:
            click.echo(
                "Display the licensed Rapid7 products that you're authorized for, "
                "not authorized for, and the ones that are not applicable.",
                err=True,
            )
        rows = build_matrix(licensed, percent=percent, solution=solution, adjusted_mapping=adjusted_mapping)
        click.echo(render_matrix(rows))

        if not solution:
            recommendations = build_recommendations(licensed, percent=percent)
            if recommendations:
                click.echo(recommendations, err=True)

        if deployment_status is not None:
            action_items = build_action_items(deployment_status)
            if action_items:
                click.echo(action_items, err=True)

    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)



