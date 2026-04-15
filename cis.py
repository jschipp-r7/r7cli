"""CIS controls lookup for r7-cli.

Loads the master controls CSV bundled with the package and provides
filtering by product (CLI solution name) and CIS Implementation Group.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Any

import click

from r7cli.output import format_output

# ---------------------------------------------------------------------------
# Data path
# ---------------------------------------------------------------------------

_CSV_PATH = Path(__file__).parent / "controls.csv"

# ---------------------------------------------------------------------------
# CLI solution name → Rapid7 product names that appear in the CSV columns
# "Rapid7 Implementation Products (Custom Script)" and
# "Rapid7 Supporting Products (Custom Script)".
# ---------------------------------------------------------------------------

_SOLUTION_PRODUCTS: dict[str, list[str]] = {
    "vm":      ["insightVM", "Nexpose"],
    "siem":    ["insightIDR"],
    "asm":     ["Surface Command"],
    "drp":     ["DRP", "DRPS", "Threat Command"],
    "appsec":  ["insightAppSec"],
    "cnapp":   ["insightCloudSec"],
    "soar":    ["insightConnect"],
    "dspm":    ["DSPM Add-On"],
    "grc":     ["Cyber GRC Add-On"],
    "patching": ["Automox Add-On"],
}

# Friendly display names
_SOLUTION_DISPLAY: dict[str, str] = {
    "vm":      "InsightVM",
    "siem":    "InsightIDR",
    "asm":     "Surface Command",
    "drp":     "Digital Risk Protection",
    "appsec":  "InsightAppSec",
    "cnapp":   "InsightCloudSec",
    "soar":    "InsightConnect",
    "dspm":    "DSPM",
    "grc":     "Cyber GRC",
    "patching": "Automox (Patching)",
}

# Fields to display for CIS
_DISPLAY_FIELDS = [
    "Framework",
    "Version",
    "CIS Asset Type",
    "Control ID",
    "Control Description",
]

# Fields to display for NIST CSF
_CSF_DISPLAY_FIELDS = [
    "Framework",
    "Version",
    "NIST Category",
    "Control ID",
    "Control Description",
]


# ---------------------------------------------------------------------------
# Core loader
# ---------------------------------------------------------------------------

def _load_cis_rows() -> list[dict[str, str]]:
    """Load all CIS rows from the bundled CSV."""
    if not _CSV_PATH.exists():
        click.echo(f"Controls CSV not found: {_CSV_PATH}", err=True)
        sys.exit(1)
    with open(_CSV_PATH, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return [r for r in reader if "CIS" in r.get("Framework", "")]


def _load_csf_rows() -> list[dict[str, str]]:
    """Load all NIST CSF rows from the bundled CSV."""
    if not _CSV_PATH.exists():
        click.echo(f"Controls CSV not found: {_CSV_PATH}", err=True)
        sys.exit(1)
    with open(_CSV_PATH, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return [r for r in reader if r.get("Framework", "").strip() == "NIST CSF"]


def _matches_product(row: dict[str, str], solution: str) -> bool:
    """Return True if *row* references any Rapid7 product for *solution*."""
    products = _SOLUTION_PRODUCTS.get(solution, [])
    if not products:
        return False
    impl = row.get("Rapid7 Implementation Products (Custom Script)", "")
    supp = row.get("Rapid7 Supporting Products (Custom Script)", "")
    combined = f"{impl}, {supp}"
    for prod in products:
        if prod.lower() in combined.lower():
            return True
    return False


def _matches_no_product(row: dict[str, str]) -> bool:
    """Return True if *row* has no Rapid7 product mapping at all."""
    impl = row.get("Rapid7 Implementation Products (Custom Script)", "").strip()
    supp = row.get("Rapid7 Supporting Products (Custom Script)", "").strip()
    # Check if any known solution product appears
    for products in _SOLUTION_PRODUCTS.values():
        combined = f"{impl}, {supp}"
        for prod in products:
            if prod.lower() in combined.lower():
                return False
    # Also check for N/A-only or empty
    if impl in ("", "N/A") and supp in ("", "N/A"):
        return True
    # Has some product text but none of our known ones
    return True


def _matches_ig(row: dict[str, str], ig_level: str) -> bool:
    """Return True if *row*'s Framework field contains the given IG level."""
    fw = row.get("Framework", "")
    return ig_level.upper() in fw.upper()


def _filter_framework(row: dict[str, str], ig_level: str) -> str:
    """Return only the matching IG from the Framework field."""
    return f"CIS {ig_level.upper()}"


def _extract_list(raw: str) -> list[str]:
    """Split a comma-separated CSV field into a sorted, deduplicated list."""
    items: list[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        item = item.strip()
        if item and item != "N/A" and item.lower() not in seen:
            seen.add(item.lower())
            items.append(item)
    return items


def _project_row(row: dict[str, str], ig_level: str | None = None, csf: bool = False) -> dict[str, Any]:
    """Extract only the display fields from a row, plus solutions and market categories."""
    fields = _CSF_DISPLAY_FIELDS if csf else _DISPLAY_FIELDS
    result: dict[str, Any] = {}
    for field in fields:
        result[field] = row.get(field, "").strip()
    if ig_level:
        result["Framework"] = _filter_framework(row, ig_level)

    # Rapid7 solutions (implementation + supporting)
    impl = row.get("Rapid7 Implementation Products (Custom Script)", "")
    supp = row.get("Rapid7 Supporting Products (Custom Script)", "")
    combined_products = f"{impl}, {supp}" if supp.strip() else impl
    result["Solutions"] = _extract_list(combined_products)

    # Market categories (implementation + supporting)
    impl_tech = row.get("Implementation Market Technologies", "")
    supp_tech = row.get("Supporting Market Technologies", "")
    combined_tech = f"{impl_tech}, {supp_tech}" if supp_tech.strip() else impl_tech
    result["Market Categories"] = _extract_list(combined_tech)

    return result


# ---------------------------------------------------------------------------
# Public query function
# ---------------------------------------------------------------------------

def query_cis_controls(
    *,
    solution: str | None = None,
    ig1: bool = False,
    ig2: bool = False,
    ig3: bool = False,
    other: bool = False,
    dspm: bool = False,
    grc: bool = False,
    patching: bool = False,
    csf: bool = False,
) -> list[dict[str, str]]:
    """Query CIS or NIST CSF controls with optional product and IG filters.

    Returns a list of dicts with the display fields.
    """
    if csf:
        rows = _load_csf_rows()
    else:
        rows = _load_cis_rows()

    # Determine IG filter (only applies to CIS, not NIST CSF)
    ig_level: str | None = None
    if not csf:
        if ig1:
            ig_level = "IG1"
        elif ig2:
            ig_level = "IG2"
        elif ig3:
            ig_level = "IG3"

        # Filter by IG level
        if ig_level:
            rows = [r for r in rows if _matches_ig(r, ig_level)]

    # Filter by product
    if other:
        rows = [r for r in rows if _matches_no_product(r)]
    elif dspm:
        rows = [r for r in rows if _matches_product(r, "dspm")]
    elif grc:
        rows = [r for r in rows if _matches_product(r, "grc")]
    elif patching:
        rows = [r for r in rows if _matches_product(r, "patching")]
    elif solution:
        rows = [r for r in rows if _matches_product(r, solution)]

    # Project to display fields
    results = [_project_row(r, ig_level, csf=csf) for r in rows]

    # Deduplicate by Control ID (same control can appear with different frameworks)
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for r in results:
        key = r["Control ID"]
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    # Sort by Control ID numerically
    def _sort_key(r: dict) -> tuple:
        parts = r["Control ID"].split(".")
        nums = []
        for p in parts:
            try:
                nums.append(int(p))
            except ValueError:
                nums.append(0)
        return tuple(nums)

    deduped.sort(key=_sort_key)
    return deduped


# ---------------------------------------------------------------------------
# Shared Click options + command factory
# ---------------------------------------------------------------------------

def _add_cis_options(cmd):
    """Decorate a Click command with the standard CIS filter options."""
    cmd = click.option("--ig1", is_flag=True, help="Show only CIS IG1 controls.")(cmd)
    cmd = click.option("--ig2", is_flag=True, help="Show only CIS IG2 controls.")(cmd)
    cmd = click.option("--ig3", is_flag=True, help="Show only CIS IG3 controls.")(cmd)
    cmd = click.option("--other", is_flag=True, help="Show controls not mapped to any Rapid7 product.")(cmd)
    return cmd


def make_cis_command(solution: str) -> click.Command:
    """Create a ``cis`` subcommand for the given solution."""

    @click.command("cis")
    @click.option("--ig1", is_flag=True, help="Show only CIS IG1 controls.")
    @click.option("--ig2", is_flag=True, help="Show only CIS IG2 controls.")
    @click.option("--ig3", is_flag=True, help="Show only CIS IG3 controls.")
    @click.option("--csf", is_flag=True, help="Show NIST CSF controls instead of CIS.")
    @click.option("--other", is_flag=True, help="Show controls not mapped to any Rapid7 product.")
    @click.option("--dspm", is_flag=True, help="Show CIS controls for DSPM.")
    @click.option("--grc", is_flag=True, help="Show CIS controls for Cyber GRC.")
    @click.option("--patching", is_flag=True, help="Show CIS controls for Automox (Patching).")
    @click.pass_context
    def cis_cmd(ctx, ig1, ig2, ig3, csf, other, dspm, grc, patching):
        f"""List CIS controls relevant to {_SOLUTION_DISPLAY.get(solution, solution)}.

        \b
        Examples:
          r7-cli {solution} cis
          r7-cli {solution} cis --ig1
          r7-cli {solution} cis --csf
          r7-cli -o table {solution} cis --ig2
        """
        config = ctx.obj["config"]
        if other:
            results = query_cis_controls(ig1=ig1, ig2=ig2, ig3=ig3, other=True, csf=csf)
        elif dspm:
            results = query_cis_controls(ig1=ig1, ig2=ig2, ig3=ig3, dspm=True, csf=csf)
        elif grc:
            results = query_cis_controls(ig1=ig1, ig2=ig2, ig3=ig3, grc=True, csf=csf)
        elif patching:
            results = query_cis_controls(ig1=ig1, ig2=ig2, ig3=ig3, patching=True, csf=csf)
        else:
            results = query_cis_controls(solution=solution, ig1=ig1, ig2=ig2, ig3=ig3, csf=csf)
        if not results:
            click.echo("No matching CIS controls found.", err=True)
            return
        click.echo(format_output(results, config.output_format, config.limit, config.search, short=config.short))

    cis_cmd.help = (
        f"List CIS controls relevant to {_SOLUTION_DISPLAY.get(solution, solution)}.\n\n"
        f"Use --ig1, --ig2, or --ig3 to filter by Implementation Group.\n"
        f"Use --other to show controls not mapped to any Rapid7 product."
    )
    return cis_cmd
