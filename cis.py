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
}

# Fields to display
_DISPLAY_FIELDS = [
    "Framework",
    "Version",
    "CIS Asset Type",
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


def _project_row(row: dict[str, str], ig_level: str | None = None) -> dict[str, str]:
    """Extract only the display fields from a row."""
    result = {}
    for field in _DISPLAY_FIELDS:
        result[field] = row.get(field, "").strip()
    if ig_level:
        result["Framework"] = _filter_framework(row, ig_level)
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
) -> list[dict[str, str]]:
    """Query CIS controls with optional product and IG filters.

    Returns a list of dicts with the display fields.
    """
    rows = _load_cis_rows()

    # Determine IG filter
    ig_level: str | None = None
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
    elif solution:
        rows = [r for r in rows if _matches_product(r, solution)]

    # Project to display fields
    results = [_project_row(r, ig_level) for r in rows]

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
    @click.option("--other", is_flag=True, help="Show controls not mapped to any Rapid7 product.")
    @click.pass_context
    def cis_cmd(ctx, ig1, ig2, ig3, other):
        f"""List CIS controls relevant to {_SOLUTION_DISPLAY.get(solution, solution)}.

        \b
        Examples:
          r7-cli {solution} cis
          r7-cli {solution} cis --ig1
          r7-cli -o table {solution} cis --ig2
        """
        config = ctx.obj["config"]
        if other:
            results = query_cis_controls(ig1=ig1, ig2=ig2, ig3=ig3, other=True)
        else:
            results = query_cis_controls(solution=solution, ig1=ig1, ig2=ig2, ig3=ig3)
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
