"""Compliance command — VM policy export pipeline with SQL output."""
from __future__ import annotations

import glob
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
import pyarrow.parquet as pq

from r7cli.cli_group import GlobalFlagHintGroup
from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import (
    IVM_BULK_GQL,
    GQL_GET_EXPORT,
    R7Error,
)
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Policy schema columns (for reference / ordering)
# ---------------------------------------------------------------------------
POLICY_COLUMNS = [
    "benchmarkNaturalId",
    "profileNaturalId",
    "benchmarkVersion",
    "ruleNaturalId",
    "orgId",
    "assetId",
    "finalStatus",
    "proof",
    "lastAssessmentTimestamp",
    "benchmarkTitle",
    "profileTitle",
    "publisher",
    "ruleTitle",
    "fixTexts",
    "rationales",
]

LIST_COLUMNS = {"fixTexts", "rationales"}
TIMESTAMP_COLUMNS = {"lastAssessmentTimestamp"}


# ---------------------------------------------------------------------------
# Parquet reading
# ---------------------------------------------------------------------------

def _read_policy_parquet(paths: list[Path]) -> list[dict]:
    """Read asset_policy Parquet files and return rows as list of dicts.

    Only files whose name starts with ``asset_policy`` are read.
    Timestamps are converted to ISO-8601 strings.
    List columns (fixTexts, rationales) are converted to Python lists.
    """
    policy_paths = [p for p in paths if Path(p).name.startswith("asset_policy")]
    rows: list[dict] = []
    for path in policy_paths:
        try:
            table = pq.read_table(str(path))
        except Exception as exc:
            click.echo(f"Failed to read Parquet file '{path}': {exc}", err=True)
            sys.exit(2)
        # Convert to Python dicts, handling special column types
        col_names = table.column_names
        for row_idx in range(table.num_rows):
            row: dict[str, Any] = {}
            for col_name in col_names:
                col = table.column(col_name)
                val = col[row_idx].as_py()
                # Convert timestamps to ISO-8601 strings
                if col_name in TIMESTAMP_COLUMNS and val is not None:
                    if isinstance(val, datetime):
                        val = val.isoformat()
                    else:
                        val = str(val)
                # Ensure list columns are Python lists
                if col_name in LIST_COLUMNS:
                    if val is None:
                        val = []
                    elif not isinstance(val, list):
                        val = list(val)
                row[col_name] = val
            rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# SQL formatting
# ---------------------------------------------------------------------------

def _escape_sql_string(val: str) -> str:
    """Escape single quotes for SQL string literals."""
    return val.replace("'", "''")


def _format_sql_value(val: Any, col_name: str) -> str:
    """Format a single value as a SQL literal."""
    if val is None:
        return "NULL"
    if col_name in LIST_COLUMNS:
        if not val:
            return "ARRAY[]::varchar[]"
        elements = ",".join(f"'{_escape_sql_string(str(v))}'" for v in val)
        return f"ARRAY[{elements}]"
    if col_name in TIMESTAMP_COLUMNS:
        return f"'{_escape_sql_string(str(val))}'"
    return f"'{_escape_sql_string(str(val))}'"


def _format_sql(rows: list[dict], table_name: str, timestamp: str) -> str:
    """Convert rows to SQL INSERT statements with a header comment.

    Parameters
    ----------
    rows:
        List of policy row dicts.
    table_name:
        Target SQL table name.
    timestamp:
        Export timestamp for the header comment.

    Returns
    -------
    str
        Complete SQL output with header comment and INSERT statements.
    """
    if not rows:
        return f"-- Compliance export: {timestamp} | Rows: 0\n"

    # Use column order from first row (preserving Policy_Schema order when possible)
    columns = list(rows[0].keys())
    col_list = ", ".join(columns)

    lines: list[str] = []
    lines.append(f"-- Compliance export: {timestamp} | Rows: {len(rows)}")

    for row in rows:
        values = ", ".join(_format_sql_value(row.get(c), c) for c in columns)
        lines.append(f"INSERT INTO {table_name} ({col_list}) VALUES ({values});")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# File download and naming
# ---------------------------------------------------------------------------

def _download_and_rename(
    client: R7Client,
    export: dict,
    output_dir: str,
) -> list[Path]:
    """Download Parquet files from export result with standardized naming.

    Each result entry has a ``prefix`` and ``urls`` list. Files are named
    ``{prefix}.{timestamp}.parquet`` using the export's ``timestamp`` field.
    For multi-URL entries, a zero-based index is appended before ``.parquet``.

    Returns list of Path objects for all downloaded files.
    """
    from r7cli.solutions.vm import _download_parquet_urls

    result_data = export.get("result", [])
    export_ts = export.get("timestamp", datetime.now(timezone.utc).isoformat())

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    all_files: list[Path] = []

    if isinstance(result_data, list):
        for entry in result_data:
            if not isinstance(entry, dict):
                continue
            prefix = entry.get("prefix", "export")
            urls = entry.get("urls", [])
            if urls:
                downloaded = _download_parquet_urls(client, urls, output_dir, prefix=prefix, timestamp=export_ts)
                all_files.extend(downloaded)
    elif isinstance(result_data, dict):
        prefix = result_data.get("prefix", "export")
        urls = result_data.get("urls", [])
        if urls:
            downloaded = _download_parquet_urls(client, urls, output_dir, prefix=prefix, timestamp=export_ts)
            all_files.extend(downloaded)

    return all_files


# ---------------------------------------------------------------------------
# Cache lookup
# ---------------------------------------------------------------------------

def _find_cached_files(output_dir: str) -> list[Path]:
    """Glob for ``asset_policy.*.parquet`` in the output directory."""
    pattern = str(Path(output_dir) / "asset_policy.*.parquet")
    return [Path(p) for p in glob.glob(pattern)]


# ---------------------------------------------------------------------------
# Click command
# ---------------------------------------------------------------------------

@click.group("compliance", invoke_without_command=True)
@click.option("--output-dir", type=click.Path(), default=".", help="Directory for Parquet files.")
@click.option("--table-name", default="policy_compliance", help="SQL target table name.")
@click.option("--sql-file", type=click.Path(), default=None, help="Write output to file instead of stdout.")
@click.option("--poll-interval", type=int, default=10, help="Export poll interval in seconds.")
@click.pass_context
def compliance(ctx, output_dir, table_name, sql_file, poll_interval):
    """Generate a SQL dump of VM policy compliance data.

    Triggers a VM policy export, downloads the Parquet files, reads the
    asset_policy data, and emits SQL INSERT statements (or json/table/csv/tsv).
    The downloaded files are stored in the Parquet format.

    \b
    Subcommands:
      list   List CIS controls by product

    \b
    Examples:
      # Generate SQL dump to stdout
      r7-cli compliance

    \b
      # Save SQL to a file
      r7-cli compliance --sql-file policy_dump.sql

    \b
      # Use cached Parquet files (skip export)
      r7-cli -c compliance

    \b
      # Output as JSON instead of SQL
      r7-cli -o json compliance

    \b
      # Custom table name
      r7-cli compliance --table-name my_policy_table

    \b
      # Specify output directory for Parquet files
      r7-cli compliance --output-dir ./exports
    """
    # If a subcommand was invoked, skip the default export behavior
    if ctx.invoked_subcommand is not None:
        return

    config: Config = ctx.obj["config"]

    # Default output format to "sql" when user hasn't explicitly set --output
    fmt = config.output_format
    if fmt == "json":
        # Check if the user explicitly passed -o/--output by inspecting the
        # Click context params. If not explicitly set, default to sql.
        root_ctx = ctx.parent
        if root_ctx and root_ctx.get_parameter_source("output_format") != click.core.ParameterSource.COMMANDLINE:
            fmt = "sql"

    try:
        # --- Cache check ---
        if config.use_cache:
            cached = _find_cached_files(output_dir)
            if cached:
                click.echo(f"Using {len(cached)} cached file(s): {', '.join(str(f) for f in cached)}", err=True)
                parquet_files = cached
            else:
                click.echo("No cached files found, running export pipeline…", err=True)
                parquet_files = _run_export_pipeline(config, output_dir, poll_interval)
        else:
            parquet_files = _run_export_pipeline(config, output_dir, poll_interval)

        # --- Read Parquet ---
        rows = _read_policy_parquet(parquet_files)

        # --- Format output ---
        if fmt == "sql":
            timestamp = datetime.now(timezone.utc).isoformat()
            output_text = _format_sql(rows, table_name, timestamp)
        elif fmt == "tsv":
            output_text = format_output(rows, "tsv", config.limit, config.search, short=config.short)
        else:
            output_text = format_output(rows, fmt, config.limit, config.search, short=config.short)

        # --- Write output ---
        if sql_file:
            try:
                with open(sql_file, "w") as fh:
                    fh.write(output_text)
                click.echo(f"{sql_file}", err=True)
            except OSError as exc:
                click.echo(f"Cannot write to '{sql_file}': {exc}", err=True)
                sys.exit(1)
        else:
            click.echo(output_text, nl=False)

    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


def _run_export_pipeline(config: Config, output_dir: str, poll_interval: int) -> list[Path]:
    """Run the full export pipeline: submit, poll, download, rename."""
    from r7cli.solutions.vm import _poll_export, _download_parquet_urls
    from r7cli.models import GQL_CREATE_POLICY_EXPORT, IVM_BULK_GQL, APIError
    from r7cli.jobs import JobStore
    import re
    import json as _json

    client = R7Client(config)
    gql_url = IVM_BULK_GQL.format(region=config.region)
    store = JobStore()

    mutation = {
        "query": "mutation CreatePolicyExport { createPolicyExport(input:{}) {id} }"
    }

    job_id: str | None = None
    try:
        result = client.post(gql_url, json=mutation, solution="vm", subcommand="export-policies")
        data = result.get("data", {})
        for val in data.values():
            if isinstance(val, dict) and "id" in val:
                job_id = val["id"]
                break
    except APIError as exc:
        if "FAILED_PRECONDITION" in exc.body:
            match = re.search(r"exportId[\":\s]+([a-f0-9-]+)", exc.body, re.IGNORECASE)
            if match:
                job_id = match.group(1)
                click.echo(f"Export already in progress: {job_id}", err=True)
            else:
                raise
        else:
            raise

    if job_id is None:
        click.echo("Failed to extract job ID from response.", err=True)
        sys.exit(2)

    click.echo(f"Export job: {job_id}", err=True)

    # Poll until terminal
    export = _poll_export(client, config, job_id, poll_interval)
    status = export.get("status", "")

    if status == "FAILED":
        click.echo(f"Export {job_id} FAILED.", err=True)
        sys.exit(2)

    # Download and rename
    return _download_and_rename(client, export, output_dir)

# ---------------------------------------------------------------------------
# compliance list — CIS controls by product
# ---------------------------------------------------------------------------

@compliance.command("list")
@click.option("--vm", "show_vm", is_flag=True, help="Show CIS controls for InsightVM.")
@click.option("--siem", "show_siem", is_flag=True, help="Show CIS controls for InsightIDR.")
@click.option("--asm", "show_asm", is_flag=True, help="Show CIS controls for Surface Command.")
@click.option("--drp", "show_drp", is_flag=True, help="Show CIS controls for Digital Risk Protection.")
@click.option("--appsec", "show_appsec", is_flag=True, help="Show CIS controls for InsightAppSec.")
@click.option("--cnapp", "show_cnapp", is_flag=True, help="Show CIS controls for InsightCloudSec.")
@click.option("--soar", "show_soar", is_flag=True, help="Show CIS controls for InsightConnect.")
@click.option("--dspm", "show_dspm", is_flag=True, help="Show CIS controls for DSPM.")
@click.option("--grc", "show_grc", is_flag=True, help="Show CIS controls for Cyber GRC.")
@click.option("--patching", "show_patching", is_flag=True, help="Show CIS controls for Automox (Patching).")
@click.option("--ig1", is_flag=True, help="Show only CIS IG1 controls.")
@click.option("--ig2", is_flag=True, help="Show only CIS IG2 controls.")
@click.option("--ig3", is_flag=True, help="Show only CIS IG3 controls.")
@click.option("--csf", is_flag=True, help="Show NIST CSF controls instead of CIS.")
@click.option("--other", is_flag=True, help="Show controls not mapped to any Rapid7 product.")
@click.pass_context
def compliance_list(ctx, show_vm, show_siem, show_asm, show_drp, show_appsec, show_cnapp, show_soar, show_dspm, show_grc, show_patching, ig1, ig2, ig3, csf, other):
    """List CIS or NIST CSF controls, optionally filtered by product.

    \b
    Examples:
      r7-cli platform compliance list
      r7-cli platform compliance list --vm
      r7-cli platform compliance list --siem --ig1
      r7-cli platform compliance list --csf
      r7-cli platform compliance list --csf --vm
      r7-cli platform compliance list --dspm
      r7-cli platform compliance list --grc
      r7-cli -o table platform compliance list --asm
      r7-cli platform compliance list --other
    """
    from r7cli.cis import query_cis_controls
    from r7cli.output import format_output as _fmt

    config: Config = ctx.obj["config"]

    # Determine which solution to filter by
    solution = None
    flags = {
        "vm": show_vm, "siem": show_siem, "asm": show_asm,
        "drp": show_drp, "appsec": show_appsec, "cnapp": show_cnapp,
        "soar": show_soar,
    }
    selected = [k for k, v in flags.items() if v]
    if len(selected) > 1 or (selected and (show_dspm or show_grc or show_patching)) or sum([show_dspm, show_grc, show_patching]) > 1:
        click.echo("Specify at most one product flag.", err=True)
        sys.exit(1)
    if selected:
        solution = selected[0]

    results = query_cis_controls(
        solution=solution,
        ig1=ig1,
        ig2=ig2,
        ig3=ig3,
        other=other,
        dspm=show_dspm,
        grc=show_grc,
        patching=show_patching,
        csf=csf,
    )

    if not results:
        click.echo("No matching CIS controls found.", err=True)
        return

    click.echo(_fmt(results, config.output_format, config.limit, config.search, short=config.short))
