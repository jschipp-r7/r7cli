"""Parquet file resolution, schema detection, reading, filtering, and auto-join.

Used by the ``vm export list`` command to query locally downloaded Parquet files.
"""
from __future__ import annotations

import glob
import operator
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from decimal import Decimal

import click
import pyarrow.parquet as pq

# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

SCHEMA_ASSET = "asset"
SCHEMA_VULNERABILITY = "vulnerability"
SCHEMA_POLICY = "policy"
SCHEMA_REMEDIATION = "remediation"

# Columns that indicate numeric filter behaviour
NUMERIC_COLUMNS = {"cvssScore", "cvssV3Score", "riskScore", "port"}

# Columns that indicate boolean filter behaviour
BOOLEAN_COLUMNS = {"hasExploits", "pciCompliant"}

# Columns that indicate date filter behaviour
DATE_COLUMNS = {"firstFoundTimestamp", "lastFoundTimestamp"}


# ---------------------------------------------------------------------------
# File Resolution
# ---------------------------------------------------------------------------

def resolve_files(use_cache: bool, file_pattern: str | None) -> list[Path]:
    """Return Parquet file paths from cache glob or explicit pattern.

    *file_pattern* takes precedence over *use_cache*.
    Falls back to searching the current directory if neither is specified.
    Exits with code 1 when no files are found.
    """
    paths: list[Path] = []

    if file_pattern:
        paths = [Path(p) for p in glob.glob(file_pattern)]
    elif use_cache:
        paths = [Path(p) for p in glob.glob("*.parquet")]
    else:
        # Auto-search current directory
        cwd = Path.cwd().resolve()
        click.echo(f"No Parquet files specified with --files, searching for Parquet files in {cwd} instead", err=True)
        paths = [Path(p) for p in glob.glob("*.parquet")]

    if not paths:
        click.echo(
            "No Parquet files found. Use the VM export commands to download bulk data first:\n"
            "  r7-cli vm export vulnerabilities --auto\n"
            "  r7-cli vm export policies --auto\n"
            "  r7-cli vm export remediations --auto",
            err=True,
        )
        sys.exit(1)

    return sorted(paths)


# ---------------------------------------------------------------------------
# Schema Detection
# ---------------------------------------------------------------------------

def detect_schema(path: Path) -> str | None:
    """Classify a Parquet file by inspecting column names only.

    Priority order: vulnId → vulnerability, benchmarkNaturalId → policy,
    remediationCount → remediation, hostName → asset.
    Returns ``None`` (with a warning) for unknown schemas.
    """
    try:
        schema = pq.read_schema(str(path.resolve()))
    except Exception as exc:
        click.echo(f"Warning: cannot read schema of '{path}': {exc}", err=True)
        return None

    columns = set(schema.names)

    if "vulnId" in columns:
        return SCHEMA_VULNERABILITY
    if "benchmarkNaturalId" in columns:
        return SCHEMA_POLICY
    if "remediationCount" in columns:
        return SCHEMA_REMEDIATION
    if "hostName" in columns:
        return SCHEMA_ASSET

    click.echo(f"Warning: unknown schema in '{path}', skipping.", err=True)
    return None


# ---------------------------------------------------------------------------
# Parquet Reading
# ---------------------------------------------------------------------------

def read_parquet_files(paths: list[Path]) -> list[dict]:
    """Read Parquet files and return rows as ``list[dict]``.

    * Timestamp columns are converted to ISO-8601 strings.
    * List-typed columns are converted to Python lists.
    * Exits with code 2 on corrupt / unreadable files.
    """
    rows: list[dict] = []
    for path in paths:
        try:
            table = pq.read_table(str(path.resolve()))
        except Exception as exc:
            click.echo(f"Error: failed to read '{path}': {exc}", err=True)
            sys.exit(2)

        col_names = table.column_names
        schema = table.schema

        for row_idx in range(table.num_rows):
            row: dict[str, Any] = {}
            for col_name in col_names:
                col = table.column(col_name)
                val = col[row_idx].as_py()

                # Timestamp → ISO-8601 string
                if val is not None and isinstance(val, datetime):
                    val = val.isoformat()

                # Decimal → float (pyarrow decimal columns)
                if isinstance(val, Decimal):
                    val = float(val)

                # Ensure list-typed columns stay as Python lists
                if val is not None and isinstance(val, list):
                    pass  # already a list from as_py()

                row[col_name] = val
            rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Comparison Parsing
# ---------------------------------------------------------------------------

_OPERATORS: list[tuple[str, Callable]] = [
    (">=", operator.ge),
    ("<=", operator.le),
    ("==", operator.eq),
    (">", operator.gt),
    ("<", operator.lt),
    ("=", operator.eq),
]


def parse_comparison(expr: str) -> tuple[Callable, str]:
    """Parse an expression like ``'>=9.0'`` into ``(operator.ge, '9.0')``.

    Supported operators: ``>=``, ``<=``, ``>``, ``<``, ``==``, ``=``.
    If no operator prefix is found the expression is returned with ``operator.eq``.
    """
    for op_str, op_func in _OPERATORS:
        if expr.startswith(op_str):
            return op_func, expr[len(op_str):]
    return operator.eq, expr


# ---------------------------------------------------------------------------
# Filter Engine
# ---------------------------------------------------------------------------

def _match_string(row_val: Any, filter_val: str) -> bool:
    """Case-insensitive substring or glob match.

    If *filter_val* contains ``*`` or ``?``, it is treated as a glob pattern
    (using :func:`fnmatch.fnmatch`).  Otherwise it is a substring match.
    """
    if row_val is None:
        return False
    val_str = str(row_val).lower()
    fv = filter_val.lower()
    if "*" in filter_val or "?" in filter_val:
        import fnmatch
        return fnmatch.fnmatch(val_str, fv)
    return fv in val_str


def _match_numeric(row_val: Any, filter_expr: str) -> bool:
    """Parse comparison operator + threshold and compare as float."""
    if row_val is None:
        return False
    op_func, threshold_str = parse_comparison(filter_expr)
    try:
        threshold = float(threshold_str)
    except ValueError:
        click.echo(f"Error: invalid numeric filter value '{filter_expr}'. Example: '>=9.0'", err=True)
        sys.exit(1)
    try:
        return op_func(float(row_val), threshold)
    except (ValueError, TypeError):
        return False


def _match_boolean(row_val: Any, filter_expr: str) -> bool:
    """Compare against boolean literal (true/false, case-insensitive)."""
    if row_val is None:
        return False
    expected = filter_expr.strip().lower() == "true"
    if isinstance(row_val, bool):
        return row_val == expected
    return str(row_val).lower() == str(expected).lower()


def _match_date(row_val: Any, filter_expr: str) -> bool:
    """Parse ISO-8601 date comparison."""
    if row_val is None:
        return False
    op_func, date_str = parse_comparison(filter_expr)
    try:
        threshold = datetime.fromisoformat(date_str)
    except ValueError:
        click.echo(f"Error: invalid date filter value '{filter_expr}'. Use ISO-8601 format.", err=True)
        sys.exit(1)
    try:
        if isinstance(row_val, str):
            row_dt = datetime.fromisoformat(row_val)
        elif isinstance(row_val, datetime):
            row_dt = row_val
        else:
            return False
        return op_func(row_dt, threshold)
    except (ValueError, TypeError):
        return False


def apply_filters(rows: list[dict], filters: dict) -> list[dict]:
    """Apply all filter predicates as logical AND.

    *filters* maps column names to filter expressions.  The column name
    determines the matching strategy:

    * Columns in ``NUMERIC_COLUMNS`` → numeric comparison
    * Columns in ``BOOLEAN_COLUMNS`` → boolean match
    * Columns in ``DATE_COLUMNS`` → date comparison
    * Everything else → case-insensitive substring
    """
    if not filters:
        return rows

    result: list[dict] = []
    for row in rows:
        match = True
        for col, expr in filters.items():
            if col not in row:
                continue  # ignore filters for columns not in the row
            if col in NUMERIC_COLUMNS:
                if not _match_numeric(row[col], expr):
                    match = False
                    break
            elif col in BOOLEAN_COLUMNS:
                if not _match_boolean(row[col], expr):
                    match = False
                    break
            elif col in DATE_COLUMNS:
                if not _match_date(row[col], expr):
                    match = False
                    break
            else:
                if not _match_string(row[col], expr):
                    match = False
                    break
        if match:
            result.append(row)
    return result


# ---------------------------------------------------------------------------
# Generic --where filter
# ---------------------------------------------------------------------------

_WHERE_RE = re.compile(r"^(\S+)\s+(>=|<=|==|!=|>|<|=)\s+(.+)$")


def apply_where(rows: list[dict], where_clauses: list[str], schema_columns: dict) -> list[dict]:
    """Parse and apply ``--where 'column op value'`` clauses (AND logic).

    *schema_columns* maps column names to pyarrow type strings so the
    correct comparison strategy can be chosen automatically.
    """
    if not where_clauses:
        return rows

    predicates: list[tuple[str, Callable, str]] = []
    for clause in where_clauses:
        m = _WHERE_RE.match(clause.strip())
        if not m:
            click.echo(
                f"Error: invalid --where syntax '{clause}'. Expected: 'column op value'",
                err=True,
            )
            sys.exit(1)
        col, op_str, val = m.group(1), m.group(2), m.group(3).strip()
        # Resolve operator
        op_func: Callable | None = None
        for sym, fn in _OPERATORS:
            if sym == op_str:
                op_func = fn
                break
        if op_func is None:
            op_func = operator.eq
        predicates.append((col, op_func, val))

    result: list[dict] = []
    for row in rows:
        match = True
        for col, op_func, val in predicates:
            row_val = row.get(col)
            if row_val is None:
                match = False
                break

            col_type = schema_columns.get(col, "string")

            # Determine comparison strategy from schema type
            if "int" in col_type or "float" in col_type or "double" in col_type:
                try:
                    if not op_func(float(row_val), float(val)):
                        match = False
                        break
                except (ValueError, TypeError):
                    match = False
                    break
            elif "timestamp" in col_type or "date" in col_type:
                try:
                    row_dt = datetime.fromisoformat(str(row_val)) if isinstance(row_val, str) else row_val
                    val_dt = datetime.fromisoformat(val)
                    if not op_func(row_dt, val_dt):
                        match = False
                        break
                except (ValueError, TypeError):
                    match = False
                    break
            else:
                # String comparison — use substring for = / ==, otherwise lexicographic
                if op_func in (operator.eq,):
                    if val.lower() not in str(row_val).lower():
                        match = False
                        break
                else:
                    if not op_func(str(row_val).lower(), val.lower()):
                        match = False
                        break
        if match:
            result.append(row)
    return result


# ---------------------------------------------------------------------------
# Auto-Join
# ---------------------------------------------------------------------------

def auto_join(primary_rows: list[dict], asset_rows: list[dict]) -> list[dict]:
    """Join primary rows with asset data on ``assetId``.

    Builds an ``assetId → asset_row`` lookup, then enriches each primary
    row with asset fields so that asset-specific filters can be applied.
    Returns enriched rows (asset fields are kept for filtering).
    """
    if not asset_rows:
        return primary_rows

    # Build lookup — last asset row per assetId wins
    asset_lookup: dict[str, dict] = {}
    for arow in asset_rows:
        aid = arow.get("assetId")
        if aid is not None:
            asset_lookup[str(aid)] = arow

    enriched: list[dict] = []
    for row in primary_rows:
        aid = row.get("assetId")
        if aid is not None and str(aid) in asset_lookup:
            merged = {**asset_lookup[str(aid)], **row}
            enriched.append(merged)
        else:
            enriched.append(row)
    return enriched
