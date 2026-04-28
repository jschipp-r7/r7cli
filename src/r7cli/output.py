"""Output formatting for r7-cli.

Supports ``json``, ``table`` (via tabulate), and ``csv`` output formats.
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
from typing import Any

from tabulate import tabulate


# ---------------------------------------------------------------------------
# Short-mode priority constants
# ---------------------------------------------------------------------------

HIGH_PRIORITY_FIELDS: frozenset[str] = frozenset({
    "name", "title", "status", "type", "severity", "value",
    "description", "hostName", "ip", "domain", "hostname", "mac",
    "product_code", "organization_name", "riskScore", "risk_score",
    "cvss", "cvssScore", "cvss_score",
})

LOW_PRIORITY_SUBSTRINGS: tuple[str, ...] = ("id", "uuid", "token", "url", "hash", "base64")

MEDIUM_PRIORITY_SUBSTRINGS: tuple[str, ...] = ("date", "time", "timestamp", "count", "version", "created")

UUID_PATTERN: re.Pattern = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def _get_terminal_width() -> int:
    """Get the terminal width, even when stdout is piped.

    Falls back to stderr's width (usually still a TTY), then the
    controlling terminal, then 120 as a reasonable default.
    """
    import os

    # Try stdout first (works when not piped)
    try:
        width = os.get_terminal_size(1).columns  # fd 1 = stdout
        if width > 0:
            return width
    except (ValueError, OSError):
        pass

    # Try stderr (usually still a TTY even when stdout is piped)
    try:
        width = os.get_terminal_size(2).columns  # fd 2 = stderr
        if width > 0:
            return width
    except (ValueError, OSError):
        pass

    # Last resort: shutil fallback
    return shutil.get_terminal_size((120, 24)).columns


def _classify_field(key: str, value: Any) -> int:
    """Return priority tier for a field: 0=high, 1=medium, 2=low, 3=default.

    Precedence: high > low > medium > default.
    """
    if key in HIGH_PRIORITY_FIELDS:
        return 0
    key_lower = key.lower()
    if any(sub in key_lower for sub in LOW_PRIORITY_SUBSTRINGS) or (
        isinstance(value, str) and UUID_PATTERN.match(value)
    ):
        return 2
    if any(sub in key_lower for sub in MEDIUM_PRIORITY_SUBSTRINGS) or isinstance(value, bool):
        return 1
    return 3


def _reorder_fields(obj: dict) -> dict:
    """Reorder dict keys by priority tier: 0 → 1 → 3 → 2.

    Preserves original insertion order within each tier.
    """
    tiers: dict[int, list[tuple[str, Any]]] = {0: [], 1: [], 2: [], 3: []}
    for key, value in obj.items():
        tier = _classify_field(key, value)
        tiers[tier].append((key, value))
    result: dict[str, Any] = {}
    for tier in (0, 1, 3, 2):
        for k, v in tiers[tier]:
            result[k] = v
    return result


def _truncate_line(line: str, width: int) -> str:
    """Truncate *line* to *width* characters, appending ``…`` if needed."""
    if len(line) <= width:
        return line
    return line[: width - 1] + "…"


def _format_short(data: Any, terminal_width: int) -> str:
    """Format *data* as compact one-line-per-row JSON with field reordering and truncation."""
    rows = _extract_rows(data)
    if not rows:
        return ""
    lines: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            row = _reorder_fields(row)
        line = json.dumps(row, separators=(",", ":"), default=str)
        line = _truncate_line(line, terminal_width)
        lines.append(line)
    return "\n".join(lines)


def apply_limit(data: Any, n: int) -> Any:
    """Truncate the row data to *n* items.

    - If *data* is a list, truncate it directly.
    - If *data* is a dict, find the largest top-level list field and truncate it.
    - Other types are returned unchanged.
    """
    if isinstance(data, list):
        return data[:n]

    if not isinstance(data, dict):
        return data

    # Find the key whose value is the longest list
    best_key: str | None = None
    best_len = -1
    for key, val in data.items():
        if isinstance(val, list) and len(val) > best_len:
            best_key = key
            best_len = len(val)

    if best_key is None:
        return data

    result = dict(data)
    result[best_key] = data[best_key][:n]
    return result


def format_output(data: Any, fmt: str, limit: int | None = None, search: str | None = None, short: bool = False) -> str:
    """Serialize *data* to the requested format string.

    This is the single output path for all CLI commands. Every command
    calls ``format_output()`` (or the ``emit()`` shorthand) rather than
    formatting data directly.

    Parameters
    ----------
    data : Any
        The structured data to format (dict, list of dicts, etc.).
    fmt : str
        One of ``"json"``, ``"table"``, ``"csv"``, ``"tsv"``, ``"sql"``.
    limit : int, optional
        If set, truncate the largest top-level array to this many items
        before formatting.
    search : str, optional
        If set, search the data for this field name and return matching
        values instead of the full output.
    short : bool
        If True and *fmt* is ``"json"`` and *search* is None, use compact
        single-line-per-row output with field reordering and terminal-width
        truncation.

    Returns
    -------
    str
        The formatted output string, ready for ``click.echo()``.
    """
    if limit is not None:
        data = apply_limit(data, limit)

    if search is not None:
        values = search_field(data, search)
        return format_search_results(values, search)

    if short and fmt == "json":
        return _format_short(data, _get_terminal_width())

    if fmt == "json":
        return json.dumps(data, indent=2)

    if fmt == "table":
        if short:
            return _format_table_short(data, _get_terminal_width())
        return _format_table(data)

    if fmt == "csv":
        return _format_csv(data)

    if fmt == "tsv":
        return _format_tsv(data)

    # Fallback to JSON for unknown formats
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _format_table(data: Any) -> str:
    """Render *data* as a grid table via :func:`tabulate`."""
    rows = _extract_rows(data)
    if not rows:
        return ""
    if isinstance(rows[0], dict):
        return tabulate(rows, headers="keys", tablefmt="grid")
    return tabulate(rows, tablefmt="grid")


def _format_table_short(data: Any, terminal_width: int) -> str:
    """Render *data* as a compact table with columns truncated to fit the terminal.

    No single column may exceed 25% of the terminal width. The table is
    guaranteed to fit within *terminal_width* characters.
    """
    rows = _extract_rows(data)
    if not rows:
        return ""
    if not isinstance(rows[0], dict):
        return tabulate(rows, tablefmt="grid")

    headers = list(rows[0].keys())
    num_cols = len(headers)
    if num_cols == 0:
        return ""

    # Calculate the max content width per column (header + all rows)
    max_widths: list[int] = []
    for h in headers:
        col_max = len(h)
        for row in rows:
            val = str(row.get(h, ""))
            col_max = max(col_max, len(val))
        max_widths.append(col_max)

    # Tabulate grid overhead: "| " + content + " " per col, plus final "|"
    # = 3 chars per column + 1
    overhead = 3 * num_cols + 1
    available = max(terminal_width - overhead, num_cols * 4)

    # Cap: no column gets more than 25% of terminal width
    max_col_width = max(int(terminal_width * 0.25), 8)

    # First pass: cap natural widths, use natural width if it fits
    capped = [min(w, max_col_width) for w in max_widths]
    total_capped = sum(capped) or 1

    # Second pass: if capped total fits, use it; otherwise scale down
    if total_capped <= available:
        col_widths = capped
    else:
        ratio = available / total_capped
        col_widths = [max(int(w * ratio), 4) for w in capped]

    # Final squeeze: ensure sum(col_widths) + overhead <= terminal_width
    while sum(col_widths) + overhead > terminal_width and max(col_widths) > 4:
        # Shrink the widest column by 1
        widest = col_widths.index(max(col_widths))
        col_widths[widest] -= 1

    # Truncate cell values
    truncated_rows: list[dict[str, str]] = []
    for row in rows:
        new_row: dict[str, str] = {}
        for h, cw in zip(headers, col_widths):
            val = str(row.get(h, ""))
            if len(val) > cw:
                val = val[: cw - 1] + "…"
            new_row[h] = val
        truncated_rows.append(new_row)

    # Also truncate headers
    short_headers: list[str] = []
    for h, cw in zip(headers, col_widths):
        if len(h) > cw:
            h = h[: cw - 1] + "…"
        short_headers.append(h)

    # Build rows as lists matching the (possibly truncated) header order
    table_rows = [[row[h] for h in headers] for row in truncated_rows]
    return tabulate(table_rows, headers=short_headers, tablefmt="grid")


def _format_csv(data: Any) -> str:
    """Render *data* as CSV with a header row."""
    rows = _extract_rows(data)
    if not rows:
        return ""
    buf = io.StringIO()
    if isinstance(rows[0], dict):
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        writer = csv.writer(buf)
        for row in rows:
            writer.writerow(row if isinstance(row, (list, tuple)) else [row])
    return buf.getvalue()


def _extract_rows(data: Any) -> list:
    """Normalise *data* into a list of row-like objects for table/csv output."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # If there's a list field, use the largest one as the row source
        lists = {k: v for k, v in data.items() if isinstance(v, list)}
        if lists:
            best_key = max(lists, key=lambda k: len(lists[k]))
            return lists[best_key]
        # Single dict → one-row table
        return [data]
    return [data]


def _format_tsv(data: Any) -> str:
    """Render *data* as tab-separated values with a header row."""
    rows = _extract_rows(data)
    if not rows:
        return ""
    if isinstance(rows[0], dict):
        headers = list(rows[0].keys())
        lines = ["\t".join(headers)]
        for row in rows:
            lines.append("\t".join(str(row.get(h, "")) for h in headers))
        return "\n".join(lines)
    return "\n".join("\t".join(str(c) for c in row) for row in rows)


# ---------------------------------------------------------------------------
# Field search
# ---------------------------------------------------------------------------

def search_field(data: Any, field_name: str) -> list[Any]:
    """Recursively traverse *data* and return all values for keys matching *field_name*."""
    results: list[Any] = []
    _walk(data, field_name, results)
    return results


def _walk(obj: Any, field_name: str, results: list[Any]) -> None:
    """Depth-first walk collecting values where key == field_name."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key == field_name:
                results.append(val)
            _walk(val, field_name, results)
    elif isinstance(obj, list):
        for item in obj:
            _walk(item, field_name, results)


def format_search_results(values: list[Any], field_name: str) -> str:
    """Format search results as a JSON object with field:value pairs and a count."""
    if not values:
        return json.dumps({"count": 0, "message": f"No matches found for field '{field_name}'."}, indent=2)
    result: dict[str, Any] = {}
    matches: list[dict[str, Any]] = []
    for val in values:
        matches.append({field_name: val})
    result["matches"] = matches
    result["count"] = len(values)
    return json.dumps(result, indent=2, default=str)
