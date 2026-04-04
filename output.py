"""Output formatting for r7-cli.

Supports ``json``, ``table`` (via tabulate), and ``csv`` output formats.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from tabulate import tabulate


def apply_limit(data: Any, n: int) -> Any:
    """Find the largest top-level array field and truncate it to *n* items.

    Non-dict data or dicts with no list fields are returned unchanged.
    """
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


def format_output(data: Any, fmt: str, limit: int | None = None) -> str:
    """Serialize *data* to the requested format string.

    Parameters
    ----------
    data:
        The structured data to format (dict, list of dicts, etc.).
    fmt:
        One of ``"json"``, ``"table"``, ``"csv"``.
    limit:
        If set, truncate the largest top-level array to this many items
        before formatting.
    """
    if limit is not None:
        data = apply_limit(data, limit)

    if fmt == "json":
        return json.dumps(data, indent=2)

    if fmt == "table":
        return _format_table(data)

    if fmt == "csv":
        return _format_csv(data)

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
