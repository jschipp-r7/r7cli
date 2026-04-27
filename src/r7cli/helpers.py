"""Shared helpers for r7-cli solution modules.

These functions were previously duplicated across every solution module.
They are intentionally simple and stable — changes here affect all solutions.
"""
from __future__ import annotations

import json
import operator
import sys
import time
from functools import wraps
from typing import Any, Callable

import click

from r7cli.config import Config
from r7cli.models import R7Error, UserInputError
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Config extraction
# ---------------------------------------------------------------------------

def get_config(ctx: click.Context) -> Config:
    """Extract the resolved Config from the Click context.

    Parameters
    ----------
    ctx : click.Context
        The Click context object, expected to have ``obj["config"]`` set
        by the top-level CLI callback.

    Returns
    -------
    Config
        The resolved runtime configuration.
    """
    return ctx.obj["config"]


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def extract_items(data: Any) -> list[dict]:
    """Find the largest list of dicts in *data* (recursive).

    Useful for normalizing API responses that wrap result arrays under
    varying key names (``data``, ``resources``, ``items``, etc.).

    Parameters
    ----------
    data : Any
        The API response — typically a dict or list.

    Returns
    -------
    list[dict]
        The largest list of dicts found, or an empty list.
    """
    if isinstance(data, list):
        if data and isinstance(data[0], dict):
            return data
        return []
    if isinstance(data, dict):
        best: list[dict] = []
        for val in data.values():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                if len(val) > len(best):
                    best = val
            elif isinstance(val, dict):
                nested = extract_items(val)
                if len(nested) > len(best):
                    best = nested
        return best
    return []


def extract_item_id(item: dict) -> str:
    """Extract the best available identifier from a dict.

    Tries common key names in order: ``id``, ``_id``, ``workflowId``,
    ``job_id``, ``rrn``.
    """
    for key in ("id", "_id", "workflowId", "job_id", "rrn"):
        val = item.get(key, "")
        if val:
            return str(val)
    return ""


def resolve_body(data_str: str | None, data_file: str | None) -> dict | None:
    """Parse a JSON body from ``--data`` or ``--data-file``.

    Parameters
    ----------
    data_str : str or None
        Inline JSON string from the ``--data`` flag.
    data_file : str or None
        Path to a JSON file from the ``--data-file`` flag.

    Returns
    -------
    dict or None
        Parsed JSON body, or None if neither argument was provided.

    Raises
    ------
    UserInputError
        If both arguments are provided, or if the file exceeds 10 MB.
    json.JSONDecodeError
        If the JSON is malformed.
    """
    _MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB

    if data_str and data_file:
        raise UserInputError("Provide either --data or --data-file, not both.")
    if data_str:
        return json.loads(data_str)
    if data_file:
        from pathlib import Path
        size = Path(data_file).stat().st_size
        if size > _MAX_BODY_SIZE:
            raise UserInputError(
                f"File too large ({size:,} bytes). Maximum is {_MAX_BODY_SIZE // (1024 * 1024)} MB."
            )
        with open(data_file) as fh:
            return json.load(fh)
    return None


# ---------------------------------------------------------------------------
# Comparison expression parsing
# ---------------------------------------------------------------------------

_CMP_OPS: list[tuple[str, Callable]] = [
    (">=", operator.ge),
    ("<=", operator.le),
    (">", operator.gt),
    ("<", operator.lt),
    ("=", operator.eq),
]


def parse_cmp_expr(expr: str) -> tuple[Callable, str]:
    """Parse ``'>=7.5'`` into ``(operator.ge, '7.5')``.

    Returns ``(operator.eq, expr)`` when no operator prefix is found.
    """
    expr = expr.strip()
    for sym, func in _CMP_OPS:
        if expr.startswith(sym):
            return func, expr[len(sym):].strip()
    return operator.eq, expr


# ---------------------------------------------------------------------------
# Output shorthand
# ---------------------------------------------------------------------------

def emit(data: Any, config: Config) -> None:
    """Format *data* using the resolved config and echo to stdout."""
    click.echo(format_output(
        data,
        config.output_format,
        config.limit,
        config.search,
        short=config.short,
    ))


# ---------------------------------------------------------------------------
# Error-handling decorator
# ---------------------------------------------------------------------------

def handle_errors(fn: Callable) -> Callable:
    """Decorator that catches :class:`R7Error` and exits with the right code.

    Replaces the ``except R7Error as exc: click.echo(…); sys.exit(…)``
    epilogue that was duplicated in every command function.
    """
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except R7Error as exc:
            click.echo(str(exc), err=True)
            sys.exit(exc.exit_code)
    return wrapper


# ---------------------------------------------------------------------------
# Polling loop
# ---------------------------------------------------------------------------

def poll_loop(
    *,
    fetch: Callable[[], Any],
    config: Config,
    interval: int = 10,
    extract: Callable[[Any], list[dict]] | None = None,
    id_func: Callable[[dict], str] | None = None,
) -> None:
    """Generic auto-poll loop that prints only new items.

    Parameters
    ----------
    fetch:
        Zero-arg callable that returns the API response (called repeatedly).
    config:
        Resolved CLI config (for output formatting).
    interval:
        Seconds between polls.
    extract:
        Function to pull a list of dicts from the response.
        Defaults to :func:`extract_items`.
    id_func:
        Function to pull a unique ID string from each dict.
        Defaults to :func:`extract_item_id`.
    """
    if extract is None:
        extract = extract_items
    if id_func is None:
        id_func = extract_item_id

    # Seed with the first fetch (already done by caller — re-fetch here)
    result = fetch()
    seen_ids: set[str] = set()
    items = extract(result)
    for item in items:
        item_id = id_func(item)
        if item_id:
            seen_ids.add(item_id)

    click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
    try:
        while True:
            time.sleep(interval)
            new_result = fetch()
            new_items = extract(new_result)
            for item in new_items:
                item_id = id_func(item)
                if item_id and item_id not in seen_ids:
                    seen_ids.add(item_id)
                    emit(item, config)
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)


# ---------------------------------------------------------------------------
# Common Click option groups
# ---------------------------------------------------------------------------

def auto_poll_options(fn: Callable) -> Callable:
    """Attach ``-a/--auto`` and ``-i/--interval`` Click options."""
    fn = click.option(
        "-i", "--interval", type=int, default=10,
        help="Polling interval in seconds (default: 10).",
    )(fn)
    fn = click.option(
        "-a", "--auto", "auto_poll", is_flag=True,
        help="Poll for new entries and only print new ones.",
    )(fn)
    return fn


def data_body_options(fn: Callable) -> Callable:
    """Attach ``--data`` and ``--data-file`` Click options."""
    fn = click.option(
        "--data-file", type=click.Path(exists=True), default=None,
        help="Path to JSON file.",
    )(fn)
    fn = click.option(
        "--data", "data_str", default=None,
        help="JSON body string.",
    )(fn)
    return fn
