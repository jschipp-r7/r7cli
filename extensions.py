"""Extensions library command for r7-cli.

Queries the Rapid7 Extension Library at https://extensions.rapid7.com/
No API key authentication required.
"""
from __future__ import annotations

import sys
from typing import Any

import click
import httpx

from r7cli.output import format_output

EXTENSIONS_API = "https://extensions-api.rapid7.com/v2/public/extensions"

# CLI name → API product code
PRODUCT_MAP: dict[str, str] = {
    "asm":    "SC",
    "soar":   "ICON",
    "siem":   "IDR",
    "vm":     "IVM",
    "appsec": "AS",
}

# API product code → supported types
PRODUCT_TYPES: dict[str, list[str]] = {
    "SC":   ["connector"],
    "ICON": ["workflow", "plugin", "integration"],
    "IDR":  ["workflow", "integration", "event_source"],
    "IVM":  ["integration", "workflow"],
    "AS":   ["integration", "workflow"],
}

# Plural → singular normalization
TYPE_ALIASES: dict[str, str] = {
    "workflows":     "workflow",
    "plugins":       "plugin",
    "integrations":  "integration",
    "event_sources": "event_source",
    "connectors":    "connector",
}

VALID_SORTS = ["relevance", "alphabetical", "updated", "created"]


def _normalize_type(t: str) -> str:
    """Normalize a type string, handling plurals."""
    t = t.strip().lower()
    return TYPE_ALIASES.get(t, t)


def _make_list_command(cli_name: str, api_product: str) -> click.Command:
    """Create a 'list' command for a specific product."""

    @click.command("list")
    @click.option("-t", "--type", "ext_types", multiple=True,
                  help=f"Extension type(s). Valid: {', '.join(PRODUCT_TYPES[api_product])}. Plurals accepted.")
    @click.option("--sort", "sort_by", default="relevance",
                  type=click.Choice(VALID_SORTS, case_sensitive=True),
                  help="Sort order (default: relevance).")
    @click.option("-l", "--limit", "limit_val", type=int, default=20,
                  help="Number of results (default: 20).")
    @click.option("-q", "--query", "search_query", default=None,
                  help="Search query string.")
    @click.option("-c", "--count", "count_only", is_flag=True,
                  help="Only return the total count of matching extensions.")
    @click.pass_context
    def list_cmd(ctx, ext_types, sort_by, limit_val, search_query, count_only):
        config = ctx.obj["config"]
        valid_types = PRODUCT_TYPES[api_product]

        # Normalize types (handle plurals)
        normalized = [_normalize_type(t) for t in ext_types]
        for t in normalized:
            if t not in valid_types:
                click.echo(
                    f"Error: type '{t}' is not valid for {cli_name}. "
                    f"Valid types: {', '.join(valid_types)}",
                    err=True,
                )
                sys.exit(1)

        params: dict[str, Any] = {
            "sort": sort_by,
            "first": limit_val,
            "products": api_product,
        }
        if normalized:
            params["types"] = ",".join(normalized)
        if search_query:
            params["query"] = search_query

        try:
            resp = httpx.get(EXTENSIONS_API, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            click.echo(f"API error: {exc.response.status_code} {exc.response.text[:200]}", err=True)
            sys.exit(2)
        except httpx.RequestError as exc:
            click.echo(f"Network error: {exc}", err=True)
            sys.exit(3)

        if count_only:
            total = data.get("totalCount", 0) if isinstance(data, dict) else 0
            click.echo(format_output({"totalCount": total}, config.output_format, config.limit, config.search, short=config.short))
        else:
            click.echo(format_output(data, config.output_format, config.limit, config.search, short=config.short))

    valid = PRODUCT_TYPES[api_product]
    list_cmd.__doc__ = (
        f"List {cli_name} extensions from the Rapid7 Extension Library.\n\n"
        f"    \\b\n"
        f"    Examples:\n"
        f"      r7-cli extensions {cli_name} list\n"
        f"      r7-cli extensions {cli_name} list -t {valid[0]}\n"
        f"      r7-cli extensions {cli_name} list -q \"phishing\" --sort alphabetical\n"
    )
    return list_cmd


@click.group("extensions")
@click.pass_context
def extensions(ctx: click.Context) -> None:
    """Browse the Rapid7 Extension Library (no API key required)."""
    pass


# Register per-product subgroups
for _cli_name, _api_product in PRODUCT_MAP.items():
    _group = click.Group(name=_cli_name, help=f"{_cli_name} extensions.")
    _group.add_command(_make_list_command(_cli_name, _api_product))
    extensions.add_command(_group)


@extensions.command("types")
@click.pass_context
def extensions_types(ctx):
    """Show supported products and their extension types."""
    lines = ["Supported products and types:", ""]
    for cli_name, api_product in PRODUCT_MAP.items():
        types = PRODUCT_TYPES[api_product]
        lines.append(f"  {cli_name:<8s} ({api_product})  {', '.join(types)}")
    click.echo("\n".join(lines))
