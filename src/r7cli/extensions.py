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
            "first": 1 if count_only else limit_val,
            "products": api_product,
        }
        if normalized:
            params["types"] = ",".join(normalized)
        if search_query:
            params["query"] = search_query

        try:
            if config.verbose:
                from urllib.parse import urlencode
                click.echo(f"GET {EXTENSIONS_API}?{urlencode(params)}", err=True)
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


# ---------------------------------------------------------------------------
# Global extension commands (not product-scoped)
# ---------------------------------------------------------------------------

def _ext_request(config, url: str, follow_redirects: bool = False) -> Any:
    """Make a GET request to the extensions API with verbose logging."""
    if config.verbose:
        click.echo(f"GET {url}", err=True)
    try:
        resp = httpx.get(url, timeout=30, follow_redirects=follow_redirects)
        resp.raise_for_status()
        return resp
    except httpx.HTTPStatusError as exc:
        click.echo(f"API error: {exc.response.status_code} {exc.response.text[:200]}", err=True)
        sys.exit(2)
    except httpx.RequestError as exc:
        click.echo(f"Network error: {exc}", err=True)
        sys.exit(3)


@extensions.command("get")
@click.option("-j", "--id", "slug", required=True, help="Extension slug or ID.")
@click.pass_context
def extensions_get(ctx, slug):
    """Get details for a specific extension by slug/ID.

    \b
    Examples:
      r7-cli extensions get -j abnormal-security
      r7-cli extensions get --id microsoft-teams
    """
    config = ctx.obj["config"]
    url = f"{EXTENSIONS_API}/{slug}"
    resp = _ext_request(config, url)
    click.echo(format_output(resp.json(), config.output_format, config.limit, config.search, short=config.short))


@extensions.command("version")
@click.option("-j", "--id", "slug", required=True, help="Extension slug or ID.")
@click.option("--version", "ver", required=True, help="Version string.")
@click.pass_context
def extensions_version(ctx, slug, ver):
    """Get a specific version of an extension.

    \b
    Examples:
      r7-cli extensions version -j abnormal-security --version 2.0.3
    """
    config = ctx.obj["config"]
    url = f"{EXTENSIONS_API}/{slug}/v/{ver}"
    resp = _ext_request(config, url)
    click.echo(format_output(resp.json(), config.output_format, config.limit, config.search, short=config.short))


@extensions.command("help")
@click.option("-j", "--id", "slug", required=True, help="Extension slug or ID.")
@click.pass_context
def extensions_help(ctx, slug):
    """Get the help/documentation for an extension (markdown).

    \b
    Examples:
      r7-cli extensions help -j abnormal-security
    """
    config = ctx.obj["config"]
    url = f"{EXTENSIONS_API}/{slug}/help"
    resp = _ext_request(config, url, follow_redirects=True)
    # Help returns markdown text, not JSON
    click.echo(resp.text)


@extensions.command("count")
@click.pass_context
def extensions_count(ctx):
    """Show extension counts by product and type.

    Queries the extensions API for each product and type combination,
    returning a breakdown of available extensions.

    \b
    Examples:
      r7-cli extensions count
      r7-cli -o table extensions count
    """
    config = ctx.obj["config"]

    def _get_count(params: dict) -> int:
        """Fetch totalCount from the extensions API with first=1."""
        params["first"] = 1
        params["sort"] = "relevance"
        try:
            resp = httpx.get(EXTENSIONS_API, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return data.get("totalCount", 0) if isinstance(data, dict) else 0
        except (httpx.HTTPStatusError, httpx.RequestError):
            return 0

    # Get total count (no product filter)
    total = _get_count({})

    result: dict[str, Any] = {"totalCount": total, "products": {}}

    for cli_name, api_product in PRODUCT_MAP.items():
        product_count = _get_count({"products": api_product})
        product_entry: dict[str, Any] = {"totalCount": product_count}

        types = PRODUCT_TYPES[api_product]
        if len(types) > 1:
            product_entry["types"] = {}
            for t in types:
                type_count = _get_count({"products": api_product, "types": t})
                product_entry["types"][t] = type_count

        result["products"][cli_name] = product_entry

        if config.verbose:
            click.echo(f"  {cli_name}: {product_count}", err=True)

    click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))


@extensions.command("leaderboard")
@click.option("-g", "--group", "group", default="all", help="Leaderboard group (default: all).")
@click.option("-c", "--category", "category", default="all", help="Category (default: all).")
@click.pass_context
def extensions_leaderboard(ctx, group, category):
    """Show the community extension leaderboard.

    \b
    Examples:
      r7-cli extensions leaderboard
      r7-cli extensions leaderboard -g all -c all
    """
    config = ctx.obj["config"]
    url = f"https://extensions-api.rapid7.com/v2/public/leaderboard/{group}/categories/{category}"
    resp = _ext_request(config, url)
    click.echo(format_output(resp.json(), config.output_format, config.limit, config.search, short=config.short))
