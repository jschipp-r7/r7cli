"""Attack Surface Management (ASM) solution commands — Surface Command queries."""
from __future__ import annotations

import sys
from typing import Any

import click
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import SC_BASE, R7Error
from r7cli.output import format_output

_SC_TABLE_URL = "{base}/graph-api/objects/table"
_LIST_CYPHER = 'MATCH (m:`sys.cypher-query`) RETURN m'


def _get_config(ctx: click.Context) -> Config:
    return ctx.obj["config"]


def _fetch_queries(client: R7Client, config: Config) -> list[dict]:
    """Fetch all saved queries from the Surface Command graph API."""
    base = SC_BASE.format(region=config.region)
    url = _SC_TABLE_URL.format(base=base)
    result = client.post(
        url,
        json={"cypher": _LIST_CYPHER},
        params={"format": "json"},
        solution="asm",
        subcommand="list",
    )
    return result.get("items", []) if isinstance(result, dict) else result


def _query_name(item: dict) -> str:
    """Extract the human name from a query item (data[1])."""
    data = item.get("data", [])
    return str(data[1]) if len(data) > 1 else "unnamed"


def _query_id(item: dict) -> str:
    """Extract the query ID from a query item (data[0])."""
    data = item.get("data", [])
    return str(data[0]) if data else "?"


def _query_cypher(item: dict) -> str:
    """Extract the Cypher text from a query item (data[3])."""
    data = item.get("data", [])
    return str(data[3]) if len(data) > 3 else ""


def _interactive_query_select(client: R7Client, config: Config) -> dict:
    """Fetch queries, show numbered menu with name and id, return selected item."""
    items = _fetch_queries(client, config)
    if not items:
        click.echo("No saved queries found.", err=True)
        sys.exit(1)

    click.echo("Available queries:", err=True)
    for idx, item in enumerate(items, 1):
        name = _query_name(item)
        qid = _query_id(item)
        click.echo(f"  {idx}. {name} | {qid}", err=True)

    choice = click.prompt("Select a query number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)

    return items[choice - 1]


# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def asm(ctx):
    """Attack Surface Management / Surface Command commands."""
    pass


# ---------------------------------------------------------------------------
# asm connectors
# ---------------------------------------------------------------------------

@asm.group(cls=GlobalFlagHintGroup)
@click.pass_context
def connectors(ctx):
    """Connector commands."""
    pass


@connectors.command("list")
@click.pass_context
def connectors_list(ctx):
    """List connectors from Surface Command."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = SC_BASE.format(region=config.region)
    url = _SC_TABLE_URL.format(base=base)

    try:
        result = client.post(
            url,
            json={"cypher": "MATCH (a:`sys.apps.integration`) RETURN a"},
            params={"format": "json"},
            solution="asm",
            subcommand="connectors-list",
        )
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# asm queries
# ---------------------------------------------------------------------------

@asm.group(cls=GlobalFlagHintGroup)
@click.pass_context
def queries(ctx):
    """Saved query commands."""
    pass


@queries.command("list")
@click.pass_context
def queries_list(ctx):
    """List the available saved queries from Surface Command."""
    config = _get_config(ctx)
    client = R7Client(config)

    try:
        items = _fetch_queries(client, config)
        click.echo(format_output(items, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# asm queries get
# ---------------------------------------------------------------------------

@queries.command("get")
@click.option("-j", "--id", "query_id", default=None, help="Query ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True,
              help="Interactively select a query from the list.")
@click.pass_context
def queries_get(ctx, query_id, auto_select):
    """Get a saved query by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not query_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")

    try:
        if auto_select:
            selected = _interactive_query_select(client, config)
            click.echo(format_output(selected, config.output_format, config.limit, config.search, short=config.short))
            return

        # Filter from the full list
        items = _fetch_queries(client, config)
        match = [i for i in items if _query_id(i) == query_id]
        if not match:
            click.echo(f"No query found with ID '{query_id}'.", err=True)
            sys.exit(1)
        click.echo(format_output(match[0], config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# asm queries execute
# ---------------------------------------------------------------------------

@queries.command("execute")
@click.option("-q", "--query", "query", default=None, help="Cypher query string.")
@click.option("-f", "--query-file", type=click.Path(exists=True), default=None,
              help="Path to file containing a Cypher query.")
@click.option("-a", "--auto", "auto_select", is_flag=True,
              help="Interactively select a saved query and execute it.")
@click.pass_context
def queries_execute(ctx, query, query_file, auto_select):
    """Execute a Cypher query against Surface Command."""
    config = _get_config(ctx)
    client = R7Client(config)

    if auto_select:
        selected = _interactive_query_select(client, config)
        cypher = _query_cypher(selected)
        if not cypher:
            click.echo("Selected query has no Cypher text.", err=True)
            sys.exit(1)
        name = _query_name(selected)
        click.echo(f"Executing: {name}", err=True)
    elif query and query_file:
        raise click.ClickException("Provide --query, --query-file, or --auto — not multiple.")
    elif query_file:
        with open(query_file) as fh:
            cypher = fh.read().strip()
    elif query:
        cypher = query
    else:
        raise click.ClickException("Provide --query, --query-file, or --auto.")

    base = SC_BASE.format(region=config.region)
    url = _SC_TABLE_URL.format(base=base)

    try:
        result = client.post(
            url,
            json={"cypher": cypher},
            params={"format": "json"},
            solution="asm",
            subcommand="execute",
        )
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
