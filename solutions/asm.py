"""Attack Surface Management (ASM) solution commands — Surface Command queries."""
from __future__ import annotations

import sys

import click
from r7cli.cli_group import GlobalFlagHintGroup
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import SC_BASE, R7Error
from r7cli.output import format_output


def _get_config(ctx: click.Context) -> Config:
    return ctx.obj["config"]


@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def asm(ctx):
    """Attack Surface Management / Surface Command commands."""
    pass


@asm.command("list-queries")
@click.option("-a", "--auto", "auto_exec", is_flag=True,
              help="Interactively select and execute a listed query.")
@click.pass_context
def list_queries(ctx, auto_exec):
    """List saved Surface Command Cypher queries."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = SC_BASE.format(region=config.region)

    try:
        result = client.post(
            url,
            json={"query": "MATCH (m:`sys.cypher-query`) RETURN m"},
            solution="asm",
            subcommand="list-queries",
        )
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    # Extract the list of queries from the response
    queries = _extract_queries(result)

    if not queries:
        click.echo("No saved queries found.", err=True)
        return

    if not auto_exec:
        click.echo(format_output(queries, config.output_format, config.limit))
        return

    # --auto: show numbered menu and let user pick one to execute
    click.echo("Available queries:", err=True)
    for idx, q in enumerate(queries, 1):
        name = q.get("name", q.get("m.name", f"Query {idx}"))
        click.echo(f"  {idx}. {name}", err=True)

    choice = click.prompt("Select a query to execute", type=int, err=True)
    if choice < 1 or choice > len(queries):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)

    selected = queries[choice - 1]
    query_text = selected.get("query", selected.get("m.query", selected.get("body", "")))
    if not query_text:
        click.echo("Selected query has no query text.", err=True)
        sys.exit(1)

    click.echo(f"Executing: {query_text}", err=True)
    try:
        exec_result = client.post(
            url,
            json={"query": query_text},
            solution="asm",
            subcommand="execute",
        )
        click.echo(format_output(exec_result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@asm.command("execute")
@click.option("-q", "--query", "query", default=None, help="Cypher query string.")
@click.option("-f", "--query-file", type=click.Path(exists=True), default=None,
              help="Path to file containing a Cypher query.")
@click.pass_context
def execute(ctx, query, query_file):
    """Execute a Cypher query against Surface Command."""
    if query and query_file:
        raise click.ClickException("Provide either --query or --query-file, not both.")
    if not query and not query_file:
        raise click.ClickException("Provide either --query or --query-file.")

    if query_file:
        with open(query_file) as fh:
            query = fh.read().strip()

    config = _get_config(ctx)
    client = R7Client(config)
    url = SC_BASE.format(region=config.region)

    try:
        result = client.post(
            url,
            json={"query": query},
            solution="asm",
            subcommand="execute",
        )
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


def _extract_queries(result: dict) -> list[dict]:
    """Pull the list of query objects out of the SC response."""
    if isinstance(result, list):
        return result
    # The SC API may nest results under various keys
    for key in ("data", "results", "rows", "records"):
        val = result.get(key)
        if isinstance(val, list):
            return val
    # Might be a single-level dict with a nested list
    for val in result.values():
        if isinstance(val, list):
            return val
    return [result] if result else []
