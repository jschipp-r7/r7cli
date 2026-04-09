"""Top-level agents command for r7-cli.

Lists all agents available in the Rapid7 platform (VM + SIEM) via GraphQL.
"""
from __future__ import annotations

import sys
import time
from typing import Any

import click

from r7cli.client import R7Client
from r7cli.models import IDR_GQL, GQL_AGENTS_LIST, APIError, R7Error
from r7cli.output import format_output
from r7cli.solutions.siem import _resolve_org_id, _flatten_agent_node, _apply_agent_filters


@click.group("agents")
@click.pass_context
def agents(ctx: click.Context) -> None:
    """List all agents available in the Rapid7 platform (VM + SIEM) via GraphQL."""
    pass


@agents.command("list")
@click.option("-l", "--limit", "agent_limit", type=int, default=10, help="Agents per page (default: 10, max: 10000).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new agents.")
@click.option("-i", "--interval", type=int, default=30, help="Polling interval in seconds.")
@click.option("--ngav-status", default=None, help="Filter by NGAV health: GOOD, POOR, N/A, Not Monitored.")
@click.option("--velociraptor-status", default=None, type=click.Choice(["RUNNING", "NOT_RUNNING"]),
              help="Filter by velociraptor state.")
@click.pass_context
def agents_list(ctx, agent_limit, all_pages, auto_poll, interval, ngav_status, velociraptor_status):
    """List all agents in the Rapid7 platform (VM + SIEM) via GraphQL.

    \b
    Examples:
      r7-cli agents list
      r7-cli agents list -l 50 --all-pages
      r7-cli agents list -a -i 30
      r7-cli -s agents list
    """
    config = ctx.obj["config"]
    client = R7Client(config)
    gql_url = IDR_GQL.format(region=config.region)

    try:
        org_id = _resolve_org_id(client, config)
        cursor = None
        all_records: list[dict] = []

        while True:
            variables: dict[str, Any] = {"orgId": org_id, "first": agent_limit, "cursor": cursor}
            result = client.post(
                gql_url,
                json={"query": GQL_AGENTS_LIST, "variables": variables},
                solution="platform",
                subcommand="agents-list",
            )

            errors = result.get("errors")
            if errors:
                raise APIError(errors[0].get("message", "Unknown GraphQL error"))

            assets = (
                result.get("data", {})
                .get("organization", {})
                .get("assets", {})
            )
            edges = assets.get("edges", [])
            page_info = assets.get("pageInfo", {})

            for edge in edges:
                node = edge.get("node", {})
                if node.get("agent") is None:
                    continue
                record = _flatten_agent_node(node)
                all_records.append(record)

            if all_pages and page_info.get("hasNextPage"):
                cursor = page_info.get("endCursor")
            else:
                break

        filtered = _apply_agent_filters(all_records, ngav_status, velociraptor_status)

        if not auto_poll:
            click.echo(format_output(filtered, config.output_format, config.limit, config.search, short=config.short))
        else:
            seen_ids: set[str] = set()
            for rec in filtered:
                aid = rec.get("agent_id")
                if aid:
                    seen_ids.add(aid)
            click.echo(format_output(filtered, config.output_format, config.limit, config.search, short=config.short))
            click.echo(f"Polling for new agents every {interval}s (Ctrl+C to stop)...", err=True)

            while True:
                time.sleep(interval)
                cursor = None
                poll_records: list[dict] = []

                while True:
                    variables = {"orgId": org_id, "first": agent_limit, "cursor": cursor}
                    result = client.post(
                        gql_url,
                        json={"query": GQL_AGENTS_LIST, "variables": variables},
                        solution="platform",
                        subcommand="agents-list",
                    )
                    errors = result.get("errors")
                    if errors:
                        raise APIError(errors[0].get("message", "Unknown GraphQL error"))

                    assets = (
                        result.get("data", {})
                        .get("organization", {})
                        .get("assets", {})
                    )
                    edges = assets.get("edges", [])
                    page_info = assets.get("pageInfo", {})

                    for edge in edges:
                        node = edge.get("node", {})
                        if node.get("agent") is None:
                            continue
                        record = _flatten_agent_node(node)
                        poll_records.append(record)

                    if all_pages and page_info.get("hasNextPage"):
                        cursor = page_info.get("endCursor")
                    else:
                        break

                poll_filtered = _apply_agent_filters(poll_records, ngav_status, velociraptor_status)
                new_records = []
                for rec in poll_filtered:
                    aid = rec.get("agent_id")
                    if aid and aid not in seen_ids:
                        seen_ids.add(aid)
                        new_records.append(rec)

                if new_records:
                    click.echo(format_output(new_records, config.output_format, config.limit, config.search, short=config.short))

    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
