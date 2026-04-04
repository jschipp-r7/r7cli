"""InsightIDR / SIEM solution commands.

Covers health-metrics, log storage/retention, logsets, log queries,
event sources, and agent quarantine state.
"""
from __future__ import annotations

import sys
import time
from datetime import date
from typing import Any

import click
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import (
    IDR_GQL,
    IDR_LOGS_BASE,
    IDR_V1_BASE,
    GQL_QUARANTINE_STATE,
    R7Error,
    UserInputError,
)
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_config(ctx: click.Context) -> Config:
    return ctx.obj["config"]


def _resolve_body(data_str: str | None, data_file: str | None) -> dict | None:
    """Parse a JSON body from --data or --data-file."""
    import json as _json
    if data_str and data_file:
        raise UserInputError("Provide either --data or --data-file, not both.")
    if data_str:
        return _json.loads(data_str)
    if data_file:
        with open(data_file) as fh:
            return _json.load(fh)
    return None


_DOC_BASE = "https://help.rapid7.com/insightidr/en-us/api/v1/docs.html"


_VALID_RESOURCE_TYPES = (
    "agent",
    "collectors",
    "network_sensors",
    "orchestrator",
    "data_exporters",
    "scan_engines",
    "honeypots",
    "event_sources",
)

_VALID_QUARANTINE_STATES = (
    "QUARANTINED",
    "UNQUARANTINED",
    "QUARANTINE_IN_PROGRESS",
    "UNQUARANTINE_IN_PROGRESS",
)

_MS_PER_DAY = 86_400_000


# ---------------------------------------------------------------------------
# Click groups
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def siem(ctx):
    """InsightIDR / SIEM commands."""
    pass


# ---------------------------------------------------------------------------
# siem health-metrics
# ---------------------------------------------------------------------------

@siem.command("health-metrics")
@click.option(
    "--resource-type",
    type=click.Choice(_VALID_RESOURCE_TYPES, case_sensitive=False),
    default=None,
    help="Filter by resource type.",
)
@click.pass_context
def health_metrics(ctx, resource_type):
    """Retrieve IDR agent/sensor health metrics."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/health-metrics"

    params: dict[str, str] = {}
    if resource_type:
        params["resourceTypes"] = resource_type

    try:
        result = client.get(
            url, params=params or None, solution="siem", subcommand="health-metrics",
        )
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem log-storage
# ---------------------------------------------------------------------------

@siem.command("log-storage")
@click.option("--from", "from_date", default="2017-01-31", help="Start date (YYYY-MM-DD).")
@click.option("--to", "to_date", default=None, help="End date (YYYY-MM-DD, default: today).")
@click.pass_context
def log_storage(ctx, from_date, to_date):
    """Retrieve IDR log storage usage over time."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/usage/organizations"

    if to_date is None:
        to_date = date.today().isoformat()

    params = {"from": from_date, "to": to_date}

    try:
        result = client.get(url, params=params, solution="siem", subcommand="log-storage")
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    # Sort daily_usage by date descending (most recent first)
    daily = result.get("daily_usage", [])
    if isinstance(daily, list):
        daily.sort(key=lambda d: d.get("date", ""), reverse=True)
        result["daily_usage"] = daily

    click.echo(format_output(result, config.output_format, config.limit))


# ---------------------------------------------------------------------------
# siem log-retention
# ---------------------------------------------------------------------------

@siem.command("log-retention")
@click.option("--min-days", type=int, default=None, help="Exit non-zero if retention < threshold days.")
@click.pass_context
def log_retention(ctx, min_days):
    """Retrieve IDR log retention settings (converted from ms to days)."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/organizations"

    try:
        result = client.get(url, solution="siem", subcommand="log-retention")
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    # Convert ms → days for the three retention fields
    for field in ("max_retention_period", "retention_period", "cold_retention"):
        ms_val = result.get(field)
        if ms_val is not None:
            try:
                result[field] = int(ms_val) // _MS_PER_DAY
            except (TypeError, ValueError):
                pass

    click.echo(format_output(result, config.output_format, config.limit))

    # Threshold check
    if min_days is not None:
        retention_days = result.get("retention_period")
        if isinstance(retention_days, (int, float)) and retention_days < min_days:
            click.echo(
                f"Retention {retention_days} days is below threshold {min_days} days",
                err=True,
            )
            sys.exit(1)


# ---------------------------------------------------------------------------
# siem logsets
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def logsets(ctx):
    """IDR logset commands."""
    pass


@logsets.command("list")
@click.pass_context
def logsets_list(ctx):
    """List all IDR logsets."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/logsets"

    try:
        result = client.get(url, solution="siem", subcommand="logsets-list")
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    click.echo(format_output(result, config.output_format, config.limit))


# ---------------------------------------------------------------------------
# siem logs
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def logs(ctx):
    """IDR log query commands."""
    pass


def _resolve_log_ids(client: R7Client, config: Config, logset_name: str, time_range: str) -> list[str]:
    """Resolve a logset name to its Log_IDs via the query/logsets endpoint."""
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/logsets"
    params = {"logset_name": logset_name, "time_range": time_range}
    result = client.get(url, params=params, solution="siem", subcommand="logs-query")

    # Extract Log_IDs from the response
    if isinstance(result, dict):
        # Could be nested under various keys
        logs_list = result.get("logs", result.get("data", result.get("statistics", {}).get("logs", [])))
        if isinstance(logs_list, list):
            return [str(entry.get("id", entry)) if isinstance(entry, dict) else str(entry) for entry in logs_list]
        # Might be a flat dict with log IDs as keys
        if result.get("id"):
            return [result["id"]]
    if isinstance(result, list):
        return [str(entry.get("id", entry)) if isinstance(entry, dict) else str(entry) for entry in result]
    return []


def _poll_log_query(client: R7Client, config: Config, links: list[dict], max_pages: int) -> list[str]:
    """Poll async log query links, collecting event lines.

    Returns a list of log event strings.
    """
    events: list[str] = []
    pages_fetched = 0

    # Find the polling href from links
    poll_url: str | None = None
    for link in links:
        href = link.get("href")
        if href:
            poll_url = href
            break

    if not poll_url:
        return events

    while poll_url and pages_fetched < max_pages:
        time.sleep(20)
        try:
            result = client.get(poll_url, solution="siem", subcommand="logs-query-poll")
        except R7Error as exc:
            # Check for link-expired error code 101056
            if "101056" in str(exc):
                click.echo(f"Warning: polling link expired for query.", err=True)
                break
            raise

        # Check for error code 101056 in the response body
        if isinstance(result, dict):
            error_code = result.get("error_code") or result.get("errorCode")
            if str(error_code) == "101056":
                click.echo("Warning: polling link expired for query.", err=True)
                break

        # Extract events from this page
        page_events = []
        if isinstance(result, dict):
            page_events = result.get("events", result.get("data", []))
        elif isinstance(result, list):
            page_events = result

        if isinstance(page_events, list):
            for ev in page_events:
                if isinstance(ev, dict):
                    msg = ev.get("message", ev.get("log_line", str(ev)))
                    events.append(str(msg))
                else:
                    events.append(str(ev))

        pages_fetched += 1

        # Check for next page link
        poll_url = None
        next_links = result.get("links", []) if isinstance(result, dict) else []
        for link in next_links:
            rel = link.get("rel", "")
            if rel == "Next" or rel == "next":
                poll_url = link.get("href")
                break

        # If the query is complete (no more links), stop
        if not poll_url:
            break

    return events


@logs.command("query")
@click.option("-n", "--logset-name", required=True, help="Logset name to query.")
@click.option("--time-range", default="Last 30 days", help="Time range for the query.")
@click.option("-p", "--max-pages", type=int, default=20, help="Max pages to retrieve per Log_ID.")
@click.pass_context
def logs_query(ctx, logset_name, time_range, max_pages):
    """Query log lines from a named logset."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)

    try:
        # Step 1: Resolve logset name → Log_IDs
        log_ids = _resolve_log_ids(client, config, logset_name, time_range)
        if not log_ids:
            click.echo(f"No Log_IDs found for logset '{logset_name}'.", err=True)
            sys.exit(1)

        all_events: list[str] = []

        # Step 2 & 3: For each Log_ID, initiate async query and poll
        for log_id in log_ids:
            query_url = f"{base}/query/logs/{log_id}"
            params = {"time_range": time_range}
            result = client.get(
                query_url, params=params, solution="siem", subcommand="logs-query",
            )

            # Extract links for polling
            links = result.get("links", []) if isinstance(result, dict) else []

            # Also grab any events already in the initial response
            if isinstance(result, dict):
                initial_events = result.get("events", [])
                if isinstance(initial_events, list):
                    for ev in initial_events:
                        if isinstance(ev, dict):
                            msg = ev.get("message", ev.get("log_line", str(ev)))
                            all_events.append(str(msg))
                        else:
                            all_events.append(str(ev))

            # Poll if there are links
            if links:
                polled = _poll_log_query(client, config, links, max_pages)
                all_events.extend(polled)

    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    if not all_events:
        click.echo("No log events found.", err=True)
        return

    for line in all_events:
        click.echo(line)


# ---------------------------------------------------------------------------
# siem event-sources
# ---------------------------------------------------------------------------

@siem.group("event-sources", cls=GlobalFlagHintGroup)
@click.pass_context
def event_sources(ctx):
    """IDR event source commands."""
    pass


@event_sources.command("list")
@click.option("-g", "--log-id", default=None, help="Log ID to query event sources for.")
@click.option("-n", "--logset-name", default=None, help="Logset name (resolves to Log_IDs).")
@click.pass_context
def event_sources_list(ctx, log_id, logset_name):
    """List event sources for a log or logset."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)

    if not log_id and not logset_name:
        raise UserInputError("Provide either --log-id or --logset-name.")

    try:
        log_ids: list[str] = []
        if log_id:
            log_ids = [log_id]
        else:
            log_ids = _resolve_log_ids(client, config, logset_name, "Last 1 day")

        if not log_ids:
            click.echo(f"No Log_IDs found for logset '{logset_name}'.", err=True)
            sys.exit(1)

        # If single log_id, return raw response
        if len(log_ids) == 1:
            url = f"{base}/management/logs/{log_ids[0]}/event-sources"
            result = client.get(url, solution="siem", subcommand="event-sources-list")
            click.echo(format_output(result, config.output_format, config.limit))
            return

        # Multiple log_ids — collect all results
        all_results: list[dict] = []
        for lid in log_ids:
            url = f"{base}/management/logs/{lid}/event-sources"
            result = client.get(url, solution="siem", subcommand="event-sources-list")
            all_results.append({"log_id": lid, "response": result})

        click.echo(format_output(all_results, config.output_format, config.limit))

    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem quarantine-state
# ---------------------------------------------------------------------------

@siem.command("quarantine-state")
@click.option(
    "--state",
    type=click.Choice(_VALID_QUARANTINE_STATES, case_sensitive=True),
    default=None,
    help="Filter by quarantine state.",
)
@click.pass_context
def quarantine_state(ctx, state):
    """Retrieve agent quarantine state via IDR GraphQL."""
    config = _get_config(ctx)
    client = R7Client(config)
    gql_url = IDR_GQL.format(region=config.region)

    try:
        result = client.post(
            gql_url,
            json={"query": GQL_QUARANTINE_STATE, "variables": {}},
            solution="siem",
            subcommand="quarantine-state",
        )

        if not state:
            click.echo(format_output(result, config.output_format, config.limit))
            return

        # With --state filter, extract and filter nodes
        assets_data = (
            result.get("data", {})
            .get("organization", {})
            .get("assets", {})
        )
        edges = assets_data.get("edges", [])
        filtered: list[dict] = []
        for edge in edges:
            node = edge.get("node", {})
            agent = node.get("agent")
            host = node.get("host")
            if agent is None or host is None:
                continue
            q_state = (agent.get("quarantineState") or {}).get("currentState")
            if q_state == state:
                filtered.append(node)

        click.echo(format_output(filtered, config.output_format, config.limit))

    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem accounts
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def accounts(ctx):
    """IDR account commands."""
    pass


@accounts.command("search")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@click.option("--data", "data_str", default=None, help="JSON search body string.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON search body.")
@click.pass_context
def accounts_search(ctx, index, size, data_str, data_file):
    """Search IDR accounts."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/accounts/_search"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/searchAccounts", err=True)

    params = {"index": index, "size": size}
    body = _resolve_body(data_str, data_file) or {}

    try:
        result = client.post(url, json=body, params=params, solution="siem", subcommand="accounts-search")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@accounts.command("get")
@click.argument("rrn")
@click.pass_context
def accounts_get(ctx, rrn):
    """Get an IDR account by RRN."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/accounts/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/findAccountByRrn", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="accounts-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem idr-assets
# ---------------------------------------------------------------------------

@siem.group("idr-assets", cls=GlobalFlagHintGroup)
@click.pass_context
def idr_assets(ctx):
    """IDR asset commands."""
    pass


@idr_assets.command("search")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@click.option("--data", "data_str", default=None, help="JSON search body string.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON search body.")
@click.pass_context
def idr_assets_search(ctx, index, size, data_str, data_file):
    """Search IDR assets."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/assets/_search"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/searchAssets", err=True)

    params = {"index": index, "size": size}
    body = _resolve_body(data_str, data_file) or {}

    try:
        result = client.post(url, json=body, params=params, solution="siem", subcommand="idr-assets-search")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@idr_assets.command("get")
@click.argument("rrn")
@click.pass_context
def idr_assets_get(ctx, rrn):
    """Get an IDR asset by RRN."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/assets/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/findAssetByRrn", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="idr-assets-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem investigations
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def investigations(ctx):
    """IDR investigation commands."""
    pass


@investigations.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@click.pass_context
def investigations_list(ctx, index, size):
    """List IDR investigations."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/investigations"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/listInvestigations", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="siem", subcommand="investigations-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@investigations.command("set-status")
@click.argument("investigation_id")
@click.argument("status", type=click.Choice(["OPEN", "INVESTIGATING", "CLOSED"], case_sensitive=True))
@click.pass_context
def investigations_set_status(ctx, investigation_id, status):
    """Set the status of an investigation."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/investigations/{investigation_id}/status/{status}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/setStatus", err=True)

    try:
        result = client.request("PUT", url, solution="siem", subcommand="investigations-set-status")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@investigations.command("close-bulk")
@click.option("--data", "data_str", default=None, help="JSON body with investigation IDs.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def investigations_close_bulk(ctx, data_str, data_file):
    """Close investigations in bulk."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/investigations/bulk_close"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/bulkCloseInvestigations", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with investigation IDs.")

    try:
        result = client.post(url, json=body, solution="siem", subcommand="investigations-close-bulk")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem users
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def users(ctx):
    """IDR user commands."""
    pass


@users.command("search")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@click.option("--data", "data_str", default=None, help="JSON search body string.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON search body.")
@click.pass_context
def users_search(ctx, index, size, data_str, data_file):
    """Search IDR users."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/users/_search"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/searchUsers", err=True)

    params = {"index": index, "size": size}
    body = _resolve_body(data_str, data_file) or {}

    try:
        result = client.post(url, json=body, params=params, solution="siem", subcommand="users-search")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@users.command("get")
@click.argument("rrn")
@click.pass_context
def users_get(ctx, rrn):
    """Get an IDR user by RRN."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/users/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/getUserByRrn", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="users-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem threats
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def threats(ctx):
    """IDR community threat commands."""
    pass


@threats.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for threat creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def threats_create(ctx, data_str, data_file):
    """Create a community threat."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/customthreats"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/createCommunityThreat", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with threat definition.")

    try:
        result = client.post(url, json=body, solution="siem", subcommand="threats-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@threats.command("add-indicators")
@click.argument("key")
@click.option("--data", "data_str", default=None, help="JSON body with indicators.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def threats_add_indicators(ctx, key, data_str, data_file):
    """Add indicators to a community threat by key."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/customthreats/key/{key}/indicators/add"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/addIndicators", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with indicators.")

    try:
        result = client.post(url, json=body, solution="siem", subcommand="threats-add-indicators")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@threats.command("replace-indicators")
@click.argument("key")
@click.option("--data", "data_str", default=None, help="JSON body with indicators.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def threats_replace_indicators(ctx, key, data_str, data_file):
    """Replace indicators for a community threat by key."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/customthreats/key/{key}/indicators/replace"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/replaceIndicators", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with indicators.")

    try:
        result = client.post(url, json=body, solution="siem", subcommand="threats-replace-indicators")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem comments
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def comments(ctx):
    """IDR comment commands."""
    pass


@comments.command("list")
@click.option("--target", required=True, help="Target RRN (e.g. investigation RRN).")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@click.pass_context
def comments_list(ctx, target, index, size):
    """List comments for a target."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/comments"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/listComments", err=True)

    params: dict = {"target": target, "index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="siem", subcommand="comments-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@comments.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for comment creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def comments_create(ctx, data_str, data_file):
    """Create a comment."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/comments"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/createComment", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with comment body.")

    try:
        result = client.post(url, json=body, solution="siem", subcommand="comments-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@comments.command("get")
@click.argument("rrn")
@click.pass_context
def comments_get(ctx, rrn):
    """Get a comment by RRN."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/comments/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/getComment", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="comments-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem attachments
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def attachments(ctx):
    """IDR attachment commands."""
    pass


@attachments.command("list")
@click.option("--target", required=True, help="Target RRN (e.g. investigation RRN).")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@click.pass_context
def attachments_list(ctx, target, index, size):
    """List attachments for a target."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/attachments"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/listAttachments", err=True)

    params: dict = {"target": target, "index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="siem", subcommand="attachments-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@attachments.command("get")
@click.argument("rrn")
@click.pass_context
def attachments_get(ctx, rrn):
    """Get attachment metadata by RRN."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/attachments/{rrn}/metadata"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/getAttachment", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="attachments-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem collectors
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def collectors(ctx):
    """IDR collector commands."""
    pass


@collectors.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for collector creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def collectors_create(ctx, data_str, data_file):
    """Add a new collector."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/collectors"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/addCollector", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with collector definition.")

    try:
        result = client.post(url, json=body, solution="siem", subcommand="collectors-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem saved-queries  (from log-search / insightops schemas)
# ---------------------------------------------------------------------------

_LOG_SEARCH_DOC = "https://docs.rapid7.com/insightidr/log-search-api/"


@siem.group("saved-queries", cls=GlobalFlagHintGroup)
@click.pass_context
def saved_queries(ctx):
    """Log Search saved query commands."""
    pass


@saved_queries.command("list")
@click.pass_context
def saved_queries_list(ctx):
    """List saved queries."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/saved_queries"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="saved-queries-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@saved_queries.command("get")
@click.argument("query_id")
@click.pass_context
def saved_queries_get(ctx, query_id):
    """Get a saved query by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/saved_queries/{query_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="saved-queries-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@saved_queries.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for saved query creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def saved_queries_create(ctx, data_str, data_file):
    """Create a saved query."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/saved_queries"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with saved query definition.")

    try:
        result = client.post(url, json=body, solution="siem", subcommand="saved-queries-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@saved_queries.command("update")
@click.argument("query_id")
@click.option("--data", "data_str", default=None, help="JSON body for saved query update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def saved_queries_update(ctx, query_id, data_str, data_file):
    """Update a saved query."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/saved_queries/{query_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with saved query definition.")

    try:
        result = client.request("PUT", url, json=body, solution="siem", subcommand="saved-queries-update")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@saved_queries.command("delete")
@click.argument("query_id")
@click.pass_context
def saved_queries_delete(ctx, query_id):
    """Delete a saved query."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/saved_queries/{query_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.request("DELETE", url, solution="siem", subcommand="saved-queries-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem variables  (LEQL variables)
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def variables(ctx):
    """LEQL variable commands."""
    pass


@variables.command("list")
@click.pass_context
def variables_list(ctx):
    """List all LEQL variables."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/variables"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="variables-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@variables.command("get")
@click.argument("variable_id")
@click.pass_context
def variables_get(ctx, variable_id):
    """Get a LEQL variable by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/variables/{variable_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="variables-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem detection-rules  (basic detection rules / tags)
# ---------------------------------------------------------------------------

@siem.group("detection-rules", cls=GlobalFlagHintGroup)
@click.pass_context
def detection_rules(ctx):
    """Basic detection rule commands."""
    pass


@detection_rules.command("list")
@click.pass_context
def detection_rules_list(ctx):
    """List basic detection rules."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/tags"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="detection-rules-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@detection_rules.command("get")
@click.argument("rule_id")
@click.pass_context
def detection_rules_get(ctx, rule_id):
    """Get a basic detection rule by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/tags/{rule_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="detection-rules-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@detection_rules.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for rule creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def detection_rules_create(ctx, data_str, data_file):
    """Create a basic detection rule."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/tags"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with rule definition.")

    try:
        result = client.post(url, json=body, solution="siem", subcommand="detection-rules-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@detection_rules.command("delete")
@click.argument("rule_id")
@click.pass_context
def detection_rules_delete(ctx, rule_id):
    """Delete a basic detection rule."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/tags/{rule_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.request("DELETE", url, solution="siem", subcommand="detection-rules-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem log-keys  (top keys for a log)
# ---------------------------------------------------------------------------

@siem.command("log-keys")
@click.argument("log_id")
@click.pass_context
def log_keys(ctx, log_id):
    """Get the most common keys for a log."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/logs/{log_id}/topkeys"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="log-keys")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem log-mgmt  (individual log CRUD from management API)
# ---------------------------------------------------------------------------

@siem.group("log-mgmt", cls=GlobalFlagHintGroup)
@click.pass_context
def log_mgmt(ctx):
    """Log management commands (list, get, create, delete)."""
    pass


@log_mgmt.command("list")
@click.pass_context
def log_mgmt_list(ctx):
    """List all logs."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/logs"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="log-mgmt-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@log_mgmt.command("get")
@click.argument("log_id")
@click.pass_context
def log_mgmt_get(ctx, log_id):
    """Get a log by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/logs/{log_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="log-mgmt-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@log_mgmt.command("delete")
@click.argument("log_id")
@click.pass_context
def log_mgmt_delete(ctx, log_id):
    """Delete a log by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/logs/{log_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.request("DELETE", url, solution="siem", subcommand="log-mgmt-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem pre-computed  (pre-computed queries / metrics)
# ---------------------------------------------------------------------------

@siem.group("pre-computed", cls=GlobalFlagHintGroup)
@click.pass_context
def pre_computed(ctx):
    """Pre-computed query commands."""
    pass


@pre_computed.command("list")
@click.pass_context
def pre_computed_list(ctx):
    """List pre-computed queries."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/metrics"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="pre-computed-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@pre_computed.command("get")
@click.argument("metric_id")
@click.pass_context
def pre_computed_get(ctx, metric_id):
    """Get a pre-computed query by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/metrics/{metric_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="pre-computed-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@pre_computed.command("results")
@click.argument("metric_id")
@click.option("--from", "from_ts", default=None, help="Start timestamp (epoch ms).")
@click.option("--to", "to_ts", default=None, help="End timestamp (epoch ms).")
@click.option("--time-range", default=None, help="Time range (e.g. 'Last 7 days').")
@click.pass_context
def pre_computed_results(ctx, metric_id, from_ts, to_ts, time_range):
    """Fetch results for a pre-computed query."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/metrics/{metric_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    params: dict = {}
    if from_ts:
        params["from"] = from_ts
    if to_ts:
        params["to"] = to_ts
    if time_range:
        params["time_range"] = time_range

    try:
        result = client.get(url, params=params or None, solution="siem", subcommand="pre-computed-results")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@pre_computed.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for pre-computed query creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def pre_computed_create(ctx, data_str, data_file):
    """Create a pre-computed query."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/metrics"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with pre-computed query definition.")

    try:
        result = client.post(url, json=body, solution="siem", subcommand="pre-computed-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@pre_computed.command("delete")
@click.argument("metric_id")
@click.pass_context
def pre_computed_delete(ctx, metric_id):
    """Delete a pre-computed query."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/metrics/{metric_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.request("DELETE", url, solution="siem", subcommand="pre-computed-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem exports  (CSV export jobs)
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def exports(ctx):
    """Log data CSV export commands."""
    pass


@exports.command("list")
@click.pass_context
def exports_list(ctx):
    """List export jobs."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/exports"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="exports-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@exports.command("get")
@click.argument("export_id")
@click.pass_context
def exports_get(ctx, export_id):
    """Get an export job by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/exports/{export_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="exports-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem notifications  (alert notification settings / actions)
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def notifications(ctx):
    """Detection rule notification commands."""
    pass


@notifications.command("list")
@click.pass_context
def notifications_list(ctx):
    """List alert notification settings."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/actions"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="notifications-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@notifications.command("get")
@click.argument("action_id")
@click.pass_context
def notifications_get(ctx, action_id):
    """Get a notification setting by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/actions/{action_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="notifications-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem targets  (notification targets)
# ---------------------------------------------------------------------------

@siem.group("notif-targets", cls=GlobalFlagHintGroup)
@click.pass_context
def notif_targets(ctx):
    """Notification target commands."""
    pass


@notif_targets.command("list")
@click.pass_context
def notif_targets_list(ctx):
    """List notification targets."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/targets"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="notif-targets-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@notif_targets.command("get")
@click.argument("target_id")
@click.pass_context
def notif_targets_get(ctx, target_id):
    """Get a notification target by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/targets/{target_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="notif-targets-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem usage  (per-log usage from usage API)
# ---------------------------------------------------------------------------

@siem.command("log-usage")
@click.argument("log_key")
@click.option("--from", "from_date", default=None, help="Start date (YYYY-MM-DD).")
@click.option("--to", "to_date", default=None, help="End date (YYYY-MM-DD).")
@click.pass_context
def log_usage(ctx, log_key, from_date, to_date):
    """Get storage usage for a specific log."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/usage/organizations/logs/{log_key}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    params: dict = {}
    if from_date:
        params["from"] = from_date
    if to_date:
        params["to"] = to_date

    try:
        result = client.get(url, params=params or None, solution="siem", subcommand="log-usage")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
