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
    ACCOUNT_BASE,
    IDR_GQL,
    IDR_LOGS_BASE,
    IDR_V1_BASE,
    GQL_AGENTS_LIST,
    GQL_QUARANTINE_STATE,
    REGION_ALIASES,
    APIError,
    R7Error,
    UserInputError,
)
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_config(ctx: click.Context) -> Config:
    return ctx.obj["config"]


def _extract_items(data) -> list[dict]:
    """Find the largest list of dicts in the response."""
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
                nested = _extract_items(val)
                if len(nested) > len(best):
                    best = nested
        return best
    return []


def _extract_item_id(item: dict) -> str:
    """Extract the best available ID from a dict."""
    for key in ("id", "_id", "workflowId", "job_id", "rrn"):
        val = item.get(key, "")
        if val:
            return str(val)
    return ""


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


# ---------------------------------------------------------------------------
# Agent helpers
# ---------------------------------------------------------------------------

def _resolve_org_id(client: R7Client, config: Config) -> str:
    """Resolve the organization ID by matching the configured region."""
    url = ACCOUNT_BASE.format(region=config.region) + "/organizations"
    orgs = client.get(url, solution="siem", subcommand="agents-list")
    if isinstance(orgs, dict):
        orgs = orgs.get("organizations", orgs.get("data", []))
    for org in orgs:
        org_region = REGION_ALIASES.get(org.get("region", ""), org.get("region", ""))
        if org_region == config.region:
            return org["id"]
    raise UserInputError(f"No organization found for region '{config.region}'")


def _flatten_agent_node(node: dict) -> dict:
    """Convert a nested GQL agent node into a flat Agent_Record dict."""
    agent = node.get("agent") or {}

    return {
        "agent_id": agent.get("id"),
        "agent_status": agent.get("agentStatus"),
        "agent_semantic_version": agent.get("agentSemanticVersion"),
        "deploy_time": agent.get("deployTime"),
        "agent_last_update": agent.get("agentLastUpdateTime"),
        "public_ip": node.get("publicIpAddress"),
        "platform": node.get("platform"),
    }


def _apply_agent_filters(
    records: list[dict],
    ngav_status: str | None,
    velociraptor_status: str | None,
) -> list[dict]:
    """Filter agent records by NGAV health and/or velociraptor state."""
    result = records
    if ngav_status is not None:
        result = [r for r in result if r.get("ngav_status") == ngav_status]
    if velociraptor_status == "RUNNING":
        result = [r for r in result if r.get("velociraptor_state") == "RUNNING"]
    elif velociraptor_status == "NOT_RUNNING":
        result = [r for r in result if r.get("velociraptor_state") != "RUNNING"]
    return result


_VALID_RESOURCE_TYPES = (
    "agent",
    "collector",
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


def _ms_to_human(ms: int) -> str:
    """Convert milliseconds to a human-readable duration string."""
    days = ms // _MS_PER_DAY
    if days >= 365 and days % 365 == 0:
        years = days // 365
        return f"{years} year{'s' if years != 1 else ''}"
    if days >= 30 and days % 30 == 0:
        months = days // 30
        return f"{months} month{'s' if months != 1 else ''}"
    return f"{days} day{'s' if days != 1 else ''}"


# ---------------------------------------------------------------------------
# Click groups
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def siem(ctx):
    """InsightIDR / SIEM commands."""
    pass


# Parent groups for reorganized commands
@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def queries(ctx):
    """LEQL query, saved query, variable, and pre-computed query commands."""
    pass


@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def detections(ctx):
    """Detection rules, notifications, and notification target commands."""
    pass


# ---------------------------------------------------------------------------
# siem health
# ---------------------------------------------------------------------------

@siem.command("health")
@click.option(
    "--resource-type",
    type=click.Choice(_VALID_RESOURCE_TYPES, case_sensitive=False),
    default=None,
    help="Filter by resource type.",
)
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--state", default=None, help="Filter by state (e.g. RUNNING, WARNING, FATAL_ERROR, ONLINE, HEALTHY).")
@click.option("--name", "health_name", default=None, help="Filter by name (substring match).")
@click.option("--issues-only", is_flag=True, help="Show only resources with issues.")
@click.pass_context
def health_metrics(ctx, resource_type, auto_poll, interval, state, health_name, issues_only):
    """Retrieve IDR agent/sensor health metrics.

    \b
    Examples:
      # All health metrics
      r7-cli siem health

    \b
      # Only collectors
      r7-cli siem health --resource-type COLLECTOR

    \b
      # Only resources with issues
      r7-cli siem health --issues-only

    \b
      # Filter by state
      r7-cli siem health --state WARNING

    \b
      # Filter by name
      r7-cli siem health --name 'AWS'

    \b
      # Poll for changes
      r7-cli siem health -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/health-metrics"

    params: dict[str, str] = {}
    if resource_type:
        # Normalize singular to plural for the API
        rt = resource_type.lower()
        if rt == "collector":
            rt = "collectors"
        params["resourceTypes"] = rt

    try:
        result = client.get(
            url, params=params or None, solution="siem", subcommand="health-metrics",
        )

        has_filters = any([state, health_name, issues_only])

        if not auto_poll:
            if has_filters:
                items = _extract_items(result)
                if state:
                    s_upper = state.upper()
                    items = [r for r in items if r.get("state", "").upper() == s_upper]
                if health_name:
                    n_lower = health_name.lower()
                    items = [r for r in items if n_lower in r.get("name", "").lower()]
                if issues_only:
                    items = [r for r in items if r.get("issue") is not None]
                click.echo(format_output(items, config.output_format, config.limit, config.search, short=config.short))
            else:
                click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, params=params or None, solution="siem", subcommand="health-metrics")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem logs
# ---------------------------------------------------------------------------

@siem.group(cls=GlobalFlagHintGroup)
@click.pass_context
def logs(ctx):
    """IDR log query commands."""
    pass


# ---------------------------------------------------------------------------
# siem logs logsets
# ---------------------------------------------------------------------------

@logs.group(cls=GlobalFlagHintGroup)
@click.pass_context
def logsets(ctx):
    """IDR logset commands."""
    pass


@logsets.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def logsets_list(ctx, auto_poll, interval):
    """List all IDR logsets."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/logsets"

    try:
        result = client.get(url, solution="siem", subcommand="logsets-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, solution="siem", subcommand="logsets-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


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


@logs.command("storage")
@click.option("--from", "from_date", default="2017-01-31", help="Start date (YYYY-MM-DD).")
@click.option("--to", "to_date", default=None, help="End date (YYYY-MM-DD, default: today).")
@click.pass_context
def log_storage(ctx, from_date, to_date):
    """Retrieve IDR log storage usage over time.

    \b
    Examples:
      r7-cli siem logs storage
      r7-cli siem logs storage --from 2025-01-01 --to 2025-06-01
    """
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

    daily = result.get("daily_usage", [])
    if isinstance(daily, list):
        daily.sort(key=lambda d: d.get("date", ""), reverse=True)
        result["daily_usage"] = daily

    click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))


@logs.command("retention")
@click.option("--min-days", type=int, default=None, help="Exit non-zero if retention < threshold days.")
@click.pass_context
def log_retention(ctx, min_days):
    """Retrieve IDR log retention settings with human-readable durations.

    \b
    Examples:
      r7-cli siem logs retention
      r7-cli siem logs retention --min-days 90
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/organizations"

    try:
        result = client.get(url, solution="siem", subcommand="log-retention")
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    _PERIOD_FIELDS = ("max_retention_period", "retention_period", "cold_retention")

    # Determine the target dict (flat vs nested under "account")
    target = result.get("account") if isinstance(result.get("account"), dict) else result

    # Grab raw retention_period in ms before we overwrite it
    raw_retention_ms = target.get("retention_period")

    for field in _PERIOD_FIELDS:
        ms_val = target.get(field)
        if ms_val is not None:
            try:
                target[field] = _ms_to_human(int(ms_val))
            except (TypeError, ValueError):
                pass

    click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))

    if min_days is not None and raw_retention_ms is not None:
        try:
            retention_days = int(raw_retention_ms) // _MS_PER_DAY
        except (TypeError, ValueError):
            retention_days = None
        if retention_days is not None and retention_days < min_days:
            click.echo(
                f"Retention {retention_days} days is below threshold {min_days} days",
                err=True,
            )
            sys.exit(1)


# ---------------------------------------------------------------------------
# siem event-sources
# ---------------------------------------------------------------------------

@siem.group("event-sources", cls=GlobalFlagHintGroup)
@click.pass_context
def event_sources(ctx):
    """IDR event source commands."""
    pass


@event_sources.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--state", default=None, help="Filter by state (e.g. RUNNING, WARNING, FATAL_ERROR, ONLINE, HEALTHY).")
@click.option("--name", "es_name", default=None, help="Filter by name (substring match).")
@click.option("--issues-only", is_flag=True, help="Show only event sources with issues.")
@click.pass_context
def event_sources_list(ctx, auto_poll, interval, state, es_name, issues_only):
    """List event sources via the health-metrics API.

    \b
    Examples:
      r7-cli siem event-sources list
      r7-cli siem event-sources list --state WARNING
      r7-cli siem event-sources list --name 'AWS'
      r7-cli siem event-sources list --issues-only
      r7-cli siem event-sources list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/health-metrics"
    params = {"resourceTypes": "event_sources"}

    has_filters = any([state, es_name, issues_only])

    try:
        result = client.get(url, params=params, solution="siem", subcommand="event-sources-list")

        if not auto_poll:
            if has_filters:
                items = _extract_items(result)
                if state:
                    s_upper = state.upper()
                    items = [r for r in items if r.get("state", "").upper() == s_upper]
                if es_name:
                    n_lower = es_name.lower()
                    items = [r for r in items if n_lower in r.get("name", "").lower()]
                if issues_only:
                    items = [r for r in items if r.get("issue") is not None]
                click.echo(format_output(items, config.output_format, config.limit, config.search, short=config.short))
            else:
                click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, params=params, solution="siem", subcommand="event-sources-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
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
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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

        click.echo(format_output(filtered, config.output_format, config.limit, config.search, short=config.short))

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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@accounts.command("get")
@click.option("-j", "--id", "rrn", required=True, help="Account RRN.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem accounts assets (formerly idr-assets)
# ---------------------------------------------------------------------------

@accounts.group("assets", cls=GlobalFlagHintGroup)
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
    """Search IDR assets.

    \b
    Example:
      r7-cli siem accounts assets search
    """
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@idr_assets.command("get")
@click.option("-j", "--id", "rrn", required=True, help="Asset RRN.")
@click.pass_context
def idr_assets_get(ctx, rrn):
    """Get an IDR asset by RRN.

    \b
    Example:
      r7-cli siem accounts assets get <ASSET_RRN>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/assets/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/findAssetByRrn", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="idr-assets-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@idr_assets.command("local-account")
@click.option("--rrn", required=True, help="Local account RRN.")
@click.pass_context
def idr_assets_local_account(ctx, rrn):
    """Get a local account by RRN.

    \b
    Example:
      r7-cli siem accounts assets local-account --rrn <LOCAL_ACCOUNT_RRN>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IDR_V1_BASE.format(region=config.region) + f"/assets/local-accounts/{rrn}"
    try:
        result = client.get(url, solution="siem", subcommand="idr-assets-local-account")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@idr_assets.command("search-local-accounts")
@click.option("--index", type=int, default=0, help="Page index.")
@click.option("--size", type=int, default=20, help="Page size.")
@click.option("--data", "data_str", default=None, help="JSON search body.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def idr_assets_search_local_accounts(ctx, index, size, data_str, data_file):
    """Search local accounts.

    \b
    Example:
      r7-cli siem accounts assets search-local-accounts --data '{"search": [{"field": "asset.rrn", "operator": "EQUALS", "value": "<ASSET_RRN>"}]}'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    body = _resolve_body(data_str, data_file) or {}
    url = IDR_V1_BASE.format(region=config.region) + "/assets/local-accounts/_search"
    params = {"index": index, "size": size}
    try:
        result = client.post(url, json=body, params=params, solution="siem", subcommand="idr-assets-search-local-accounts")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--status", default=None, help="Filter by status (e.g. OPEN, INVESTIGATING, WAITING, CLOSED).")
@click.option("--source", default=None, help="Filter by source (e.g. ALERT, MANUAL).")
@click.option("--disposition", default=None, help="Filter by disposition (e.g. UNDECIDED, MALICIOUS, BENIGN).")
@click.option("--title", default=None, help="Filter by title (substring match).")
@click.option("--assignee", default=None, help="Filter by assignee name or email (substring match).")
@click.pass_context
def investigations_list(ctx, index, size, all_pages, auto_poll, interval, status, source, disposition, title, assignee):
    """List IDR investigations.

    \b
    Examples:
      # List first page
      r7-cli siem investigations list

    \b
      # Fetch all investigations
      r7-cli siem investigations list --all-pages

    \b
      # Only open investigations
      r7-cli siem investigations list --status OPEN --all-pages

    \b
      # Investigations being investigated
      r7-cli siem investigations list --status INVESTIGATING

    \b
      # Filter by title
      r7-cli siem investigations list --title 'CloudTrail' --all-pages

    \b
      # Filter by assignee
      r7-cli siem investigations list --assignee 'David' --all-pages

    \b
      # Poll for new investigations
      r7-cli siem investigations list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/investigations"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/listInvestigations", err=True)

    has_filters = any([status, source, disposition, title, assignee])

    def _apply_filters(items):
        filtered = items
        if status:
            s_upper = status.upper()
            filtered = [inv for inv in filtered if inv.get("status", "").upper() == s_upper]
        if source:
            src_upper = source.upper()
            filtered = [inv for inv in filtered if inv.get("source", "").upper() == src_upper]
        if disposition:
            d_upper = disposition.upper()
            filtered = [inv for inv in filtered if inv.get("disposition", "").upper() == d_upper]
        if title:
            t_lower = title.lower()
            filtered = [inv for inv in filtered if t_lower in inv.get("title", "").lower()]
        if assignee:
            a_lower = assignee.lower()
            filtered = [inv for inv in filtered if isinstance(inv.get("assignee"), dict) and (
                a_lower in inv["assignee"].get("name", "").lower() or
                a_lower in inv["assignee"].get("email", "").lower()
            )]
        return filtered

    def _fetch_all_idr_pages():
        all_items = []
        current_index = index
        while True:
            params = {"index": current_index, "size": size}
            result = client.get(url, params=params, solution="siem", subcommand="investigations-list")
            items = _extract_items(result)
            all_items.extend(items)
            metadata = result.get("metadata", {})
            total_pages = metadata.get("total_pages", 1)
            current_index += 1
            if current_index >= total_pages:
                break
        return all_items

    params = {"index": index, "size": size}

    try:
        if all_pages or has_filters:
            all_items = _fetch_all_idr_pages()
            if has_filters:
                all_items = _apply_filters(all_items)
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="siem", subcommand="investigations-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, params=params, solution="siem", subcommand="investigations-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@investigations.command("set-status")
@click.option("--id", "-j", "investigation_id", required=True, help="Investigation ID or RRN.")
@click.option("--status", required=True, type=click.Choice(["OPEN", "INVESTIGATING", "CLOSED"], case_sensitive=True), help="New status.")
@click.pass_context
def investigations_set_status(ctx, investigation_id, status):
    """Set the status of an investigation.

    \b
    Examples:
      r7-cli siem investigations set-status --id <INVESTIGATION_ID> --status OPEN
      r7-cli siem investigations set-status -j <INVESTIGATION_ID> --status CLOSED
      r7-cli siem investigations set-status --id <INVESTIGATION_ID> --status INVESTIGATING
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/investigations/{investigation_id}/status/{status}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/setStatus", err=True)

    try:
        result = client.request("PUT", url, solution="siem", subcommand="investigations-set-status")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo("Provide --data or --data-file with investigation IDs.", err=True)
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="siem", subcommand="investigations-close-bulk")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@investigations.command("assign")
@click.option("-j", "--id", "investigation_id", required=True, help="Investigation ID.")
@click.option("--user-email", required=True, help="Email of the user to assign.")
@click.pass_context
def investigations_assign(ctx, investigation_id, user_email):
    """Assign a user to an investigation.

    \b
    Example:
      r7-cli siem investigations assign --id <INVESTIGATION_ID> --user-email [email]
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IDR_V1_BASE.format(region=config.region) + f"/investigations/{investigation_id}/assignee"
    try:
        result = client.request("PUT", url, json={"user_email_address": user_email}, solution="siem", subcommand="investigations-assign")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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


@users.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages and return combined results.")
@click.option("--data", "data_str", default=None, help="JSON search body string.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON search body.")
@click.pass_context
def users_search(ctx, index, size, all_pages, data_str, data_file):
    """List IDR users."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/users/_search"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/searchUsers", err=True)

    body = _resolve_body(data_str, data_file) or {}

    try:
        if not all_pages:
            params = {"index": index, "size": size}
            result = client.post(url, json=body, params=params, solution="siem", subcommand="users-list")
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            all_data: list[dict] = []
            page = index
            while True:
                params = {"index": page, "size": size}
                result = client.post(url, json=body, params=params, solution="siem", subcommand="users-list")
                items = _extract_items(result)
                all_data.extend(items)
                meta = result.get("metadata", {}) if isinstance(result, dict) else {}
                total_pages = meta.get("total_pages", 1)
                if config.verbose:
                    click.echo(f"Page {page + 1}/{total_pages} — {len(items)} items", err=True)
                page += 1
                if page >= total_pages:
                    break
            click.echo(format_output(all_data, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@users.command("get")
@click.option("--id", "rrn", default=None, help="User RRN to retrieve.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a user from the list.")
@click.pass_context
def users_get(ctx, rrn, auto_select):
    """Get an IDR user by RRN."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)

    if not rrn and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        rrn = _interactive_user_select(client, config, base)

    url = f"{base}/users/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/getUserByRrn", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="users-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


def _interactive_user_select(client: R7Client, config: Config, base: str) -> str:
    """Fetch users, display an interactive menu, return the selected user RRN."""
    import questionary

    url = f"{base}/users/_search"
    result = client.post(url, json={}, params={"size": 30}, solution="siem", subcommand="users-list")

    items = _extract_items(result)
    if not items:
        click.echo("No users found.", err=True)
        sys.exit(1)

    choices = []
    for u in items:
        name = u.get("name", "")
        domain = u.get("domain", "")
        rrn = str(u.get("rrn", "?"))
        label = f"{name} [{domain}] ({rrn})" if name else rrn
        choices.append(questionary.Choice(title=label, value=rrn))

    selected = questionary.select("Select a user:", choices=choices).ask()
    if selected is None:
        click.echo("No selection made.", err=True)
        sys.exit(1)
    return selected


# ---------------------------------------------------------------------------
# detections threats
# ---------------------------------------------------------------------------

@detections.group(cls=GlobalFlagHintGroup)
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
        click.echo("Provide --data or --data-file with threat definition.", err=True)
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="siem", subcommand="threats-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@threats.command("add-indicators")
@click.option("-j", "--id", "key", required=True, help="Community threat key.")
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
        click.echo("Provide --data or --data-file with indicators.", err=True)
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="siem", subcommand="threats-add-indicators")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@threats.command("replace-indicators")
@click.option("-j", "--id", "key", required=True, help="Community threat key.")
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
        click.echo("Provide --data or --data-file with indicators.", err=True)
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="siem", subcommand="threats-replace-indicators")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@threats.command("delete")
@click.option("--key", required=True, help="Community threat key.")
@click.pass_context
def threats_delete(ctx, key):
    """Delete a community threat by key.

    \b
    Example:
      r7-cli siem threats delete --key <THREAT_KEY>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IDR_V1_BASE.format(region=config.region) + f"/customthreats/key/{key}/delete"
    try:
        result = client.post(url, solution="siem", subcommand="threats-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# investigations comments
# ---------------------------------------------------------------------------

@investigations.group(cls=GlobalFlagHintGroup)
@click.pass_context
def comments(ctx):
    """IDR comment commands."""
    pass


@comments.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@click.pass_context
def comments_list(ctx, index, size):
    """List investigations that have comments.

    Fetches all investigations and checks each for comments,
    returning only those with at least one comment.

    \b
    Examples:
      r7-cli siem investigations comments list
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    inv_url = f"{base}/investigations"
    comments_url = f"{base}/comments"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/listComments", err=True)

    try:
        # Fetch all investigations across pages
        all_investigations: list[dict] = []
        current_index = index
        while True:
            params = {"index": current_index, "size": size}
            result = client.get(inv_url, params=params, solution="siem", subcommand="investigations-list")
            items = _extract_items(result)
            all_investigations.extend(items)
            metadata = result.get("metadata", {})
            total_pages = metadata.get("total_pages", 1)
            current_index += 1
            if current_index >= total_pages:
                break

        if not all_investigations:
            click.echo("No investigations found.", err=True)
            return

        # Check each investigation for comments
        with_comments: list[dict] = []
        for inv in all_investigations:
            inv_rrn = inv.get("rrn", "")
            if not inv_rrn:
                continue
            try:
                cmt_result = client.get(
                    comments_url,
                    params={"target": inv_rrn, "index": 0, "size": 1},
                    solution="siem",
                    subcommand="comments-list",
                )
                cmt_data = cmt_result.get("data", [])
                if isinstance(cmt_data, list) and len(cmt_data) > 0:
                    with_comments.append(inv)
                else:
                    # Also check metadata total_data
                    total = cmt_result.get("metadata", {}).get("total_data", 0)
                    if total and int(total) > 0:
                        with_comments.append(inv)
            except R7Error:
                # Skip investigations where comment lookup fails
                continue

        click.echo(format_output(with_comments, config.output_format, config.limit, config.search, short=config.short))

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
        click.echo("Provide --data or --data-file with comment body.", err=True)
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="siem", subcommand="comments-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@comments.command("get")
@click.option("-j", "--id", "rrn", required=True, help="Comment RRN.")
@click.pass_context
def comments_get(ctx, rrn):
    """Get a comment by RRN.

    \b
    Examples:
      r7-cli siem investigations comments get --id <COMMENT_RRN>
      r7-cli siem investigations comments get -j <COMMENT_RRN>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/comments/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/getComment", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="comments-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@comments.command("update")
@click.option("-j", "--id", "rrn", required=True, help="Comment RRN.")
@click.option("--visibility", required=True, type=click.Choice(["public", "private"], case_sensitive=False), help="Comment visibility.")
@click.pass_context
def comments_update(ctx, rrn, visibility):
    """Update a comment's visibility.

    \b
    Examples:
      r7-cli siem investigations comments update --id <COMMENT_RRN> --visibility public
      r7-cli siem investigations comments update -j <COMMENT_RRN> --visibility private
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IDR_V1_BASE.format(region=config.region) + f"/comments/{rrn}/{visibility}"
    try:
        result = client.request("PUT", url, solution="siem", subcommand="comments-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@comments.command("delete")
@click.option("-j", "--id", "rrn", required=True, help="Comment RRN.")
@click.pass_context
def comments_delete(ctx, rrn):
    """Delete a comment.

    \b
    Examples:
      r7-cli siem investigations comments delete --id <COMMENT_RRN>
      r7-cli siem investigations comments delete -j <COMMENT_RRN>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IDR_V1_BASE.format(region=config.region) + f"/comments/{rrn}"
    try:
        result = client.request("DELETE", url, solution="siem", subcommand="comments-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# investigations attachments
# ---------------------------------------------------------------------------

@investigations.group(cls=GlobalFlagHintGroup)
@click.pass_context
def attachments(ctx):
    """IDR attachment commands."""
    pass


@attachments.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@click.pass_context
def attachments_list(ctx, index, size):
    """List investigations that have attachments.

    Fetches all investigations and checks each for attachments,
    returning only those with at least one attachment.

    \b
    Examples:
      r7-cli siem investigations attachments list
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    inv_url = f"{base}/investigations"
    attachments_url = f"{base}/attachments"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/listAttachments", err=True)

    try:
        # Fetch all investigations across pages
        all_investigations: list[dict] = []
        current_index = index
        while True:
            params = {"index": current_index, "size": size}
            result = client.get(inv_url, params=params, solution="siem", subcommand="investigations-list")
            items = _extract_items(result)
            all_investigations.extend(items)
            metadata = result.get("metadata", {})
            total_pages = metadata.get("total_pages", 1)
            current_index += 1
            if current_index >= total_pages:
                break

        if not all_investigations:
            click.echo("No investigations found.", err=True)
            return

        # Check each investigation for attachments
        with_attachments: list[dict] = []
        for inv in all_investigations:
            inv_rrn = inv.get("rrn", "")
            if not inv_rrn:
                continue
            try:
                att_result = client.get(
                    attachments_url,
                    params={"target": inv_rrn, "index": 0, "size": 1},
                    solution="siem",
                    subcommand="attachments-list",
                )
                att_data = att_result.get("data", [])
                if isinstance(att_data, list) and len(att_data) > 0:
                    with_attachments.append(inv)
                else:
                    total = att_result.get("metadata", {}).get("total_data", 0)
                    if total and int(total) > 0:
                        with_attachments.append(inv)
            except R7Error:
                continue

        click.echo(format_output(with_attachments, config.output_format, config.limit, config.search, short=config.short))

    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@attachments.command("get")
@click.option("--id", "-j", "rrn", required=True, help="Attachment RRN.")
@click.pass_context
def attachments_get(ctx, rrn):
    """Get attachment metadata by RRN.

    \b
    Examples:
      r7-cli siem investigations attachments get --id <ATTACHMENT_RRN>
      r7-cli siem investigations attachments get -j <ATTACHMENT_RRN>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/attachments/{rrn}/metadata"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/getAttachment", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="attachments-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@attachments.command("delete")
@click.option("--id", "-j", "rrn", required=True, help="Attachment RRN.")
@click.pass_context
def attachments_delete(ctx, rrn):
    """Delete an attachment.

    \b
    Examples:
      r7-cli siem investigations attachments delete --id <ATTACHMENT_RRN>
      r7-cli siem investigations attachments delete -j <ATTACHMENT_RRN>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IDR_V1_BASE.format(region=config.region) + f"/attachments/{rrn}"
    try:
        result = client.request("DELETE", url, solution="siem", subcommand="attachments-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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


@collectors.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--state", default=None, help="Filter by state (e.g. RUNNING, WARNING, FATAL_ERROR).")
@click.option("--name", "coll_name", default=None, help="Filter by collector name (substring match).")
@click.pass_context
def collectors_list(ctx, auto_poll, interval, state, coll_name):
    """List collectors via the health-metrics API.

    \b
    Examples:
      r7-cli siem collectors list
      r7-cli siem collectors list --state RUNNING
      r7-cli siem collectors list --name 'AWS'
      r7-cli siem collectors list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_V1_BASE.format(region=config.region)
    url = f"{base}/health-metrics"
    params = {"resourceTypes": "collectors"}

    try:
        result = client.get(url, params=params, solution="siem", subcommand="collectors-list")

        if not auto_poll:
            items = _extract_items(result)
            if state:
                s_upper = state.upper()
                items = [c for c in items if c.get("state", "").upper() == s_upper]
            if coll_name:
                n_lower = coll_name.lower()
                items = [c for c in items if n_lower in c.get("name", "").lower()]
            click.echo(format_output(items if (state or coll_name) else result, config.output_format, config.limit, config.search, short=config.short))
        else:
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                time.sleep(interval)
                new_result = client.get(url, params=params, solution="siem", subcommand="collectors-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


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
        click.echo("Provide --data or --data-file with collector definition.", err=True)
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="siem", subcommand="collectors-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem saved-queries  (from log-search / insightops schemas)
# ---------------------------------------------------------------------------

_LOG_SEARCH_DOC = "https://docs.rapid7.com/insightidr/log-search-api/"


@queries.group("saved-queries", cls=GlobalFlagHintGroup)
@click.pass_context
def saved_queries(ctx):
    """Log Search saved query commands."""
    pass


@saved_queries.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def saved_queries_list(ctx, auto_poll, interval):
    """List saved queries."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/saved_queries"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="saved-queries-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, solution="siem", subcommand="saved-queries-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@saved_queries.command("get")
@click.option("-j", "--id", "query_id", required=True, help="Saved query ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo("Provide --data or --data-file with saved query definition.", err=True)
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="siem", subcommand="saved-queries-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@saved_queries.command("update")
@click.option("-j", "--id", "query_id", required=True, help="Saved query ID.")
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
        click.echo("Provide --data or --data-file with saved query definition.", err=True)
        sys.exit(1)

    try:
        result = client.request("PUT", url, json=body, solution="siem", subcommand="saved-queries-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@saved_queries.command("delete")
@click.option("-j", "--id", "query_id", required=True, help="Saved query ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# queries variables  (LEQL variables)
# ---------------------------------------------------------------------------

@queries.group(cls=GlobalFlagHintGroup)
@click.pass_context
def variables(ctx):
    """LEQL variable commands."""
    pass


@variables.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def variables_list(ctx, auto_poll, interval):
    """List all LEQL variables."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/query/variables"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="variables-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, solution="siem", subcommand="variables-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@variables.command("get")
@click.option("-j", "--id", "variable_id", required=True, help="Variable ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@variables.command("update")
@click.option("-j", "--id", "variable_id", required=True, help="Variable ID.")
@click.option("--data", "data_str", default=None, help="JSON body for variable update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def variables_update(ctx, variable_id, data_str, data_file):
    """Update a LEQL variable.

    \b
    Example:
      r7-cli siem variables update --id <VAR_ID> --data '{"name": "my_var", "value": "new_value"}'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the variable definition.", err=True)
        sys.exit(1)
    url = IDR_LOGS_BASE.format(region=config.region) + f"/variables/{variable_id}"
    try:
        result = client.request("PUT", url, json=body, solution="siem", subcommand="variables-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@variables.command("delete")
@click.option("-j", "--id", "variable_id", required=True, help="Variable ID.")
@click.pass_context
def variables_delete(ctx, variable_id):
    """Delete a LEQL variable.

    \b
    Example:
      r7-cli siem variables delete --id <VAR_ID>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IDR_LOGS_BASE.format(region=config.region) + f"/variables/{variable_id}"
    try:
        result = client.request("DELETE", url, solution="siem", subcommand="variables-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


def _interactive_select_detection_rule(client, config, base):
    """Fetch detection rules and show interactive menu."""
    import questionary

    url = f"{base}/management/tags"
    result = client.get(url, solution="siem", subcommand="detection-rules-list")
    items = result.get("tags", result.get("data", []))
    if not isinstance(items, list) or not items:
        click.echo("No detection rules found.", err=True)
        sys.exit(1)

    choices = []
    for item in items:
        name = item.get("name", "")
        rtype = item.get("type", "")
        rid = str(item.get("id", "?"))
        label = f"{name} [{rtype}] ({rid})" if name else rid
        choices.append(questionary.Choice(title=label, value=rid))

    selected = questionary.select("Select a detection rule:", choices=choices).ask()
    if selected is None:
        click.echo("No selection made.", err=True)
        sys.exit(1)
    return selected


# ---------------------------------------------------------------------------
# siem detection-rules  (basic detection rules / tags)
# ---------------------------------------------------------------------------

@detections.group("detection-rules", cls=GlobalFlagHintGroup)
@click.pass_context
def detection_rules(ctx):
    """Basic detection rule commands."""
    pass


@detection_rules.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--name", "rule_name", default=None, help="Filter by rule name (substring match).")
@click.option("--type", "rule_type", default=None, help="Filter by type (e.g. AlertNotify).")
@click.option("--sub-type", default=None, help="Filter by sub_type (e.g. InactivityAlert, AnomalyAlert).")
@click.option("--priority", default=None, help="Filter by priority (e.g. '>=2', '=1').")
@click.option("--enabled", type=click.Choice(["true", "false"], case_sensitive=False), default=None, help="Filter by whether actions are enabled.")
@click.pass_context
def detection_rules_list(ctx, auto_poll, interval, rule_name, rule_type, sub_type, priority, enabled):
    """List basic detection rules.

    \b
    Examples:
      # List all detection rules
      r7-cli siem detection-rules list

    \b
      # Filter by name
      r7-cli siem detection-rules list --name 'Firewall'

    \b
      # Filter by sub-type
      r7-cli siem detection-rules list --sub-type InactivityAlert

    \b
      # Filter by priority
      r7-cli siem detection-rules list --priority '>=2'

    \b
      # Only rules with enabled actions
      r7-cli siem detection-rules list --enabled true

    \b
      # Poll for new rules
      r7-cli siem detection-rules list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/tags"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="detection-rules-list")

        has_filters = any([rule_name, rule_type, sub_type, priority, enabled])

        if not auto_poll:
            if has_filters:
                items = result.get("tags", result.get("data", [])) if isinstance(result, dict) else result
                if not isinstance(items, list):
                    items = [items]
                if rule_name:
                    n_lower = rule_name.lower()
                    items = [r for r in items if n_lower in r.get("name", "").lower()]
                if rule_type:
                    rt_lower = rule_type.lower()
                    items = [r for r in items if r.get("type", "").lower() == rt_lower]
                if sub_type:
                    st_lower = sub_type.lower()
                    items = [r for r in items if r.get("sub_type", "").lower() == st_lower]
                if priority:
                    import operator as _op
                    expr = priority.strip()
                    for sym, func in [(">=", _op.ge), ("<=", _op.le), (">", _op.gt), ("<", _op.lt), ("=", _op.eq)]:
                        if expr.startswith(sym):
                            try:
                                threshold = int(expr[len(sym):].strip())
                            except ValueError:
                                threshold = 0
                            items = [r for r in items if r.get("priority") is not None and func(r["priority"], threshold)]
                            break
                    else:
                        try:
                            threshold = int(expr)
                            items = [r for r in items if r.get("priority") == threshold]
                        except ValueError:
                            pass
                if enabled is not None:
                    en_val = enabled.lower() == "true"
                    items = [r for r in items if any(
                        a.get("enabled") is en_val for a in r.get("actions", [])
                    )]
                click.echo(format_output(items, config.output_format, config.limit, config.search, short=config.short))
            else:
                click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, solution="siem", subcommand="detection-rules-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@detection_rules.command("get")
@click.option("-j", "--id", "rule_id", default=None, help="Detection rule ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def detection_rules_get(ctx, rule_id, auto_select):
    """Get a basic detection rule by ID.

    \b
    Examples:
      r7-cli siem detection-rules get --id <RULE_ID>
      r7-cli siem detection-rules get --auto
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)

    if not rule_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        rule_id = _interactive_select_detection_rule(client, config, base)

    url = f"{base}/management/tags/{rule_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="detection-rules-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo(
            "Provide --data or --data-file with a JSON body containing the rule definition.\n\n"
            "Example:\n"
            '  r7-cli siem detection-rules create --data \'{"type": "AlertNotify", "name": "My Rule", '
            '"sub_type": "InactivityAlert", "patterns": [""], "sources": [{"id": "<LOG_ID>"}]}\'\n',
            err=True,
        )
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="siem", subcommand="detection-rules-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@detection_rules.command("delete")
@click.option("-j", "--id", "rule_id", default=None, help="Detection rule ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def detection_rules_delete(ctx, rule_id, auto_select):
    """Delete a basic detection rule.

    \b
    Examples:
      r7-cli siem detection-rules delete --id <RULE_ID>
      r7-cli siem detection-rules delete --auto
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)

    if not rule_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        rule_id = _interactive_select_detection_rule(client, config, base)

    url = f"{base}/management/tags/{rule_id}"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.request("DELETE", url, solution="siem", subcommand="detection-rules-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem log-keys  (top keys for a log)
# ---------------------------------------------------------------------------

@logs.command("keys")
@click.option("-j", "--id", "log_id", required=True, help="Log ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem log-mgmt  (individual log CRUD from management API)
# ---------------------------------------------------------------------------

@logs.group("mgmt", cls=GlobalFlagHintGroup)
@click.pass_context
def log_mgmt(ctx):
    """Log management commands (list, get, create, delete)."""
    pass


@log_mgmt.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--name", "log_name", default=None, help="Filter by log name (substring match).")
@click.option("--source-type", default=None, help="Filter by source_type (e.g. token, internal).")
@click.option("--logset", "logset_name", default=None, help="Filter by logset name (substring match).")
@click.pass_context
def log_mgmt_list(ctx, auto_poll, interval, log_name, source_type, logset_name):
    """List all logs.

    \b
    Examples:
      r7-cli siem logs mgmt list
      r7-cli siem logs mgmt list --name 'Office 365'
      r7-cli siem logs mgmt list --source-type internal
      r7-cli siem logs mgmt list --logset 'Raw Log'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/logs"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    has_filters = any([log_name, source_type, logset_name])

    def _apply_log_filters(items):
        filtered = items
        if log_name:
            n_lower = log_name.lower()
            filtered = [lg for lg in filtered if n_lower in lg.get("name", "").lower()]
        if source_type:
            st_lower = source_type.lower()
            filtered = [lg for lg in filtered if lg.get("source_type", "").lower() == st_lower]
        if logset_name:
            ls_lower = logset_name.lower()
            filtered = [
                lg for lg in filtered
                if any(ls_lower in ls.get("name", "").lower() for ls in lg.get("logsets_info", []))
            ]
        return filtered

    try:
        result = client.get(url, solution="siem", subcommand="log-mgmt-list")

        if not auto_poll:
            if has_filters:
                items = _extract_items(result)
                items = _apply_log_filters(items)
                click.echo(format_output(items, config.output_format, config.limit, config.search, short=config.short))
            else:
                click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, solution="siem", subcommand="log-mgmt-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@log_mgmt.command("get")
@click.option("-j", "--id", "log_id", required=True, help="Log ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@log_mgmt.command("delete")
@click.option("-j", "--id", "log_id", required=True, help="Log ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem pre-computed  (pre-computed queries / metrics)
# ---------------------------------------------------------------------------

@queries.group("pre-computed", cls=GlobalFlagHintGroup)
@click.pass_context
def pre_computed(ctx):
    """Pre-computed query commands."""
    pass


@pre_computed.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def pre_computed_list(ctx, auto_poll, interval):
    """List pre-computed queries."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/metrics"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="pre-computed-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, solution="siem", subcommand="pre-computed-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@pre_computed.command("get")
@click.option("-j", "--id", "metric_id", required=True, help="Pre-computed query ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@pre_computed.command("results")
@click.option("-j", "--id", "metric_id", required=True, help="Pre-computed query ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo("Provide --data or --data-file with pre-computed query definition.", err=True)
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="siem", subcommand="pre-computed-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@pre_computed.command("delete")
@click.option("-j", "--id", "metric_id", required=True, help="Pre-computed query ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def exports_list(ctx, auto_poll, interval):
    """List export jobs."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/exports"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="exports-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, solution="siem", subcommand="exports-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@exports.command("get")
@click.option("-j", "--id", "export_id", required=True, help="Export job ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@exports.command("delete")
@click.option("-j", "--id", "export_id", required=True, help="Export job ID.")
@click.pass_context
def exports_delete(ctx, export_id):
    """Delete an export job.

    \b
    Example:
      r7-cli siem exports delete --id <EXPORT_ID>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IDR_LOGS_BASE.format(region=config.region) + f"/exports/{export_id}"
    try:
        result = client.request("DELETE", url, solution="siem", subcommand="exports-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# detections notifications  (alert notification settings / actions)
# ---------------------------------------------------------------------------

@detections.group(cls=GlobalFlagHintGroup)
@click.pass_context
def notifications(ctx):
    """Detection rule notification commands."""
    pass


@notifications.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def notifications_list(ctx, auto_poll, interval):
    """List alert notification settings."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/actions"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="notifications-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, solution="siem", subcommand="notifications-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@notifications.command("get")
@click.option("-j", "--id", "action_id", required=True, help="Notification action ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem targets  (notification targets)
# ---------------------------------------------------------------------------

@detections.group("notif-targets", cls=GlobalFlagHintGroup)
@click.pass_context
def notif_targets(ctx):
    """Notification target commands."""
    pass


@notif_targets.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def notif_targets_list(ctx, auto_poll, interval):
    """List notification targets."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = IDR_LOGS_BASE.format(region=config.region)
    url = f"{base}/management/targets"

    if config.verbose:
        click.echo(f"Docs: {_LOG_SEARCH_DOC}", err=True)

    try:
        result = client.get(url, solution="siem", subcommand="notif-targets-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, solution="siem", subcommand="notif-targets-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@notif_targets.command("get")
@click.option("-j", "--id", "target_id", required=True, help="Notification target ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# siem usage  (per-log usage from usage API)
# ---------------------------------------------------------------------------

@logs.command("usage")
@click.option("-j", "--id", "log_key", required=True, help="Log key/ID.")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

# ---------------------------------------------------------------------------
# siem agents
# ---------------------------------------------------------------------------

@siem.group("agents")
@click.pass_context
def agents(ctx):
    """InsightIDR agent commands."""
    pass


@agents.command("list")
@click.option("-l", "--limit", "agent_limit", type=int, default=10, help="Agents per page (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new agents.")
@click.option("-i", "--interval", type=int, default=30, help="Polling interval in seconds.")
@click.option("--ngav-status", default=None, help="Filter by NGAV health: GOOD, POOR, N/A, Not Monitored.")
@click.option("--velociraptor-status", default=None, type=click.Choice(["RUNNING", "NOT_RUNNING"]), help="Filter by velociraptor state.")
@click.pass_context
def agents_list(ctx, agent_limit, all_pages, auto_poll, interval, ngav_status, velociraptor_status):
    """List agents with host info, NGAV status, and velociraptor state.

    \b
    Examples:
      # List first 10 agents
      r7-cli siem agents list

    \b
      # List 50 agents per page, all pages
      r7-cli siem agents list -l 50 --all-pages

    \b
      # Filter by NGAV health
      r7-cli siem agents list --ngav-status GOOD

    \b
      # Filter by velociraptor state
      r7-cli siem agents list --velociraptor-status RUNNING

    \b
      # Poll for new agents every 30s
      r7-cli siem agents list -a -i 30
    """
    config = _get_config(ctx)
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
                solution="siem",
                subcommand="agents-list",
            )

            # Check for GQL errors
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
            # Output initial batch
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
                        solution="siem",
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
