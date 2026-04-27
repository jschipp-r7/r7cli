"""Digital Risk Protection (DRP) solution commands.

DRP uses HTTP Basic auth with the DRP token as username and empty password.
Base URL is hardcoded: https://api.ti.insight.rapid7.com (no region).
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import click
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import DRP_BASE, APIError, R7Error
from r7cli.output import format_output
from r7cli.helpers import (
    extract_items,
    extract_item_id,
    get_config,
    emit,
    handle_errors,
    parse_cmp_expr,
    poll_loop,
    auto_poll_options,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Shared helpers imported from r7cli.helpers:
#   get_config, extract_items, extract_item_id, parse_cmp_expr, emit, handle_errors, poll_loop

# Keep underscore aliases for backward compatibility within this module
_get_config = get_config
_parse_cmp_expr = parse_cmp_expr
_extract_poll_items = extract_items
_extract_item_id = extract_item_id


def _require_token(config: Config) -> None:
    """Exit with a friendly message if the DRP token is not configured."""
    if not config.drp_token:
        click.echo(
            "DRP token is required.\n\n"
            "Set the R7_DRP_TOKEN environment variable or pass --drp-token in account_id:api_key format.\n\n"
            "Example:\n"
            "  export R7_DRP_TOKEN='<ACCOUNT_ID>:<API_KEY>'\n"
            "  r7-cli drp api-version",
            err=True,
        )
        sys.exit(1)


def _drp_auth(config: Config) -> tuple[str, str]:
    """Return the Basic auth tuple for DRP requests.

    The DRP token is in the format ``account_id:api_key``.
    curl uses ``-u 'account_id:api_key'`` which maps to
    HTTP Basic auth with account_id as username and api_key as password.
    """
    token = config.drp_token
    if ":" in token:
        parts = token.split(":", 1)
        return (parts[0], parts[1])
    # Fallback: treat the whole token as username with empty password
    return (token, "")


def _drp_client(config: Config) -> R7Client:
    """Create an R7Client for DRP requests."""
    return R7Client(config)


def _fetch_details(
    client: R7Client,
    config: Config,
    ids: list[str],
    detail_url_template: str,
    limit: int | None,
) -> list[dict]:
    """Iterate *ids*, fetch detail for each, stop early when *limit* reached."""
    results: list[dict] = []
    auth = _drp_auth(config)
    for item_id in ids:
        if limit is not None and len(results) >= limit:
            break
        url = detail_url_template.format(id=item_id)
        detail = client.get(url, auth=auth, solution="drp", subcommand="detail")
        results.append(detail)
    return results


# ---------------------------------------------------------------------------
# Click groups
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def drp(ctx):
    """Digital Risk Protection commands."""
    pass


from r7cli.cis import make_cis_command as _make_cis_drp  # noqa: E402
drp.add_command(_make_cis_drp("drp"))


# ---------------------------------------------------------------------------
# drp validate
# ---------------------------------------------------------------------------

@drp.command()
@click.pass_context
def validate(ctx):
    """Validate DRP credentials via HEAD test-credentials."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v1/test-credentials"
    try:
        client.head(url, auth=_drp_auth(config), solution="drp", subcommand="validate")
        click.echo("Credentials valid")
    except APIError as exc:
        if exc.status_code == 401:
            click.echo("Credentials invalid", err=True)
            sys.exit(1)
        raise


# ---------------------------------------------------------------------------
# drp api-version
# ---------------------------------------------------------------------------

@drp.command("api-version")
@click.pass_context
def api_version(ctx):
    """Print the DRP API version."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v1/api/version"
    result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="api-version")
    click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))


# ---------------------------------------------------------------------------
# drp modules
# ---------------------------------------------------------------------------

@drp.command()
@click.pass_context
def modules(ctx):
    """Print the DRP account system modules map."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v1/account/system-modules"
    result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="modules")
    click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))


# ---------------------------------------------------------------------------
# drp assets
# ---------------------------------------------------------------------------

@drp.group(cls=GlobalFlagHintGroup)
@click.pass_context
def assets(ctx):
    """DRP monitored asset commands."""
    pass


@assets.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def assets_list(ctx, auto_poll, interval):
    """List monitored assets."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v2/data/assets"

    try:
        result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="assets-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_poll_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="assets-list")
                new_items = _extract_poll_items(new_result)
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
# drp ioc-sources
# ---------------------------------------------------------------------------

@assets.command("count")
@click.pass_context
def drp_assets_count(ctx):
    """Get the total count of DRP monitored assets.

    \b
    Examples:
      r7-cli drp assets count
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = DRP_BASE + "/public/v2/data/assets"
    auth = _drp_auth(config)

    try:
        result = client.get(url, auth=auth, solution="drp", subcommand="assets-count")
        total = len(result) if isinstance(result, list) else 0
        click.echo(format_output({"totalDRPAssets": total}, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------

@drp.group("ioc-sources", cls=GlobalFlagHintGroup)
@click.pass_context
def ioc_sources(ctx):
    """DRP threat intelligence source commands."""
    pass


@ioc_sources.command("list")
@click.option("--enabled-only", is_flag=True, help="Show only enabled sources.")
@click.option("--name", "name_filter", default=None, help="Filter by source name (substring match).")
@click.option("--confidence", default=None, help="Filter by confidence level (e.g. '>=2', '<3', '=1').")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def ioc_sources_list(ctx, enabled_only, name_filter, confidence, auto_poll, interval):
    """List threat intelligence sources.

    \b
    Examples:
      # List all sources
      r7-cli drp ioc-sources list

    \b
      # Only enabled sources
      r7-cli drp ioc-sources list --enabled-only

    \b
      # Filter by confidence level
      r7-cli drp ioc-sources list --confidence '>=2'

    \b
      # Search by name
      r7-cli drp ioc-sources list --name 'Rapid7'

    \b
      # Combine filters
      r7-cli drp ioc-sources list --enabled-only --confidence '>=2' --name 'Abuse'
    """
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v1/iocs/sources"

    try:
        result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="ioc-sources-list")

        has_filters = any([enabled_only, name_filter, confidence is not None])

        if not auto_poll:
            if not has_filters:
                click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
                return
            # Flatten all source lists from the response
            all_sources = []
            if isinstance(result, dict):
                for key, val in result.items():
                    if isinstance(val, list):
                        all_sources.extend(val)
            elif isinstance(result, list):
                all_sources = result
            # Apply filters
            if enabled_only:
                all_sources = [s for s in all_sources if s.get("IsEnabled") is True]
            if name_filter:
                nf_lower = name_filter.lower()
                all_sources = [s for s in all_sources if nf_lower in s.get("Name", "").lower()]
            if confidence is not None:
                cmp_func, val = _parse_cmp_expr(confidence)
                try:
                    threshold = int(val)
                except ValueError:
                    click.echo(f"Invalid --confidence value: '{confidence}'. Use e.g. '>=2', '<3', '=1'", err=True)
                    sys.exit(1)
                all_sources = [s for s in all_sources if s.get("ConfidenceLevel") is not None and cmp_func(s["ConfidenceLevel"], threshold)]
            click.echo(format_output(all_sources, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _extract_poll_items(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="ioc-sources-list")
                new_items = _extract_poll_items(new_result)
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
# drp alerts
# ---------------------------------------------------------------------------

@drp.group(cls=GlobalFlagHintGroup)
@click.pass_context
def alerts(ctx):
    """DRP alert commands."""
    pass


@alerts.command("list")
@click.option("--severity", default=None, help="Filter by severity.")
@click.option("--alert-type", default=None, help="Filter by alert type.")
@click.option("--remediation-status", default=None, help="Filter by remediation status.")
@click.option("-d", "--days", type=int, default=None, help="Filter by FoundDate within N days.")
@click.option("-r", "--resolve", is_flag=True, help="Resolve full details for each alert (slow — one request per alert).")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def alerts_list(ctx, severity, alert_type, remediation_status, days, resolve, auto_poll, interval):
    """List DRP alerts.

    By default returns the alert ID list from the alerts-list endpoint.
    Use --resolve / -r to fetch full details for each alert (slow — makes
    one API request per alert ID).

    \b
    Examples:
      # List alert IDs (fast)
      r7-cli drp alerts list

    \b
      # List with full details (slow)
      r7-cli drp alerts list --resolve

    \b
      # Filter by severity
      r7-cli drp alerts list --severity High

    \b
      # Filter by type and resolve
      r7-cli drp alerts list --alert-type Phishing --resolve

    \b
      # Alerts from the last 7 days
      r7-cli drp alerts list --resolve --days 7

    \b
      # Poll for new alerts
      r7-cli drp alerts list -a -i 30
    """
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)

    # Build query params
    params: dict[str, str] = {}
    if severity:
        params["severity"] = severity
    if alert_type:
        params["alertType"] = alert_type
    if remediation_status:
        params["remediationStatus"] = remediation_status

    url = f"{DRP_BASE}/public/v2/data/alerts/alerts-list"
    detail_url = f"{DRP_BASE}/public/v1/data/alerts/get-complete-alert/{{id}}"

    try:
        result = client.get(url, params=params or None, auth=_drp_auth(config),
                            solution="drp", subcommand="alerts-list")

        if not resolve and not auto_poll:
            # Fast mode — just return the raw alert list
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
            return

        # Resolve mode or polling — need to fetch details
        ids = _extract_ids(result)
        if not ids:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
            return

        if resolve:
            details = _fetch_details(client, config, ids, detail_url, config.limit)
            if days is not None:
                details = _filter_by_date(details, "FoundDate", days)

        if not auto_poll:
            click.echo(format_output(details, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            if resolve:
                for item in details:
                    item_id = _extract_item_id(item)
                    if item_id:
                        seen_ids.add(item_id)
            else:
                # Seed seen IDs from the raw list
                for aid in ids:
                    seen_ids.add(aid)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, params=params or None, auth=_drp_auth(config),
                                        solution="drp", subcommand="alerts-list")
                new_ids_list = _extract_ids(new_result)
                if not new_ids_list:
                    continue
                new_alert_ids = [aid for aid in new_ids_list if aid not in seen_ids]
                if not new_alert_ids:
                    continue
                for aid in new_alert_ids:
                    seen_ids.add(aid)
                if resolve:
                    new_details = _fetch_details(client, config, new_alert_ids, detail_url, config.limit)
                    if days is not None:
                        new_details = _filter_by_date(new_details, "FoundDate", days)
                    for item in new_details:
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
                else:
                    for aid in new_alert_ids:
                        click.echo(aid)
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@alerts.command("get")
@click.option("-j", "--id", "alert_id", required=True, help="Alert ID.")
@click.pass_context
def alerts_get(ctx, alert_id):
    """Get full details for a single alert.

    \b
    Example:
      r7-cli drp alerts get --id <ALERT_ID>
    """
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v1/data/alerts/get-complete-alert/{alert_id}"
    try:
        result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="alerts-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# drp phishing-threats
# ---------------------------------------------------------------------------

@drp.group("phishing-threats", cls=GlobalFlagHintGroup)
@click.pass_context
def phishing_threats(ctx):
    """DRP phishing domain threat commands."""
    pass


@phishing_threats.command("list")
@click.option("--active", "active_only", is_flag=True, help="Show only Alert/Potential Threat status (requires --resolve).")
@click.option("-d", "--days", type=int, default=None, help="Filter by LastSourceDate within N days (requires --resolve).")
@click.option("-r", "--resolve", is_flag=True, help="Resolve full details for each threat (slow — one request per threat ID).")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def phishing_threats_list(ctx, active_only, days, resolve, auto_poll, interval):
    """List phishing domain threats.

    By default returns the threat ID list from the threats-list endpoint.
    Use --resolve / -r to fetch full details for each threat (slow — makes
    one API request per threat ID).

    \b
    Examples:
      # List threat IDs (fast)
      r7-cli drp phishing-threats list

    \b
      # List with full details (slow)
      r7-cli drp phishing-threats list --resolve

    \b
      # Only active threats with details
      r7-cli drp phishing-threats list --resolve --active

    \b
      # Threats from the last 7 days
      r7-cli drp phishing-threats list --resolve --days 7

    \b
      # Poll for new threats
      r7-cli drp phishing-threats list -a -i 30
    """
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)

    url = f"{DRP_BASE}/public/v1/data/phishing-domains-threats/threats-list"
    detail_url = f"{DRP_BASE}/public/v1/data/phishing-domains-threats/get-complete-threat/{{id}}"

    try:
        result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="phishing-threats-list")

        if not resolve and not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
            return

        ids = _extract_ids(result)
        if not ids:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
            return

        if resolve:
            details = _fetch_details(client, config, ids, detail_url, config.limit)
            if active_only:
                details = [d for d in details if d.get("Status") in ("Alert", "Potential Threat")]
            if days is not None:
                details = _filter_by_date(details, "LastSourceDate", days)

        if not auto_poll:
            click.echo(format_output(details, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            if resolve:
                for item in details:
                    item_id = _extract_item_id(item)
                    if item_id:
                        seen_ids.add(item_id)
            else:
                for aid in ids:
                    seen_ids.add(aid)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="phishing-threats-list")
                new_ids_list = _extract_ids(new_result)
                if not new_ids_list:
                    continue
                new_threat_ids = [aid for aid in new_ids_list if aid not in seen_ids]
                if not new_threat_ids:
                    continue
                for aid in new_threat_ids:
                    seen_ids.add(aid)
                if resolve:
                    new_details = _fetch_details(client, config, new_threat_ids, detail_url, config.limit)
                    if active_only:
                        new_details = [d for d in new_details if d.get("Status") in ("Alert", "Potential Threat")]
                    if days is not None:
                        new_details = _filter_by_date(new_details, "LastSourceDate", days)
                    for item in new_details:
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
                else:
                    for aid in new_threat_ids:
                        click.echo(aid)
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@phishing_threats.command("get")
@click.option("-j", "--id", "threat_id", required=True, help="Phishing threat ID.")
@click.pass_context
def phishing_threats_get(ctx, threat_id):
    """Get full details for a single phishing threat.

    \b
    Example:
      r7-cli drp phishing-threats get --id <THREAT_ID>
    """
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v1/data/phishing-domains-threats/get-complete-threat/{threat_id}"
    try:
        result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="phishing-threats-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# drp takedowns
# ---------------------------------------------------------------------------

@drp.group(cls=GlobalFlagHintGroup)
@click.pass_context
def takedowns(ctx):
    """DRP domain takedown commands."""
    pass


@takedowns.command("list")
@click.option("-d", "--days", type=int, default=None, help="Filter by FoundDate within N days.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--type", "threat_type", default=None, help="Filter by threat type (e.g. Phishing, vip).")
@click.option("--severity", default=None, help="Filter by severity (e.g. Medium, High).")
@click.option("--status", default=None, help="Filter by TakedownStatus (e.g. Resolved, InProgress).")
@click.option("--title", default=None, help="Filter by title (substring match).")
@click.pass_context
def takedowns_list(ctx, days, auto_poll, interval, threat_type, severity, status, title):
    """List resolved domain takedowns.

    \b
    Examples:
      # List all takedowns
      r7-cli drp takedowns list

    \b
      # Takedowns from the last 30 days
      r7-cli drp takedowns list --days 30

    \b
      # Only phishing takedowns
      r7-cli drp takedowns list --type Phishing

    \b
      # Filter by severity
      r7-cli drp takedowns list --severity Medium

    \b
      # Search by title
      r7-cli drp takedowns list --title 'Suspicious'

    \b
      # Combine filters
      r7-cli drp takedowns list --type Phishing --severity Medium --days 90
    """
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)

    url = f"{DRP_BASE}/public/v2/data/alerts/alerts-list"
    params = {"remediationStatus": "CompletedSuccessfully"}
    detail_url = f"{DRP_BASE}/public/v1/data/alerts/get-complete-alert/{{id}}"

    def _fetch_and_filter():
        result = client.get(url, params=params, auth=_drp_auth(config),
                            solution="drp", subcommand="takedowns-list")
        ids = _extract_ids(result)
        if not ids:
            return result, []
        details = _fetch_details(client, config, ids, detail_url, config.limit)
        details = [d for d in details if d.get("TakedownStatus") == "Resolved"]
        if days is not None:
            details = _filter_by_date(details, "FoundDate", days)
        # Apply additional client-side filters
        if threat_type:
            tt_lower = threat_type.lower()
            details = [d for d in details if isinstance(d.get("Details"), dict) and d["Details"].get("Type", "").lower() == tt_lower]
        if severity:
            sev_lower = severity.lower()
            details = [d for d in details if isinstance(d.get("Details"), dict) and d["Details"].get("Severity", "").lower() == sev_lower]
        if status:
            st_lower = status.lower()
            details = [d for d in details if d.get("TakedownStatus", "").lower() == st_lower]
        if title:
            t_lower = title.lower()
            details = [d for d in details if isinstance(d.get("Details"), dict) and t_lower in d["Details"].get("Title", "").lower()]
        return result, details

    try:
        result, details = _fetch_and_filter()
        ids = _extract_ids(result)

        if not ids:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
            return

        if not auto_poll:
            click.echo(format_output(details, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            for item in details:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                _, new_details = _fetch_and_filter()
                for item in new_details:
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
# drp risk-score
# ---------------------------------------------------------------------------

@drp.command("risk-score")
@click.option("--fail-above", type=float, default=None, help="Exit non-zero if score exceeds threshold.")
@click.pass_context
def risk_score(ctx, fail_above):
    """Print the DRP system risk score."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v1/data/alerts/system-risk-score"
    result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="risk-score")

    # The API returns a plain string like "21.63", not JSON
    if isinstance(result, str):
        click.echo(result)
        try:
            score = float(result.strip('"'))
        except ValueError:
            score = None
    elif isinstance(result, (int, float)):
        click.echo(str(result))
        score = result
    elif isinstance(result, dict):
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        score = result.get("Score", result.get("score"))
    else:
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        score = None

    if fail_above is not None and score is not None and score > fail_above:
        sys.exit(1)


# ---------------------------------------------------------------------------
# drp reported-domains
# ---------------------------------------------------------------------------

@drp.group("reported-domains", cls=GlobalFlagHintGroup)
@click.pass_context
def reported_domains(ctx):
    """DRP reported domain commands."""
    pass


@reported_domains.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def reported_domains_list(ctx, auto_poll, interval):
    """List domains reported to external registries."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    auth = _drp_auth(config)

    url = f"{DRP_BASE}/public/v2/data/alerts/alerts-list"
    params = {"remediationStatus": "CompletedSuccessfully"}

    def _fetch_reported():
        result = client.get(url, params=params, auth=auth, solution="drp",
                            subcommand="reported-domains-list")
        ids = _extract_ids(result)
        if not ids:
            return []
        results_list: list[dict] = []
        for item_id in ids:
            if config.limit is not None and len(results_list) >= config.limit:
                break
            report_url = f"{DRP_BASE}/public/v1/data/alerts/report-status/{item_id}"
            report = client.get(report_url, auth=auth, solution="drp", subcommand="report-status")
            if isinstance(report, list) and not report:
                continue
            services = report if isinstance(report, list) else report.get("Services", report.get("services", []))
            if isinstance(services, list) and any(s.get("Status") == "Sent" for s in services):
                results_list.append(report)
        return results_list

    try:
        results = _fetch_reported()

        if not results:
            if not auto_poll:
                click.echo("No reported domains found.", err=True)
                return
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            import time as _time
            seen_ids: set[str] = set()
            while True:
                _time.sleep(interval)
                new_results = _fetch_reported()
                for item in new_results:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
        elif not auto_poll:
            click.echo(format_output(results, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            for item in results:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_results = _fetch_reported()
                for item in new_results:
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
# drp ssl-cert-threats
# ---------------------------------------------------------------------------

@drp.group("ssl-cert-threats", cls=GlobalFlagHintGroup)
@click.pass_context
def ssl_cert_threats(ctx):
    """DRP SSL certificate threat commands."""
    pass


@ssl_cert_threats.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--domain", default=None, help="Filter by matched domain (substring match).")
@click.option("--common-name", default=None, help="Filter by CommonName (substring match).")
@click.option("--expired", type=click.Choice(["true", "false"], case_sensitive=False), default=None, help="Filter by expired status.")
@click.option("--name-mismatch", type=click.Choice(["true", "false"], case_sensitive=False), default=None, help="Filter by name mismatch status.")
@click.option("--valid", type=click.Choice(["true", "false"], case_sensitive=False), default=None, help="Filter by valid status.")
@click.pass_context
def ssl_cert_threats_list(ctx, auto_poll, interval, domain, common_name, expired, name_mismatch, valid):
    """List SSL certificate threats.

    \b
    Examples:
      # List all SSL cert threats
      r7-cli drp ssl-cert-threats list

    \b
      # Filter by matched domain
      r7-cli drp ssl-cert-threats list --domain 'anonymoose.com'

    \b
      # Only expired certificates
      r7-cli drp ssl-cert-threats list --expired true

    \b
      # Certificates with name mismatch
      r7-cli drp ssl-cert-threats list --name-mismatch true

    \b
      # Only invalid certificates
      r7-cli drp ssl-cert-threats list --valid false

    \b
      # Filter by CommonName
      r7-cli drp ssl-cert-threats list --common-name 'bitsmith'
    """
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)

    url = f"{DRP_BASE}/public/v1/data/ssl-certificate-threats/threats-list"
    detail_url = f"{DRP_BASE}/public/v1/data/ssl-certificate-threats/get-complete-threat/{{id}}"

    def _fetch_all():
        result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="ssl-cert-threats-list")
        ids = _extract_ids(result)
        if not ids:
            return result, []
        details = _fetch_details(client, config, ids, detail_url, config.limit)
        return result, details

    try:
        result, details = _fetch_all()
        ids = _extract_ids(result)

        if not ids:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
            return

        if not auto_poll:
            # Apply client-side filters
            if any([domain, common_name, expired, name_mismatch, valid]):
                filtered = details
                if domain:
                    d_lower = domain.lower()
                    filtered = [t for t in filtered if any(d_lower in a.lower() for a in t.get("MatchedAssets", []))]
                if common_name:
                    cn_lower = common_name.lower()
                    filtered = [t for t in filtered if cn_lower in t.get("CommonName", "").lower()]
                if expired is not None:
                    exp_val = expired.lower() == "true"
                    filtered = [t for t in filtered if isinstance(t.get("CertificateStatus"), dict) and t["CertificateStatus"].get("Certificate expired") is exp_val]
                if name_mismatch is not None:
                    nm_val = name_mismatch.lower() == "true"
                    filtered = [t for t in filtered if isinstance(t.get("CertificateStatus"), dict) and t["CertificateStatus"].get("Certificate name mismatch") is nm_val]
                if valid is not None:
                    v_val = valid.lower() == "true"
                    filtered = [t for t in filtered if isinstance(t.get("CertificateStatus"), dict) and t["CertificateStatus"].get("Valid") is v_val]
                click.echo(format_output(filtered, config.output_format, config.limit, config.search, short=config.short))
            else:
                click.echo(format_output(details, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            for item in details:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                _, new_details = _fetch_all()
                for item in new_details:
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
# drp ssl-issue-threats
# ---------------------------------------------------------------------------

@drp.group("ssl-issue-threats", cls=GlobalFlagHintGroup)
@click.pass_context
def ssl_issue_threats(ctx):
    """DRP SSL issue threat commands."""
    pass


@ssl_issue_threats.command("list")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--domain", default=None, help="Filter by matched domain (substring match).")
@click.option("--ip", default=None, help="Filter by server IP address (substring match).")
@click.option("--issue", default=None, help="Filter by detected issue name or title (substring match).")
@click.pass_context
def ssl_issue_threats_list(ctx, auto_poll, interval, domain, ip, issue):
    """List SSL issue threats.

    \b
    Examples:
      # List all SSL issue threats
      r7-cli drp ssl-issue-threats list

    \b
      # Filter by matched domain
      r7-cli drp ssl-issue-threats list --domain 'anonymoose.com'

    \b
      # Filter by server IP
      r7-cli drp ssl-issue-threats list --ip '157.245'

    \b
      # Filter by issue type
      r7-cli drp ssl-issue-threats list --issue 'TLS 1.0'

    \b
      # Combine filters
      r7-cli drp ssl-issue-threats list --domain 'anonymoose' --issue 'handshake'
    """
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)

    url = f"{DRP_BASE}/public/v1/data/ssl-issues-threats/threats-list"
    detail_url = f"{DRP_BASE}/public/v1/data/ssl-issues-threats/get-complete-threat/{{id}}"

    def _fetch_all():
        result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="ssl-issue-threats-list")
        ids = _extract_ids(result)
        if not ids:
            return result, []
        details = _fetch_details(client, config, ids, detail_url, config.limit)
        return result, details

    try:
        result, details = _fetch_all()
        ids = _extract_ids(result)

        if not ids:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
            return

        if not auto_poll:
            # Apply client-side filters
            if any([domain, ip, issue]):
                filtered = details
                if domain:
                    d_lower = domain.lower()
                    filtered = [t for t in filtered if any(d_lower in a.lower() for a in t.get("MatchedAssets", []))]
                if ip:
                    filtered = [t for t in filtered if ip in t.get("ServerIPAddress", "")]
                if issue:
                    i_lower = issue.lower()
                    filtered = [t for t in filtered if any(
                        i_lower in di.get("name", "").lower() or i_lower in di.get("title", "").lower()
                        for di in t.get("DetectedIssues", [])
                    )]
                click.echo(format_output(filtered, config.output_format, config.limit, config.search, short=config.short))
            else:
                click.echo(format_output(details, config.output_format, config.limit, config.search, short=config.short))
        else:
            import time as _time
            seen_ids: set[str] = set()
            for item in details:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                _, new_details = _fetch_all()
                for item in new_details:
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
# Shared utilities
# ---------------------------------------------------------------------------

def _extract_ids(result: Any) -> list[str]:
    """Extract a list of string IDs from a DRP list response."""
    if isinstance(result, list):
        return [str(item) for item in result]
    if isinstance(result, dict):
        # Try common wrapper keys
        for key in ("content", "data", "ids", "Ids"):
            val = result.get(key)
            if isinstance(val, list):
                return [str(item) if not isinstance(item, dict) else str(item.get("_id", item.get("id", item)))
                        for item in val]
    return []


def _filter_by_date(items: list[dict], date_field: str, days: int) -> list[dict]:
    """Keep only items whose *date_field* is within *days* of now."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    filtered: list[dict] = []
    for item in items:
        raw = item.get(date_field)
        if raw is None:
            continue
        try:
            ts = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if ts >= cutoff:
                filtered.append(item)
        except (ValueError, TypeError):
            # Can't parse — include it to be safe
            filtered.append(item)
    return filtered
