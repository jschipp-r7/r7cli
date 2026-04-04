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
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import DRP_BASE, APIError, R7Error, UserInputError
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_config(ctx: click.Context) -> Config:
    return ctx.obj["config"]


def _require_token(config: Config) -> None:
    """Raise UserInputError if the DRP token is not configured."""
    if not config.drp_token:
        raise UserInputError(
            "DRP token is required. Set R7_DRP_TOKEN or pass --drp-token."
        )


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
    click.echo(format_output(result, config.output_format, config.limit))


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
    click.echo(format_output(result, config.output_format, config.limit))


# ---------------------------------------------------------------------------
# drp assets
# ---------------------------------------------------------------------------

@drp.group(cls=GlobalFlagHintGroup)
@click.pass_context
def assets(ctx):
    """DRP monitored asset commands."""
    pass


@assets.command("list")
@click.pass_context
def assets_list(ctx):
    """List monitored assets."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v2/data/assets"
    result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="assets-list")
    click.echo(format_output(result, config.output_format, config.limit))


# ---------------------------------------------------------------------------
# drp ioc-sources
# ---------------------------------------------------------------------------

@drp.group("ioc-sources", cls=GlobalFlagHintGroup)
@click.pass_context
def ioc_sources(ctx):
    """DRP threat intelligence source commands."""
    pass


@ioc_sources.command("list")
@click.option("--enabled-only", is_flag=True, help="Show only enabled sources.")
@click.pass_context
def ioc_sources_list(ctx, enabled_only):
    """List threat intelligence sources."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    url = f"{DRP_BASE}/public/v1/iocs/sources"
    result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="ioc-sources-list")

    if not enabled_only:
        click.echo(format_output(result, config.output_format, config.limit))
        return

    # Apply client-side filter for --enabled-only
    items = result if isinstance(result, list) else result.get("content", result.get("data", []))
    if not isinstance(items, list):
        items = [items]
    items = [s for s in items if s.get("IsEnabled") is True]
    click.echo(format_output(items, config.output_format, config.limit))


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
@click.pass_context
def alerts_list(ctx, severity, alert_type, remediation_status, days):
    """List DRP alerts with full details."""
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
    result = client.get(url, params=params or None, auth=_drp_auth(config),
                        solution="drp", subcommand="alerts-list")

    ids = _extract_ids(result)
    if not ids:
        click.echo(format_output(result, config.output_format, config.limit))
        return

    detail_url = f"{DRP_BASE}/public/v1/data/alerts/get-complete-alert/{{id}}"
    details = _fetch_details(client, config, ids, detail_url, config.limit)

    # Filter by --days on FoundDate
    if days is not None:
        details = _filter_by_date(details, "FoundDate", days)

    click.echo(format_output(details, config.output_format, config.limit))


# ---------------------------------------------------------------------------
# drp phishing-threats
# ---------------------------------------------------------------------------

@drp.group("phishing-threats", cls=GlobalFlagHintGroup)
@click.pass_context
def phishing_threats(ctx):
    """DRP phishing domain threat commands."""
    pass


@phishing_threats.command("list")
@click.option("--active", "active_only", is_flag=True, help="Show only Alert/Potential Threat status.")
@click.option("-d", "--days", type=int, default=None, help="Filter by LastSourceDate within N days.")
@click.pass_context
def phishing_threats_list(ctx, active_only, days):
    """List phishing domain threats."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)

    url = f"{DRP_BASE}/public/v1/data/phishing-domains-threats/threats-list"
    result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="phishing-threats-list")

    ids = _extract_ids(result)
    if not ids:
        click.echo(format_output(result, config.output_format, config.limit))
        return

    detail_url = f"{DRP_BASE}/public/v1/data/phishing-domains-threats/get-complete-threat/{{id}}"
    details = _fetch_details(client, config, ids, detail_url, config.limit)

    if active_only:
        details = [d for d in details if d.get("Status") in ("Alert", "Potential Threat")]

    if days is not None:
        details = _filter_by_date(details, "LastSourceDate", days)

    click.echo(format_output(details, config.output_format, config.limit))


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
@click.pass_context
def takedowns_list(ctx, days):
    """List resolved domain takedowns."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)

    url = f"{DRP_BASE}/public/v2/data/alerts/alerts-list"
    params = {"remediationStatus": "CompletedSuccessfully"}
    result = client.get(url, params=params, auth=_drp_auth(config),
                        solution="drp", subcommand="takedowns-list")

    ids = _extract_ids(result)
    if not ids:
        click.echo(format_output(result, config.output_format, config.limit))
        return

    detail_url = f"{DRP_BASE}/public/v1/data/alerts/get-complete-alert/{{id}}"
    details = _fetch_details(client, config, ids, detail_url, config.limit)

    # Filter to TakedownStatus == Resolved
    details = [d for d in details if d.get("TakedownStatus") == "Resolved"]

    if days is not None:
        details = _filter_by_date(details, "FoundDate", days)

    click.echo(format_output(details, config.output_format, config.limit))


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
        click.echo(format_output(result, config.output_format, config.limit))
        score = result.get("Score", result.get("score"))
    else:
        click.echo(format_output(result, config.output_format, config.limit))
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
@click.pass_context
def reported_domains_list(ctx):
    """List domains reported to external registries."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)
    auth = _drp_auth(config)

    url = f"{DRP_BASE}/public/v2/data/alerts/alerts-list"
    params = {"remediationStatus": "CompletedSuccessfully"}
    result = client.get(url, params=params, auth=auth, solution="drp",
                        subcommand="reported-domains-list")

    ids = _extract_ids(result)
    if not ids:
        click.echo("No reported domains found.", err=True)
        return

    results: list[dict] = []
    for item_id in ids:
        if config.limit is not None and len(results) >= config.limit:
            break
        report_url = f"{DRP_BASE}/public/v1/data/alerts/report-status/{item_id}"
        report = client.get(report_url, auth=auth, solution="drp", subcommand="report-status")

        # Skip empty arrays
        if isinstance(report, list) and not report:
            continue

        # Filter: at least one service with Status=Sent
        services = report if isinstance(report, list) else report.get("Services", report.get("services", []))
        if isinstance(services, list) and any(s.get("Status") == "Sent" for s in services):
            results.append(report)

    if not results:
        click.echo(format_output([], config.output_format, config.limit))
        return

    click.echo(format_output(results, config.output_format, config.limit))


# ---------------------------------------------------------------------------
# drp ssl-cert-threats
# ---------------------------------------------------------------------------

@drp.group("ssl-cert-threats", cls=GlobalFlagHintGroup)
@click.pass_context
def ssl_cert_threats(ctx):
    """DRP SSL certificate threat commands."""
    pass


@ssl_cert_threats.command("list")
@click.pass_context
def ssl_cert_threats_list(ctx):
    """List SSL certificate threats."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)

    url = f"{DRP_BASE}/public/v1/data/ssl-certificate-threats/threats-list"
    result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="ssl-cert-threats-list")

    ids = _extract_ids(result)
    if not ids:
        click.echo(format_output(result, config.output_format, config.limit))
        return

    detail_url = f"{DRP_BASE}/public/v1/data/ssl-certificate-threats/get-complete-threat/{{id}}"
    details = _fetch_details(client, config, ids, detail_url, config.limit)
    click.echo(format_output(details, config.output_format, config.limit))


# ---------------------------------------------------------------------------
# drp ssl-issue-threats
# ---------------------------------------------------------------------------

@drp.group("ssl-issue-threats", cls=GlobalFlagHintGroup)
@click.pass_context
def ssl_issue_threats(ctx):
    """DRP SSL issue threat commands."""
    pass


@ssl_issue_threats.command("list")
@click.pass_context
def ssl_issue_threats_list(ctx):
    """List SSL issue threats."""
    config = _get_config(ctx)
    _require_token(config)
    client = _drp_client(config)

    url = f"{DRP_BASE}/public/v1/data/ssl-issues-threats/threats-list"
    result = client.get(url, auth=_drp_auth(config), solution="drp", subcommand="ssl-issue-threats-list")

    ids = _extract_ids(result)
    if not ids:
        click.echo(format_output(result, config.output_format, config.limit))
        return

    detail_url = f"{DRP_BASE}/public/v1/data/ssl-issues-threats/get-complete-threat/{{id}}"
    details = _fetch_details(client, config, ids, detail_url, config.limit)
    click.echo(format_output(details, config.output_format, config.limit))


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
