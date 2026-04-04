"""InsightVM solution commands — health, scans, engines, exports, job status."""
from __future__ import annotations

import ipaddress
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import click
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.jobs import JobStore
from r7cli.models import (
    INSIGHT_BASE,
    IVM_BULK_GQL,
    IVM_V4_BASE,
    GQL_GET_EXPORT,
    APIError,
    JobEntry,
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


def _poll_export(
    client: R7Client,
    config: Config,
    job_id: str,
    poll_interval: int = 10,
) -> dict:
    """Poll GetExport until the job reaches a terminal state.

    Returns the final export payload dict.
    """
    gql_url = IVM_BULK_GQL.format(region=config.region)
    while True:
        result = client.post(
            gql_url,
            json={"query": GQL_GET_EXPORT, "variables": {"id": job_id}},
            solution="vm",
            subcommand="job-status",
        )
        export = result.get("data", {}).get("export", {})
        status = export.get("status", "")
        if status in ("SUCCEEDED", "FAILED"):
            return export
        click.echo(f"Job {job_id} status: {status} — polling in {poll_interval}s …", err=True)
        time.sleep(poll_interval)


def _download_parquet_urls(
    client: R7Client,
    urls: list[str],
    output_dir: str,
) -> list[Path]:
    """Download each URL to *output_dir* and return the list of saved paths."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    for url in urls:
        filename = url.rsplit("/", 1)[-1].split("?")[0] or "export.parquet"
        dest = out / filename
        # Use the underlying httpx client for raw download
        resp = client._http.get(url)
        dest.write_bytes(resp.content)
        click.echo(f"Downloaded {dest}", err=True)
        saved.append(dest)
    return saved


def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is in an RFC-1918 private range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return addr.is_private


def _paginate_v4(client: R7Client, config: Config, url: str, subcommand: str) -> list[dict]:
    """Follow ``links`` pagination on IVM v4 endpoints, collecting all records."""
    all_records: list[dict] = []
    next_url: str | None = url
    while next_url:
        result = client.get(next_url, solution="vm", subcommand=subcommand)
        resources = result.get("resources", result.get("data", []))
        if isinstance(resources, list):
            all_records.extend(resources)
        # Follow next link
        next_url = None
        for link in result.get("links", []):
            if link.get("rel") == "next":
                next_url = link.get("href")
                break
    return all_records


def _paginate_v4_post(client, config, url, params, body, subcommand):
    """Cursor-based pagination for IVM v4 POST endpoints (e.g. /integration/vulnerabilities)."""
    all_records: list[dict] = []
    cur_params = dict(params)
    while True:
        result = client.post(url, json=body or None, params=cur_params, solution="vm", subcommand=subcommand)
        resources = result.get("resources", result.get("data", []))
        if isinstance(resources, list):
            all_records.extend(resources)
        # Follow next cursor
        next_cursor = None
        metadata = result.get("metadata", {})
        if isinstance(metadata, dict) and metadata.get("cursor"):
            next_cursor = metadata["cursor"]
        if next_cursor is None:
            for link in result.get("links", []):
                if link.get("rel") == "next":
                    # Extract cursor from next link URL
                    href = link.get("href", "")
                    import urllib.parse as _up
                    parsed = _up.urlparse(href)
                    qs = _up.parse_qs(parsed.query)
                    if "cursor" in qs:
                        next_cursor = qs["cursor"][0]
                    break
        if not next_cursor or not resources:
            break
        cur_params = dict(params, cursor=next_cursor)
    return all_records


def _submit_export(
    client: R7Client,
    config: Config,
    mutation_body: dict,
    export_type: str,
    *,
    wait: bool = False,
    auto: bool = False,
    output_dir: str | None = None,
) -> None:
    """Submit a GQL export mutation, handle conflicts, optionally poll & download."""
    gql_url = IVM_BULK_GQL.format(region=config.region)
    store = JobStore()

    job_id: str | None = None
    try:
        result = client.post(gql_url, json=mutation_body, solution="vm", subcommand=f"export-{export_type}")
        # Extract job id from the response — the mutation name varies
        data = result.get("data", {})
        for val in data.values():
            if isinstance(val, dict) and "id" in val:
                job_id = val["id"]
                break
    except APIError as exc:
        # Handle FAILED_PRECONDITION — extract in-progress exportId
        if "FAILED_PRECONDITION" in exc.body:
            match = re.search(r"exportId[\":\s]+([a-f0-9-]+)", exc.body, re.IGNORECASE)
            if match:
                job_id = match.group(1)
                click.echo(f"Export already in progress: {job_id}", err=True)
                if not wait and not auto:
                    click.echo(job_id)
                    sys.exit(exc.exit_code)
            else:
                raise
        else:
            raise

    if job_id is None:
        click.echo("Failed to extract job ID from response.", err=True)
        sys.exit(2)

    # Persist to job store
    store.add(JobEntry(
        job_id=job_id,
        export_type=export_type,
        created_at=datetime.now(timezone.utc).isoformat(),
    ))

    if auto:
        wait = True

    if not wait:
        click.echo(format_output({"job_id": job_id}, config.output_format, config.limit, config.search))
        return

    # Poll until terminal
    export = _poll_export(client, config, job_id)
    status = export.get("status", "")
    store.mark_terminal(job_id, status)

    if status == "FAILED":
        click.echo(f"Export {job_id} FAILED.", err=True)
        sys.exit(2)

    click.echo(format_output(export, config.output_format, config.limit, config.search))

    # Download if auto or output_dir
    if auto or output_dir:
        result_data = export.get("result", [])
        # result is a list of {prefix, urls} objects — collect all URLs
        all_urls: list[str] = []
        if isinstance(result_data, list):
            for entry in result_data:
                if isinstance(entry, dict):
                    all_urls.extend(entry.get("urls", []))
        elif isinstance(result_data, dict):
            all_urls.extend(result_data.get("urls", []))
        if all_urls:
            dest = output_dir or "."
            _download_parquet_urls(client, all_urls, dest)


# ---------------------------------------------------------------------------
# Click groups
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def vm(ctx):
    """InsightVM commands (health, scans, engines, exports, job status)."""
    pass


# ---------------------------------------------------------------------------
# vm health
# ---------------------------------------------------------------------------

@vm.command()
@click.pass_context
def health(ctx):
    """Check IVM v4 API health status.

    \b
    Example:
      r7-cli vm health
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = INSIGHT_BASE.format(region=config.region) + "/vm/admin/health"
    try:
        result = client.get(url, solution="vm", subcommand="health")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
        status = result.get("status", "UNKNOWN")
        if status != "UP":
            sys.exit(2)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# vm scans
# ---------------------------------------------------------------------------

@vm.group(cls=GlobalFlagHintGroup)
@click.pass_context
def scans(ctx):
    """IVM v4 scan commands."""
    pass


# ---------------------------------------------------------------------------
# vm assets
# ---------------------------------------------------------------------------

@vm.group(cls=GlobalFlagHintGroup)
@click.pass_context
def assets(ctx):
    """IVM v4 asset commands."""
    pass


@assets.command("list")
@click.option("--size", type=int, default=100, help="Page size (default: 100).")
@click.option("--cursor", default=None, help="Pagination cursor.")
@click.option("--asset-filter", "asset_filter", default=None, help="Asset search criteria string.")
@click.option("--vuln-filter", "vuln_filter", default=None, help="Vulnerability search criteria string.")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--hostname", default=None, help="Filter by hostname (substring match).")
@click.option("--ip", default=None, help="Filter by IP address (substring match).")
@click.option("--os-family", default=None, help="Filter by OS family (e.g. Windows, Linux, 'Mac OS X').")
@click.option("--tag", default=None, help="Filter by tag name (substring match).")
@click.option("--risk-score", default=None, help="Filter by risk_score (e.g. '>=10000', '>0').")
@click.option("--critical-vulns", default=None, help="Filter by critical_vulnerabilities count (e.g. '>=1', '>10').")
@click.pass_context
def assets_search(ctx, size, cursor, asset_filter, vuln_filter, all_pages, auto_poll, interval, hostname, ip, os_family, tag, risk_score, critical_vulns):
    """List assets (POST /v4/integration/assets).

    \b
    Examples:
      # List first page of assets
      r7-cli vm assets list

    \b
      # Fetch all assets
      r7-cli vm assets list --all-pages

    \b
      # Filter by hostname
      r7-cli vm assets list --hostname 'webserver'

    \b
      # Only Linux assets
      r7-cli vm assets list --os-family Linux --all-pages

    \b
      # Assets with high risk score
      r7-cli vm assets list --risk-score '>=100000' --all-pages

    \b
      # Assets with critical vulns
      r7-cli vm assets list --critical-vulns '>=1' --all-pages

    \b
      # Filter by tag
      r7-cli vm assets list --tag 'CISA KEV' --all-pages

    \b
      # Filter by IP
      r7-cli vm assets list --ip '10.0.7'

    \b
      # Use API-level filters
      r7-cli vm assets list --asset-filter 'asset.name CONTAINS webserver'

    \b
      # Poll for new assets
      r7-cli vm assets list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/assets"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationAssets", err=True)

    params: dict[str, Any] = {"size": size}
    if cursor:
        params["cursor"] = cursor

    body: dict[str, str] = {}
    if asset_filter:
        body["asset"] = asset_filter
    if vuln_filter:
        body["vulnerability"] = vuln_filter

    has_filters = any([hostname, ip, os_family, tag, risk_score, critical_vulns])

    try:
        if all_pages or has_filters:
            all_items = _paginate_v4_post(client, config, url, params, body, "assets-list")
            if has_filters:
                all_items = _filter_vm_assets(all_items, hostname=hostname, ip=ip, os_family=os_family, tag=tag, risk_score=risk_score, critical_vulns=critical_vulns)
            click.echo(format_output(all_items, config.output_format, config.limit, config.search))
            return

        result = client.post(url, json=body or None, params=params, solution="vm", subcommand="assets-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search))
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
                new_result = client.post(url, json=body or None, params=params, solution="vm", subcommand="assets-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@assets.command("get")
@click.option("-j", "--id", "asset_id", default=None, help="Asset ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def assets_get(ctx, asset_id, auto_select):
    """Get a single asset by ID.

    \b
    Examples:
      # Get by ID
      r7-cli vm assets get --id <ASSET_ID>

    \b
      # Interactive selection
      r7-cli vm assets get --auto
    """
    config = _get_config(ctx)
    client = R7Client(config)

    if not asset_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")

    if auto_select:
        # Fetch first page of assets for interactive selection
        url = IVM_V4_BASE.format(region=config.region) + "/integration/assets"
        result = client.post(url, json=None, params={"size": 30}, solution="vm", subcommand="assets-list")
        items = result.get("data", result.get("resources", []))
        if not isinstance(items, list) or not items:
            click.echo("No assets found.", err=True)
            sys.exit(1)
        click.echo("Available assets:", err=True)
        for idx, item in enumerate(items, 1):
            hname = item.get("host_name", "")
            ip_addr = item.get("ip", "")
            rscore = item.get("risk_score", 0)
            os_t = item.get("os_type", "")
            os_n = item.get("os_name", "")
            aid = item.get("id", "?")
            parts = []
            if hname:
                parts.append(hname)
            if ip_addr:
                parts.append(f"ip={ip_addr}")
            parts.append(f"risk={rscore}")
            if os_n:
                parts.append(f"os={os_n}")
            if os_t:
                parts.append(f"type={os_t}")
            parts.append(f"id={aid}")
            click.echo(f"  {idx}. {' | '.join(parts)}", err=True)
        choice = click.prompt("Select an asset number", type=int, err=True)
        if choice < 1 or choice > len(items):
            click.echo("Invalid selection.", err=True)
            sys.exit(1)
        asset_id = str(items[choice - 1].get("id", ""))

    url = IVM_V4_BASE.format(region=config.region) + f"/integration/assets/{asset_id}"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getIntegrationAsset", err=True)

    try:
        result = client.get(url, solution="vm", subcommand="assets-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("list")
@click.option("-d", "--days", type=int, default=None, help="Filter scans finished within N days.")
@click.option("-s", "--status", "scan_status", default=None, help="Filter by scan status (e.g. Success, Stopped, Paused).")
@click.option("--started", default=None, help="Filter by started date (e.g. '>=2024-12-13').")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def scans_list(ctx, days, scan_status, started, all_pages, auto_poll, interval):
    """List vulnerability scans.

    \b
    Examples:
      # List recent scans
      r7-cli vm scans list

    \b
      # Fetch all scans
      r7-cli vm scans list --all-pages

    \b
      # Scans from the last 7 days
      r7-cli vm scans list --days 7

    \b
      # Only successful scans
      r7-cli vm scans list --status Success

    \b
      # Only stopped scans
      r7-cli vm scans list --status Stopped

    \b
      # Scans started after a date
      r7-cli vm scans list --started '>=2024-12-13'

    \b
      # Poll for new scans every 30s
      r7-cli vm scans list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/scan"

    def _apply_filters(records):
        if days is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            filtered = []
            for rec in records:
                finished = rec.get("finished")
                if finished:
                    try:
                        ts = datetime.fromisoformat(finished.replace("Z", "+00:00"))
                        if ts < cutoff:
                            continue
                    except (ValueError, TypeError):
                        pass
                filtered.append(rec)
            records = filtered
        if scan_status:
            records = [r for r in records if r.get("status", "").lower() == scan_status.lower()]
        if started:
            cmp_func, val = _parse_cmp_op_vm(started)
            try:
                dt_threshold = datetime.fromisoformat(val.replace("Z", "+00:00"))
            except ValueError:
                click.echo(f"Invalid --started value: '{started}'", err=True)
                sys.exit(1)
            def _parse_s(s):
                if not s:
                    return None
                try:
                    return datetime.fromisoformat(s.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    return None
            records = [r for r in records if _parse_s(r.get("started")) and cmp_func(_parse_s(r["started"]), dt_threshold)]
        return records

    has_filters = any([days is not None, scan_status, started])

    try:
        if all_pages:
            all_items = _paginate_v4(client, config, url, "scans-list")
            if has_filters:
                all_items = _apply_filters(all_items)
            click.echo(format_output(all_items, config.output_format, config.limit, config.search))
            return

        result = client.get(url, solution="vm", subcommand="scans-list")

        if not auto_poll:
            if not has_filters:
                click.echo(format_output(result, config.output_format, config.limit, config.search))
                return
            records = result.get("data", []) if isinstance(result, dict) else result
            records = _apply_filters(records)
            if isinstance(result, dict):
                result = dict(result)
                result["data"] = records
            else:
                result = records
            click.echo(format_output(result, config.output_format, config.limit, config.search))
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
                new_result = client.get(url, solution="vm", subcommand="scans-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("get")
@click.option("-j", "--id", "scan_id", default=None, help="Scan ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scans_get(ctx, scan_id, auto_select):
    """Get a single scan by ID.

    \b
    Examples:
      r7-cli vm scans get --id <SCAN_ID>
      r7-cli vm scans get --auto
    """
    config = _get_config(ctx)
    client = R7Client(config)

    if not scan_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        scan_id = _interactive_select_vm_scan(client, config)

    url = IVM_V4_BASE.format(region=config.region) + f"/integration/scan/{scan_id}"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getScan", err=True)

    try:
        result = client.get(url, solution="vm", subcommand="scans-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("start")
@click.option("--data", "data_str", default=None, help="JSON request body string.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def scans_start(ctx, data_str, data_file):
    """Start a new scan (POST /v4/integration/scan).

    \b
    Examples:
      # Start a scan with inline JSON
      r7-cli vm scans start --data '{"site_id": "123", "scan_template_id": "full-audit"}'

    \b
      # Start a scan from a file
      r7-cli vm scans start --data-file scan-config.json
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/scan"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/startScan", err=True)

    import json as _json
    body = _resolve_body(data_str, data_file)

    try:
        result = client.post(url, json=body, solution="vm", subcommand="scans-start")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("stop")
@click.option("-j", "--id", "scan_id", default=None, help="Scan ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scans_stop(ctx, scan_id, auto_select):
    """Stop a running scan.

    \b
    Examples:
      r7-cli vm scans stop --id <SCAN_ID>
      r7-cli vm scans stop --auto
    """
    config = _get_config(ctx)
    client = R7Client(config)

    if not scan_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        scan_id = _interactive_select_vm_scan(client, config)

    url = IVM_V4_BASE.format(region=config.region) + f"/integration/scan/{scan_id}/stop"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/stopScan", err=True)

    try:
        result = client.post(url, solution="vm", subcommand="scans-stop")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# vm engines get
# ---------------------------------------------------------------------------

@vm.group("scan-engines", cls=GlobalFlagHintGroup)
@click.pass_context
def engines(ctx):
    """IVM v4 scan engine commands."""
    pass


@engines.command("list")
@click.option("--unhealthy", is_flag=True, help="Show only engines with status != HEALTHY.")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def engines_list(ctx, unhealthy, all_pages, auto_poll, interval):
    """List registered scan engines.

    \b
    Examples:
      # List all engines
      r7-cli vm scan-engines list

    \b
      # Fetch all pages
      r7-cli vm scan-engines list --all-pages

    \b
      # Only unhealthy engines
      r7-cli vm scan-engines list --unhealthy

    \b
      # Poll for engine status changes
      r7-cli vm scan-engines list -a -i 60
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/scan/engine"

    try:
        if all_pages:
            all_items = _paginate_v4(client, config, url, "engines-list")
            if unhealthy:
                all_items = [r for r in all_items if r.get("status") != "HEALTHY"]
            click.echo(format_output(all_items, config.output_format, config.limit, config.search))
            return

        result = client.get(url, solution="vm", subcommand="engines-list")

        if not auto_poll:
            if not unhealthy:
                click.echo(format_output(result, config.output_format, config.limit, config.search))
                return
            # Apply client-side filter
            records = result.get("data", []) if isinstance(result, dict) else result
            records = [r for r in records if r.get("status") != "HEALTHY"]
            if isinstance(result, dict):
                result["data"] = records
            else:
                result = records
            click.echo(format_output(result, config.output_format, config.limit, config.search))
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
                new_result = client.get(url, solution="vm", subcommand="engines-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engines.command("get")
@click.option("-j", "--id", "engine_id", default=None, help="Scan engine ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def engines_get(ctx, engine_id, auto_select):
    """Get a single scan engine by ID.

    \b
    Examples:
      r7-cli vm scan-engines get --id <ENGINE_ID>
      r7-cli vm scan-engines get --auto
    """
    config = _get_config(ctx)
    client = R7Client(config)

    if not engine_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        # Fetch engines for interactive selection
        list_url = IVM_V4_BASE.format(region=config.region) + "/integration/scan/engine"
        result = client.get(list_url, solution="vm", subcommand="engines-list")
        items = result.get("data", result.get("resources", []))
        if not isinstance(items, list) or not items:
            click.echo("No scan engines found.", err=True)
            sys.exit(1)
        click.echo("Available scan engines:", err=True)
        for idx, item in enumerate(items, 1):
            name = item.get("name", "")
            status = item.get("status", "")
            eid = item.get("id", "?")
            parts = []
            if name:
                parts.append(name)
            if status:
                parts.append(f"status={status}")
            parts.append(f"id={eid}")
            click.echo(f"  {idx}. {' | '.join(parts)}", err=True)
        choice = click.prompt("Select an engine number", type=int, err=True)
        if choice < 1 or choice > len(items):
            click.echo("Invalid selection.", err=True)
            sys.exit(1)
        engine_id = str(items[choice - 1].get("id", ""))

    url = IVM_V4_BASE.format(region=config.region) + f"/integration/scan/engine/{engine_id}"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getScanEngine", err=True)

    try:
        result = client.get(url, solution="vm", subcommand="engines-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engines.command("update-config")
@click.option("-j", "--id", "engine_id", required=True, help="Scan engine ID.")
@click.option("--data", "data_str", default=None, help="JSON body for engine configuration.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def engines_update_config(ctx, engine_id, data_str, data_file):
    """Update scan engine configuration.

    \b
    Examples:
      r7-cli vm scan-engines update-config --id <ENGINE_ID> --data '{"key": "value"}'
      r7-cli vm scan-engines update-config --id <ENGINE_ID> --data-file config.json
    """
    from r7cli.models import UserInputError
    config = _get_config(ctx)
    client = R7Client(config)

    import json as _json
    body = None
    if data_str and data_file:
        click.echo("Provide either --data or --data-file, not both.", err=True)
        sys.exit(1)
    if data_str:
        body = _json.loads(data_str)
    if data_file:
        with open(data_file) as fh:
            body = _json.load(fh)
    if not body:
        click.echo("Provide --data or --data-file with the engine configuration.", err=True)
        sys.exit(1)

    url = IVM_V4_BASE.format(region=config.region) + f"/integration/scan/engine/{engine_id}/configuration"
    try:
        result = client.post(url, json=body, solution="vm", subcommand="engines-update-config")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engines.command("remove-config")
@click.option("-j", "--id", "engine_id", required=True, help="Scan engine ID.")
@click.pass_context
def engines_remove_config(ctx, engine_id):
    """Remove scan engine configuration.

    \b
    Example:
      r7-cli vm scan-engines remove-config --id <ENGINE_ID>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + f"/integration/scan/engine/{engine_id}/configuration"
    try:
        result = client.request("DELETE", url, solution="vm", subcommand="engines-remove-config")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# vm sites
# ---------------------------------------------------------------------------

@vm.group(cls=GlobalFlagHintGroup)
@click.pass_context
def sites(ctx):
    """IVM v4 site commands."""
    pass


@sites.command("list")
@click.option("--size", type=int, default=100, help="Page size (default: 100).")
@click.option("--cursor", default=None, help="Pagination cursor.")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--name", "site_name", default=None, help="Filter by site name (substring match).")
@click.option("--type", "site_type", default=None, help="Filter by site type (e.g. SITE).")
@click.pass_context
def sites_list(ctx, size, cursor, all_pages, auto_poll, interval, site_name, site_type):
    """List sites (POST /v4/integration/sites).

    \b
    Examples:
      # List first page of sites
      r7-cli vm sites list

    \b
      # Fetch all sites
      r7-cli vm sites list --all-pages

    \b
      # Filter by name
      r7-cli vm sites list --name 'Arlington' --all-pages

    \b
      # Filter by type
      r7-cli vm sites list --type SITE

    \b
      # Poll for new sites
      r7-cli vm sites list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/sites"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getSites", err=True)

    params: dict[str, Any] = {"size": size}
    if cursor:
        params["cursor"] = cursor

    has_filters = any([site_name, site_type])

    try:
        if all_pages or has_filters:
            all_items = _paginate_v4_post(client, config, url, params, None, "sites-list")
            if has_filters:
                if site_name:
                    n_lower = site_name.lower()
                    all_items = [s for s in all_items if n_lower in s.get("name", "").lower()]
                if site_type:
                    t_upper = site_type.upper()
                    all_items = [s for s in all_items if s.get("type", "").upper() == t_upper]
            click.echo(format_output(all_items, config.output_format, config.limit, config.search))
            return

        result = client.post(url, params=params, solution="vm", subcommand="sites-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search))
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
                new_result = client.post(url, params=params, solution="vm", subcommand="sites-list")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


def _interactive_select_vm_scan(client, config):
    """Fetch scans and show interactive menu with status and dates."""
    url = IVM_V4_BASE.format(region=config.region) + "/integration/scan"
    result = client.get(url, solution="vm", subcommand="scans-list")
    items = result.get("data", result.get("resources", []))
    if not isinstance(items, list) or not items:
        click.echo("No scans found.", err=True)
        sys.exit(1)
    click.echo("Available scans:", err=True)
    for idx, item in enumerate(items, 1):
        sid = item.get("id", "?")
        status = item.get("status", "")
        started = item.get("started", "")
        finished = item.get("finished", "")
        parts = []
        if status:
            parts.append(f"status={status}")
        if started:
            parts.append(f"started={started[:19]}")
        if finished:
            parts.append(f"finished={finished[:19]}")
        parts.append(f"id={sid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)
    choice = click.prompt("Select a scan number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)
    return str(items[choice - 1].get("id", ""))


# ---------------------------------------------------------------------------
# vm vulns
# ---------------------------------------------------------------------------


def _filter_vm_assets(items, hostname=None, ip=None, os_family=None, tag=None, risk_score=None, critical_vulns=None):
    """Apply client-side filters to a list of IVM asset dicts."""
    filtered = items
    if hostname:
        h_lower = hostname.lower()
        filtered = [a for a in filtered if h_lower in a.get("host_name", "").lower()]
    if ip:
        filtered = [a for a in filtered if ip in a.get("ip", "")]
    if os_family:
        of_lower = os_family.lower()
        filtered = [a for a in filtered if a.get("os_family", "").lower() == of_lower]
    if tag:
        t_lower = tag.lower()
        filtered = [a for a in filtered if any(t_lower in t.get("name", "").lower() for t in a.get("tags", []))]
    if risk_score:
        cmp_func, val = _parse_cmp_op_vm(risk_score)
        try:
            threshold = float(val)
        except ValueError:
            threshold = 0.0
        filtered = [a for a in filtered if a.get("risk_score") is not None and cmp_func(float(a["risk_score"]), threshold)]
    if critical_vulns:
        cmp_func, val = _parse_cmp_op_vm(critical_vulns)
        try:
            threshold = int(val)
        except ValueError:
            threshold = 0
        filtered = [a for a in filtered if a.get("critical_vulnerabilities") is not None and cmp_func(a["critical_vulnerabilities"], threshold)]
    return filtered


def _parse_cmp_op_vm(expr):
    """Extract (operator_func, remainder) from an expression like '>=7.5'."""
    import operator as _op
    expr = expr.strip()
    for sym, func in [(">=", _op.ge), ("<=", _op.le), (">", _op.gt), ("<", _op.lt), ("=", _op.eq)]:
        if expr.startswith(sym):
            return func, expr[len(sym):].strip()
    return _op.eq, expr


def _filter_vm_vulns(items, severity=None, cvss_score=None, categories=None, published=None, cve=None):
    """Apply client-side filters to a list of IVM vulnerability dicts."""
    filtered = items
    if severity:
        sev_lower = severity.lower()
        filtered = [v for v in filtered if v.get("severity", "").lower() == sev_lower]
    if cvss_score:
        cmp_func, val = _parse_cmp_op_vm(cvss_score)
        try:
            threshold = float(val)
        except ValueError:
            click.echo(f"Invalid --cvss-score value: '{cvss_score}'. Use e.g. '>=7.0'", err=True)
            sys.exit(1)
        filtered = [v for v in filtered if v.get("cvss_v3_score") is not None and cmp_func(float(v["cvss_v3_score"]), threshold)]
    if categories:
        cat_lower = categories.lower()
        filtered = [v for v in filtered if cat_lower in v.get("categories", "").lower()]
    if published:
        cmp_func, val = _parse_cmp_op_vm(published)
        try:
            dt_threshold = datetime.fromisoformat(val.replace("Z", "+00:00"))
        except ValueError:
            click.echo(f"Invalid --published value: '{published}'. Use ISO format e.g. '>=2025-01-01'", err=True)
            sys.exit(1)
        def _parse(s):
            if not s:
                return None
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                return None
        filtered = [v for v in filtered if _parse(v.get("published")) and cmp_func(_parse(v["published"]), dt_threshold)]
    if cve:
        cve_upper = cve.upper()
        filtered = [v for v in filtered if cve_upper in v.get("cves", "").upper()]
    return filtered

@vm.group(cls=GlobalFlagHintGroup)
@click.pass_context
def vulns(ctx):
    """IVM v4 vulnerability commands."""
    pass


@vulns.command("list")
@click.option("--size", type=int, default=100, help="Page size (default: 100).")
@click.option("--cursor", default=None, help="Pagination cursor.")
@click.option("--asset-filter", "asset_filter", default=None, help="Asset search criteria string.")
@click.option("--vuln-filter", "vuln_filter", default=None, help="Vulnerability search criteria string.")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--severity", default=None, help="Filter by severity (e.g. critical, severe, moderate).")
@click.option("--cvss-score", default=None, help="Filter by cvss_v3_score (e.g. '>=7.0', '<5').")
@click.option("--categories", default=None, help="Filter by categories (substring match, e.g. 'XSS').")
@click.option("--published", default=None, help="Filter by published date (e.g. '>=2025-01-01').")
@click.option("--cve", default=None, help="Filter by CVE ID (e.g. 'CVE-2025-0411').")
@click.pass_context
def vulns_search(ctx, size, cursor, asset_filter, vuln_filter, all_pages, auto_poll, interval, severity, cvss_score, categories, published, cve):
    """List vulnerabilities (POST /v4/integration/vulnerabilities).

    \b
    Examples:
      # List first page of vulns
      r7-cli vm vulns list

    \b
      # Fetch all critical vulns
      r7-cli vm vulns list --severity critical --all-pages

    \b
      # High CVSS score vulns
      r7-cli vm vulns list --cvss-score '>=9.0' --all-pages

    \b
      # Filter by category
      r7-cli vm vulns list --categories 'SQL Injection' --all-pages

    \b
      # Vulns published after a date
      r7-cli vm vulns list --published '>=2025-01-01' --all-pages

    \b
      # Search for a specific CVE
      r7-cli vm vulns list --cve CVE-2025-0411

    \b
      # Combine filters
      r7-cli vm vulns list --severity critical --cvss-score '>=9.0' --published '>=2025-01-01'

    \b
      # Poll for new vulns every 30s
      r7-cli vm vulns list -a -i 30

    \b
      # Use API-level filters
      r7-cli vm vulns list --vuln-filter 'vulnerability.categories CONTAINS 7-Zip'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/vulnerabilities"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationVulnerabilities", err=True)

    params: dict[str, Any] = {"size": size}
    if cursor:
        params["cursor"] = cursor

    body: dict[str, str] = {}
    if asset_filter:
        body["asset"] = asset_filter
    if vuln_filter:
        body["vulnerability"] = vuln_filter

    has_filters = any([severity, cvss_score, categories, published, cve])

    try:
        if all_pages or has_filters:
            all_items = _paginate_v4_post(client, config, url, params, body, "vulns-search")
            if has_filters:
                all_items = _filter_vm_vulns(all_items, severity=severity, cvss_score=cvss_score, categories=categories, published=published, cve=cve)
            click.echo(format_output(all_items, config.output_format, config.limit, config.search))
            return

        result = client.post(url, json=body or None, params=params, solution="vm", subcommand="vulns-search")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search))
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
                new_result = client.post(url, json=body or None, params=params, solution="vm", subcommand="vulns-search")
                new_items = _extract_items(new_result)
                for item in new_items:
                    item_id = _extract_item_id(item)
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        click.echo(format_output(item, config.output_format, config.limit, config.search))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# vm export
# ---------------------------------------------------------------------------

@vm.group(cls=GlobalFlagHintGroup)
@click.pass_context
def export(ctx):
    """IVM bulk export commands."""
    pass


@export.command("vulnerabilities")
@click.option("-w", "--wait", is_flag=True, help="Poll until export completes.")
@click.option("-a", "--auto", is_flag=True, help="Wait and auto-download Parquet files.")
@click.option("--output-dir", type=click.Path(), default=None, help="Directory to save downloaded files.")
@click.pass_context
def export_vulnerabilities(ctx, wait, auto, output_dir):
    """Trigger a bulk vulnerability export.

    \b
    Examples:
      # Export and wait for completion
      r7-cli vm export vulnerabilities --wait

    \b
      # Export with interactive download
      r7-cli vm export vulnerabilities --wait --auto

    \b
      # Export to a specific directory
      r7-cli vm export vulnerabilities --wait --auto --output-dir ./vuln-data
    """
    config = _get_config(ctx)
    client = R7Client(config)
    mutation = {
        "query": "mutation CreateVulnerabilityExport { createVulnerabilityExport(input:{}) {id} }"
    }
    try:
        _submit_export(client, config, mutation, "vulnerabilities",
                       wait=wait, auto=auto, output_dir=output_dir)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@export.command("policies")
@click.option("-w", "--wait", is_flag=True, help="Poll until export completes.")
@click.option("-a", "--auto", is_flag=True, help="Wait and auto-download Parquet files.")
@click.option("--output-dir", type=click.Path(), default=None, help="Directory to save downloaded files.")
@click.pass_context
def export_policies(ctx, wait, auto, output_dir):
    """Trigger a bulk policy export.

    \b
    Examples:
      # Export and wait for completion
      r7-cli vm export policies --wait

    \b
      # Export with interactive download
      r7-cli vm export policies --wait --auto

    \b
      # Export to a specific directory
      r7-cli vm export policies --wait --auto --output-dir ./policy-data
    """
    config = _get_config(ctx)
    client = R7Client(config)
    mutation = {
        "query": "mutation CreatePolicyExport { createPolicyExport(input:{}) {id} }"
    }
    try:
        _submit_export(client, config, mutation, "policies",
                       wait=wait, auto=auto, output_dir=output_dir)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@export.command("remediations")
@click.option("-w", "--wait", is_flag=True, help="Poll until export completes.")
@click.option("-a", "--auto", is_flag=True, help="Wait and auto-download Parquet files.")
@click.option("--output-dir", type=click.Path(), default=None, help="Directory to save downloaded files.")
@click.option("--start-date", required=True, help="Start date (YYYY-MM-DD).")
@click.option("--end-date", required=True, help="End date (YYYY-MM-DD).")
@click.pass_context
def export_remediations(ctx, wait, auto, output_dir, start_date, end_date):
    """Trigger a bulk vulnerability remediation export.

    \b
    Examples:
      # Export remediations and wait
      r7-cli vm export remediations --wait

    \b
      # Export with date range
      r7-cli vm export remediations --wait --start-date 2025-01-01 --end-date 2025-06-01

    \b
      # Export with interactive download
      r7-cli vm export remediations --wait --auto --output-dir ./remediation-data
    """
    # Validate date order
    if start_date > end_date:
        click.echo(f"Error: --start-date ({start_date}) must be <= --end-date ({end_date}).", err=True)
        sys.exit(1)

    config = _get_config(ctx)
    client = R7Client(config)
    mutation = {
        "query": (
            "mutation CreateVulnerabilityRemediationExport("
            "$input: VulnerabilityRemediationExportConfiguration!) "
            "{ createVulnerabilityRemediationExport(input: $input) { id } }"
        ),
        "variables": {
            "input": {
                "startDate": start_date,
                "endDate": end_date,
            }
        },
    }
    try:
        _submit_export(client, config, mutation, "remediations",
                       wait=wait, auto=auto, output_dir=output_dir)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# vm export external-assets
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# vm job status
# ---------------------------------------------------------------------------

@export.group("job", cls=GlobalFlagHintGroup)
@click.pass_context
def job(ctx):
    """Export job management."""
    pass


@job.command("status")
@click.option("-j", "--id", "job_id", default=None, help="Export job ID (auto-selects from store if omitted).")
@click.option("--poll", "do_poll", is_flag=True, help="Poll until job reaches terminal state.")
@click.option("-i", "--poll-interval", type=int, default=10, help="Seconds between polls (default: 10).")
@click.pass_context
def job_status(ctx, job_id, do_poll, poll_interval):
    """Check or poll an export job's status.

    \b
    Examples:
      # Check job status once
      r7-cli vm export job status --id <JOB_ID>

    \b
      # Poll until job completes
      r7-cli vm export job status --id <JOB_ID> --poll

    \b
      # Poll with custom interval
      r7-cli vm export job status --id <JOB_ID> --poll --interval 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    store = JobStore()

    # Auto-select job ID if not provided
    if not job_id:
        # Try to find the latest active job across all export types
        for etype in ("vulnerabilities", "policies", "remediations"):
            active = store.get_active(etype)
            if active:
                if len(active) == 1:
                    job_id = active[0].job_id
                    break
                # Multiple active — present menu
                click.echo("Multiple active jobs found:", err=True)
                for idx, entry in enumerate(active, 1):
                    parts = [entry.export_type]
                    parts.append(f"id={entry.job_id}")
                    parts.append(entry.created_at)
                    click.echo(f"  {idx}. {' | '.join(parts)}", err=True)
                choice = click.prompt("Select job number", type=int)
                if 1 <= choice <= len(active):
                    job_id = active[choice - 1].job_id
                else:
                    click.echo("Invalid selection.", err=True)
                    sys.exit(1)
                break

        if not job_id:
            # Fall back to get_latest across types
            latest = None
            for etype in ("vulnerabilities", "policies", "remediations"):
                entry = store.get_latest(etype)
                if entry and (latest is None or entry.created_at > latest.created_at):
                    latest = entry
            if latest:
                job_id = latest.job_id
            else:
                click.echo("No jobs found in store. Provide --id.", err=True)
                sys.exit(1)

    gql_url = IVM_BULK_GQL.format(region=config.region)

    try:
        if do_poll:
            export = _poll_export(client, config, job_id, poll_interval)
            status = export.get("status", "")
            store.mark_terminal(job_id, status)
            click.echo(format_output(export, config.output_format, config.limit, config.search))
            if status == "FAILED":
                sys.exit(2)
        else:
            result = client.post(
                gql_url,
                json={"query": GQL_GET_EXPORT, "variables": {"id": job_id}},
                solution="vm",
                subcommand="job-status",
            )
            export = result.get("data", {}).get("export", {})
            status = export.get("status", "")
            if status in ("SUCCEEDED", "FAILED"):
                store.mark_terminal(job_id, status)
            click.echo(format_output(export, config.output_format, config.limit, config.search))
            if status == "FAILED":
                sys.exit(2)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
