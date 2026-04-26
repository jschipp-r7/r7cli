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
    from r7cli.progress import progress_bar, progress_done

    gql_url = IVM_BULK_GQL.format(region=config.region)
    poll_count = 0
    # Estimate ~5 min typical export; cap at 95% until done
    estimated_polls = 30  # 30 * 10s = 5 min
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
            progress_done(f"Export {status.lower()}.")
            return export
        poll_count += 1
        frac = min(poll_count / estimated_polls, 0.95)
        progress_bar(frac, f"status: {status} (polling every {poll_interval}s)")
        time.sleep(poll_interval)


def _download_parquet_urls(
    client: R7Client,
    urls: list[str],
    output_dir: str,
    prefix: str | None = None,
    timestamp: str | None = None,
) -> list[Path]:
    """Download each URL to *output_dir* and return the list of saved paths.

    When *prefix* and *timestamp* are provided, files are named as
    ``{prefix}.{timestamp}.parquet`` (or ``{prefix}.{timestamp}.{idx}.parquet``
    for multi-URL entries) instead of using the raw S3 filename.
    """
    from r7cli.progress import progress_download, progress_done

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    multi = len(urls) > 1
    total = len(urls)
    for idx, url in enumerate(urls):
        if prefix and timestamp:
            # Flatten prefix: replace / with _ to avoid subdirectories
            flat_prefix = prefix.replace("/", "_")
            # Use short ISO 8601 timestamp for the filename
            ts = _short_iso_timestamp(timestamp)
            if multi:
                filename = f"{flat_prefix}.{ts}.{idx}.parquet"
            else:
                filename = f"{flat_prefix}.{ts}.parquet"
        else:
            filename = url.rsplit("/", 1)[-1].split("?")[0] or "export.parquet"
        dest = out / filename
        progress_download(idx + 1, total, filename)
        # Use the underlying httpx client for raw download
        resp = client._http.get(url)
        dest.write_bytes(resp.content)
        saved.append(dest)
    progress_done(f"Downloaded {total} file(s) to {out}/")
    return saved


def _short_iso_timestamp(ts: str) -> str:
    """Convert a full ISO timestamp to short form for filenames.

    E.g. ``2026-04-07T16:38:10.555Z`` → ``2026-04-07T16:38Z``
    """
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%MZ")
    except (ValueError, AttributeError):
        return ts


def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is in an RFC-1918 private range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return addr.is_private


def _paginate_v4(client: R7Client, config: Config, url: str, subcommand: str) -> list[dict]:
    """Follow ``links`` pagination on IVM v4 endpoints, collecting all records."""
    from r7cli.progress import progress_pages, progress_done

    all_records: list[dict] = []
    next_url: str | None = url
    page_num = 0
    total_pages: int | None = None
    while next_url:
        result = client.get(next_url, solution="vm", subcommand=subcommand)
        resources = result.get("resources", result.get("data", []))
        if isinstance(resources, list):
            all_records.extend(resources)
        page_num += 1
        # Try to extract total from page metadata
        if total_pages is None:
            page_meta = result.get("page", {})
            if isinstance(page_meta, dict):
                total_pages = page_meta.get("totalPages", page_meta.get("total_pages"))
        progress_pages(page_num, total_pages, len(all_records))
        # Follow next link
        next_url = None
        for link in result.get("links", []):
            if link.get("rel") == "next":
                next_url = link.get("href")
                break
    progress_done(f"Fetched {len(all_records)} records across {page_num} page(s).")
    return all_records


def _paginate_v4_post(client, config, url, params, body, subcommand):
    """Cursor-based pagination for IVM v4 POST endpoints (e.g. /integration/vulnerabilities)."""
    from r7cli.progress import progress_pages, progress_done

    all_records: list[dict] = []
    cur_params = dict(params)
    page_num = 0
    total_pages: int | None = None
    while True:
        result = client.post(url, json=body or None, params=cur_params, solution="vm", subcommand=subcommand)
        resources = result.get("resources", result.get("data", []))
        if isinstance(resources, list):
            all_records.extend(resources)
        page_num += 1
        # Try to extract total from metadata
        metadata = result.get("metadata", {})
        if isinstance(metadata, dict):
            if total_pages is None:
                tp = metadata.get("totalPages", metadata.get("total_pages"))
                if tp is not None:
                    total_pages = int(tp)
        progress_pages(page_num, total_pages, len(all_records))
        # Follow next cursor
        next_cursor = None
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
    progress_done(f"Fetched {len(all_records)} records across {page_num} page(s).")
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
        data = result.get("data") or {}
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
        click.echo(format_output({"job_id": job_id}, config.output_format, config.limit, config.search, short=config.short))
        return

    # Poll until terminal
    export = _poll_export(client, config, job_id)
    status = export.get("status", "")
    store.mark_terminal(job_id, status)

    if status == "FAILED":
        click.echo(f"Export {job_id} FAILED.", err=True)
        sys.exit(2)

    click.echo(format_output(export, config.output_format, config.limit, config.search, short=config.short))

    # Download if auto or output_dir
    if auto or output_dir:
        result_data = export.get("result", [])
        export_ts = export.get("timestamp", "")
        dest = output_dir or "."
        if isinstance(result_data, list):
            for entry in result_data:
                if isinstance(entry, dict):
                    entry_prefix = entry.get("prefix", "export")
                    entry_urls = entry.get("urls", [])
                    if entry_urls:
                        _download_parquet_urls(client, entry_urls, dest, prefix=entry_prefix, timestamp=export_ts)
        elif isinstance(result_data, dict):
            entry_prefix = result_data.get("prefix", "export")
            entry_urls = result_data.get("urls", [])
            if entry_urls:
                _download_parquet_urls(client, entry_urls, dest, prefix=entry_prefix, timestamp=export_ts)


# ---------------------------------------------------------------------------
# Click groups
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def vm(ctx):
    """InsightVM commands (health, scans, engines, exports, job status)."""
    pass


from r7cli.cis import make_cis_command as _make_cis  # noqa: E402
vm.add_command(_make_cis("vm"))


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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("--force", is_flag=True, help="Force fetching all pages even for large datasets (>4k assets).")
@click.pass_context
def assets_search(ctx, size, cursor, asset_filter, vuln_filter, all_pages, auto_poll, interval, hostname, ip, os_family, tag, risk_score, critical_vulns, force):
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
            # Check total asset count before fetching all pages
            if all_pages and not force:
                count_result = client.post(url, json=body or None, params={"size": 1}, solution="vm", subcommand="assets-count")
                total = 0
                if isinstance(count_result, dict):
                    total = count_result.get("metadata", {}).get("totalResources", 0)
                if total > 4000:
                    click.echo(
                        f"Your organization has {total:,} assets. For datasets over 4,000 assets, "
                        f"we recommend using the more efficient bulk export APIs:\n\n"
                        f"  r7-cli vm export vulnerabilities --auto\n\n"
                        f"Then use 'r7-cli vm export list' to filter the downloaded data locally.\n\n"
                        f"To proceed anyway, use --force. If you do, consider using -c/--cache on "
                        f"subsequent commands to filter the cached data instead of re-fetching.",
                        err=True,
                    )
                    sys.exit(0)
                elif total > 3000:
                    click.echo(
                        f"Fetching {total:,} assets — this may take a few minutes.",
                        err=True,
                    )

            all_items = _paginate_v4_post(client, config, url, params, body, "assets-list")
            if has_filters:
                all_items = _filter_vm_assets(all_items, hostname=hostname, ip=ip, os_family=os_family, tag=tag, risk_score=risk_score, critical_vulns=critical_vulns)
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.post(url, json=body or None, params=params, solution="vm", subcommand="assets-list")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@assets.command("count")
@click.pass_context
def assets_count(ctx):
    """Get the total count of IVM assets.

    \b
    Examples:
      r7-cli vm assets count
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/assets"

    try:
        result = client.post(url, json=None, params={"size": 1}, solution="vm", subcommand="assets-count")
        total = 0
        if isinstance(result, dict):
            metadata = result.get("metadata", {})
            total = metadata.get("totalResources", 0)
        click.echo(format_output({"totalAssets": total}, config.output_format, config.limit, config.search, short=config.short))
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
        import questionary
        # Fetch first page of assets for interactive selection
        url = IVM_V4_BASE.format(region=config.region) + "/integration/assets"
        result = client.post(url, json=None, params={"size": 30}, solution="vm", subcommand="assets-list")
        items = result.get("data", result.get("resources", []))
        if not isinstance(items, list) or not items:
            click.echo("No assets found.", err=True)
            sys.exit(1)
        choices = []
        for item in items:
            hname = item.get("host_name", "")
            ip_addr = item.get("ip", "")
            aid = str(item.get("id", "?"))
            label = f"{hname} {ip_addr} ({aid})" if hname else aid
            choices.append(questionary.Choice(title=label, value=aid))
        asset_id = questionary.select("Select an asset:", choices=choices).ask()
        if asset_id is None:
            click.echo("No selection made.", err=True)
            sys.exit(1)

    url = IVM_V4_BASE.format(region=config.region) + f"/integration/assets/{asset_id}"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getIntegrationAsset", err=True)

    try:
        result = client.get(url, solution="vm", subcommand="assets-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, solution="vm", subcommand="scans-list")

        if not auto_poll:
            if not has_filters:
                click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
                return
            records = result.get("data", []) if isinstance(result, dict) else result
            records = _apply_filters(records)
            if isinstance(result, dict):
                result = dict(result)
                result["data"] = records
            else:
                result = records
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
                new_result = client.get(url, solution="vm", subcommand="scans-list")
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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

    body = _resolve_body(data_str, data_file)

    try:
        result = client.post(url, json=body, solution="vm", subcommand="scans-start")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, solution="vm", subcommand="engines-list")

        if not auto_poll:
            if not unhealthy:
                click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
                return
            # Apply client-side filter
            records = result.get("data", []) if isinstance(result, dict) else result
            records = [r for r in records if r.get("status") != "HEALTHY"]
            if isinstance(result, dict):
                result["data"] = records
            else:
                result = records
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
                new_result = client.get(url, solution="vm", subcommand="engines-list")
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
        import questionary
        # Fetch engines for interactive selection
        list_url = IVM_V4_BASE.format(region=config.region) + "/integration/scan/engine"
        result = client.get(list_url, solution="vm", subcommand="engines-list")
        items = result.get("data", result.get("resources", []))
        if not isinstance(items, list) or not items:
            click.echo("No scan engines found.", err=True)
            sys.exit(1)
        choices = []
        for item in items:
            name = item.get("name", "")
            status = item.get("status", "")
            eid = str(item.get("id", "?"))
            label = f"{name} [{status}] ({eid})" if name else eid
            choices.append(questionary.Choice(title=label, value=eid))
        engine_id = questionary.select("Select a scan engine:", choices=choices).ask()
        if engine_id is None:
            click.echo("No selection made.", err=True)
            sys.exit(1)

    url = IVM_V4_BASE.format(region=config.region) + f"/integration/scan/engine/{engine_id}"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getScanEngine", err=True)

    try:
        result = client.get(url, solution="vm", subcommand="engines-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.post(url, params=params, solution="vm", subcommand="sites-list")

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
                new_result = client.post(url, params=params, solution="vm", subcommand="sites-list")
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


def _interactive_select_vm_scan(client, config):
    """Fetch scans and show interactive menu."""
    import questionary

    url = IVM_V4_BASE.format(region=config.region) + "/integration/scan"
    result = client.get(url, solution="vm", subcommand="scans-list")
    items = result.get("data", result.get("resources", []))
    if not isinstance(items, list) or not items:
        click.echo("No scans found.", err=True)
        sys.exit(1)

    choices = []
    for item in items:
        sid = str(item.get("id", "?"))
        status = item.get("status", "")
        started = item.get("started", "")[:19] if item.get("started") else ""
        label = f"{status} {started} ({sid})" if status else sid
        choices.append(questionary.Choice(title=label, value=sid))

    selected = questionary.select("Select a scan:", choices=choices).ask()
    if selected is None:
        click.echo("No selection made.", err=True)
        sys.exit(1)
    return selected


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
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.post(url, json=body or None, params=params, solution="vm", subcommand="vulns-search")

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
                        click.echo(format_output(item, config.output_format, config.limit, config.search, short=config.short))
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
    """Download your entire data set via the command-line using the bulk export APIs. This is the most efficient option to get VM data out of the platform and must be used when working with large datasets."""
    pass


from r7cli.solutions.mcp import mcp_group as _mcp_group  # noqa: E402
export.add_command(_mcp_group)


@export.command("vulnerabilities")
@click.option("-w", "--wait", is_flag=True, help="Poll until export completes.")
@click.option("-a", "--auto", is_flag=True, help="Wait and auto-download Parquet files.")
@click.option("--output-dir", type=click.Path(), default=None, help="Directory to save downloaded files.")
@click.pass_context
def export_vulnerabilities(ctx, wait, auto, output_dir):
    """Download all the bulk data on vulnerabilities.

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
    """Download all the bulk data on policies (scan engine + agent compliance checks).

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


def _parse_month(value: str) -> int:
    """Return month number (1-12) from short or long name, case-insensitive."""
    import calendar
    val = value.strip().lower()
    for i in range(1, 13):
        if val in (calendar.month_name[i].lower(), calendar.month_abbr[i].lower()):
            return i
    raise click.BadParameter(f"Unknown month: {value}")


def _month_date_range(month: int, year: int) -> tuple[str, str]:
    """Return (start_date, end_date) strings for the given month/year."""
    import calendar
    last_day = calendar.monthrange(year, month)[1]
    start = f"{year}-{month:02d}-01"
    end = f"{year}-{month:02d}-{last_day:02d}"
    return start, end


# Earliest month the API has data for
_REMEDIATION_DATA_ORIGIN = (2025, 8)  # August 2025


def _generate_month_ranges(start_year: int, start_month: int,
                           end_year: int, end_month: int) -> list[tuple[str, str]]:
    """Generate a list of (start_date, end_date) pairs for each month in the range."""
    ranges: list[tuple[str, str]] = []
    y, m = start_year, start_month
    while (y, m) <= (end_year, end_month):
        ranges.append(_month_date_range(m, y))
        m += 1
        if m > 12:
            m = 1
            y += 1
    return ranges


def _submit_remediation_export(client, config, start_date, end_date, *,
                               wait, auto, output_dir):
    """Build and submit a single remediation export for the given date range."""
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
    _submit_export(client, config, mutation, "remediations",
                   wait=wait, auto=auto, output_dir=output_dir)


@export.command("remediations")
@click.option("-w", "--wait", is_flag=True, help="Poll until export completes.")
@click.option("-a", "--auto", is_flag=True, help="Wait and auto-download Parquet files.")
@click.option("--output-dir", type=click.Path(), default=None, help="Directory to save downloaded files.")
@click.option("--start-date", default=None, help="Start date (YYYY-MM-DD). Defaults to 31 days ago.")
@click.option("--end-date", default=None, help="End date (YYYY-MM-DD). Defaults to today.")
@click.option("-m", "--month", "month_name", default=None, help="Month name (e.g. feb, february). Sets date range to that month.")
@click.option("-y", "--year", "year", default=None, type=int, help="Year (e.g. 2025). Used with --month or --all-pages.")
@click.option("--all-pages", is_flag=True, help="Fetch all months from Aug 2025 to now (or the given --year).")
@click.pass_context
def export_remediations(ctx, wait, auto, output_dir, start_date, end_date, month_name, year, all_pages):
    """Download all the bulk data on remediations.

    \b
    API Limitations:
      - Earliest supported date: August 1, 2025
      - Maximum date range per request: 31 days
      - Use --month, --year, or --all-pages to fetch larger periods

    \b
    If no dates are specified, downloads the last 31 days by default.
    Use --month to target a specific month, optionally with --year.
    Use --all-pages to iterate over every month from August 2025 to now.

    \b
    Examples:
      # Last 31 days (default)
      r7-cli vm export remediations --auto

    \b
      # Specific month (current year)
      r7-cli vm export remediations --auto -m march

    \b
      # Specific month and year
      r7-cli vm export remediations --auto -m feb -y 2026

    \b
      # All available data since Aug 2025
      r7-cli vm export remediations --auto --all-pages

    \b
      # All months for a specific year
      r7-cli vm export remediations --auto --all-pages -y 2026

    \b
      # Explicit date range (max 31 days)
      r7-cli vm export remediations --auto --start-date 2025-09-01 --end-date 2025-09-30
    """
    today = datetime.now(timezone.utc).date()

    # --month / --year validation
    if month_name and (start_date or end_date):
        click.echo("Error: --month cannot be combined with --start-date/--end-date.", err=True)
        sys.exit(1)
    if year and not month_name and not all_pages:
        click.echo("Error: --year requires --month or --all-pages.", err=True)
        sys.exit(1)
    if all_pages and (start_date or end_date):
        click.echo("Error: --all-pages cannot be combined with --start-date/--end-date.", err=True)
        sys.exit(1)
    if all_pages and month_name:
        click.echo("Error: --all-pages cannot be combined with --month.", err=True)
        sys.exit(1)

    config = _get_config(ctx)
    client = R7Client(config)

    # --- all-pages mode: iterate month by month ---
    if all_pages:
        origin_y, origin_m = _REMEDIATION_DATA_ORIGIN
        if year:
            # Only pull months for the given year
            start_y, start_m = year, 1
            if year < origin_y or (year == origin_y and 1 < origin_m):
                start_y, start_m = origin_y, origin_m
            end_y, end_m = year, today.month if year == today.year else 12
        else:
            start_y, start_m = origin_y, origin_m
            end_y, end_m = today.year, today.month

        ranges = _generate_month_ranges(start_y, start_m, end_y, end_m)
        click.echo(f"Fetching {len(ranges)} month(s) of remediation data …", err=True)
        for sd, ed in ranges:
            # Clamp end date to today if in the future
            if ed > today.isoformat():
                ed = today.isoformat()
            click.echo(f"\n— {sd} → {ed}", err=True)
            try:
                _submit_remediation_export(client, config, sd, ed,
                                           wait=wait, auto=auto, output_dir=output_dir)
            except R7Error as exc:
                click.echo(str(exc), err=True)
        return

    # --- single-range mode ---
    if month_name:
        month_num = _parse_month(month_name)
        yr = year or today.year
        start_date, end_date = _month_date_range(month_num, yr)
    elif not start_date and not end_date:
        # Default: last 31 days
        end_date = today.isoformat()
        start_date = (today - timedelta(days=31)).isoformat()
        click.echo(
            f"Using default date range: {start_date} → {end_date} (last 31 days). "
            f"Use --month, --year, or --all-pages for more data.",
            err=True,
        )
    elif not start_date or not end_date:
        click.echo("Error: provide both --start-date and --end-date, or neither.", err=True)
        sys.exit(1)

    # Validate: earliest supported date
    _EARLIEST_DATE = "2025-08-01"
    if start_date < _EARLIEST_DATE:
        click.echo(
            f"Error: the earliest supported date by the API is August 1, 2025. "
            f"Got --start-date {start_date}.",
            err=True,
        )
        sys.exit(1)
    if end_date < _EARLIEST_DATE:
        click.echo(
            f"Error: the earliest supported date by the API is August 1, 2025. "
            f"Got --end-date {end_date}.",
            err=True,
        )
        sys.exit(1)

    if start_date > end_date:
        click.echo(f"Error: --start-date ({start_date}) must be <= --end-date ({end_date}).", err=True)
        sys.exit(1)

    # Validate: max 31 days per request
    from datetime import date as _date
    try:
        sd = _date.fromisoformat(start_date)
        ed = _date.fromisoformat(end_date)
        if (ed - sd).days > 31:
            click.echo(
                f"Error: the API limits the date range to no more than 31 days per request. "
                f"Your range is {(ed - sd).days} days ({start_date} → {end_date}). "
                f"Use --month or --all-pages to fetch larger periods.",
                err=True,
            )
            sys.exit(1)
    except ValueError:
        pass  # date parsing errors handled elsewhere

    try:
        _submit_remediation_export(client, config, start_date, end_date,
                                   wait=wait, auto=auto, output_dir=output_dir)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# vm export list
# ---------------------------------------------------------------------------

@export.command("list")
@click.option("--files", "file_pattern", default=None, help="File path(s) or glob pattern for Parquet files (e.g. '*.parquet').")
@click.option("--hostname", default=None, help="Filter by hostname (substring match).")
@click.option("--ip", default=None, help="Filter by IP address (substring match).")
@click.option("--os-family", default=None, help="Filter by OS family (substring match).")
@click.option("--severity", default=None, help="Filter by severity (substring match).")
@click.option("--cvss-score", default=None, help="Filter by CVSS score (e.g. '>=9.0').")
@click.option("--risk-score", default=None, help="Filter by risk score (e.g. '>=10000').")
@click.option("--has-exploits", default=None, help="Filter by exploit availability (true/false).")
@click.option("--first-found", default=None, help="Filter by first-found date (e.g. '>=2025-01-01').")
@click.option("--status", "status_filter", default=None, help="Filter by finalStatus (substring or glob, e.g. '*PASS*').")
@click.option("--benchmark-title", default=None, help="Filter by benchmarkTitle (substring or glob, e.g. '*Red Hat*').")
@click.option("--profile-title", default=None, help="Filter by profileTitle (substring or glob, e.g. '*Level 1*').")
@click.option("--publisher", default=None, help="Filter by publisher (substring or glob, e.g. 'CIS').")
@click.option("--rule-title", default=None, help="Filter by ruleTitle (substring or glob, e.g. '*wireless*').")
@click.option("--benchmark-version", default=None, help="Filter by benchmarkVersion (substring or glob).")
@click.option("--where", "where_clauses", multiple=True, help="Generic filter: 'column op value'.")
@click.option("--only", "only_columns", default=None, help="Only show these columns (comma-separated, e.g. 'ruleTitle,publisher').")
@click.pass_context
def export_list(ctx, file_pattern, hostname, ip, os_family, severity, cvss_score,
                risk_score, has_exploits, first_found, status_filter,
                benchmark_title, profile_title, publisher, rule_title,
                benchmark_version, where_clauses, only_columns):
    """Query and filter locally downloaded Parquet export files.

    Reads Parquet files from disk, auto-detects their schema, optionally
    joins asset data for cross-table filtering, and outputs results in
    JSON, table, or CSV format.  No API key or network required.

    \b
    Examples:
      # List all rows from cached Parquet files
      r7-cli -c vm export list

    \b
      # Filter by CVSS score
      r7-cli vm export list --files 'asset_vulnerability.*.parquet' --cvss-score '>=9.0'

    \b
      # Filter by hostname across joined data
      r7-cli -c vm export list --hostname web --severity Critical

    \b
      # Generic where filter
      r7-cli -c vm export list --where 'severity == Critical'

    \b
      # Filter policy data by rule title (glob pattern)
      r7-cli vm export list --files 'asset_policy.*.parquet' --rule-title '*wireless*'

    \b
      # Filter by benchmark and publisher
      r7-cli vm export list --files 'asset_policy.*.parquet' --publisher CIS --benchmark-title '*Red Hat*'
    """
    from r7cli.parquet_filter import (
        resolve_files,
        detect_schema,
        read_parquet_files,
        auto_join,
        apply_filters,
        apply_where,
        SCHEMA_ASSET,
        SCHEMA_POLICY,
    )

    config = _get_config(ctx)

    # 1. Resolve files
    paths = resolve_files(config.use_cache, file_pattern)

    if config.verbose:
        click.echo(f"Searching through the following {len(paths)} file(s):", err=True)
        for p in paths:
            click.echo(f"  {p.resolve()}", err=True)

    # 2. Group files by schema
    schema_groups: dict[str, list] = {}
    skipped_files: list[tuple[Path, str | None]] = []
    for p in paths:
        s = detect_schema(p)
        if s is not None:
            schema_groups.setdefault(s, []).append(p)
        else:
            skipped_files.append((p, None))

    # Use only the most recent file per schema (sorted by name, last = newest)
    for schema_name in schema_groups:
        all_files = sorted(schema_groups[schema_name])
        schema_groups[schema_name] = [all_files[-1]]
        if config.verbose and len(all_files) > 1:
            for older in all_files[:-1]:
                skipped_files.append((older, f"older {schema_name} file"))

    # Determine which schemas the user's filters target
    _FILTER_SCHEMA_MAP = {
        "benchmarkTitle": SCHEMA_POLICY, "profileTitle": SCHEMA_POLICY,
        "publisher": SCHEMA_POLICY, "ruleTitle": SCHEMA_POLICY,
        "benchmarkVersion": SCHEMA_POLICY, "finalStatus": SCHEMA_POLICY,
        "vulnId": "vulnerability", "cvssScore": "vulnerability",
        "cvssV3Score": "vulnerability", "severity": "vulnerability",
        "hasExploits": "vulnerability", "firstFoundTimestamp": "vulnerability",
    }
    targeted_schemas: set[str] = set()
    for col_name in [k for k, v in {
        "benchmarkTitle": benchmark_title, "profileTitle": profile_title,
        "publisher": publisher, "ruleTitle": rule_title,
        "benchmarkVersion": benchmark_version, "finalStatus": status_filter,
        "severity": severity, "cvssScore": cvss_score,
        "hasExploits": has_exploits, "firstFoundTimestamp": first_found,
    }.items() if v is not None]:
        schema = _FILTER_SCHEMA_MAP.get(col_name)
        if schema:
            targeted_schemas.add(schema)

    if config.verbose and skipped_files:
        click.echo("Ignoring the following files:", err=True)
        for fp, reason in skipped_files:
            r = f" ({reason})" if reason else " (unknown schema)"
            click.echo(f"  {fp.resolve()}{r}", err=True)

    # 3. Read non-asset files as primary data
    primary_paths = []
    for schema_name, file_list in schema_groups.items():
        if schema_name != SCHEMA_ASSET:
            primary_paths.extend(file_list)

    if not primary_paths:
        # If only asset files, treat them as primary
        primary_paths = schema_groups.get(SCHEMA_ASSET, [])

    primary_rows = read_parquet_files(primary_paths)

    # 4. If asset files exist and we have non-asset primary data, auto-join
    asset_paths = schema_groups.get(SCHEMA_ASSET, [])
    has_asset_data = bool(asset_paths) and primary_paths != asset_paths
    if has_asset_data:
        asset_rows = read_parquet_files(asset_paths)
        primary_rows = auto_join(primary_rows, asset_rows)

    # 4b. Validate --only columns that require asset data
    _ASSET_ONLY_COLUMNS = {"hostName", "ip", "mac", "osFamily", "osProduct", "osVendor",
                           "osVersion", "osType", "osDescription", "osArchitecture",
                           "agentId", "awsInstanceId", "azureResourceId", "gcpObjectId",
                           "sites", "assetGroups", "tags"}
    if only_columns:
        requested_cols = {c.strip() for c in only_columns.split(",")}
        asset_cols_requested = requested_cols & _ASSET_ONLY_COLUMNS
        if asset_cols_requested and not has_asset_data:
            click.echo(
                f"Error: asset field(s) {', '.join(sorted(asset_cols_requested))} specified in --only "
                f"but no asset Parquet file was found. Include an asset.*.parquet file to use asset fields.",
                err=True,
            )
            sys.exit(1)

    # 5. Build filters dict from CLI options
    filters: dict[str, str] = {}
    option_map = {
        "hostName": hostname,
        "ip": ip,
        "osFamily": os_family,
        "severity": severity,
        "cvssV3Severity": severity,
        "cvssScore": cvss_score,
        "cvssV3Score": cvss_score,
        "riskScore": risk_score,
        "hasExploits": has_exploits,
        "firstFoundTimestamp": first_found,
        "finalStatus": status_filter,
        "benchmarkTitle": benchmark_title,
        "profileTitle": profile_title,
        "publisher": publisher,
        "ruleTitle": rule_title,
        "benchmarkVersion": benchmark_version,
    }
    for col, val in option_map.items():
        if val is not None:
            filters[col] = val

    # 5b. Validate policy-specific filters against schema
    _POLICY_ONLY_FILTERS = {"benchmarkTitle", "profileTitle", "publisher", "ruleTitle", "benchmarkVersion"}
    active_policy_filters = _POLICY_ONLY_FILTERS & set(filters.keys())
    if active_policy_filters and SCHEMA_POLICY not in [detect_schema(p) for p in primary_paths]:
        click.echo(
            f"Warning: {', '.join('--' + f for f in active_policy_filters)} are only valid for policy schema files. "
            f"These filters will be ignored.",
            err=True,
        )
        for f in active_policy_filters:
            del filters[f]

    # 5c. Inform user if no filters are active
    if not filters and not where_clauses:
        click.echo(
            f"Returning all data ({len(primary_rows)} rows). Use filters to narrow results "
            f"(e.g. --hostname, --severity, --cvss-score, --where).",
            err=True,
        )

    # 6. Apply filters then where clauses
    filtered = apply_filters(primary_rows, filters)

    # Build schema_columns dict for --where type detection
    schema_columns: dict[str, str] = {}
    if primary_paths:
        import pyarrow.parquet as pq
        try:
            pa_schema = pq.read_schema(str(primary_paths[0].resolve()))
            for i in range(len(pa_schema)):
                schema_columns[pa_schema.field(i).name] = str(pa_schema.field(i).type)
        except Exception:
            pass

    filtered = apply_where(filtered, list(where_clauses), schema_columns)

    # 7. Column projection (--only)
    if only_columns:
        cols = [c.strip() for c in only_columns.split(",")]
        filtered = [{c: row.get(c) for c in cols if c in row} for row in filtered]

    # 8. Output — apply limit directly since we pass a plain list
    if config.limit is not None:
        filtered = filtered[:config.limit]

    click.echo(
        format_output(filtered, config.output_format, limit=None, search=config.search, short=config.short)
    )


# ---------------------------------------------------------------------------
# vm export external-assets
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# vm export schema
# ---------------------------------------------------------------------------

# Hard-coded schemas so the command works without any parquet files on disk.
# Each entry is (column_name, column_type, example_value).
_EXPORT_SCHEMAS: dict[str, list[tuple[str, str, str]]] = {
    "asset": [
        ("orgId", "VARCHAR", "4be646d8-b4aa-…-a7c58d0a6396"),
        ("assetId", "VARCHAR", "3a0f4d79-1089-…-6964b801291d"),
        ("agentId", "VARCHAR", "cc2fe28324824836abdc23bdd1228ffb"),
        ("awsInstanceId", "VARCHAR", "i-0cac20ad3a055e8c9"),
        ("azureResourceId", "VARCHAR", ""),
        ("gcpObjectId", "VARCHAR", ""),
        ("mac", "VARCHAR", "0AFF000096D1"),
        ("ip", "VARCHAR", "10.2.153.2"),
        ("hostName", "VARCHAR", "ws-violet_bernard.mustafar.lab"),
        ("osArchitecture", "VARCHAR", "x86"),
        ("osFamily", "VARCHAR", "Windows"),
        ("osProduct", "VARCHAR", "Windows Vista Enterprise Edition"),
        ("osVendor", "VARCHAR", "Microsoft"),
        ("osVersion", "VARCHAR", "7.1.2"),
        ("osType", "VARCHAR", "Workstation"),
        ("osDescription", "VARCHAR", "Microsoft Windows Vista Enterprise…"),
        ("riskScore", "DOUBLE", "0.0"),
        ("sites", "VARCHAR[]", "['Bangalore']"),
        ("assetGroups", "VARCHAR[]", "['Windows 8.1']"),
        ("tags", "STRUCT(…)[]", "[{name:Ben tag test,tagType:CUSTOM}]"),
    ],
    "vulnerability": [
        ("orgId", "VARCHAR", "4be646d8-b4aa-…-a7c58d0a6396"),
        ("assetId", "VARCHAR", "3a0f4d79-1089-…-6964b801291d"),
        ("vulnId", "VARCHAR", "adobe-apsb12-22-cve-2012-5673"),
        ("checkId", "VARCHAR", "microsoft-windows-cve-2016-0026-…"),
        ("port", "INTEGER", "443"),
        ("protocol", "VARCHAR", "TCP"),
        ("nic", "VARCHAR", "f65471a7-7550-…-9eb434678606"),
        ("proof", "VARCHAR", "<p>Vulnerable OS: Apple Mac OS X…"),
        ("firstFoundTimestamp", "TIMESTAMP", "2025-11-07T04:24:22"),
        ("reintroducedTimestamp", "TIMESTAMP", "2026-03-23T04:25:21"),
        ("cves", "VARCHAR[]", "['CVE-2012-5673']"),
        ("cvssAccessComplexity", "VARCHAR", "L"),
        ("cvssAccessVector", "VARCHAR", "N"),
        ("cvssAuthentication", "VARCHAR", "N"),
        ("cvssAvailabilityImpact", "VARCHAR", "C"),
        ("cvssConfidentialityImpact", "VARCHAR", "C"),
        ("cvssIntegrityImpact", "VARCHAR", "C"),
        ("cvssScore", "DOUBLE", "8.8"),
        ("cvssV3AttackComplexity", "VARCHAR", "Low"),
        ("cvssV3AttackVector", "VARCHAR", "Network"),
        ("cvssV3Availability", "VARCHAR", "High"),
        ("cvssV3Confidentiality", "VARCHAR", "High"),
        ("cvssV3Integrity", "VARCHAR", "High"),
        ("cvssV3PrivilegesRequired", "VARCHAR", "None"),
        ("cvssV3Scope", "VARCHAR", "Unchanged"),
        ("cvssV3Score", "DOUBLE", "8.8"),
        ("cvssV3Severity", "VARCHAR", "High"),
        ("cvssV3SeverityRank", "INTEGER", "4"),
        ("cvssV3UserInteraction", "VARCHAR", "Required"),
        ("dateAdded", "TIMESTAMP", "2012-11-09T00:00:00"),
        ("dateModified", "TIMESTAMP", "2025-02-18T00:00:00"),
        ("datePublished", "TIMESTAMP", "2012-10-08T00:00:00"),
        ("description", "VARCHAR", "Unspecified vulnerability in Adobe…"),
        ("hasExploits", "BOOLEAN", "false"),
        ("pciCompliant", "BOOLEAN", "false"),
        ("pciSeverity", "INTEGER", "5"),
        ("riskScore", "DOUBLE", "897.96"),
        ("riskScoreV2_0", "INTEGER", "589"),
        ("severity", "VARCHAR", "Critical"),
        ("severityRank", "INTEGER", "3"),
        ("severityScore", "INTEGER", "10"),
        ("skillLevel", "VARCHAR", "unknown"),
        ("skillLevelRank", "INTEGER", "4"),
        ("threatFeedExists", "BOOLEAN", "false"),
        ("title", "VARCHAR", "APSB12-22: Security updates for Adobe…"),
        ("tags", "VARCHAR[]", "['Adobe','Adobe Flash']"),
        ("epssscore", "DECIMAL(10,9)", "0.013470000"),
        ("epsspercentile", "DECIMAL(10,9)", "0.797390000"),
    ],
    "policy": [
        ("benchmarkNaturalId", "VARCHAR", "xccdf_org.cisecurity…CIS_RHEL_7"),
        ("profileNaturalId", "VARCHAR", "xccdf_org.cisecurity…Level_1_Server"),
        ("benchmarkVersion", "VARCHAR", "4.0.0"),
        ("ruleNaturalId", "VARCHAR", "xccdf_org.cisecurity…noexec_tmp"),
        ("orgId", "VARCHAR", "4be646d8-b4aa-…-a7c58d0a6396"),
        ("assetId", "VARCHAR", "3a0f4d79-1089-…-6964b801291d"),
        ("finalStatus", "VARCHAR", "NOT_APPLICABLE"),
        ("proof", "VARCHAR", "<p>This is a complex check…"),
        ("lastAssessmentTimestamp", "TIMESTAMP", "2026-02-23T03:14:15"),
        ("benchmarkTitle", "VARCHAR", "CIS Red Hat Enterprise Linux 7…"),
        ("profileTitle", "VARCHAR", "Level 1 - Server"),
        ("publisher", "VARCHAR", "CIS"),
        ("ruleTitle", "VARCHAR", "1.1.2.1.4. Ensure noexec on /tmp"),
        ("fixTexts", "VARCHAR[]", "['Edit /etc/fstab and add noexec…']"),
        ("rationales", "VARCHAR[]", "['Since /tmp is only for temp…']"),
    ],
    "remediation": [
        ("orgId", "VARCHAR", "4be646d8-b4aa-…-a7c58d0a6396"),
        ("assetId", "VARCHAR", "3a0f4d79-1089-…-6964b801291d"),
        ("cves", "VARCHAR[]", "['CVE-2025-15367']"),
        ("vulnId", "VARCHAR", "ubuntu-cve-2025-15367"),
        ("proof", "VARCHAR", "<p>Vulnerable OS: Ubuntu Linux 22.04…"),
        ("firstFoundTimestamp", "TIMESTAMP", "2026-02-06T21:55:06"),
        ("reintroducedTimestamp", "TIMESTAMP", ""),
        ("lastDetected", "TIMESTAMP", "2026-02-06T21:58:12"),
        ("lastRemoved", "TIMESTAMP", "2026-02-10T04:06:26"),
        ("title", "VARCHAR", "Ubuntu: (CVE-2025-15367): Python…"),
        ("description", "VARCHAR", "The poplib module, when passed a…"),
        ("cvssV2Score", "DECIMAL(3,1)", "7.5"),
        ("cvssV3Score", "DECIMAL(3,1)", "7.1"),
        ("cvssV2Severity", "VARCHAR", "High"),
        ("cvssV3Severity", "VARCHAR", "High"),
        ("cvssV2AttackVector", "VARCHAR", "(AV:N/AC:L/Au:S/C:P/I:C/A:N)"),
        ("cvssV3AttackVector", "VARCHAR", "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/…"),
        ("riskScoreV2_0", "INTEGER", "475"),
        ("riskScoreV2_0Severity", "VARCHAR", "Moderate"),
        ("datePublished", "TIMESTAMP", "2026-01-20T00:00:00"),
        ("dateAdded", "TIMESTAMP", "2026-02-06T00:00:00"),
        ("dateModified", "TIMESTAMP", "2026-03-27T00:00:00"),
        ("epssScore", "DECIMAL(10,9)", "0.000770000"),
        ("epssPercentile", "DECIMAL(10,9)", "0.230340000"),
        ("remediationCount", "BIGINT", "1"),
    ],
}


@export.command("schema")
@click.argument("schema_type", required=False, default=None,
                type=click.Choice(list(_EXPORT_SCHEMAS.keys()), case_sensitive=False))
@click.pass_context
def export_schema(ctx, schema_type):
    """Show the column schema for a bulk-export dataset.

    \b
    Schema types: asset, vulnerability, policy, remediation

    \b
    Examples:
      # List available schemas
      r7-cli vm export schema

    \b
      # Show the vulnerability export schema
      r7-cli vm export schema vulnerability

    \b
      # Show the asset export schema
      r7-cli vm export schema asset
    """
    if schema_type is None:
        click.echo("Available export schemas:\n")
        for name in _EXPORT_SCHEMAS:
            count = len(_EXPORT_SCHEMAS[name])
            click.echo(f"  {name:<20s} {count} columns")
        click.echo("\nUsage: r7-cli vm export schema <type>")
        return

    columns = _EXPORT_SCHEMAS[schema_type.lower()]
    name_w = max(len(c[0]) for c in columns)
    type_w = max(len(c[1]) for c in columns)

    header = f"{'column_name':<{name_w}}  {'column_type':<{type_w}}  example"
    sep = "─" * len(header)

    click.echo(f"{schema_type}")
    click.echo(sep)
    click.echo(header)
    click.echo(sep)
    for col_name, col_type, example in columns:
        click.echo(f"{col_name:<{name_w}}  {col_type:<{type_w}}  {example}")
    click.echo(sep)
    click.echo(f"{len(columns)} columns")


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
                import questionary
                choices = []
                for entry in active:
                    label = f"{entry.export_type} | {entry.created_at} ({entry.job_id})"
                    choices.append(questionary.Choice(title=label, value=entry.job_id))
                selected = questionary.select("Select a job:", choices=choices).ask()
                if selected is None:
                    click.echo("No selection made.", err=True)
                    sys.exit(1)
                job_id = selected
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
            click.echo(format_output(export, config.output_format, config.limit, config.search, short=config.short))
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
            click.echo(format_output(export, config.output_format, config.limit, config.search, short=config.short))
            if status == "FAILED":
                sys.exit(2)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
