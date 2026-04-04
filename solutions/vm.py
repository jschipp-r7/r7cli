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
        click.echo(format_output({"job_id": job_id}, config.output_format, config.limit))
        return

    # Poll until terminal
    export = _poll_export(client, config, job_id)
    status = export.get("status", "")
    store.mark_terminal(job_id, status)

    if status == "FAILED":
        click.echo(f"Export {job_id} FAILED.", err=True)
        sys.exit(2)

    click.echo(format_output(export, config.output_format, config.limit))

    # Download if auto or output_dir
    if auto or output_dir:
        urls = export.get("result", {}).get("urls", [])
        if urls:
            dest = output_dir or "."
            _download_parquet_urls(client, urls, dest)


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
    """Check IVM v4 API health status."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = INSIGHT_BASE.format(region=config.region) + "/vm/admin/health"
    try:
        result = client.get(url, solution="vm", subcommand="health")
        click.echo(format_output(result, config.output_format, config.limit))
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


@assets.command("search")
@click.option("--size", type=int, default=100, help="Page size (default: 100).")
@click.option("--cursor", default=None, help="Pagination cursor.")
@click.option("--asset-filter", "asset_filter", default=None, help="Asset search criteria string.")
@click.option("--vuln-filter", "vuln_filter", default=None, help="Vulnerability search criteria string.")
@click.pass_context
def assets_search(ctx, size, cursor, asset_filter, vuln_filter):
    """Search assets (POST /v4/integration/assets)."""
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

    try:
        result = client.post(url, json=body or None, params=params, solution="vm", subcommand="assets-search")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@assets.command("get")
@click.argument("asset_id")
@click.pass_context
def assets_get(ctx, asset_id):
    """Get a single asset by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + f"/integration/assets/{asset_id}"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getIntegrationAsset", err=True)

    try:
        result = client.get(url, solution="vm", subcommand="assets-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("list")
@click.option("-d", "--days", type=int, default=None, help="Filter scans finished within N days.")
@click.option("-s", "--status", "scan_status", default=None, help="Filter by scan status value.")
@click.pass_context
def scans_list(ctx, days, scan_status):
    """List vulnerability scans."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/scan"

    try:
        result = client.get(url, solution="vm", subcommand="scans-list")
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    # If no filters, return raw response
    if not scan_status and days is None:
        click.echo(format_output(result, config.output_format, config.limit))
        return

    # Apply client-side filters to the data array
    records = result.get("data", []) if isinstance(result, dict) else result
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
        records = [r for r in records if r.get("status") == scan_status]

    # Rebuild the response with filtered data
    if isinstance(result, dict):
        result["data"] = records
    else:
        result = records

    click.echo(format_output(result, config.output_format, config.limit))


@scans.command("get")
@click.argument("scan_id")
@click.pass_context
def scans_get(ctx, scan_id):
    """Get a single scan by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + f"/integration/scan/{scan_id}"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getScan", err=True)

    try:
        result = client.get(url, solution="vm", subcommand="scans-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("start")
@click.option("--data", "data_str", default=None, help="JSON request body string.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def scans_start(ctx, data_str, data_file):
    """Start a new scan (POST /v4/integration/scan)."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/scan"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/startScan", err=True)

    import json as _json
    body = _resolve_body(data_str, data_file)

    try:
        result = client.post(url, json=body, solution="vm", subcommand="scans-start")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("stop")
@click.argument("scan_id")
@click.pass_context
def scans_stop(ctx, scan_id):
    """Stop a running scan."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + f"/integration/scan/{scan_id}/stop"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/stopScan", err=True)

    try:
        result = client.post(url, solution="vm", subcommand="scans-stop")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# vm engines get
# ---------------------------------------------------------------------------

@vm.group(cls=GlobalFlagHintGroup)
@click.pass_context
def engines(ctx):
    """IVM v4 scan engine commands."""
    pass


@engines.command("list")
@click.option("--unhealthy", is_flag=True, help="Show only engines with status != HEALTHY.")
@click.pass_context
def engines_list(ctx, unhealthy):
    """List registered scan engines."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/scan/engine"

    try:
        result = client.get(url, solution="vm", subcommand="engines-list")
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    if not unhealthy:
        click.echo(format_output(result, config.output_format, config.limit))
        return

    # Apply client-side filter
    records = result.get("data", []) if isinstance(result, dict) else result
    records = [r for r in records if r.get("status") != "HEALTHY"]
    if isinstance(result, dict):
        result["data"] = records
    else:
        result = records

    click.echo(format_output(result, config.output_format, config.limit))


@engines.command("get")
@click.argument("engine_id")
@click.pass_context
def engines_get(ctx, engine_id):
    """Get a single scan engine by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + f"/integration/scan/engine/{engine_id}"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getScanEngine", err=True)

    try:
        result = client.get(url, solution="vm", subcommand="engines-get")
        click.echo(format_output(result, config.output_format, config.limit))
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
@click.pass_context
def sites_list(ctx, size, cursor):
    """List sites (POST /v4/integration/sites)."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IVM_V4_BASE.format(region=config.region) + "/integration/sites"

    if config.verbose:
        click.echo("Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/getSites", err=True)

    params: dict[str, Any] = {"size": size}
    if cursor:
        params["cursor"] = cursor

    try:
        result = client.post(url, params=params, solution="vm", subcommand="sites-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# vm vulns
# ---------------------------------------------------------------------------

@vm.group(cls=GlobalFlagHintGroup)
@click.pass_context
def vulns(ctx):
    """IVM v4 vulnerability commands."""
    pass


@vulns.command("search")
@click.option("--size", type=int, default=100, help="Page size (default: 100).")
@click.option("--cursor", default=None, help="Pagination cursor.")
@click.option("--asset-filter", "asset_filter", default=None, help="Asset search criteria string.")
@click.option("--vuln-filter", "vuln_filter", default=None, help="Vulnerability search criteria string.")
@click.pass_context
def vulns_search(ctx, size, cursor, asset_filter, vuln_filter):
    """Search vulnerabilities (POST /v4/integration/vulnerabilities)."""
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

    try:
        result = client.post(url, json=body or None, params=params, solution="vm", subcommand="vulns-search")
        click.echo(format_output(result, config.output_format, config.limit))
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
    """Trigger a bulk vulnerability export."""
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
    """Trigger a bulk policy export."""
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
    """Trigger a bulk vulnerability remediation export."""
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

_EXTERNAL_ASSET_FIELDS = [
    "assetId", "ip", "hostName", "riskScore",
    "osVendor", "osType", "osVersion",
    "sites", "assetGroups", "tags",
]


@export.command("external-assets")
@click.option("--output-dir", type=click.Path(), default=None, help="Directory to save downloaded Parquet files.")
@click.pass_context
def export_external_assets(ctx, output_dir):
    """Download assets Parquet and filter to public (non-RFC-1918) IPs."""
    config = _get_config(ctx)
    client = R7Client(config)

    # Trigger vuln export with auto behaviour
    gql_url = IVM_BULK_GQL.format(region=config.region)
    mutation = {
        "query": "mutation CreateVulnerabilityExport { createVulnerabilityExport(input:{}) {id} }"
    }

    job_id: str | None = None
    try:
        result = client.post(gql_url, json=mutation, solution="vm", subcommand="export-vulnerabilities")
        data = result.get("data", {})
        for val in data.values():
            if isinstance(val, dict) and "id" in val:
                job_id = val["id"]
                break
    except APIError as exc:
        if "FAILED_PRECONDITION" in exc.body:
            match = re.search(r"exportId[\":\s]+([a-f0-9-]+)", exc.body, re.IGNORECASE)
            if match:
                job_id = match.group(1)
                click.echo(f"Export already in progress: {job_id}", err=True)
            else:
                raise
        else:
            raise

    if job_id is None:
        click.echo("Failed to extract job ID from response.", err=True)
        sys.exit(2)

    # Poll until done
    export_result = _poll_export(client, config, job_id)
    status = export_result.get("status", "")
    if status == "FAILED":
        click.echo(f"Export {job_id} FAILED.", err=True)
        sys.exit(2)

    # Download parquet files
    urls = export_result.get("result", {}).get("urls", [])
    if not urls:
        click.echo("No download URLs in export result.", err=True)
        sys.exit(2)

    dest = output_dir or "."
    saved = _download_parquet_urls(client, urls, dest)

    # Find the assets table and read it
    try:
        import pyarrow.parquet as pq
    except ImportError:
        click.echo("pyarrow is required for Parquet reading. Install with: pip install pyarrow", err=True)
        sys.exit(1)

    # Look for an assets file among the downloaded files
    assets_file = None
    for p in saved:
        if "asset" in p.name.lower():
            assets_file = p
            break
    if assets_file is None and saved:
        assets_file = saved[0]

    if assets_file is None:
        click.echo("No assets Parquet file found.", err=True)
        sys.exit(2)

    table = pq.read_table(str(assets_file))
    df_dicts = table.to_pydict()

    # Build row-oriented records
    num_rows = len(next(iter(df_dicts.values()))) if df_dicts else 0
    records: list[dict[str, Any]] = []
    for i in range(num_rows):
        row = {col: df_dicts[col][i] for col in df_dicts if col in _EXTERNAL_ASSET_FIELDS}
        ip_val = row.get("ip", "")
        if ip_val and not is_private_ip(str(ip_val)):
            records.append(row)

    if not records:
        click.echo("No assets with public IP addresses found.")
        return

    click.echo(format_output(records, config.output_format, config.limit))


# ---------------------------------------------------------------------------
# vm job status
# ---------------------------------------------------------------------------

@vm.group("job", cls=GlobalFlagHintGroup)
@click.pass_context
def job(ctx):
    """Export job management."""
    pass


@job.command("status")
@click.option("-j", "--job-id", default=None, help="Export job ID (auto-selects from store if omitted).")
@click.option("--poll", "do_poll", is_flag=True, help="Poll until job reaches terminal state.")
@click.option("-i", "--poll-interval", type=int, default=10, help="Seconds between polls (default: 10).")
@click.pass_context
def job_status(ctx, job_id, do_poll, poll_interval):
    """Check or poll an export job's status."""
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
                    click.echo(f"  {idx}. {entry.job_id} ({entry.export_type}, {entry.created_at})", err=True)
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
                click.echo("No jobs found in store. Provide --job-id.", err=True)
                sys.exit(1)

    gql_url = IVM_BULK_GQL.format(region=config.region)

    try:
        if do_poll:
            export = _poll_export(client, config, job_id, poll_interval)
            status = export.get("status", "")
            store.mark_terminal(job_id, status)
            click.echo(format_output(export, config.output_format, config.limit))
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
            click.echo(format_output(export, config.output_format, config.limit))
            if status == "FAILED":
                sys.exit(2)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
