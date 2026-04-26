"""InsightCloudSec / CNAPP solution commands.

Covers IaC scans, AWS access keys, AWS roles, AWS accounts,
and Insight findings from the InsightCloudSec v4 API.
"""
from __future__ import annotations

import sys

import click
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import CLOUDSEC_V4_BASE, R7Error, UserInputError
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DOC_BASE = "https://docs.rapid7.com/insightcloudsec/api/v4/"


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
    import json as _json
    if data_str and data_file:
        raise UserInputError("Provide either --data or --data-file, not both.")
    if data_str:
        return _json.loads(data_str)
    if data_file:
        with open(data_file) as fh:
            return _json.load(fh)
    return None


def _base_url(config: Config) -> str:
    """Resolve the CloudSec base URL.

    Uses R7_CLOUDSEC_URL env var if set, otherwise falls back to a
    conventional hostname.
    """
    import os
    host = os.environ.get("R7_CLOUDSEC_URL", "")
    if not host:
        host = "my.insightcloudsec.com"
    return CLOUDSEC_V4_BASE.format(insightcloudsec_url=host)


# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def cnapp(ctx):
    """InsightCloudSec / CNAPP commands."""
    pass


from r7cli.cis import make_cis_command as _make_cis_cnapp  # noqa: E402
cnapp.add_command(_make_cis_cnapp("cnapp"))


# ---------------------------------------------------------------------------
# cnapp iac-scans
# ---------------------------------------------------------------------------

@cnapp.group("iac-scans", cls=GlobalFlagHintGroup)
@click.pass_context
def iac_scans(ctx):
    """IaC scan commands."""
    pass


@iac_scans.command("list")
@click.option("--page", type=int, default=1, help="Page number (default: 1).")
@click.option("--page-size", type=int, default=25, help="Page size (default: 25).")
@click.option("--sort", default="create_time", help="Sort field (id, create_time).")
@click.option("--sort-dir", default="desc", type=click.Choice(["asc", "desc"]), help="Sort direction.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def iac_scans_list(ctx, page, page_size, sort, sort_dir, auto_poll, interval):
    """List IaC scans.

    \b
    Examples:
      r7-cli cnapp iac-scans list
      r7-cli cnapp iac-scans list --page-size 50
      r7-cli cnapp iac-scans list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/iac/scans"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params = {"page": page, "page_size": page_size, "sort": sort, "sort_dir": sort_dir}

    try:
        result = client.get(url, params=params, solution="cnapp", subcommand="iac-scans-list")

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
                new_result = client.get(url, params=params, solution="cnapp", subcommand="iac-scans-list")
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


@iac_scans.command("get")
@click.argument("scan_id")
@click.pass_context
def iac_scans_get(ctx, scan_id):
    """Get an IaC scan by ID.

    \b
    Example:
      r7-cli cnapp iac-scans get --id <SCAN_ID>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/iac/scans/{scan_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="cnapp", subcommand="iac-scans-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@iac_scans.command("report")
@click.argument("scan_id")
@click.pass_context
def iac_scans_report(ctx, scan_id):
    """Get the SARIF report for an IaC scan.

    \b
    Example:
      r7-cli cnapp iac-scans report --id <SCAN_ID>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/iac/scans/{scan_id}/report"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="cnapp", subcommand="iac-scans-report")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# cnapp aws-keys
# ---------------------------------------------------------------------------

@cnapp.group("aws-keys", cls=GlobalFlagHintGroup)
@click.pass_context
def aws_keys(ctx):
    """AWS access key configuration commands."""
    pass


@aws_keys.command("list")
@click.option("--page", type=int, default=None, help="Page number.")
@click.option("--page-size", type=int, default=None, help="Page size.")
@click.option("--include-session", is_flag=True, help="Include STS session keys.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def aws_keys_list(ctx, page, page_size, include_session, auto_poll, interval):
    """List AWS access keys.

    \b
    Examples:
      r7-cli cnapp aws-keys list
      r7-cli cnapp aws-keys list --include-session
      r7-cli cnapp aws-keys list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/accesskeys"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params: dict = {}
    if page is not None:
        params["page"] = page
    if page_size is not None:
        params["page_size"] = page_size
    if include_session:
        params["include_session"] = "true"

    try:
        result = client.get(url, params=params or None, solution="cnapp", subcommand="aws-keys-list")

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
                new_result = client.get(url, params=params or None, solution="cnapp", subcommand="aws-keys-list")
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


@aws_keys.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for key creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def aws_keys_create(ctx, data_str, data_file):
    """Create an AWS access key.

    \b
    Example:
      r7-cli cnapp aws-keys create --data '{"name": "my-key", "access_key_id": "AKIA...", "secret_access_key": "..."}'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/accesskeys"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with key definition.")

    try:
        result = client.post(url, json=body, solution="cnapp", subcommand="aws-keys-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_keys.command("delete")
@click.argument("key_id")
@click.pass_context
def aws_keys_delete(ctx, key_id):
    """Delete an AWS access key by ID.

    \b
    Example:
      r7-cli cnapp aws-keys delete --id <KEY_ID>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/accesskeys/{key_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.request("DELETE", url, solution="cnapp", subcommand="aws-keys-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# cnapp aws-roles
# ---------------------------------------------------------------------------

@cnapp.group("aws-roles", cls=GlobalFlagHintGroup)
@click.pass_context
def aws_roles(ctx):
    """AWS role configuration commands."""
    pass


@aws_roles.command("list")
@click.option("--page", type=int, default=None, help="Page number.")
@click.option("--page-size", type=int, default=None, help="Page size.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def aws_roles_list(ctx, page, page_size, auto_poll, interval):
    """List AWS role configurations.

    \b
    Examples:
      r7-cli cnapp aws-roles list
      r7-cli cnapp aws-roles list -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/roles"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params: dict = {}
    if page is not None:
        params["page"] = page
    if page_size is not None:
        params["page_size"] = page_size

    try:
        result = client.get(url, params=params or None, solution="cnapp", subcommand="aws-roles-list")

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
                new_result = client.get(url, params=params or None, solution="cnapp", subcommand="aws-roles-list")
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


@aws_roles.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for role creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def aws_roles_create(ctx, data_str, data_file):
    """Create an AWS role configuration.

    \b
    Example:
      r7-cli cnapp aws-roles create --data '{"name": "my-role", "role_arn": "arn:aws:iam::..."}'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/roles"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with role definition.")

    try:
        result = client.post(url, json=body, solution="cnapp", subcommand="aws-roles-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_roles.command("update")
@click.argument("role_id")
@click.option("--data", "data_str", default=None, help="JSON body for role update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def aws_roles_update(ctx, role_id, data_str, data_file):
    """Update an AWS role configuration.

    \b
    Example:
      r7-cli cnapp aws-roles update --id <ROLE_ID> --data '{"name": "updated-role"}'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/roles/{role_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with role definition.")

    try:
        result = client.post(url, json=body, solution="cnapp", subcommand="aws-roles-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_roles.command("delete")
@click.argument("role_id")
@click.pass_context
def aws_roles_delete(ctx, role_id):
    """Delete an AWS role configuration by ID.

    \b
    Example:
      r7-cli cnapp aws-roles delete --id <ROLE_ID>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/roles/{role_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.request("DELETE", url, solution="cnapp", subcommand="aws-roles-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# cnapp aws-accounts
# ---------------------------------------------------------------------------

@cnapp.group("aws-accounts", cls=GlobalFlagHintGroup)
@click.pass_context
def aws_accounts(ctx):
    """AWS EKS harvesting account commands."""
    pass


@aws_accounts.command("get")
@click.argument("org_service_id")
@click.pass_context
def aws_accounts_get(ctx, org_service_id):
    """Get AWS EKS harvesting account config.

    \b
    Example:
      r7-cli cnapp aws-accounts get --id <ORG_SERVICE_ID>
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/accounts/{org_service_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="cnapp", subcommand="aws-accounts-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_accounts.command("update")
@click.argument("org_service_id")
@click.option("--data", "data_str", default=None, help="JSON body for account update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def aws_accounts_update(ctx, org_service_id, data_str, data_file):
    """Update AWS EKS harvesting account config.

    \b
    Example:
      r7-cli cnapp aws-accounts update --id <ORG_SERVICE_ID> --data '{"enabled": true}'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/accounts/{org_service_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with account definition.")

    try:
        result = client.post(url, json=body, solution="cnapp", subcommand="aws-accounts-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# cnapp findings
# ---------------------------------------------------------------------------

@cnapp.group(cls=GlobalFlagHintGroup)
@click.pass_context
def findings(ctx):
    """Insight findings commands."""
    pass


@findings.command("list")
@click.argument("org_service_id")
@click.option("--cursor", default=None, help="Pagination cursor from previous response.")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def findings_list(ctx, org_service_id, cursor, auto_poll, interval):
    """Get findings for a cloud account.

    \b
    Examples:
      r7-cli cnapp findings list --id <ORG_SERVICE_ID>
      r7-cli cnapp findings list --id <ORG_SERVICE_ID> -a -i 30
    """
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/insights/findings-per-cloud/{org_service_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params: dict = {}
    if cursor:
        params["cursor"] = cursor

    try:
        result = client.get(url, params=params or None, solution="cnapp", subcommand="findings-list")

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
                new_result = client.get(url, params=params or None, solution="cnapp", subcommand="findings-list")
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
