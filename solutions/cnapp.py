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
@click.pass_context
def iac_scans_list(ctx, page, page_size, sort, sort_dir):
    """List IaC scans."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/iac/scans"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params = {"page": page, "page_size": page_size, "sort": sort, "sort_dir": sort_dir}

    try:
        result = client.get(url, params=params, solution="cnapp", subcommand="iac-scans-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@iac_scans.command("get")
@click.argument("scan_id")
@click.pass_context
def iac_scans_get(ctx, scan_id):
    """Get an IaC scan by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/iac/scans/{scan_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="cnapp", subcommand="iac-scans-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@iac_scans.command("report")
@click.argument("scan_id")
@click.pass_context
def iac_scans_report(ctx, scan_id):
    """Get the SARIF report for an IaC scan."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/iac/scans/{scan_id}/report"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="cnapp", subcommand="iac-scans-report")
        click.echo(format_output(result, config.output_format, config.limit))
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
@click.pass_context
def aws_keys_list(ctx, page, page_size, include_session):
    """List AWS access keys."""
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
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_keys.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for key creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def aws_keys_create(ctx, data_str, data_file):
    """Create an AWS access key."""
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
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_keys.command("delete")
@click.argument("key_id")
@click.pass_context
def aws_keys_delete(ctx, key_id):
    """Delete an AWS access key by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/accesskeys/{key_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.request("DELETE", url, solution="cnapp", subcommand="aws-keys-delete")
        click.echo(format_output(result, config.output_format, config.limit))
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
@click.pass_context
def aws_roles_list(ctx, page, page_size):
    """List AWS role configurations."""
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
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_roles.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for role creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def aws_roles_create(ctx, data_str, data_file):
    """Create an AWS role configuration."""
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
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_roles.command("update")
@click.argument("role_id")
@click.option("--data", "data_str", default=None, help="JSON body for role update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def aws_roles_update(ctx, role_id, data_str, data_file):
    """Update an AWS role configuration."""
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
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_roles.command("delete")
@click.argument("role_id")
@click.pass_context
def aws_roles_delete(ctx, role_id):
    """Delete an AWS role configuration by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/roles/{role_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.request("DELETE", url, solution="cnapp", subcommand="aws-roles-delete")
        click.echo(format_output(result, config.output_format, config.limit))
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
    """Get AWS EKS harvesting account config."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = _base_url(config)
    url = f"{base}/configs/aws/accounts/{org_service_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="cnapp", subcommand="aws-accounts-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@aws_accounts.command("update")
@click.argument("org_service_id")
@click.option("--data", "data_str", default=None, help="JSON body for account update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def aws_accounts_update(ctx, org_service_id, data_str, data_file):
    """Update AWS EKS harvesting account config."""
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
        click.echo(format_output(result, config.output_format, config.limit))
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
@click.pass_context
def findings_list(ctx, org_service_id, cursor):
    """Get findings for a cloud account."""
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
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
