"""InsightAppSec solution commands.

Covers apps, scans, scan configs, vulnerabilities, engines, engine groups,
schedules, blackouts, attack templates, and search.
"""
from __future__ import annotations

import sys

import click
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import IAS_V1_BASE, R7Error, UserInputError
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DOC_BASE = "https://help.rapid7.com/insightappsec/en-us/api/v1/docs.html"


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


# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def appsec(ctx):
    """InsightAppSec commands."""
    pass


# ---------------------------------------------------------------------------
# appsec apps
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def apps(ctx):
    """InsightAppSec application commands."""
    pass


@apps.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def apps_list(ctx, index, size):
    """List applications."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/apps"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-apps", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="apps-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@apps.command("get")
@click.argument("app_id")
@click.pass_context
def apps_get(ctx, app_id):
    """Get an application by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/apps/{app_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-app", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="apps-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@apps.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for app creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def apps_create(ctx, data_str, data_file):
    """Create an application."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/apps"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/create-app", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with app definition.")

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="apps-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@apps.command("delete")
@click.argument("app_id")
@click.pass_context
def apps_delete(ctx, app_id):
    """Delete an application by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/apps/{app_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/delete-app", err=True)

    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="apps-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec scans
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def scans(ctx):
    """InsightAppSec scan commands."""
    pass


@scans.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def scans_list(ctx, index, size):
    """List scans."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/scans"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scans", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="scans-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("get")
@click.argument("scan_id")
@click.pass_context
def scans_get(ctx, scan_id):
    """Get a scan by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/scans/{scan_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scans-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("submit")
@click.option("--data", "data_str", default=None, help="JSON body for scan submission.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def scans_submit(ctx, data_str, data_file):
    """Submit a new scan."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/scans"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/submit-scan", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with scan config ID.")

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="scans-submit")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("action")
@click.argument("scan_id")
@click.argument("action_type", type=click.Choice(["Pause", "Resume", "Stop", "Cancel"], case_sensitive=False))
@click.pass_context
def scans_action(ctx, scan_id, action_type):
    """Submit an action (Pause/Resume/Stop/Cancel) on a scan."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/scans/{scan_id}/action"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/submit-scan-action", err=True)

    try:
        result = client.request("PUT", url, json={"action": action_type.upper()},
                                solution="appsec", subcommand="scans-action")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("details")
@click.argument("scan_id")
@click.pass_context
def scans_details(ctx, scan_id):
    """Get scan execution details."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/scans/{scan_id}/execution-details"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-execution-details", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scans-details")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec scan-configs
# ---------------------------------------------------------------------------

@appsec.group("scan-configs", cls=GlobalFlagHintGroup)
@click.pass_context
def scan_configs(ctx):
    """InsightAppSec scan configuration commands."""
    pass


@scan_configs.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def scan_configs_list(ctx, index, size):
    """List scan configurations."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/scan-configs"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-configs", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="scan-configs-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scan_configs.command("get")
@click.argument("config_id")
@click.pass_context
def scan_configs_get(ctx, config_id):
    """Get a scan configuration by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/scan-configs/{config_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-config", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scan-configs-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scan_configs.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for scan config creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def scan_configs_create(ctx, data_str, data_file):
    """Create a scan configuration."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/scan-configs"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/create-scan-config", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with scan config definition.")

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="scan-configs-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scan_configs.command("options")
@click.argument("config_id")
@click.pass_context
def scan_configs_options(ctx, config_id):
    """Get scan config options."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/scan-configs/{config_id}/options"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-config-options", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scan-configs-options")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec vulns
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def vulns(ctx):
    """InsightAppSec vulnerability commands."""
    pass


@vulns.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def vulns_list(ctx, index, size):
    """List vulnerabilities."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/vulnerabilities"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerabilities", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="vulns-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@vulns.command("get")
@click.argument("vuln_id")
@click.pass_context
def vulns_get(ctx, vuln_id):
    """Get a vulnerability by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{vuln_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerability", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="vulns-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@vulns.command("discoveries")
@click.argument("vuln_id")
@click.pass_context
def vulns_discoveries(ctx, vuln_id):
    """Get vulnerability discoveries."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{vuln_id}/discoveries"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerability-discoveries", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="vulns-discoveries")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@vulns.command("history")
@click.argument("vuln_id")
@click.pass_context
def vulns_history(ctx, vuln_id):
    """Get vulnerability history."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{vuln_id}/history"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerability-history", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="vulns-history")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec engines
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def engines(ctx):
    """InsightAppSec engine commands."""
    pass


@engines.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def engines_list(ctx, index, size):
    """List engines."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/engines"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-engines", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="engines-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engines.command("get")
@click.argument("engine_id")
@click.pass_context
def engines_get(ctx, engine_id):
    """Get an engine by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/engines/{engine_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-engine", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="engines-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec engine-groups
# ---------------------------------------------------------------------------

@appsec.group("engine-groups", cls=GlobalFlagHintGroup)
@click.pass_context
def engine_groups(ctx):
    """InsightAppSec engine group commands."""
    pass


@engine_groups.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def engine_groups_list(ctx, index, size):
    """List engine groups."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/engine-groups"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-engine-groups", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="engine-groups-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engine_groups.command("get")
@click.argument("group_id")
@click.pass_context
def engine_groups_get(ctx, group_id):
    """Get an engine group by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/engine-groups/{group_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-engine-group", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="engine-groups-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec schedules
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def schedules(ctx):
    """InsightAppSec schedule commands."""
    pass


@schedules.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def schedules_list(ctx, index, size):
    """List schedules."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/schedules"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-schedules", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="schedules-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@schedules.command("get")
@click.argument("schedule_id")
@click.pass_context
def schedules_get(ctx, schedule_id):
    """Get a schedule by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/schedules/{schedule_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-schedule", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="schedules-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@schedules.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for schedule creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def schedules_create(ctx, data_str, data_file):
    """Create a schedule."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/schedules"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/create-schedule", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with schedule definition.")

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="schedules-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec blackouts
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def blackouts(ctx):
    """InsightAppSec blackout commands."""
    pass


@blackouts.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def blackouts_list(ctx, index, size):
    """List blackouts."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/blackouts"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-blackouts", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="blackouts-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@blackouts.command("get")
@click.argument("blackout_id")
@click.pass_context
def blackouts_get(ctx, blackout_id):
    """Get a blackout by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/blackouts/{blackout_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-blackout", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="blackouts-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec attack-templates
# ---------------------------------------------------------------------------

@appsec.group("attack-templates", cls=GlobalFlagHintGroup)
@click.pass_context
def attack_templates(ctx):
    """InsightAppSec attack template commands."""
    pass


@attack_templates.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def attack_templates_list(ctx, index, size):
    """List attack templates."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/attack-templates"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-attack-templates", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="attack-templates-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@attack_templates.command("get")
@click.argument("template_id")
@click.pass_context
def attack_templates_get(ctx, template_id):
    """Get an attack template by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/attack-templates/{template_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-attack-template", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="attack-templates-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec targets
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def targets(ctx):
    """InsightAppSec target commands."""
    pass


@targets.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def targets_list(ctx, index, size):
    """List targets."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/targets"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-targets", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="targets-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@targets.command("get")
@click.argument("target_id")
@click.pass_context
def targets_get(ctx, target_id):
    """Get a target by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/targets/{target_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-target", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="targets-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec modules
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def modules(ctx):
    """InsightAppSec vulnerability module commands."""
    pass


@modules.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def modules_list(ctx, index, size):
    """List vulnerability modules."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/modules"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-modules", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="modules-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@modules.command("get")
@click.argument("module_id")
@click.pass_context
def modules_get(ctx, module_id):
    """Get a vulnerability module by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/modules/{module_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-module", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="modules-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec reports
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def reports(ctx):
    """InsightAppSec report commands."""
    pass


@reports.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def reports_list(ctx, index, size):
    """List reports."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/reports"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-reports", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="reports-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@reports.command("get")
@click.argument("report_id")
@click.pass_context
def reports_get(ctx, report_id):
    """Get a report by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/reports/{report_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-report", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="reports-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@reports.command("generate")
@click.option("--data", "data_str", default=None, help="JSON body for report generation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def reports_generate(ctx, data_str, data_file):
    """Generate a report."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/reports"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/generate-report", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with report definition.")

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="reports-generate")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec tags
# ---------------------------------------------------------------------------

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def tags(ctx):
    """InsightAppSec tag commands."""
    pass


@tags.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def tags_list(ctx, index, size):
    """List tags."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/tags"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-tags", err=True)

    params = {"index": index, "size": size}

    try:
        result = client.get(url, params=params, solution="appsec", subcommand="tags-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@tags.command("get")
@click.argument("tag_id")
@click.pass_context
def tags_get(ctx, tag_id):
    """Get a tag by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + f"/tags/{tag_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-tag", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="tags-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec search
# ---------------------------------------------------------------------------

@appsec.command("search")
@click.option("-t", "--type", "search_type", required=True,
              help="Resource type: APP, SCAN_CONFIG, SCAN, VULNERABILITY, etc.")
@click.option("-q", "--query", "query", required=True, help="Search query string.")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def appsec_search(ctx, search_type, query, index, size):
    """Search InsightAppSec resources."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/search"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/perform-search", err=True)

    body = {"type": search_type, "query": query}
    params = {"index": index, "size": size}

    try:
        result = client.post(url, json=body, params=params, solution="appsec", subcommand="search")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
