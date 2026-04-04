"""InsightConnect / SOAR solution commands.

Covers workflows, jobs, global artifacts, entities, snippets,
and custom plugins from the InsightConnect API.
"""
from __future__ import annotations

import sys

import click
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import CONNECT_V1_BASE, CONNECT_V2_BASE, R7Error, UserInputError
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DOC_BASE = "https://docs.rapid7.com/insightconnect/api/"


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


# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def soar(ctx):
    """InsightConnect / SOAR commands."""
    pass


# ---------------------------------------------------------------------------
# soar workflows
# ---------------------------------------------------------------------------

@soar.group(cls=GlobalFlagHintGroup)
@click.pass_context
def workflows(ctx):
    """InsightConnect workflow commands."""
    pass


@workflows.command("list")
@click.option("--limit", "limit_param", type=int, default=30, help="Max workflows to return.")
@click.option("--offset", type=int, default=0, help="Offset for pagination.")
@click.option("--name", default=None, help="Filter by workflow name.")
@click.pass_context
def workflows_list(ctx, limit_param, offset, name):
    """List workflows."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/workflows"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params: dict = {"limit": limit_param, "offset": offset}
    if name:
        params["name"] = name

    try:
        result = client.get(url, params=params, solution="soar", subcommand="workflows-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("get")
@click.argument("workflow_id")
@click.pass_context
def workflows_get(ctx, workflow_id):
    """Get a workflow by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/workflows/{workflow_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="soar", subcommand="workflows-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("execute")
@click.argument("workflow_id")
@click.option("--data", "data_str", default=None, help="JSON body for workflow execution.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def workflows_execute(ctx, workflow_id, data_str, data_file):
    """Execute a workflow asynchronously."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/execute/async/workflows/{workflow_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file) or {}

    try:
        result = client.post(url, json=body, solution="soar", subcommand="workflows-execute")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("activate")
@click.argument("workflow_id")
@click.pass_context
def workflows_activate(ctx, workflow_id):
    """Activate a workflow."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/workflows/{workflow_id}/activate"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.post(url, json={}, solution="soar", subcommand="workflows-activate")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("deactivate")
@click.argument("workflow_id")
@click.pass_context
def workflows_deactivate(ctx, workflow_id):
    """Deactivate a workflow."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/workflows/{workflow_id}/deactivate"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.post(url, json={}, solution="soar", subcommand="workflows-deactivate")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("export")
@click.argument("workflow_id")
@click.pass_context
def workflows_export(ctx, workflow_id):
    """Export a workflow."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/workflows/{workflow_id}/export"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="soar", subcommand="workflows-export")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("import")
@click.option("--data", "data_str", default=None, help="JSON body for workflow import.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def workflows_import(ctx, data_str, data_file):
    """Import a workflow."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/workflows/import"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with workflow definition.")

    try:
        result = client.post(url, json=body, solution="soar", subcommand="workflows-import")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# soar jobs
# ---------------------------------------------------------------------------

@soar.group(cls=GlobalFlagHintGroup)
@click.pass_context
def jobs(ctx):
    """InsightConnect job commands."""
    pass


@jobs.command("list")
@click.option("--limit", "limit_param", type=int, default=30, help="Max jobs to return.")
@click.option("--offset", type=int, default=0, help="Offset for pagination.")
@click.option("--status", default=None, help="Filter by job status.")
@click.pass_context
def jobs_list(ctx, limit_param, offset, status):
    """List jobs."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/jobs"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params: dict = {"limit": limit_param, "offset": offset}
    if status:
        params["status"] = status

    try:
        result = client.get(url, params=params, solution="soar", subcommand="jobs-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@jobs.command("get")
@click.option("-j", "--job-id", default=None, help="Job ID to retrieve.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a job from the list.")
@click.pass_context
def jobs_get(ctx, job_id, auto_select):
    """Get a job by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)

    if not job_id and not auto_select:
        raise click.ClickException("Provide --job-id or use --auto to select interactively.")

    if auto_select:
        job_id = _interactive_job_select(client, config, base)

    url = f"{base}/jobs/{job_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="soar", subcommand="jobs-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@jobs.command("cancel")
@click.option("-j", "--job-id", default=None, help="Job ID to cancel.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a job from the list.")
@click.pass_context
def jobs_cancel(ctx, job_id, auto_select):
    """Cancel a running job."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)

    if not job_id and not auto_select:
        raise click.ClickException("Provide --job-id or use --auto to select interactively.")

    if auto_select:
        job_id = _interactive_job_select(client, config, base)

    url = f"{base}/jobs/{job_id}/events/cancel"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.post(url, json={}, solution="soar", subcommand="jobs-cancel")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


def _interactive_job_select(client: R7Client, config: Config, base: str) -> str:
    """Fetch jobs, display a numbered menu, return the selected job ID."""
    url = f"{base}/jobs"
    result = client.get(url, params={"limit": 50}, solution="soar", subcommand="jobs-list")

    # Extract the jobs array
    jobs_list = result if isinstance(result, list) else result.get("data", result.get("jobs", []))
    if not jobs_list:
        click.echo("No jobs found.", err=True)
        sys.exit(1)

    click.echo("Available jobs:", err=True)
    for idx, j in enumerate(jobs_list, 1):
        name = j.get("name", "unnamed")
        status = j.get("status", "unknown")
        jid = j.get("id", j.get("job_id", "?"))
        owner = j.get("created_by", j.get("owner", "unknown"))
        click.echo(f"  {idx}. {name}  status={status}  id={jid}  owner={owner}", err=True)

    choice = click.prompt("Select a job number", type=int, err=True)
    if choice < 1 or choice > len(jobs_list):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)

    selected = jobs_list[choice - 1]
    return selected.get("id", selected.get("job_id", ""))


# ---------------------------------------------------------------------------
# soar artifacts
# ---------------------------------------------------------------------------

@soar.group(cls=GlobalFlagHintGroup)
@click.pass_context
def artifacts(ctx):
    """InsightConnect global artifact commands."""
    pass


@artifacts.command("list")
@click.option("--limit", "limit_param", type=int, default=30, help="Max artifacts to return.")
@click.option("--offset", type=int, default=0, help="Offset for pagination.")
@click.option("--filter-text", default=None, help="Filter by artifact name.")
@click.pass_context
def artifacts_list(ctx, limit_param, offset, filter_text):
    """List global artifacts."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/globalArtifacts"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params: dict = {"limit": limit_param, "offset": offset}
    if filter_text:
        params["filterText"] = filter_text

    try:
        result = client.get(url, params=params, solution="soar", subcommand="artifacts-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@artifacts.command("get")
@click.argument("artifact_id")
@click.pass_context
def artifacts_get(ctx, artifact_id):
    """Get a global artifact by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/globalArtifacts/{artifact_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="soar", subcommand="artifacts-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@artifacts.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for artifact creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def artifacts_create(ctx, data_str, data_file):
    """Create a global artifact."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/globalArtifacts"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with artifact definition.")

    try:
        result = client.post(url, json=body, solution="soar", subcommand="artifacts-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@artifacts.command("delete")
@click.argument("artifact_id")
@click.pass_context
def artifacts_delete(ctx, artifact_id):
    """Delete a global artifact by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/globalArtifacts/{artifact_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.request("DELETE", url, solution="soar", subcommand="artifacts-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@artifacts.command("entities")
@click.argument("artifact_id")
@click.option("--limit", "limit_param", type=int, default=30, help="Max entities to return.")
@click.option("--offset", type=int, default=0, help="Offset for pagination.")
@click.pass_context
def artifacts_entities(ctx, artifact_id, limit_param, offset):
    """List entities for a global artifact."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/globalArtifacts/{artifact_id}/entities"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params: dict = {"limit": limit_param, "offset": offset}

    try:
        result = client.get(url, params=params, solution="soar", subcommand="artifacts-entities")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# soar snippets
# ---------------------------------------------------------------------------

@soar.group(cls=GlobalFlagHintGroup)
@click.pass_context
def snippets(ctx):
    """InsightConnect snippet commands."""
    pass


@snippets.command("export")
@click.argument("snippet_id")
@click.pass_context
def snippets_export(ctx, snippet_id):
    """Export a snippet by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/snippets/{snippet_id}/export"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="soar", subcommand="snippets-export")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@snippets.command("import")
@click.option("--data", "data_str", default=None, help="JSON body for snippet import.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def snippets_import(ctx, data_str, data_file):
    """Import a snippet."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/snippets/import"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with snippet definition.")

    try:
        result = client.post(url, json=body, solution="soar", subcommand="snippets-import")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# soar plugins
# ---------------------------------------------------------------------------

@soar.group(cls=GlobalFlagHintGroup)
@click.pass_context
def plugins(ctx):
    """InsightConnect custom plugin commands."""
    pass


@plugins.command("import")
@click.option("--data", "data_str", default=None, help="JSON body for plugin import.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def plugins_import(ctx, data_str, data_file):
    """Import a custom plugin."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/customPlugins/import"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with plugin spec and tar.")

    try:
        result = client.post(url, json=body, solution="soar", subcommand="plugins-import")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
