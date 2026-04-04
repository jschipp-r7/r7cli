"""InsightConnect / SOAR solution commands.

Covers workflows, jobs, global artifacts, entities, snippets,
and custom plugins from the InsightConnect API.
"""
from __future__ import annotations

import sys
from typing import Any

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
        click.echo("Provide either --data or --data-file, not both.")
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
@click.option("-a", "--auto", "auto_poll", is_flag=True,
              help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def workflows_list(ctx, limit_param, offset, name, auto_poll, interval):
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

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _find_job_dicts(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, params=params, solution="soar", subcommand="workflows-list")
                new_items = _find_job_dicts(new_result)
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


@workflows.command("get")
@click.option("--id", "workflow_id", default=None, help="Workflow ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a workflow.")
@click.pass_context
def workflows_get(ctx, workflow_id, auto_select):
    """Get a workflow by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)

    if not workflow_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        workflow_id = _interactive_workflow_select(client, config)

    url = f"{base}/workflows/{workflow_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="soar", subcommand="workflows-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("execute")
@click.option("--id", "workflow_id", default=None, help="Workflow ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a workflow.")
@click.option("--data", "data_str", default=None, help="JSON body for workflow execution.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def workflows_execute(ctx, workflow_id, auto_select, data_str, data_file):
    """Execute a workflow asynchronously."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not workflow_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        workflow_id = _interactive_workflow_select(client, config)

    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/execute/async/workflows/{workflow_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    body = _resolve_body(data_str, data_file) or {}

    try:
        result = client.post(url, json=body, solution="soar", subcommand="workflows-execute")
        if result:
            click.echo(format_output(result, config.output_format, config.limit, config.search))
        else:
            click.echo(f"Workflow {workflow_id} successfully sent for execution.")
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("activate")
@click.option("--id", "workflow_id", default=None, help="Workflow ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a workflow.")
@click.pass_context
def workflows_activate(ctx, workflow_id, auto_select):
    """Activate a workflow."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)

    if not workflow_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        workflow_id = _interactive_workflow_select(client, config, state_filter="inactive")

    url = f"{base}/workflows/{workflow_id}/activate"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.post(url, json={}, solution="soar", subcommand="workflows-activate")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("deactivate")
@click.option("--id", "workflow_id", default=None, help="Workflow ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a workflow.")
@click.pass_context
def workflows_deactivate(ctx, workflow_id, auto_select):
    """Deactivate a workflow."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)

    if not workflow_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        workflow_id = _interactive_workflow_select(client, config, state_filter="active")

    url = f"{base}/workflows/{workflow_id}/deactivate"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.post(url, json={}, solution="soar", subcommand="workflows-deactivate")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("export")
@click.option("--id", "workflow_id", default=None, help="Workflow ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a workflow.")
@click.pass_context
def workflows_export(ctx, workflow_id, auto_select):
    """Export a workflow."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)

    if not workflow_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        workflow_id = _interactive_workflow_select(client, config)

    url = f"{base}/workflows/{workflow_id}/export"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="soar", subcommand="workflows-export")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@workflows.command("import")
@click.option("--file", "file_path", type=click.Path(exists=True), default=None,
              help="Path to workflow JSON file (e.g. ./workflows/Quarantine.json).")
@click.pass_context
def workflows_import(ctx, file_path):
    """Import a workflow from a JSON file."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/workflows/import"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    if not file_path:
        click.echo(
            "Provide --file with the path to a workflow JSON file.\n"
            "  Example: r7-cli soar workflows import --file ./workflows/Quarantine.json",
            err=True,
        )
        sys.exit(1)

    import json as _json
    with open(file_path) as fh:
        body = _json.load(fh)

    try:
        result = client.post(url, json=body, solution="soar", subcommand="workflows-import")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
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
@click.option("--status", default=None,
              type=click.Choice(["failed", "waiting", "running", "success", "cancelled"], case_sensitive=False),
              help="Filter by job status (failed, waiting, running, success, cancelled).")
@click.option("-a", "--auto", "auto_poll", is_flag=True,
              help="Poll for new jobs and only print new entries.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def jobs_list(ctx, limit_param, offset, status, auto_poll, interval):
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

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search))
        else:
            import time as _time
            import json as _json
            # Track seen job IDs — page through ALL existing jobs
            seen_ids: set[str] = set()

            def _seed_page(page_result: Any) -> None:
                items = _find_job_dicts(page_result)
                for j in items:
                    jid = _extract_id(j)
                    if jid:
                        seen_ids.add(jid)
                    else:
                        seen_ids.add(_json.dumps(j, sort_keys=True, default=str))

            # Seed from all pages
            _seed_page(result)
            # Check if there are more pages
            meta = {}
            if isinstance(result, dict):
                meta = result.get("data", result).get("meta", result.get("metadata", {}))
                if isinstance(meta, dict):
                    total = meta.get("total", meta.get("total_data", 0))
                    page_offset = limit_param
                    while page_offset < total:
                        page_params = dict(params)
                        page_params["offset"] = page_offset
                        page_result = client.get(url, params=page_params, solution="soar", subcommand="jobs-list")
                        _seed_page(page_result)
                        page_offset += limit_param

            if config.verbose:
                click.echo(f"Seeded {len(seen_ids)} existing entries.", err=True)

            click.echo(f"Polling for new jobs every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                # Only check first page — newest jobs appear first
                new_result = client.get(url, params=params, solution="soar", subcommand="jobs-list")
                new_items = _find_job_dicts(new_result)
                for j in new_items:
                    jid = _extract_id(j)
                    if not jid:
                        jid = _json.dumps(j, sort_keys=True, default=str)
                    if jid not in seen_ids:
                        seen_ids.add(jid)
                        click.echo(format_output(j, config.output_format, config.limit, config.search))
    except KeyboardInterrupt:
        click.echo("\nStopped polling.", err=True)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@jobs.command("get")
@click.option("-j", "--id", "job_id", default=None, help="Job ID to retrieve.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a job from the list.")
@click.pass_context
def jobs_get(ctx, job_id, auto_select):
    """Get a job by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)

    if not job_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")

    if auto_select:
        job_id = _interactive_job_select(client, config, base)

    url = f"{base}/jobs/{job_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="soar", subcommand="jobs-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@jobs.command("cancel")
@click.option("-j", "--id", "job_id", default=None, help="Job ID to cancel.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select a job from the list.")
@click.pass_context
def jobs_cancel(ctx, job_id, auto_select):
    """Cancel a running job."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)

    if not job_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")

    if auto_select:
        job_id = _interactive_job_select(client, config, base)

    url = f"{base}/jobs/{job_id}/events/cancel"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.post(url, json={}, solution="soar", subcommand="jobs-cancel")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


def _interactive_job_select(client: R7Client, config: Config, base: str) -> str:
    """Fetch jobs, display a numbered menu, return the selected job ID."""
    url = f"{base}/jobs"
    result = client.get(url, params={"limit": 50}, solution="soar", subcommand="jobs-list")

    # Find the list of job dicts in the response — the API may nest them
    jobs_list = _find_job_dicts(result)
    if not jobs_list:
        click.echo("No jobs found.", err=True)
        sys.exit(1)

    click.echo("Available jobs:", err=True)
    for idx, j in enumerate(jobs_list, 1):
        name = j.get("name", j.get("workflow_name", ""))
        desc = j.get("description", "")
        jid = j.get("id", j.get("job_id", "?"))
        parts = []
        if name:
            parts.append(name)
        if desc:
            parts.append(desc)
        parts.append(f"id={jid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt("Select a job number", type=int, err=True)
    if choice < 1 or choice > len(jobs_list):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)

    selected = jobs_list[choice - 1]
    return str(selected.get("id", selected.get("job_id", "")))


def _extract_item_id(item: dict) -> str:
    """Extract the best available ID from a dict, trying common field names."""
    for key in ("id", "_id", "workflowId", "job_id", "rrn"):
        val = item.get(key, "")
        if val:
            return str(val)
    return ""


def _find_job_dicts(data: Any) -> list[dict]:
    """Walk the response to find the largest list of dicts (the jobs array)."""
    if isinstance(data, list):
        # If it's a list of dicts, use it directly
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
                nested = _find_job_dicts(val)
                if len(nested) > len(best):
                    best = nested
        return best
    return []


def _extract_id(item: dict) -> str:
    """Extract an ID from a dict, trying common field names and nested objects."""
    for key in ("id", "job_id", "jobId", "group_id", "workflowId", "_id", "rrn"):
        val = item.get(key)
        if val:
            return str(val)
    # Check nested "job" object (InsightConnect jobs response)
    nested = item.get("job")
    if isinstance(nested, dict):
        for key in ("jobId", "id", "job_id"):
            val = nested.get(key)
            if val:
                return str(val)
    return ""


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
@click.option("-a", "--auto", "auto_poll", is_flag=True,
              help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.pass_context
def artifacts_list(ctx, limit_param, offset, filter_text, auto_poll, interval):
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

        if not auto_poll:
            click.echo(format_output(result, config.output_format, config.limit, config.search))
        else:
            import time as _time
            seen_ids: set[str] = set()
            items = _find_job_dicts(result)
            for item in items:
                item_id = _extract_item_id(item)
                if item_id:
                    seen_ids.add(item_id)
            click.echo(f"Polling for new results every {interval}s (Ctrl+C to stop)...", err=True)
            while True:
                _time.sleep(interval)
                new_result = client.get(url, params=params, solution="soar", subcommand="artifacts-list")
                new_items = _find_job_dicts(new_result)
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


@artifacts.command("get")
@click.option("--id", default=None, help="Artifact ID to retrieve.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select an artifact from the list.")
@click.pass_context
def artifacts_get(ctx, artifact_id, auto_select):
    """Get a global artifact by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)

    if not artifact_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        artifact_id = _interactive_artifact_select(client, config, base)

    url = f"{base}/globalArtifacts/{artifact_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.get(url, solution="soar", subcommand="artifacts-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
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
        click.echo("Provide --data or --data-file with artifact definition.")

    try:
        result = client.post(url, json=body, solution="soar", subcommand="artifacts-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@artifacts.command("delete")
@click.option("--id", default=None, help="Artifact ID to delete.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select an artifact from the list.")
@click.pass_context
def artifacts_delete(ctx, artifact_id, auto_select):
    """Delete a global artifact by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)

    if not artifact_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        artifact_id = _interactive_artifact_select(client, config, base)

    url = f"{base}/globalArtifacts/{artifact_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    try:
        result = client.request("DELETE", url, solution="soar", subcommand="artifacts-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@artifacts.command("entities")
@click.option("--id", default=None, help="Artifact ID to list entities for.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select an artifact from the list.")
@click.option("--limit", "limit_param", type=int, default=30, help="Max entities to return.")
@click.option("--offset", type=int, default=0, help="Offset for pagination.")
@click.pass_context
def artifacts_entities(ctx, artifact_id, auto_select, limit_param, offset):
    """List entities for a global artifact."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)

    if not artifact_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        artifact_id = _interactive_artifact_select(client, config, base)

    url = f"{base}/globalArtifacts/{artifact_id}/entities"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    params: dict = {"limit": limit_param, "offset": offset}

    try:
        result = client.get(url, params=params, solution="soar", subcommand="artifacts-entities")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


def _interactive_artifact_select(client: R7Client, config: Config, base: str) -> str:
    """Fetch artifacts, display a numbered menu, return the selected artifact ID."""
    url = f"{base}/globalArtifacts"
    result = client.get(url, params={"limit": 50}, solution="soar", subcommand="artifacts-list")

    items = _find_job_dicts(result)
    if not items:
        click.echo("No artifacts found.", err=True)
        sys.exit(1)

    click.echo("Available artifacts:", err=True)
    for idx, a in enumerate(items, 1):
        name = a.get("name", "")
        desc = a.get("description", "")
        aid = a.get("id", a.get("artifact_id", "?"))
        parts = []
        if name:
            parts.append(name)
        if desc:
            parts.append(desc)
        parts.append(f"id={aid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt("Select an artifact number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)

    selected = items[choice - 1]
    return str(selected.get("id", selected.get("artifact_id", "")))


def _interactive_workflow_select(client: R7Client, config: Config, state_filter: str | None = None) -> str:
    """Fetch workflows, display a numbered menu, return the selected workflow ID.

    If *state_filter* is set (e.g. "active"), only workflows matching that state are shown.
    """
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/workflows"
    params: dict = {"limit": 30}
    if state_filter:
        params["state"] = state_filter
    result = client.get(url, params=params, solution="soar", subcommand="workflows-list")

    # Workflows are nested under data.workflows
    if isinstance(result, dict):
        items = result.get("data", {}).get("workflows", [])
        if not items:
            items = _find_job_dicts(result)
    elif isinstance(result, list):
        items = result
    else:
        items = []

    if not items:
        click.echo("No workflows found.", err=True)
        sys.exit(1)

    click.echo("Available workflows:", err=True)
    for idx, w in enumerate(items, 1):
        # Get name from publishedVersion first, fall back to unpublishedVersion
        pub = w.get("publishedVersion") or {}
        unpub = w.get("unpublishedVersion") or {}
        name = pub.get("name") or unpub.get("name") or ""
        state = w.get("state", "")
        created_by = pub.get("createdByName") or unpub.get("createdByName") or ""
        wid = w.get("workflowId", w.get("id", "?"))

        parts = []
        if name:
            parts.append(name)
        if state:
            parts.append(f"state={state}")
        if created_by:
            parts.append(f"by={created_by}")
        parts.append(f"id={wid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt("Select a workflow number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)

    selected = items[choice - 1]
    return str(selected.get("workflowId", selected.get("id", "")))


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
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@snippets.command("import")
@click.option("--file", "file_path", type=click.Path(exists=True), default=None,
              help="Path to snippet JSON file.")
@click.pass_context
def snippets_import(ctx, file_path):
    """Import a snippet from a JSON file."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V2_BASE.format(region=config.region)
    url = f"{base}/snippets/import"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    if not file_path:
        click.echo(
            "Provide --file with the path to a snippet JSON file.\n"
            "  Example: r7-cli soar snippets import --file ./snippets/my-snippet.json",
            err=True,
        )
        sys.exit(1)

    import json as _json
    with open(file_path) as fh:
        body = _json.load(fh)

    try:
        result = client.post(url, json=body, solution="soar", subcommand="snippets-import")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
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
@click.option("--file", "file_path", type=click.Path(exists=True), default=None,
              help="Path to plugin JSON file.")
@click.pass_context
def plugins_import(ctx, file_path):
    """Import a custom plugin from a JSON file."""
    config = _get_config(ctx)
    client = R7Client(config)
    base = CONNECT_V1_BASE.format(region=config.region)
    url = f"{base}/customPlugins/import"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}", err=True)

    if not file_path:
        click.echo(
            "Provide --file with the path to a plugin JSON file.\n"
            "  Example: r7-cli soar plugins import --file ./plugins/my-plugin.json",
            err=True,
        )
        sys.exit(1)

    import json as _json
    with open(file_path) as fh:
        body = _json.load(fh)

    try:
        result = client.post(url, json=body, solution="soar", subcommand="plugins-import")
        click.echo(format_output(result, config.output_format, config.limit, config.search))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
