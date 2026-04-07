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
from r7cli.models import ACCOUNT_BASE, IAS_V1_BASE, R7Error, UserInputError
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DOC_BASE = "https://help.rapid7.com/insightappsec/en-us/api/v1/docs.html"

# Cache for resolved user names to avoid repeated API calls
_user_name_cache: dict[str, str] = {}


def _resolve_user_name(client, config, user_id):
    """Resolve a platform user ID to a display name via /account/api/1/users/{id}."""
    if not user_id:
        return ""
    if user_id in _user_name_cache:
        return _user_name_cache[user_id]
    url = ACCOUNT_BASE.format(region=config.region) + f"/users/{user_id}"
    try:
        result = client.get(url, solution="platform", subcommand="users-get")
        first = result.get("first_name", "")
        last = result.get("last_name", "")
        name = f"{first} {last}".strip() or result.get("name", user_id)
        _user_name_cache[user_id] = name
        return name
    except R7Error:
        _user_name_cache[user_id] = user_id
        return user_id


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


def _interactive_select(client, config, list_path, resource_name, params=None):
    """Fetch items from list_path, show numbered menu with name and id, return selected id."""
    url = IAS_V1_BASE.format(region=config.region) + list_path
    result = client.get(url, params=params or {"index": 0, "size": 30}, solution="appsec", subcommand=f"{resource_name}-list")

    # Extract items from response
    items = result.get("data", result) if isinstance(result, dict) else result
    if isinstance(items, dict):
        for val in items.values():
            if isinstance(val, list):
                items = val
                break
    if not isinstance(items, list) or not items:
        click.echo(f"No {resource_name}s found.", err=True)
        sys.exit(1)

    # For scans, resolve app names for better context
    if resource_name == "scan":
        return _interactive_select_scan(client, config, items)

    # For blackouts, show scope, active, and rrule
    if resource_name == "blackout":
        return _interactive_select_blackout(items)

    # For scan-configs, show app name and attack template name
    if resource_name == "scan-config":
        return _interactive_select_scan_config(client, config, items)

    # For schedules, show enabled and rrule
    if resource_name == "schedule":
        return _interactive_select_schedule(items)

    # For targets, show domain and enabled
    if resource_name == "target":
        return _interactive_select_target(items)

    # For reports, show format and status
    if resource_name == "report":
        return _interactive_select_report(items)

    click.echo(f"Available {resource_name}s:", err=True)
    for idx, item in enumerate(items, 1):
        name = item.get("name", item.get("title", ""))
        iid = item.get("id", item.get("_id", "?"))
        parts = []
        if name:
            parts.append(name)
        parts.append(f"id={iid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt(f"Select a {resource_name} number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)
    return str(items[choice - 1].get("id", items[choice - 1].get("_id", "")))


def _interactive_select_scan(client, config, items):
    """Show scan menu with app names, scan-config names, status, and completion time."""
    # Collect unique app IDs and scan-config IDs
    app_ids = set()
    sc_ids = set()
    for item in items:
        app_obj = item.get("app", {})
        if isinstance(app_obj, dict) and app_obj.get("id"):
            app_ids.add(app_obj["id"])
        sc_obj = item.get("scan_config", {})
        if isinstance(sc_obj, dict) and sc_obj.get("id"):
            sc_ids.add(sc_obj["id"])

    base = IAS_V1_BASE.format(region=config.region)

    app_names: dict[str, str] = {}
    for aid in app_ids:
        try:
            app_result = client.get(
                f"{base}/apps/{aid}",
                solution="appsec", subcommand="apps-get",
            )
            app_names[aid] = app_result.get("name", aid)
        except R7Error:
            app_names[aid] = aid

    sc_names: dict[str, str] = {}
    for sid in sc_ids:
        try:
            sc_result = client.get(
                f"{base}/scan-configs/{sid}",
                solution="appsec", subcommand="scan-configs-get",
            )
            sc_names[sid] = sc_result.get("name", sid)
        except R7Error:
            sc_names[sid] = sid

    click.echo("Available scans:", err=True)
    for idx, item in enumerate(items, 1):
        app_obj = item.get("app", {})
        app_id = app_obj.get("id", "") if isinstance(app_obj, dict) else ""
        app_name = app_names.get(app_id, "unknown app")
        sc_obj = item.get("scan_config", {})
        sc_id = sc_obj.get("id", "") if isinstance(sc_obj, dict) else ""
        sc_name = sc_names.get(sc_id, "")
        status = item.get("status", "")
        completion = item.get("completion_time", "")
        scan_id = item.get("id", "?")
        parts = [app_name]
        if sc_name:
            parts.append(f"config={sc_name}")
        if status:
            parts.append(f"status={status}")
        if completion:
            parts.append(completion.split("T")[0] if "T" in completion else completion)
        parts.append(f"id={scan_id}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt("Select a scan number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)
    return str(items[choice - 1].get("id", ""))


def _interactive_select_scan_config(client, config, items):
    """Show scan-config menu with app name and attack template name."""
    base = IAS_V1_BASE.format(region=config.region)

    # Collect unique app IDs and attack template IDs
    app_ids = set()
    tmpl_ids = set()
    for item in items:
        app_obj = item.get("app", {})
        if isinstance(app_obj, dict) and app_obj.get("id"):
            app_ids.add(app_obj["id"])
        tmpl_obj = item.get("attack_template", {})
        if isinstance(tmpl_obj, dict) and tmpl_obj.get("id"):
            tmpl_ids.add(tmpl_obj["id"])

    app_names: dict[str, str] = {}
    for aid in app_ids:
        try:
            app_result = client.get(f"{base}/apps/{aid}", solution="appsec", subcommand="apps-get")
            app_names[aid] = app_result.get("name", aid)
        except R7Error:
            app_names[aid] = aid

    tmpl_names: dict[str, str] = {}
    for tid in tmpl_ids:
        try:
            tmpl_result = client.get(f"{base}/attack-templates/{tid}", solution="appsec", subcommand="attack-templates-get")
            tmpl_names[tid] = tmpl_result.get("name", tid)
        except R7Error:
            tmpl_names[tid] = tid

    click.echo("Available scan-configs:", err=True)
    for idx, item in enumerate(items, 1):
        name = item.get("name", "")
        cid = item.get("id", "?")
        app_obj = item.get("app", {})
        app_id = app_obj.get("id", "") if isinstance(app_obj, dict) else ""
        app_name = app_names.get(app_id, "")
        tmpl_obj = item.get("attack_template", {})
        tmpl_id = tmpl_obj.get("id", "") if isinstance(tmpl_obj, dict) else ""
        tmpl_name = tmpl_names.get(tmpl_id, "")
        parts = []
        if name:
            parts.append(name)
        if app_name:
            parts.append(f"app={app_name}")
        if tmpl_name:
            parts.append(f"template={tmpl_name}")
        parts.append(f"id={cid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt("Select a scan-config number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)
    return str(items[choice - 1].get("id", ""))


def _interactive_select_report(items):
    """Show report menu with name, format, status, and type."""
    click.echo("Available reports:", err=True)
    for idx, item in enumerate(items, 1):
        name = item.get("name", "")
        fmt = item.get("format", "")
        status = item.get("status", "")
        rtype = item.get("type", "")
        rid = item.get("id", "?")
        parts = []
        if name:
            parts.append(name)
        if rtype:
            parts.append(f"type={rtype}")
        if fmt:
            parts.append(f"format={fmt}")
        if status:
            parts.append(f"status={status}")
        parts.append(f"id={rid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt("Select a report number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)
    return str(items[choice - 1].get("id", ""))


def _interactive_select_target(items):
    """Show target menu with domain and enabled."""
    click.echo("Available targets:", err=True)
    for idx, item in enumerate(items, 1):
        domain = item.get("domain", "")
        enabled = item.get("enabled", "")
        tid = item.get("id", "?")
        parts = []
        if domain:
            parts.append(domain)
        parts.append(f"enabled={enabled}")
        parts.append(f"id={tid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt("Select a target number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)
    return str(items[choice - 1].get("id", ""))


def _interactive_select_schedule(items):
    """Show schedule menu with name, enabled, and rrule."""
    click.echo("Available schedules:", err=True)
    for idx, item in enumerate(items, 1):
        name = item.get("name", "")
        enabled = item.get("enabled", "")
        rrule = item.get("rrule", "")
        sid = item.get("id", "?")
        parts = []
        if name:
            parts.append(name)
        parts.append(f"enabled={enabled}")
        if rrule:
            parts.append(f"rrule={rrule}")
        parts.append(f"id={sid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt("Select a schedule number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)
    return str(items[choice - 1].get("id", ""))


def _interactive_select_blackout(items):
    """Show blackout menu with name, scope, active, and rrule."""
    click.echo("Available blackouts:", err=True)
    for idx, item in enumerate(items, 1):
        name = item.get("name", "").strip()
        scope = item.get("scope", "")
        active = item.get("active", "")
        rrule = item.get("rrule", "")
        bid = item.get("id", "?")
        parts = []
        if name:
            parts.append(name)
        if scope:
            parts.append(f"scope={scope}")
        parts.append(f"active={active}")
        if rrule:
            parts.append(f"rrule={rrule}")
        parts.append(f"id={bid}")
        click.echo(f"  {idx}. {' | '.join(parts)}", err=True)

    choice = click.prompt("Select a blackout number", type=int, err=True)
    if choice < 1 or choice > len(items):
        click.echo("Invalid selection.", err=True)
        sys.exit(1)
    return str(items[choice - 1].get("id", ""))


def _fetch_all_pages(client, config, url, params, solution, subcommand):
    """Fetch all pages from a paginated InsightAppSec endpoint."""
    page_size = params.get("size", 50)
    current_index = params.get("index", 0)
    all_items = []

    while True:
        page_params = dict(params, index=current_index)
        result = client.get(url, params=page_params, solution=solution, subcommand=subcommand)

        items = _extract_items(result)
        all_items.extend(items)

        # Determine total pages from metadata
        total_pages = None
        if isinstance(result, dict):
            page_meta = result.get("page", {})
            if isinstance(page_meta, dict):
                total_pages = page_meta.get("totalPages", page_meta.get("total_pages"))
            metadata = result.get("metadata", {})
            if isinstance(metadata, dict) and total_pages is None:
                total_pages = metadata.get("totalPages", metadata.get("total_pages"))

        current_index += 1

        if total_pages is not None:
            if current_index >= total_pages:
                break
        else:
            # Fallback: stop when returned items < page size
            if len(items) < page_size:
                break

    return all_items


def _fetch_all_pages_post(client, config, url, params, body, solution, subcommand):
    """Fetch all pages from a paginated InsightAppSec POST endpoint (e.g. /search)."""
    page_size = params.get("size", 50)
    current_index = params.get("index", 0)
    all_items = []

    while True:
        page_params = dict(params, index=current_index)
        result = client.post(url, json=body, params=page_params, solution=solution, subcommand=subcommand)

        items = _extract_items(result)
        all_items.extend(items)

        total_pages = None
        if isinstance(result, dict):
            page_meta = result.get("page", {})
            if isinstance(page_meta, dict):
                total_pages = page_meta.get("totalPages", page_meta.get("total_pages"))
            metadata = result.get("metadata", {})
            if isinstance(metadata, dict) and total_pages is None:
                total_pages = metadata.get("totalPages", metadata.get("total_pages"))

        current_index += 1

        if total_pages is not None:
            if current_index >= total_pages:
                break
        else:
            if len(items) < page_size:
                break

    return all_items


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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def apps_list(ctx, index, size, auto_poll, interval, all_pages):
    """List applications."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/apps"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-apps", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "apps-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="apps-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="apps-list")
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


@apps.command("get")
@click.option("-j", "--id", "item_id", default=None, help="App ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def apps_get(ctx, item_id, auto_select):
    """Get an application by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/apps", "app")

    url = IAS_V1_BASE.format(region=config.region) + f"/apps/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-app", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="apps-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo(
            "Provide --data or --data-file with a JSON body containing the app definition.\n\n"
            "Example:\n"
            '  r7-cli appsec apps create --data \'{"name": "My App", "type": "WEB"}\'\n',
            err=True,
        )
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="apps-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@apps.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="App ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def apps_delete(ctx, item_id, auto_select):
    """Delete an application by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/apps", "app")

    url = IAS_V1_BASE.format(region=config.region) + f"/apps/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/delete-app", err=True)

    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="apps-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@apps.command("update")
@click.option("-j", "--id", "item_id", default=None, help="App ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for app update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def apps_update(ctx, item_id, auto_select, data_str, data_file):
    """Update an application by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/apps", "app")

    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the updated app definition.", err=True)
        sys.exit(1)

    url = IAS_V1_BASE.format(region=config.region) + f"/apps/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/update-app", err=True)

    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="apps-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec scans
# ---------------------------------------------------------------------------


def _resolve_scan_config_id_by_name(client, config, name):
    """Fetch scan configs and return the ID of the first matching *name* (case-insensitive)."""
    url = IAS_V1_BASE.format(region=config.region) + "/scan-configs"
    all_configs = _fetch_all_pages(client, config, url, {"index": 0, "size": 50}, "appsec", "scan-configs-list")
    name_lower = name.lower()
    for sc in all_configs:
        if sc.get("name", "").lower() == name_lower:
            return sc.get("id")
    for sc in all_configs:
        if name_lower in sc.get("name", "").lower():
            return sc.get("id")
    click.echo(f"No scan config found matching name '{name}'.", err=True)
    sys.exit(1)


def _filter_scans(items, app_id=None, config_id=None, status=None, completion_date=None):
    """Apply client-side filters to a list of scan dicts."""
    filtered = items
    if app_id:
        filtered = [s for s in filtered if isinstance(s.get("app"), dict) and s["app"].get("id") == app_id]
    if config_id:
        filtered = [s for s in filtered if isinstance(s.get("scan_config"), dict) and s["scan_config"].get("id") == config_id]
    if status:
        stat_upper = status.upper()
        filtered = [s for s in filtered if s.get("status", "").upper() == stat_upper]
    if completion_date:
        cmp_func, dt_threshold = _parse_date_expr(completion_date)
        filtered = [s for s in filtered if _parse_dt(s.get("completion_time")) and cmp_func(_parse_dt(s["completion_time"]), dt_threshold)]
    return filtered

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def scans(ctx):
    """InsightAppSec scan commands."""
    pass


@scans.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("--name", "app_name", default=None, help="Filter by app name.")
@click.option("-j", "--app-id", "filter_app_id", default=None, help="Filter by app ID.")
@click.option("--config-name", default=None, help="Filter by scan config name.")
@click.option("--config-id", default=None, help="Filter by scan config ID.")
@click.option("--status", default=None, help="Filter by status (e.g. COMPLETE, FAILED).")
@click.option("--date", "completion_date", default=None, help="Filter on completion_time (e.g. '>=2025-01-01', '<2025-06-01').")
@click.pass_context
def scans_list(ctx, index, size, auto_poll, interval, all_pages, app_name, filter_app_id, config_name, config_id, status, completion_date):
    """List scans."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/scans"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scans", err=True)

    params = {"index": index, "size": size}

    # Resolve --name to app ID
    resolved_app_id = filter_app_id
    if app_name:
        resolved_app_id = _resolve_app_id_by_name(client, config, app_name)

    # Resolve --config-name to config ID
    resolved_config_id = config_id
    if config_name:
        resolved_config_id = _resolve_scan_config_id_by_name(client, config, config_name)

    has_filters = any([resolved_app_id, resolved_config_id, status, completion_date])

    try:
        if all_pages or has_filters:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "scans-list")
            if has_filters:
                all_items = _filter_scans(all_items, app_id=resolved_app_id, config_id=resolved_config_id, status=status, completion_date=completion_date)
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="scans-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="scans-list")
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
@click.option("-j", "--id", "item_id", default=None, help="Scan ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scans_get(ctx, item_id, auto_select):
    """Get a scan by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scans", "scan")

    url = IAS_V1_BASE.format(region=config.region) + f"/scans/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scans-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo(
            "Provide --data or --data-file with a JSON body containing the scan config ID.\n\n"
            "Example:\n"
            '  r7-cli appsec scans submit --data \'{"scan_config": {"id": "<SCAN_CONFIG_ID>"}}\'\n\n'
            "To find your scan config IDs:\n"
            "  r7-cli appsec scan-configs list",
            err=True,
        )
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="scans-submit")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("action")
@click.option("-j", "--id", "item_id", default=None, help="Scan ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.argument("action_type", type=click.Choice(["Pause", "Resume", "Stop", "Cancel"], case_sensitive=False))
@click.pass_context
def scans_action(ctx, item_id, auto_select, action_type):
    """Submit an action (Pause/Resume/Stop/Cancel) on a scan."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scans", "scan")

    url = IAS_V1_BASE.format(region=config.region) + f"/scans/{item_id}/action"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/submit-scan-action", err=True)

    try:
        result = client.request("PUT", url, json={"action": action_type.upper()},
                                solution="appsec", subcommand="scans-action")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("details")
@click.option("-j", "--id", "item_id", default=None, help="Scan ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scans_details(ctx, item_id, auto_select):
    """Get scan execution details."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scans", "scan")

    url = IAS_V1_BASE.format(region=config.region) + f"/scans/{item_id}/execution-details"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-execution-details", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scans-details")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Scan ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scans_delete(ctx, item_id, auto_select):
    """Delete a scan by ID (must be in Failed state)."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scans", "scan")

    url = IAS_V1_BASE.format(region=config.region) + f"/scans/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/delete-scan", err=True)

    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="scans-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("engine-events")
@click.option("-j", "--id", "item_id", default=None, help="Scan ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scans_engine_events(ctx, item_id, auto_select):
    """Get engine events for a scan."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scans", "scan")

    url = IAS_V1_BASE.format(region=config.region) + f"/scans/{item_id}/engine-events"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-engine-events", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scans-engine-events")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scans.command("platform-events")
@click.option("-j", "--id", "item_id", default=None, help="Scan ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scans_platform_events(ctx, item_id, auto_select):
    """Get platform events for a scan."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scans", "scan")

    url = IAS_V1_BASE.format(region=config.region) + f"/scans/{item_id}/platform-events"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-platform-events", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scans-platform-events")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def scan_configs_list(ctx, index, size, auto_poll, interval, all_pages):
    """List scan configurations."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/scan-configs"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-configs", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "scan-configs-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="scan-configs-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="scan-configs-list")
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


@scan_configs.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Scan config ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scan_configs_get(ctx, item_id, auto_select):
    """Get a scan configuration by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scan-configs", "scan-config")

    url = IAS_V1_BASE.format(region=config.region) + f"/scan-configs/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-config", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scan-configs-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo(
            "Provide --data or --data-file with a JSON body containing the scan config.\n\n"
            "Example:\n"
            '  r7-cli appsec scan-configs create --data \'{"name": "My Config", "app": {"id": "<APP_ID>"}, '
            '"attack_template": {"id": "<TEMPLATE_ID>"}}\'\n\n'
            "To find your app IDs:\n"
            "  r7-cli appsec apps list\n\n"
            "To find attack template IDs:\n"
            "  r7-cli appsec attack-templates list",
            err=True,
        )
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="scan-configs-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scan_configs.command("options")
@click.option("-j", "--id", "item_id", default=None, help="Scan config ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scan_configs_options(ctx, item_id, auto_select):
    """Get scan config options."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scan-configs", "scan-config")

    url = IAS_V1_BASE.format(region=config.region) + f"/scan-configs/{item_id}/options"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-scan-config-options", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="scan-configs-options")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scan_configs.command("update")
@click.option("-j", "--id", "item_id", default=None, help="Scan config ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for scan config update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def scan_configs_update(ctx, item_id, auto_select, data_str, data_file):
    """Update a scan configuration by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scan-configs", "scan-config")

    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the updated scan config.", err=True)
        sys.exit(1)

    url = IAS_V1_BASE.format(region=config.region) + f"/scan-configs/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/update-scan-config", err=True)

    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="scan-configs-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@scan_configs.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Scan config ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def scan_configs_delete(ctx, item_id, auto_select):
    """Delete a scan configuration by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/scan-configs", "scan-config")

    url = IAS_V1_BASE.format(region=config.region) + f"/scan-configs/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/delete-scan-config", err=True)

    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="scan-configs-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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


def _resolve_app_id_by_name(client, config, name):
    """Fetch apps and return the ID of the first app matching *name* (case-insensitive)."""
    url = IAS_V1_BASE.format(region=config.region) + "/apps"
    all_apps = _fetch_all_pages(client, config, url, {"index": 0, "size": 50}, "appsec", "apps-list")
    name_lower = name.lower()
    for app in all_apps:
        app_name = app.get("name", "")
        if app_name.lower() == name_lower:
            return app.get("id")
    # Partial match fallback
    for app in all_apps:
        app_name = app.get("name", "")
        if name_lower in app_name.lower():
            return app.get("id")
    click.echo(f"No app found matching name '{name}'.", err=True)
    sys.exit(1)


def _parse_cmp_op(expr):
    """Extract (operator_symbol, operator_func, remainder) from an expression.

    Supported operators: >=, <=, >, <, =
    If no operator prefix is found returns ('=', operator.eq, expr).
    """
    import operator as _op
    expr = expr.strip()
    for sym, func in [(">=", _op.ge), ("<=", _op.le), (">", _op.gt), ("<", _op.lt), ("=", _op.eq)]:
        if expr.startswith(sym):
            return sym, func, expr[len(sym):].strip()
    return "=", _op.eq, expr


def _parse_score_expr(expr):
    """Parse a score expression like '>=7.5' into (operator_func, threshold)."""
    _, func, val = _parse_cmp_op(expr)
    try:
        return func, float(val)
    except ValueError:
        raise UserInputError(f"Invalid --score format '{expr}'. Use e.g. --score '>=7.5', --score '<5', --score '=9.8'")


def _parse_date_expr(expr):
    """Parse a date expression like '>=2025-01-01' into (operator_func, datetime).

    Supported operators: >=, <=, >, <, =
    If no operator prefix, defaults to '=' (exact date match).
    """
    from datetime import datetime
    _, func, val = _parse_cmp_op(expr)
    try:
        dt = datetime.fromisoformat(val)
    except ValueError:
        raise UserInputError(f"Invalid date in '{expr}'. Use ISO format e.g. '>=2025-01-01'")
    return func, dt


def _filter_vulns(items, app_id=None, severity=None, status=None,
                  last_discovered=None, first_discovered=None,
                  newly_discovered=None, score=None):
    """Apply client-side filters to a list of vulnerability dicts."""
    filtered = items
    if app_id:
        filtered = [v for v in filtered if isinstance(v.get("app"), dict) and v["app"].get("id") == app_id]
    if severity:
        sev_upper = severity.upper()
        filtered = [v for v in filtered if v.get("severity", "").upper() == sev_upper]
    if status:
        stat_upper = status.upper()
        filtered = [v for v in filtered if v.get("status", "").upper() == stat_upper]
    if last_discovered:
        cmp_func, dt_threshold = _parse_date_expr(last_discovered)
        filtered = [v for v in filtered if _parse_dt(v.get("last_discovered")) and cmp_func(_parse_dt(v["last_discovered"]), dt_threshold)]
    if first_discovered:
        cmp_func, dt_threshold = _parse_date_expr(first_discovered)
        filtered = [v for v in filtered if _parse_dt(v.get("first_discovered")) and cmp_func(_parse_dt(v["first_discovered"]), dt_threshold)]
    if newly_discovered is not None:
        target = newly_discovered.lower() in ("true", "1", "yes")
        filtered = [v for v in filtered if v.get("newly_discovered") is target]
    if score:
        cmp_func, threshold = _parse_score_expr(score)
        filtered = [v for v in filtered if v.get("vulnerability_score") is not None and cmp_func(float(v["vulnerability_score"]), threshold)]
    return filtered


def _parse_dt(val):
    """Parse an ISO datetime string, returning None on failure."""
    if not val:
        return None
    from datetime import datetime
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


@vulns.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("--name", "app_name", default=None, help="Filter by app name (resolves to app ID).")
@click.option("-j", "--app-id", "filter_app_id", default=None, help="Filter by app ID.")
@click.option("--severity", type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False), default=None, help="Filter by severity.")
@click.option("--status", type=click.Choice(["VERIFIED", "UNREVIEWED", "FALSE_POSITIVE"], case_sensitive=False), default=None, help="Filter by status.")
@click.option("--last-discovered", default=None, help="Filter on last_discovered date (e.g. '>=2025-01-01', '<2025-06-01').")
@click.option("--first-discovered", default=None, help="Filter on first_discovered date (e.g. '>=2025-01-01', '<2025-06-01').")
@click.option("--newly-discovered", default=None, help="Filter on newly_discovered (true/false).")
@click.option("--score", default=None, help="Filter by vulnerability_score (e.g. '>=7.5', '<5', '=9.8').")
@click.option("--remediated", type=click.Choice(["true", "false"], case_sensitive=False), default=None, help="Filter on remediated vulns (uses /search API).")
@click.pass_context
def vulns_list(ctx, index, size, auto_poll, interval, all_pages, app_name, filter_app_id, severity, status, last_discovered, first_discovered, newly_discovered, score, remediated):
    """List vulnerabilities."""
    config = _get_config(ctx)
    client = R7Client(config)

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerabilities", err=True)

    # --remediated uses the /search endpoint with a different query
    if remediated:
        is_remediated = remediated.lower() == "true"
        status_val = "REMEDIATED" if is_remediated else "!REMEDIATED"
        search_url = IAS_V1_BASE.format(region=config.region) + "/search"
        if is_remediated:
            body = {"type": "VULNERABILITY", "query": "vulnerability.status = 'REMEDIATED'"}
        else:
            body = {"type": "VULNERABILITY", "query": "vulnerability.status != 'REMEDIATED'"}
        params = {"index": index, "size": size}
        try:
            if all_pages:
                all_items = _fetch_all_pages_post(client, config, search_url, params, body, "appsec", "vulns-search")
            else:
                result = client.post(search_url, json=body, params=params, solution="appsec", subcommand="vulns-search")
                all_items = _extract_items(result)

            # Apply remaining client-side filters
            resolved_app_id = filter_app_id
            if app_name:
                resolved_app_id = _resolve_app_id_by_name(client, config, app_name)
            has_extra = any([resolved_app_id, severity, last_discovered, first_discovered, newly_discovered, score])
            if has_extra:
                all_items = _filter_vulns(all_items, app_id=resolved_app_id, severity=severity, last_discovered=last_discovered, first_discovered=first_discovered, newly_discovered=newly_discovered, score=score)
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
        except R7Error as exc:
            click.echo(str(exc), err=True)
            sys.exit(exc.exit_code)
        return

    url = IAS_V1_BASE.format(region=config.region) + "/vulnerabilities"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerabilities", err=True)

    params = {"index": index, "size": size}

    # Resolve --name to an app ID
    resolved_app_id = filter_app_id
    if app_name:
        resolved_app_id = _resolve_app_id_by_name(client, config, app_name)

    has_filters = any([resolved_app_id, severity, status, last_discovered, first_discovered, newly_discovered, score])

    try:
        if all_pages or has_filters:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "vulns-list")
            if has_filters:
                all_items = _filter_vulns(all_items, app_id=resolved_app_id, severity=severity, status=status, last_discovered=last_discovered, first_discovered=first_discovered, newly_discovered=newly_discovered, score=score)
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="vulns-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="vulns-list")
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


@vulns.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Vulnerability ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def vulns_get(ctx, item_id, auto_select):
    """Get a vulnerability by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/vulnerabilities", "vulnerability")

    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerability", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="vulns-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@vulns.command("discoveries")
@click.option("-j", "--id", "item_id", default=None, help="Vulnerability ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def vulns_discoveries(ctx, item_id, auto_select):
    """Get vulnerability discoveries."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/vulnerabilities", "vulnerability")

    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{item_id}/discoveries"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerability-discoveries", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="vulns-discoveries")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@vulns.command("history")
@click.option("-j", "--id", "item_id", default=None, help="Vulnerability ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def vulns_history(ctx, item_id, auto_select):
    """Get vulnerability history."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/vulnerabilities", "vulnerability")

    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{item_id}/history"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerability-history", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="vulns-history")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@vulns.command("update")
@click.option("-j", "--id", "item_id", default=None, help="Vulnerability ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for vulnerability update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def vulns_update(ctx, item_id, auto_select, data_str, data_file):
    """Update a vulnerability by ID (e.g. change severity or status)."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/vulnerabilities", "vulnerability")

    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the updated vulnerability fields.", err=True)
        sys.exit(1)

    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/update-vulnerability", err=True)

    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="vulns-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec vulns comments
# ---------------------------------------------------------------------------

@vulns.group("comments", cls=GlobalFlagHintGroup)
@click.pass_context
def vuln_comments(ctx):
    """Vulnerability comment commands."""
    pass


@vuln_comments.command("list")
@click.option("-j", "--id", "vuln_id", default=None, help="Vulnerability ID (optional — omit to list all comments across all vulns).")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select vulnerability.")
@click.pass_context
def vuln_comments_list(ctx, vuln_id, auto_select):
    """List comments for a vulnerability.

    When called without --id, fetches all vulnerabilities and lists
    comments for each one that has them. Author names are resolved
    from the platform user API.
    """
    config = _get_config(ctx)
    client = R7Client(config)

    if auto_select:
        vuln_id = _interactive_select(client, config, "/vulnerabilities", "vulnerability")

    if vuln_id:
        # Single vuln mode
        url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{vuln_id}/comments"
        if config.verbose:
            click.echo(f"Docs: {_DOC_BASE}#operation/get-vulnerability-comments", err=True)
        try:
            result = client.get(url, solution="appsec", subcommand="vulns-comments-list")
            comments = _extract_items(result)
            for comment in comments:
                author_obj = comment.get("author", {})
                author_id = author_obj.get("id", "") if isinstance(author_obj, dict) else ""
                if author_id:
                    comment["author_name"] = _resolve_user_name(client, config, author_id)
                update_obj = comment.get("last_update_author", {})
                update_id = update_obj.get("id", "") if isinstance(update_obj, dict) else ""
                if update_id:
                    comment["last_update_author_name"] = _resolve_user_name(client, config, update_id)
            click.echo(format_output(comments if comments else result, config.output_format, config.limit, config.search, short=config.short))
        except R7Error as exc:
            click.echo(str(exc), err=True)
            sys.exit(exc.exit_code)
        return

    # All vulns mode — fetch all vulns, then get comments for each
    base = IAS_V1_BASE.format(region=config.region)
    if config.verbose:
        click.echo("Fetching all vulnerabilities to find comments...", err=True)
    all_vulns = _fetch_all_pages(client, config, base + "/vulnerabilities", {"index": 0, "size": 50}, "appsec", "vulns-list")
    all_commented: list[dict] = []
    for vuln in all_vulns:
        vid = vuln.get("id", "")
        if not vid:
            continue
        try:
            comments_result = client.get(base + f"/vulnerabilities/{vid}/comments", solution="appsec", subcommand="vulns-comments-list")
            comments = _extract_items(comments_result)
            if not comments:
                continue
            vuln_name = vuln.get("root_cause", {}).get("url", "") if isinstance(vuln.get("root_cause"), dict) else ""
            for comment in comments:
                author_obj = comment.get("author", {})
                author_id = author_obj.get("id", "") if isinstance(author_obj, dict) else ""
                update_obj = comment.get("last_update_author", {})
                update_id = update_obj.get("id", "") if isinstance(update_obj, dict) else ""
                all_commented.append({
                    "vulnerability_id": vid,
                    "vulnerability_url": vuln_name,
                    "severity": vuln.get("severity", ""),
                    "status": vuln.get("status", ""),
                    "author_name": _resolve_user_name(client, config, author_id) if author_id else "",
                    "last_update_author_name": _resolve_user_name(client, config, update_id) if update_id else "",
                    **comment,
                })
        except R7Error:
            continue
    click.echo(format_output(all_commented, config.output_format, config.limit, config.search, short=config.short))


@vuln_comments.command("create")
@click.option("-j", "--id", "vuln_id", default=None, help="Vulnerability ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select vulnerability.")
@click.option("--data", "data_str", default=None, help="JSON body for comment creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def vuln_comments_create(ctx, vuln_id, auto_select, data_str, data_file):
    """Create a comment on a vulnerability.

    \b
    Example:
      r7-cli appsec vulns comments create --id <VULN_ID> --data '{"content": "Verified and assigned."}'
    """
    config = _get_config(ctx)
    client = R7Client(config)

    if not vuln_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        vuln_id = _interactive_select(client, config, "/vulnerabilities", "vulnerability")

    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo(
            "Provide --data or --data-file with a JSON body containing the comment.\n\n"
            "Example:\n"
            '  r7-cli appsec vulns comments create --id <VULN_ID> --data \'{"content": "Verified and assigned."}\'\n',
            err=True,
        )
        sys.exit(1)

    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{vuln_id}/comments"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/create-vulnerability-comment", err=True)

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="vulns-comments-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@vuln_comments.command("update")
@click.option("-j", "--id", "vuln_id", default=None, help="Vulnerability ID.")
@click.option("--comment-id", required=True, help="Comment ID to update.")
@click.option("--data", "data_str", default=None, help="JSON body for comment update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def vuln_comments_update(ctx, vuln_id, comment_id, data_str, data_file):
    """Update a comment on a vulnerability.

    \b
    Example:
      r7-cli appsec vulns comments update --id <VULN_ID> --comment-id <COMMENT_ID> --data '{"content": "Updated note."}'
    """
    config = _get_config(ctx)
    client = R7Client(config)

    if not vuln_id:
        raise click.ClickException("Provide --id for the vulnerability.")

    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo(
            "Provide --data or --data-file with a JSON body containing the updated comment.\n\n"
            "Example:\n"
            '  r7-cli appsec vulns comments update --id <VULN_ID> --comment-id <COMMENT_ID> '
            '--data \'{"content": "Updated note."}\'\n',
            err=True,
        )
        sys.exit(1)

    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{vuln_id}/comments/{comment_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/update-vulnerability-comment", err=True)

    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="vulns-comments-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@vuln_comments.command("delete")
@click.option("-j", "--id", "vuln_id", default=None, help="Vulnerability ID.")
@click.option("--comment-id", required=True, help="Comment ID to delete.")
@click.pass_context
def vuln_comments_delete(ctx, vuln_id, comment_id):
    """Delete a comment on a vulnerability."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not vuln_id:
        raise click.ClickException("Provide --id for the vulnerability.")

    url = IAS_V1_BASE.format(region=config.region) + f"/vulnerabilities/{vuln_id}/comments/{comment_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/delete-vulnerability-comment", err=True)

    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="vulns-comments-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def engines_list(ctx, index, size, auto_poll, interval, all_pages):
    """List engines."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/engines"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-engines", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "engines-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="engines-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="engines-list")
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
@click.option("-j", "--id", "item_id", default=None, help="Engine ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def engines_get(ctx, item_id, auto_select):
    """Get an engine by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/engines", "engine")

    url = IAS_V1_BASE.format(region=config.region) + f"/engines/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-engine", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="engines-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engines.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for engine creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def engines_create(ctx, data_str, data_file):
    """Create an engine."""
    config = _get_config(ctx)
    client = R7Client(config)
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the engine definition.", err=True)
        sys.exit(1)
    url = IAS_V1_BASE.format(region=config.region) + "/engines"
    try:
        result = client.post(url, json=body, solution="appsec", subcommand="engines-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engines.command("update")
@click.option("-j", "--id", "item_id", default=None, help="Engine ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for engine update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def engines_update(ctx, item_id, auto_select, data_str, data_file):
    """Update an engine by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/engines", "engine")
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the updated engine definition.", err=True)
        sys.exit(1)
    url = IAS_V1_BASE.format(region=config.region) + f"/engines/{item_id}"
    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="engines-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engines.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Engine ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def engines_delete(ctx, item_id, auto_select):
    """Delete an engine by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/engines", "engine")
    url = IAS_V1_BASE.format(region=config.region) + f"/engines/{item_id}"
    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="engines-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def engine_groups_list(ctx, index, size, auto_poll, interval, all_pages):
    """List engine groups."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/engine-groups"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-engine-groups", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "engine-groups-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="engine-groups-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="engine-groups-list")
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


@engine_groups.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Engine group ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def engine_groups_get(ctx, item_id, auto_select):
    """Get an engine group by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/engine-groups", "engine-group")

    url = IAS_V1_BASE.format(region=config.region) + f"/engine-groups/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-engine-group", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="engine-groups-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engine_groups.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for engine group creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def engine_groups_create(ctx, data_str, data_file):
    """Create an engine group."""
    config = _get_config(ctx)
    client = R7Client(config)
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the engine group definition.", err=True)
        sys.exit(1)
    url = IAS_V1_BASE.format(region=config.region) + "/engine-groups"
    try:
        result = client.post(url, json=body, solution="appsec", subcommand="engine-groups-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engine_groups.command("update")
@click.option("-j", "--id", "item_id", default=None, help="Engine group ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for engine group update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def engine_groups_update(ctx, item_id, auto_select, data_str, data_file):
    """Update an engine group by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/engine-groups", "engine-group")
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the updated engine group.", err=True)
        sys.exit(1)
    url = IAS_V1_BASE.format(region=config.region) + f"/engine-groups/{item_id}"
    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="engine-groups-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engine_groups.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Engine group ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def engine_groups_delete(ctx, item_id, auto_select):
    """Delete an engine group by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/engine-groups", "engine-group")
    url = IAS_V1_BASE.format(region=config.region) + f"/engine-groups/{item_id}"
    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="engine-groups-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@engine_groups.command("engines")
@click.option("-j", "--id", "item_id", default=None, help="Engine group ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def engine_groups_engines(ctx, item_id, auto_select):
    """List engines in an engine group."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/engine-groups", "engine-group")
    url = IAS_V1_BASE.format(region=config.region) + f"/engine-groups/{item_id}/engines"
    try:
        result = client.get(url, solution="appsec", subcommand="engine-groups-engines")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def schedules_list(ctx, index, size, auto_poll, interval, all_pages):
    """List schedules."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/schedules"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-schedules", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "schedules-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="schedules-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="schedules-list")
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


@schedules.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Schedule ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def schedules_get(ctx, item_id, auto_select):
    """Get a schedule by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/schedules", "schedule")

    url = IAS_V1_BASE.format(region=config.region) + f"/schedules/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-schedule", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="schedules-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo(
            "Provide --data or --data-file with a JSON body containing the schedule definition.\n\n"
            "Example:\n"
            '  r7-cli appsec schedules create --data \'{"name": "Weekly Scan", "scan_config": {"id": "<SCAN_CONFIG_ID>"}, '
            '"frequency": {"type": "WEEKLY", "interval": 1}}\'\n\n'
            "To find your scan config IDs:\n"
            "  r7-cli appsec scan-configs list",
            err=True,
        )
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="schedules-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@schedules.command("update")
@click.option("-j", "--id", "item_id", default=None, help="Schedule ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for schedule update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def schedules_update(ctx, item_id, auto_select, data_str, data_file):
    """Update a schedule by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/schedules", "schedule")
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the updated schedule.", err=True)
        sys.exit(1)
    url = IAS_V1_BASE.format(region=config.region) + f"/schedules/{item_id}"
    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="schedules-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@schedules.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Schedule ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def schedules_delete(ctx, item_id, auto_select):
    """Delete a schedule by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/schedules", "schedule")
    url = IAS_V1_BASE.format(region=config.region) + f"/schedules/{item_id}"
    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="schedules-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def blackouts_list(ctx, index, size, auto_poll, interval, all_pages):
    """List blackouts."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/blackouts"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-blackouts", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "blackouts-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="blackouts-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="blackouts-list")
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


@blackouts.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Blackout ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def blackouts_get(ctx, item_id, auto_select):
    """Get a blackout by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/blackouts", "blackout")

    url = IAS_V1_BASE.format(region=config.region) + f"/blackouts/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-blackout", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="blackouts-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@blackouts.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for blackout creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def blackouts_create(ctx, data_str, data_file):
    """Create a blackout."""
    config = _get_config(ctx)
    client = R7Client(config)
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the blackout definition.", err=True)
        sys.exit(1)
    url = IAS_V1_BASE.format(region=config.region) + "/blackouts"
    try:
        result = client.post(url, json=body, solution="appsec", subcommand="blackouts-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@blackouts.command("update")
@click.option("-j", "--id", "item_id", default=None, help="Blackout ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for blackout update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def blackouts_update(ctx, item_id, auto_select, data_str, data_file):
    """Update a blackout by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/blackouts", "blackout")
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the updated blackout.", err=True)
        sys.exit(1)
    url = IAS_V1_BASE.format(region=config.region) + f"/blackouts/{item_id}"
    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="blackouts-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@blackouts.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Blackout ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def blackouts_delete(ctx, item_id, auto_select):
    """Delete a blackout by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/blackouts", "blackout")
    url = IAS_V1_BASE.format(region=config.region) + f"/blackouts/{item_id}"
    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="blackouts-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def attack_templates_list(ctx, index, size, auto_poll, interval, all_pages):
    """List attack templates."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/attack-templates"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-attack-templates", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "attack-templates-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="attack-templates-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="attack-templates-list")
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


@attack_templates.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Attack template ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def attack_templates_get(ctx, item_id, auto_select):
    """Get an attack template by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/attack-templates", "attack-template")

    url = IAS_V1_BASE.format(region=config.region) + f"/attack-templates/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-attack-template", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="attack-templates-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@attack_templates.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for attack template creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def attack_templates_create(ctx, data_str, data_file):
    """Create a custom attack template."""
    config = _get_config(ctx)
    client = R7Client(config)
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the attack template definition.", err=True)
        sys.exit(1)
    url = IAS_V1_BASE.format(region=config.region) + "/attack-templates"
    try:
        result = client.post(url, json=body, solution="appsec", subcommand="attack-templates-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@attack_templates.command("update")
@click.option("-j", "--id", "item_id", default=None, help="Attack template ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for attack template update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def attack_templates_update(ctx, item_id, auto_select, data_str, data_file):
    """Update an attack template by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/attack-templates", "attack-template")
    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo("Provide --data or --data-file with the updated attack template.", err=True)
        sys.exit(1)
    url = IAS_V1_BASE.format(region=config.region) + f"/attack-templates/{item_id}"
    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="attack-templates-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@attack_templates.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Attack template ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def attack_templates_delete(ctx, item_id, auto_select):
    """Delete an attack template by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/attack-templates", "attack-template")
    url = IAS_V1_BASE.format(region=config.region) + f"/attack-templates/{item_id}"
    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="attack-templates-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def targets_list(ctx, index, size, auto_poll, interval, all_pages):
    """List targets."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/targets"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-targets", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "targets-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="targets-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="targets-list")
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


@targets.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Target ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def targets_get(ctx, item_id, auto_select):
    """Get a target by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/targets", "target")

    url = IAS_V1_BASE.format(region=config.region) + f"/targets/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-target", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="targets-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@targets.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for target creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def targets_create(ctx, data_str, data_file):
    """Create a target.

    \b
    Example:
      r7-cli appsec targets create --data '{"domain": "example.com", "enabled": true}'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/targets"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/create-target", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo(
            "Provide --data or --data-file with a JSON body containing the target definition.\n\n"
            "Example:\n"
            '  r7-cli appsec targets create --data \'{"domain": "example.com", "enabled": true}\'\n',
            err=True,
        )
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="targets-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@targets.command("update")
@click.option("-j", "--id", "item_id", default=None, help="Target ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for target update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def targets_update(ctx, item_id, auto_select, data_str, data_file):
    """Update a target by ID.

    \b
    Example:
      r7-cli appsec targets update --id <TARGET_ID> --data '{"domain": "new.example.com", "enabled": false}'
    """
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/targets", "target")

    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo(
            "Provide --data or --data-file with a JSON body containing the updated target.\n\n"
            "Example:\n"
            '  r7-cli appsec targets update --id <TARGET_ID> --data \'{"domain": "new.example.com", "enabled": false}\'\n',
            err=True,
        )
        sys.exit(1)

    url = IAS_V1_BASE.format(region=config.region) + f"/targets/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/update-target", err=True)

    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="targets-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@targets.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Target ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def targets_delete(ctx, item_id, auto_select):
    """Delete a target by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/targets", "target")

    url = IAS_V1_BASE.format(region=config.region) + f"/targets/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/delete-target", err=True)

    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="targets-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def modules_list(ctx, index, size, auto_poll, interval, all_pages):
    """List vulnerability modules."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/modules"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-modules", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "modules-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="modules-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="modules-list")
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


@modules.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Module ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def modules_get(ctx, item_id, auto_select):
    """Get a vulnerability module by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/modules", "module")

    url = IAS_V1_BASE.format(region=config.region) + f"/modules/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-module", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="modules-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec reports
# ---------------------------------------------------------------------------


def _filter_reports(items, report_type=None, report_format=None, status=None, report_name=None, generated_date=None, app_id=None):
    """Apply client-side filters to a list of report dicts."""
    filtered = items
    if report_type:
        rt_upper = report_type.upper()
        filtered = [r for r in filtered if r.get("type", "").upper() == rt_upper]
    if report_format:
        rf_upper = report_format.upper()
        filtered = [r for r in filtered if r.get("format", "").upper() == rf_upper]
    if status:
        st_upper = status.upper()
        filtered = [r for r in filtered if r.get("status", "").upper() == st_upper]
    if report_name:
        name_lower = report_name.lower()
        filtered = [r for r in filtered if name_lower in r.get("name", "").lower()]
    if generated_date:
        cmp_func, dt_threshold = _parse_date_expr(generated_date)
        filtered = [r for r in filtered if _parse_dt(r.get("generated_date")) and cmp_func(_parse_dt(r["generated_date"]), dt_threshold)]
    if app_id:
        filtered = [r for r in filtered if isinstance(r.get("app"), dict) and r["app"].get("id") == app_id]
    return filtered

@appsec.group(cls=GlobalFlagHintGroup)
@click.pass_context
def reports(ctx):
    """InsightAppSec report commands."""
    pass


@reports.command("list")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.option("--type", "report_type", default=None, help="Filter by report type (e.g. VULN_SUMMARY, PCI_COMPLIANCE, VULN_REMEDIATION).")
@click.option("--format", "report_format", default=None, help="Filter by format (PDF, HTML, CSV).")
@click.option("--status", default=None, help="Filter by status (e.g. COMPLETE).")
@click.option("--name", "report_name", default=None, help="Filter by report name (substring match).")
@click.option("--date", "generated_date", default=None, help="Filter on generated_date (e.g. '>=2025-01-01').")
@click.option("--app-name", default=None, help="Filter by app name (resolves to app ID).")
@click.option("-j", "--app-id", "filter_app_id", default=None, help="Filter by app ID.")
@click.pass_context
def reports_list(ctx, index, size, auto_poll, interval, all_pages, report_type, report_format, status, report_name, generated_date, app_name, filter_app_id):
    """List reports.

    \b
    Examples:
      # List all reports
      r7-cli appsec reports list

    \b
      # Only PCI compliance reports
      r7-cli appsec reports list --type PCI_COMPLIANCE

    \b
      # PDF reports only
      r7-cli appsec reports list --format PDF

    \b
      # Reports generated after a date
      r7-cli appsec reports list --date '>=2025-06-01'

    \b
      # Reports for a specific app
      r7-cli appsec reports list --app-name 'Juice Shop'

    \b
      # Combine filters
      r7-cli appsec reports list --type VULN_REMEDIATION --format PDF --date '>=2025-01-01'

    \b
      # Search by name
      r7-cli appsec reports list --name 'OWASP'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/reports"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-reports", err=True)

    # Resolve --app-name to app ID
    resolved_app_id = filter_app_id
    if app_name:
        resolved_app_id = _resolve_app_id_by_name(client, config, app_name)

    has_filters = any([report_type, report_format, status, report_name, generated_date, resolved_app_id])

    params = {"index": index, "size": size}

    try:
        if all_pages or has_filters:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "reports-list")
            if has_filters:
                all_items = _filter_reports(all_items, report_type=report_type, report_format=report_format, status=status, report_name=report_name, generated_date=generated_date, app_id=resolved_app_id)
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="reports-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="reports-list")
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


@reports.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Report ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def reports_get(ctx, item_id, auto_select):
    """Get a report by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/reports", "report")

    url = IAS_V1_BASE.format(region=config.region) + f"/reports/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-report", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="reports-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
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
        click.echo(
            "Provide --data or --data-file with a JSON body containing the report definition.\n\n"
            "Example:\n"
            '  r7-cli appsec reports generate --data \'{"type": "SCAN", "scan": {"id": "<SCAN_ID>"}}\'\n\n'
            "To find your scan IDs:\n"
            "  r7-cli appsec scans list",
            err=True,
        )
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="reports-generate")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@reports.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Report ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def reports_delete(ctx, item_id, auto_select):
    """Delete a report by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/reports", "report")
    url = IAS_V1_BASE.format(region=config.region) + f"/reports/{item_id}"
    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="reports-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@reports.command("download")
@click.option("-j", "--id", "item_id", default=None, help="Report ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("-o", "--output", "output_path", default=None, help="Output file path (auto-generated if omitted).")
@click.option("--poll", is_flag=True, help="Poll until report status is COMPLETE before downloading.")
@click.option("--poll-interval", type=int, default=5, help="Seconds between poll attempts (default: 5).")
@click.pass_context
def reports_download(ctx, item_id, auto_select, output_path, poll, poll_interval):
    """Download a report's contents to a file.

    \b
    Examples:
      # Download a report by ID
      r7-cli appsec reports download --id <REPORT_ID>

    \b
      # Interactive selection
      r7-cli appsec reports download --auto

    \b
      # Download to a specific file
      r7-cli appsec reports download --id <REPORT_ID> -o my-report.pdf

    \b
      # Poll until report is ready, then download
      r7-cli appsec reports download --id <REPORT_ID> --poll
    """
    import time as _time
    import httpx

    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/reports", "report")

    base = IAS_V1_BASE.format(region=config.region)

    # Get report metadata to determine format and status
    try:
        meta = client.get(f"{base}/reports/{item_id}", solution="appsec", subcommand="reports-get")
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    report_format = meta.get("format", "PDF").upper()
    report_name = meta.get("name", item_id)
    status = meta.get("status", "")

    # Poll if requested
    if poll and status != "COMPLETE":
        click.echo(f"Report status: {status}. Polling until COMPLETE...", err=True)
        while status != "COMPLETE":
            _time.sleep(poll_interval)
            try:
                meta = client.get(f"{base}/reports/{item_id}", solution="appsec", subcommand="reports-get")
                status = meta.get("status", "")
                if config.verbose:
                    click.echo(f"Status: {status}", err=True)
            except R7Error:
                pass
        click.echo("Report is COMPLETE. Downloading...", err=True)
    elif status != "COMPLETE":
        click.echo(f"Report status is '{status}', not COMPLETE. Use --poll to wait, or try again later.", err=True)
        sys.exit(1)

    # Determine Accept header and file extension
    accept_map = {
        "PDF": ("application/pdf", ".pdf"),
        "HTML": ("application/zip", ".zip"),
        "CSV": ("text/csv", ".csv"),
    }
    accept_type, ext = accept_map.get(report_format, ("application/pdf", ".pdf"))

    # Build output filename
    if not output_path:
        safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in report_name).strip()
        output_path = f"{safe_name}{ext}"

    # Download the report content directly via httpx
    download_url = f"{base}/reports/{item_id}"
    headers = {
        "X-Api-Key": config.api_key,
        "Accept": f"{accept_type}, application/json",
    }

    if config.verbose:
        click.echo(f"GET {download_url}", err=True)
        click.echo(f"Accept: {accept_type}", err=True)

    try:
        with httpx.Client(timeout=float(config.timeout)) as http:
            resp = http.get(download_url, headers=headers)

        if resp.status_code == 204:
            click.echo("Report not ready yet (204 No Content). Use --poll to wait.", err=True)
            sys.exit(1)

        resp.raise_for_status()

        with open(output_path, "wb") as f:
            f.write(resp.content)

        size_kb = len(resp.content) / 1024
        click.echo(f"Downloaded: {output_path} ({size_kb:.1f} KB)", err=True)

    except httpx.HTTPStatusError as exc:
        click.echo(f"Download failed: {exc.response.status_code} {exc.response.reason_phrase}", err=True)
        sys.exit(1)
    except httpx.RequestError as exc:
        click.echo(f"Download failed: {exc}", err=True)
        sys.exit(1)


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
@click.option("-a", "--auto", "auto_poll", is_flag=True, help="Poll for new entries and only print new ones.")
@click.option("-i", "--interval", type=int, default=10, help="Polling interval in seconds (default: 10).")
@click.option("--all-pages", is_flag=True, help="Fetch all pages.")
@click.pass_context
def tags_list(ctx, index, size, auto_poll, interval, all_pages):
    """List tags."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/tags"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-tags", err=True)

    params = {"index": index, "size": size}

    try:
        if all_pages:
            all_items = _fetch_all_pages(client, config, url, params, "appsec", "tags-list")
            click.echo(format_output(all_items, config.output_format, config.limit, config.search, short=config.short))
            return

        result = client.get(url, params=params, solution="appsec", subcommand="tags-list")

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
                new_result = client.get(url, params=params, solution="appsec", subcommand="tags-list")
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


@tags.command("get")
@click.option("-j", "--id", "item_id", default=None, help="Tag ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def tags_get(ctx, item_id, auto_select):
    """Get a tag by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/tags", "tag")

    url = IAS_V1_BASE.format(region=config.region) + f"/tags/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/get-tag", err=True)

    try:
        result = client.get(url, solution="appsec", subcommand="tags-get")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@tags.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for tag creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def tags_create(ctx, data_str, data_file):
    """Create a tag.

    \b
    Example:
      r7-cli appsec tags create --data '{"name": "production", "type": "APP", "app": {"id": "<APP_ID>"}}'
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/tags"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/create-tag", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo(
            "Provide --data or --data-file with a JSON body containing the tag definition.\n\n"
            "Example:\n"
            '  r7-cli appsec tags create --data \'{"name": "production", "type": "APP", "app": {"id": "<APP_ID>"}}\'\n\n'
            "To find your app IDs:\n"
            "  r7-cli appsec apps list",
            err=True,
        )
        sys.exit(1)

    try:
        result = client.post(url, json=body, solution="appsec", subcommand="tags-create")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@tags.command("update")
@click.option("-j", "--id", "item_id", default=None, help="Tag ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.option("--data", "data_str", default=None, help="JSON body for tag update.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def tags_update(ctx, item_id, auto_select, data_str, data_file):
    """Update a tag by ID.

    \b
    Example:
      r7-cli appsec tags update --id <TAG_ID> --data '{"name": "staging"}'
    """
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/tags", "tag")

    body = _resolve_body(data_str, data_file)
    if not body:
        click.echo(
            "Provide --data or --data-file with a JSON body containing the updated tag.\n\n"
            "Example:\n"
            '  r7-cli appsec tags update --id <TAG_ID> --data \'{"name": "staging"}\'\n',
            err=True,
        )
        sys.exit(1)

    url = IAS_V1_BASE.format(region=config.region) + f"/tags/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/update-tag", err=True)

    try:
        result = client.request("PUT", url, json=body, solution="appsec", subcommand="tags-update")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@tags.command("delete")
@click.option("-j", "--id", "item_id", default=None, help="Tag ID.")
@click.option("-a", "--auto", "auto_select", is_flag=True, help="Interactively select from list.")
@click.pass_context
def tags_delete(ctx, item_id, auto_select):
    """Delete a tag by ID."""
    config = _get_config(ctx)
    client = R7Client(config)

    if not item_id and not auto_select:
        raise click.ClickException("Provide --id or use --auto to select interactively.")
    if auto_select:
        item_id = _interactive_select(client, config, "/tags", "tag")

    url = IAS_V1_BASE.format(region=config.region) + f"/tags/{item_id}"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/delete-tag", err=True)

    try:
        result = client.request("DELETE", url, solution="appsec", subcommand="tags-delete")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# appsec search
# ---------------------------------------------------------------------------

@appsec.command("search")
@click.option("--type", "search_type", required=True,
              type=click.Choice(["APP", "SCAN_CONFIG", "SCAN", "VULNERABILITY", "ATTACK_TEMPLATE",
                                 "TARGET", "ENGINE", "ENGINE_GROUP", "SCHEDULE", "BLACKOUT",
                                 "FILE", "TAG", "REPORT"], case_sensitive=False),
              help="Resource type to search.")
@click.option("-q", "--query", "query", required=True, help="Search query string.")
@click.option("--index", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=50, help="Page size (default: 50).")
@click.pass_context
def appsec_search(ctx, search_type, query, index, size):
    """Search InsightAppSec resources.

    \b
    Operators: =, !=, >, >=, <, <=, CONTAINS, STARTS WITH, ENDS WITH,
               LIKE, IS NULL, IS NOT NULL, &&, ||, BETWEEN

    \b
    Examples:
      # Find apps by name
      r7-cli appsec search --type APP -q "app.name CONTAINS 'production'"

    \b
      # Find high severity vulns
      r7-cli appsec search --type VULNERABILITY -q "vulnerability.severity = 'HIGH'"

    \b
      # Remediated vulns
      r7-cli appsec search --type VULNERABILITY -q "vulnerability.status = 'REMEDIATED'"

    \b
      # Vulns discovered after a date
      r7-cli appsec search --type VULNERABILITY -q "vulnerability.last_discovered >= '2025-01-01'"

    \b
      # Vulns for a specific app
      r7-cli appsec search --type VULNERABILITY -q "vulnerability.app.id = '<APP_ID>'"

    \b
      # Failed scans
      r7-cli appsec search --type SCAN -q "scan.status = 'FAILED'"

    \b
      # Scans completed after a date
      r7-cli appsec search --type SCAN -q "scan.completion_time >= '2025-06-01'"

    \b
      # Scan configs for an app
      r7-cli appsec search --type SCAN_CONFIG -q "scanconfig.app.id = '<APP_ID>'"

    \b
      # Enabled schedules
      r7-cli appsec search --type SCHEDULE -q "schedule.enabled = true"

    \b
      # Combine conditions with && or ||
      r7-cli appsec search --type VULNERABILITY \\
        -q "vulnerability.severity = 'CRITICAL' && vulnerability.status != 'REMEDIATED'"

    \b
    Searchable fields by type:
      APP:             app.id, app.name, app.description
      VULNERABILITY:   vulnerability.id, .severity, .status, .app.id,
                       .root_cause.url, .root_cause.method, .first_discovered,
                       .last_discovered, .newly_discovered, .scans.id
      SCAN:            scan.id, .status, .failure_reason, .submit_time,
                       .completion_time, .app.id, .scan_config.id
      SCAN_CONFIG:     scanconfig.id, .name, .app.id, .attack_template.id
      SCHEDULE:        schedule.id, .name, .enabled, .app.id, .scan_config.id
      BLACKOUT:        blackout.id, .name, .enabled, .app.id, .scope
      ATTACK_TEMPLATE: attacktemplate.id, .name, .system_defined
      ENGINE:          engine.id, .name, .status, .engine_group.id
      ENGINE_GROUP:    enginegroup.id, .name
      TARGET:          target.id, .domain, .enabled
      TAG:             tag.id, .name, .created
      REPORT:          report.id, .name, .type, .format, .app.id
    """
    config = _get_config(ctx)
    client = R7Client(config)
    url = IAS_V1_BASE.format(region=config.region) + "/search"

    if config.verbose:
        click.echo(f"Docs: {_DOC_BASE}#operation/perform-search", err=True)

    body = {"type": search_type, "query": query}
    params = {"index": index, "size": size}

    try:
        result = client.post(url, json=body, params=params, solution="appsec", subcommand="search")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
