"""Rapid7 platform status command — fetches from status.rapid7.com."""
from __future__ import annotations

import sys
from datetime import datetime

import click
import httpx

from r7cli.helpers import emit, get_config
from r7cli.models import NetworkError, R7Error
from r7cli.output import format_output


_STATUS_BASE = "https://status.rapid7.com/api/v2"


def _fetch_json(url: str, timeout: float = 30.0) -> dict:
    """Fetch JSON from the Statuspage API (no auth required)."""
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        return resp.json()
    except httpx.TimeoutException:
        raise NetworkError(f"Timeout fetching {url}")
    except httpx.HTTPStatusError as exc:
        raise NetworkError(f"HTTP {exc.response.status_code} from {url}")
    except httpx.RequestError as exc:
        raise NetworkError(f"Network error fetching {url}: {exc}")


def _format_timestamp(ts: str | None) -> str:
    """Format an ISO timestamp to a human-friendly string."""
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y - %H:%M UTC")
    except (ValueError, AttributeError):
        return ts


def _status_indicator_symbol(indicator: str) -> str:
    """Map status indicator to a colored symbol."""
    mapping = {
        "none": "\033[32m●\033[0m",           # green
        "operational": "\033[32m●\033[0m",     # green
        "minor": "\033[33m●\033[0m",           # yellow
        "major": "\033[31m●\033[0m",           # red
        "critical": "\033[91m●\033[0m",        # bright red
        "degraded_performance": "\033[33m●\033[0m",
        "partial_outage": "\033[31m●\033[0m",
        "major_outage": "\033[91m●\033[0m",
        "under_maintenance": "\033[34m●\033[0m",  # blue
    }
    return mapping.get(indicator, "●")


def _status_label(status: str) -> str:
    """Human-friendly label for a component/incident status."""
    labels = {
        "operational": "Operational",
        "degraded_performance": "Degraded Performance",
        "partial_outage": "Partial Outage",
        "major_outage": "Major Outage",
        "under_maintenance": "Under Maintenance",
        "investigating": "Investigating",
        "identified": "Identified",
        "monitoring": "Monitoring",
        "resolved": "Resolved",
        "none": "All Systems Operational",
        "minor": "Partially Degraded Service",
        "major": "Major Service Outage",
        "critical": "Critical Service Outage",
    }
    return labels.get(status, status.replace("_", " ").title())


def _build_summary(status_data: dict, incidents_data: dict, components_data: dict) -> dict:
    """Build a structured summary combining status, incidents, and degraded components."""
    page_status = status_data.get("status", {})
    page_info = status_data.get("page", {})

    # Build a lookup: component_id → group name (for resolving affected components)
    components = components_data.get("components", [])
    group_name_by_id: dict[str, str] = {}
    for comp in components:
        if comp.get("group"):
            group_name_by_id[comp["id"]] = comp["name"]

    # Find degraded component groups (groups only, not leaf components)
    degraded_groups = []
    for comp in components:
        if comp.get("group") and comp.get("status") != "operational":
            degraded_groups.append({
                "name": comp["name"],
                "status": _status_label(comp["status"]),
            })

    # Build incidents list
    incidents = []
    for inc in incidents_data.get("incidents", []):
        updates = []
        for upd in inc.get("incident_updates", []):
            updates.append({
                "status": _status_label(upd.get("status", "")),
                "body": upd.get("body", ""),
                "created_at": _format_timestamp(upd.get("created_at")),
            })

        affected = []
        seen_groups: set[str] = set()
        for comp in inc.get("components", []):
            group_id = comp.get("group_id", "")
            # Resolve to the parent group name if available
            display_name = group_name_by_id.get(group_id, comp.get("name", ""))
            if display_name in seen_groups:
                continue
            seen_groups.add(display_name)
            affected.append({
                "name": display_name,
                "status": _status_label(comp.get("status", "")),
            })

        incidents.append({
            "name": inc.get("name", ""),
            "status": _status_label(inc.get("status", "")),
            "impact": inc.get("impact", ""),
            "started_at": _format_timestamp(inc.get("started_at")),
            "shortlink": inc.get("shortlink", ""),
            "updates": updates,
            "affected_components": affected,
        })

    return {
        "indicator": page_status.get("indicator", "none"),
        "description": page_status.get("description", ""),
        "page": page_info.get("name", "Rapid7"),
        "url": page_info.get("url", "https://status.rapid7.com"),
        "updated_at": _format_timestamp(page_info.get("updated_at")),
        "degraded_services": degraded_groups,
        "incidents": incidents,
    }


def _render_human(summary: dict) -> str:
    """Render a human-readable status report."""
    lines: list[str] = []
    indicator = summary["indicator"]
    symbol = _status_indicator_symbol(indicator)

    lines.append(f"{symbol} {summary['page']}: {summary['description']}")
    lines.append(f"  {summary['url']}  (updated {summary['updated_at']})")
    lines.append("")

    # Degraded services
    if summary["degraded_services"]:
        lines.append("\033[1mDegraded Services:\033[0m")
        for svc in summary["degraded_services"]:
            sym = _status_indicator_symbol(svc["status"].lower().replace(" ", "_"))
            lines.append(f"  {sym} {svc['name']} — {svc['status']}")
        lines.append("")

    # Active incidents
    if summary["incidents"]:
        lines.append("\033[1mActive Incidents:\033[0m")
        for inc in summary["incidents"]:
            sym = _status_indicator_symbol(inc["impact"])
            lines.append(f"  {sym} {inc['name']}")
            lines.append(f"    Status: {inc['status']}  |  Started: {inc['started_at']}")
            if inc["shortlink"]:
                lines.append(f"    Link: {inc['shortlink']}")

            if inc["affected_components"]:
                names = ", ".join(c["name"] for c in inc["affected_components"])
                lines.append(f"    Affected: {names}")

            if inc["updates"]:
                lines.append("    Updates:")
                for upd in inc["updates"]:
                    lines.append(f"      [{upd['status']}] {upd['created_at']}")
                    lines.append(f"        {upd['body']}")
            lines.append("")
    elif indicator == "none":
        lines.append("  All systems operational. No active incidents.")
        lines.append("")

    return "\n".join(lines)


@click.command("status")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON instead of human-readable format.")
@click.pass_context
def status(ctx, as_json):
    """Show Rapid7 platform operational status from status.rapid7.com.

    Displays the current platform health, any degraded services, and active
    incidents with their update history. No authentication required.
    """
    config = get_config(ctx)
    timeout = float(config.timeout)

    try:
        status_data = _fetch_json(f"{_STATUS_BASE}/status.json", timeout=timeout)
        incidents_data = _fetch_json(f"{_STATUS_BASE}/incidents/unresolved.json", timeout=timeout)
        components_data = _fetch_json(f"{_STATUS_BASE}/components.json", timeout=timeout)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)

    summary = _build_summary(status_data, incidents_data, components_data)

    # If output format is json or --json flag, use format_output
    if as_json or config.output_format != "json":
        click.echo(format_output(summary, config.output_format, config.limit, config.search, short=config.short))
    else:
        # Default: human-readable colored output
        click.echo(_render_human(summary))
