"""Top-level agents command for r7-cli.

Lists all agents available in the Rapid7 platform (VM + SIEM) via GraphQL.
"""
from __future__ import annotations

from typing import Any

import click

from r7cli.client import R7Client
from r7cli.models import IVM_V4_BASE, R7Error
from r7cli.output import format_output


@click.group("assets")
@click.pass_context
def agents(ctx: click.Context) -> None:
    """Query assets across the Rapid7 platform via GraphQL and REST APIs."""
    pass


@agents.command("count")
@click.option("--vm", "show_vm", is_flag=True, help="Show only the InsightVM asset count.")
@click.option("--siem", "show_siem", is_flag=True, help="Show only the InsightIDR agent count.")
@click.option("--asm", "show_asm", is_flag=True, help="Show only the Surface Command asset counts.")
@click.option("--appsec", "show_appsec", is_flag=True, help="Show only the InsightAppSec app count.")
@click.option("--drp", "show_drp", is_flag=True, help="Show only the DRP monitored asset count.")
@click.pass_context
def assets_count(ctx, show_vm, show_siem, show_asm, show_appsec, show_drp):
    """Get asset counts from VM, SIEM, Surface Command, AppSec, and DRP.

    \b
    Examples:
      r7-cli assets count            # all counts
      r7-cli assets count --vm       # VM asset count only
      r7-cli assets count --siem     # SIEM agent count only
      r7-cli assets count --asm      # Surface Command asset counts
      r7-cli assets count --appsec   # AppSec app count only
      r7-cli assets count --drp      # DRP monitored asset count only
    """
    config = ctx.obj["config"]
    client = R7Client(config)
    result: dict[str, Any] = {}

    show_all = not show_vm and not show_siem and not show_asm and not show_appsec and not show_drp

    # Require API key for any API-based count
    if not config.api_key:
        click.echo(
            "No API key provided. Set the R7_X_API_KEY environment variable "
            "or use -k / --api-key to provide one.",
            err=True,
        )
        import sys
        sys.exit(2)

    if show_vm or show_all:
        url = IVM_V4_BASE.format(region=config.region) + "/integration/assets"
        try:
            resp = client.post(url, json=None, params={"size": 1}, solution="vm", subcommand="assets-count")
            total = 0
            if isinstance(resp, dict):
                total = resp.get("metadata", {}).get("totalResources", 0)
            result["totalVMAssets"] = total
        except R7Error as exc:
            click.echo(f"Warning: VM asset count failed: {exc}", err=True)
            result["totalVMAssets"] = None

    if show_siem or show_all:
        from r7cli.models import IDR_V1_BASE
        url = IDR_V1_BASE.format(region=config.region) + "/health-metrics"
        try:
            resp = client.get(url, solution="siem", subcommand="agents-count")
            total = 0
            data_list = resp.get("data", []) if isinstance(resp, dict) else resp if isinstance(resp, list) else []
            for entry in data_list:
                if not isinstance(entry, dict):
                    continue
                rrn = entry.get("rrn", "")
                if "status:summary" in str(rrn):
                    total = entry.get("total", 0)
                    break
            result["totalSIEMAgents"] = total
        except R7Error as exc:
            click.echo(f"Warning: SIEM agent count failed: {exc}", err=True)
            result["totalSIEMAgents"] = None

    if show_asm or show_all:
        from r7cli.models import SC_BASE
        base = SC_BASE.format(region=config.region)
        url = f"{base}/graph-api/objects/table"

        def _sc_count(cypher: str) -> int | None:
            try:
                resp = client.post(url, json={"cypher": cypher}, params={"format": "json"},
                                   solution="asm", subcommand="assets-count")
                items = resp.get("items", []) if isinstance(resp, dict) else []
                if items and isinstance(items[0], dict):
                    data = items[0].get("data", [])
                    if data:
                        return int(data[0])
                return 0
            except (R7Error, ValueError, IndexError, TypeError) as exc:
                click.echo(f"Warning: ASM count query failed: {exc}", err=True)
                return None

        result["asmInsightAgentAssets"] = _sc_count(
            "MATCH (m:Asset) WHERE 'Rapid7InsightAgent' IN m.sources RETURN count(m)"
        )
        result["asmIVMAssets"] = _sc_count(
            "MATCH (m:Asset) WHERE 'Rapid7IVMAsset' IN m.sources RETURN count(m)"
        )
        result["asmICSAssets"] = _sc_count(
            "MATCH (m:Asset) WHERE 'Rapid7ICSInstance' IN m.sources RETURN count(m)"
        )

    if show_appsec or show_all:
        from r7cli.models import IAS_V1_BASE
        url = IAS_V1_BASE.format(region=config.region) + "/apps"
        try:
            resp = client.get(url, params={"size": 1}, solution="appsec", subcommand="apps-count")
            total = 0
            if isinstance(resp, dict):
                total = resp.get("metadata", {}).get("total_data", 0)
            result["totalAppsecApps"] = total
        except R7Error as exc:
            click.echo(f"Warning: AppSec app count failed: {exc}", err=True)
            result["totalAppsecApps"] = None

    if show_drp or show_all:
        from r7cli.models import DRP_BASE
        url = DRP_BASE + "/public/v2/data/assets"
        try:
            # DRP uses Basic auth from drp_token
            auth = None
            if config.drp_token and ":" in config.drp_token:
                parts = config.drp_token.split(":", 1)
                auth = (parts[0], parts[1])
            resp = client.get(url, auth=auth, solution="drp", subcommand="assets-count")
            total = len(resp) if isinstance(resp, list) else 0
            result["totalDRPAssets"] = total
        except R7Error as exc:
            click.echo(f"Warning: DRP asset count failed: {exc}", err=True)
            result["totalDRPAssets"] = None

    click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
