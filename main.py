"""Entry point for r7-cli.

Provides the top-level Click group that dispatches to per-solution command
groups based on the first positional argument.
"""
from __future__ import annotations

import sys

import click

from r7cli.cli_group import GlobalFlagHintGroup, GLOBAL_FLAGS  # noqa: F401
from r7cli.config import resolve_config
from r7cli.models import VALID_SOLUTIONS, STUB_SOLUTIONS, R7Error


class SolutionGroup(click.MultiCommand):
    """Dynamic multi-command that routes to per-solution Click groups."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        return sorted(VALID_SOLUTIONS | {"validate", "matrix", "compliance", "agents", "extensions"})

    def get_command(self, ctx: click.Context, name: str) -> click.Command | None:
        if name == "help":
            click.echo(ctx.parent.get_help() if ctx.parent else ctx.get_help())
            ctx.exit(0)
            return None
        if name == "validate":
            return _validate_cmd
        if name == "matrix":
            from r7cli.security_checklist import matrix
            return matrix
        if name == "compliance":
            from r7cli.compliance import compliance
            return compliance
        if name == "agents":
            from r7cli.agents import agents
            return agents
        if name == "extensions":
            from r7cli.extensions import extensions
            return extensions
        if name in STUB_SOLUTIONS:
            from r7cli.solutions.stub import create_stub_group
            return create_stub_group(name)
        if name == "soar":
            from r7cli.solutions.soar import soar
            return soar
        if name == "cnapp":
            from r7cli.solutions.cnapp import cnapp
            return cnapp
        if name == "vm":
            from r7cli.solutions.vm import vm
            return vm
        if name == "siem":
            from r7cli.solutions.siem import siem
            return siem
        if name == "drp":
            from r7cli.solutions.drp import drp
            return drp
        if name == "platform":
            from r7cli.solutions.platform import platform
            return platform
        if name == "asm":
            from r7cli.solutions.asm import asm
            return asm
        if name == "appsec":
            from r7cli.solutions.appsec import appsec
            return appsec
        return None


CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.command(cls=SolutionGroup, context_settings=CONTEXT_SETTINGS)
@click.option("-r", "--region", default=None, help="Region code (default: us).")
@click.option("-v", "--verbose", is_flag=True, help="Log request/response info to stderr.")
@click.option("-k", "--api-key", default=None, help="Insight Platform API key.")
@click.option("-o", "--output", "output_format", default="json", help="Output format: json, table, csv.")
@click.option("-c", "--cache", "use_cache", is_flag=True, help="Return last response from local cache (resp are saved), for faster testing.")
@click.option("-l", "--limit", type=int, default=None, help="Limit the output of the largest array.")
@click.option("--debug", is_flag=True, help="Log full request/response bodies to stderr.")
@click.option("--drp-token", default=None, help="Provide DRP API token in user:key format.")
@click.option("-t", "--timeout", type=int, default=30, help="Request timeout in seconds (default: 30).")
@click.option("--search-fields", "search", default=None, help="Search JSON response for a field name and print matching values.")
@click.option("-s", "--short", is_flag=True, help="Compact single-line output.")
@click.pass_context
def cli(ctx, region, verbose, api_key, output_format, use_cache, limit, debug, drp_token, timeout, search, short):
    """r7-cli: The Rapid7 Command Platform at Your Fingertips

    Usage: r7-cli SOLUTION [OPTIONS] SUBCOMMAND [ARGS]

    Solutions: siem, vm, cnapp, asm, appsec, drp, platform, soar

    Environment variables:
      R7_X_API_KEY   API key for Insight Platform
      R7_REGION      Region code (default: us)
      R7_DRP_TOKEN   DRP API token

    Supported regions: us, us1, us2, us3, ca, eu, au, ap, me-central-1, ap-south-2
    """
    try:
        ctx.ensure_object(dict)
        config = resolve_config(
            region_flag=region,
            api_key_flag=api_key,
            drp_token_flag=drp_token,
            verbose=verbose,
            debug=debug,
            output_format=output_format,
            use_cache=use_cache,
            limit=limit,
            timeout=timeout,
            search=search,
            short=short,
        )
        ctx.obj["config"] = config
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# Top-level shortcut: r7-cli validate
# ---------------------------------------------------------------------------

@click.command("validate")
@click.pass_context
def _validate_cmd(ctx):
    """Validate API key against the Insight Platform."""
    from r7cli.client import R7Client
    from r7cli.models import INSIGHT_BASE
    from r7cli.output import format_output

    config = ctx.obj["config"]
    client = R7Client(config)
    url = INSIGHT_BASE.format(region=config.region) + "/validate"
    try:
        result = client.get(url, solution="platform", subcommand="validate")
        click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
