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

# Solution name → required product codes (any match = licensed)
_SOLUTION_LICENSE_MAP: dict[str, list[str]] = {
    "vm":      ["IVM"],
    "siem":    ["IDR", "OPS"],
    "asm":     ["SC"],
    "drp":     ["TC", "IH"],
    "appsec":  ["AS"],
    "cnapp":   ["ICS"],
    "soar":    ["ICON"],
}


def _check_license(ctx: click.Context, solution: str) -> None:
    """Check if the user is licensed for the given solution.

    Makes a single API call to the products endpoint (cached in ctx.obj).
    Exits with code 1 if the required license is not found.
    Skips the check for help requests and offline commands.
    """
    # Skip if help is being requested
    raw_args = sys.argv[1:] if hasattr(sys, 'argv') else []
    if "-h" in raw_args or "--help" in raw_args or "help" in raw_args:
        return

    config = ctx.obj.get("config") if ctx.obj else None
    if not config or not config.api_key:
        return  # can't check without an API key

    # Skip if cache mode is active (using cached data, no API needed)
    if config.use_cache:
        return

    required_codes = _SOLUTION_LICENSE_MAP.get(solution)
    if not required_codes:
        return  # no license requirement (e.g. platform)

    # Skip for offline subcommands (e.g. vm export list operates on local files)
    _OFFLINE_SUBCOMMANDS = {"export list"}
    remaining = " ".join(raw_args).lower()
    for offline_cmd in _OFFLINE_SUBCOMMANDS:
        if f"{solution} {offline_cmd}" in remaining:
            return

    # Cache the product codes in ctx.obj so we only call the API once
    if "_licensed_codes" not in ctx.obj:
        try:
            from r7cli.client import R7Client
            from r7cli.models import ACCOUNT_BASE
            client = R7Client(config)
            url = ACCOUNT_BASE.format(region=config.region) + "/products"
            data = client.get(url, solution="platform", subcommand="license-check")
            codes = set()
            if isinstance(data, list):
                for item in data:
                    code = item.get("product_code", "")
                    if code:
                        codes.add(code)
            ctx.obj["_licensed_codes"] = codes
        except Exception:
            ctx.obj["_licensed_codes"] = set()  # fail open on API error
            return

    licensed = ctx.obj["_licensed_codes"]
    if not licensed:
        return  # couldn't fetch licenses, fail open

    if not any(code in licensed for code in required_codes):
        # Map solution names to friendly product names
        _FRIENDLY_NAMES = {
            "vm": "InsightVM", "siem": "InsightIDR", "asm": "Surface Command",
            "drp": "Digital Risk Protection", "appsec": "InsightAppSec",
            "cnapp": "InsightCloudSec", "soar": "InsightConnect",
        }
        friendly = _FRIENDLY_NAMES.get(solution, solution)
        click.echo(
            f"Error: your organization is not licensed for {friendly}. "
            f"This command requires one of the following product licenses: {', '.join(required_codes)}.\n"
            f"Check your licensed products with: r7-cli platform products list",
            err=True,
        )
        sys.exit(1)


class SolutionGroup(click.MultiCommand):
    """Dynamic multi-command that routes to per-solution Click groups."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        return sorted(VALID_SOLUTIONS | {"validate", "tldr"})

    def get_command(self, ctx: click.Context, name: str) -> click.Command | None:
        if name == "help":
            click.echo(ctx.parent.get_help() if ctx.parent else ctx.get_help())
            ctx.exit(0)
            return None
        if name == "tldr":
            return _tldr_cmd
        if name == "validate":
            return _validate_cmd
        if name in STUB_SOLUTIONS:
            from r7cli.solutions.stub import create_stub_group
            return create_stub_group(name)

        # Check license for solution commands (deferred — runs in group callback)
        # The actual check happens in each solution group's invoke via _check_license

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

# ---------------------------------------------------------------------------
# ANSI color banner
# ---------------------------------------------------------------------------

_BANNER = """\
\033[38;5;208m ██████╗ \033[38;5;196m███████╗\033[0m     \033[38;5;33m ██████╗██╗     ██╗\033[0m
\033[38;5;208m ██╔══██╗\033[38;5;196m╚════██║\033[0m     \033[38;5;33m██╔════╝██║     ██║\033[0m
\033[38;5;208m ██████╔╝\033[38;5;196m    ██╔╝\033[0m     \033[38;5;33m██║     ██║     ██║\033[0m
\033[38;5;208m ██╔══██╗\033[38;5;196m   ██╔╝ \033[0m     \033[38;5;33m██║     ██║     ██║\033[0m
\033[38;5;208m ██║  ██║\033[38;5;196m   ██║  \033[0m\033[38;5;245m ─── \033[0m\033[38;5;33m╚██████╗███████╗██║\033[0m
\033[38;5;208m ╚═╝  ╚═╝\033[38;5;196m   ╚═╝  \033[0m     \033[38;5;33m ╚═════╝╚══════╝╚═╝\033[0m
\033[38;5;245m  Rapid7 Command Platform\033[0m"""

# ---------------------------------------------------------------------------
# TLDR quick-reference
# ---------------------------------------------------------------------------

# ANSI helpers
_H = "\033[1;97m"   # bold white — headers
_C = "\033[38;5;33m"  # blue — commands
_G = "\033[38;5;245m" # gray — comments
_R = "\033[0m"        # reset

_TLDR = f"""{_BANNER}

{_H}Getting Started{_R}
  {_G}# Set your API key (or use -k){_R}
  export R7_X_API_KEY="your-key"

{_H}Validate{_R}
  {_C}r7-cli validate{_R}                                    {_G}# Validate API key{_R}

{_H}InsightVM{_R}
  {_C}r7-cli vm health{_R}                                   {_G}# Print VM health info{_R}
  {_C}r7-cli vm scans list --days 7{_R}                      {_G}# List scans ran in last 7 days{_R}
  {_C}r7-cli vm export vulnerabilities --auto{_R}             {_G}# Bulk export all vulnerabilities{_R}

{_H}InsightIDR / SIEM{_R}
  {_C}r7-cli siem health{_R}                                  {_G}# Print SIEM health info{_R}
  {_C}r7-cli siem logs query -n "Asset Authentication" --time-range "Last 7 days"{_R}  {_G}# Query logs{_R}
  {_C}r7-cli siem investigations list --status OPEN --all-pages{_R}  {_G}# List all open investigations{_R}

{_H}Surface Command / ASM{_R}
  {_C}r7-cli asm queries list{_R}                            {_G}# List available queries{_R}
  {_C}r7-cli asm queries execute --query 'MATCH (a:Asset) RETURN a LIMIT 10'{_R}  {_G}# Execute an OpenCypher query{_R}
  {_C}r7-cli asm connectors list{_R}                         {_G}# List installed connectors{_R}

{_H}Digital Risk Protection{_R}
  {_C}r7-cli drp validate{_R}                                {_G}# Validate DRP specific API key{_R}
  {_C}r7-cli drp alerts list --severity High --days 30{_R}   {_G}# List High severity DRP alerts{_R}
  {_C}r7-cli drp risk-score{_R}                              {_G}# Print organizational risk-score{_R}

{_H}Platform{_R}
  {_C}r7-cli platform products list{_R}                      {_G}# List licensed platform products{_R}
  {_C}r7-cli platform users list{_R}                         {_G}# List platform users{_R}
  {_C}r7-cli platform assets count{_R}                       {_G}# List licensed asset counts{_R}

{_H}Compliance & Coverage{_R}
  {_C}r7-cli platform compliance{_R}                          {_G}# SQL dump of VM policies{_R}
  {_C}r7-cli platform compliance list --vm{_R}                {_G}# CIS controls for InsightVM{_R}
  {_C}r7-cli platform matrix rapid7 --reality{_R}             {_G}# coverage matrix adjusted for deployment{_R}

{_H}CIS Controls (per product){_R}
  {_C}r7-cli vm cis --ig1{_R}                                 {_G}# IG1 controls for InsightVM{_R}
  {_C}r7-cli siem cis{_R}                                     {_G}# all CIS controls for IDR{_R}
  {_C}r7-cli asm cis --csf{_R}                                {_G}# NIST CSF controls for ASM{_R}

{_H}Output Tricks{_R}
  {_C}r7-cli -o table platform products list{_R}              {_G}# table format{_R}
  {_C}r7-cli -s platform products list{_R}                    {_G}# compact one-liner JSON{_R}
  {_C}r7-cli -c siem logs query -n "DNS Query"{_R}            {_G}# use cached response{_R}

{_H}More help{_R}
  {_C}r7-cli SOLUTION --help{_R}                              {_G}# e.g. r7-cli vm --help{_R}
  {_C}r7-cli SOLUTION SUBCOMMAND --help{_R}                   {_G}# e.g. r7-cli vm scans list --help{_R}
"""


@click.command(cls=SolutionGroup, context_settings=CONTEXT_SETTINGS)
@click.option("-r", "--region", default=None, help="Region code (default: us).")
@click.option("-v", "--verbose", is_flag=True, help="Log request/response info to stderr.")
@click.option("-k", "--api-key", default=None, help="Insight Platform API key.")
@click.option("-o", "--output", "output_format", default="json", help="Output format: json, table, csv, tsv.")
@click.option("-c", "--cache", "use_cache", is_flag=True, help="Return last response from local cache (resp are saved), for faster testing.")
@click.option("-l", "--limit", type=int, default=None, help="Limit the output of the largest array.")
@click.option("--debug", is_flag=True, help="Log full request/response bodies to stderr.")
@click.option("--drp-token", default=None, help="Provide DRP API token in user:key format.")
@click.option("-t", "--timeout", type=int, default=30, help="Request timeout in seconds (default: 30).")
@click.option("--search-fields", "search", default=None, help="Search JSON response for a field name and print matching values.")
@click.option("-s", "--short", is_flag=True, help="Compact single-line output.")
@click.option("--tldr", is_flag=True, is_eager=True, expose_value=False, callback=lambda ctx, param, value: (click.echo(_TLDR), ctx.exit(0)) if value else None, help="Show quick-reference examples.")
@click.pass_context
def cli(ctx, region, verbose, api_key, output_format, use_cache, limit, debug, drp_token, timeout, search, short):
    """placeholder"""
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


cli.help = (
    "\b\n"
    + _BANNER + "\n\n"
    "Usage: r7-cli SOLUTION [OPTIONS] SUBCOMMAND [ARGS]\n\n"
    "Solutions: siem, vm, cnapp, asm, appsec, drp, platform, soar\n\n"
    "\b\n"
    "Environment variables:\n"
    "  R7_X_API_KEY   API key for Insight Platform\n"
    "  R7_REGION      Region code (default: us)\n"
    "  R7_DRP_TOKEN   DRP API token\n\n"
    "\b\n"
    "Supported regions:\n"
    "  us, us1, us2, us3, ca, eu, au, ap, me-central-1, ap-south-2"
)


# ---------------------------------------------------------------------------
# Top-level shortcut: r7-cli validate
# ---------------------------------------------------------------------------

@click.command("validate")
@click.pass_context
def _validate_cmd(ctx):
    """Validate API key (and DRP token if provided) against the Insight Platform."""
    from r7cli.client import R7Client
    from r7cli.models import INSIGHT_BASE, DRP_BASE, APIError
    from r7cli.output import format_output

    config = ctx.obj["config"]
    client = R7Client(config)

    # --- Validate API key ---
    if config.api_key:
        url = INSIGHT_BASE.format(region=config.region) + "/validate"
        try:
            result = client.get(url, solution="platform", subcommand="validate")
            click.echo(format_output(result, config.output_format, config.limit, config.search, short=config.short))
        except R7Error as exc:
            click.echo(str(exc), err=True)
            sys.exit(exc.exit_code)
    else:
        click.echo("No API key provided — skipping platform validation.", err=True)

    # --- Validate DRP token if provided ---
    if config.drp_token:
        token = config.drp_token
        if ":" in token:
            parts = token.split(":", 1)
            auth = (parts[0], parts[1])
        else:
            auth = (token, "")
        drp_url = f"{DRP_BASE}/public/v1/test-credentials"
        try:
            client.head(drp_url, auth=auth, solution="drp", subcommand="validate")
            click.echo("DRP credentials valid")
        except APIError as exc:
            if exc.status_code == 401:
                click.echo("DRP credentials invalid", err=True)
                sys.exit(1)
            click.echo(str(exc), err=True)
            sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# Top-level shortcut: r7-cli tldr
# ---------------------------------------------------------------------------

@click.command("tldr")
@click.pass_context
def _tldr_cmd(ctx):
    """Show quick-reference examples for common commands."""
    click.echo(_TLDR)
