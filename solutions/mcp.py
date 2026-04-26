"""MCP server integration for the Rapid7 Bulk Export MCP.

Provides `r7-cli vm export mcp` subcommands to install, configure, and
interact with the rapid7-bulk-export MCP server from the command line.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import click

from r7cli.cli_group import GlobalFlagHintGroup
from r7cli.config import Config
from r7cli.models import R7Error, UserInputError
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MCP_PACKAGE = "git+https://github.com/rapid7/rapid7-bulk-export-mcp.git"
_MCP_SERVER_CMD = "rapid7-mcp-server"
_VALID_EXPORT_TYPES = ("vulnerability", "policy", "remediation")

# Kiro MCP config path (workspace-level)
_KIRO_MCP_CONFIG = Path(".kiro/settings/mcp.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_config(ctx: click.Context) -> Config:
    return ctx.obj["config"]


def _find_mcp_server() -> str | None:
    """Return the path to the rapid7-mcp-server binary, or None."""
    return shutil.which(_MCP_SERVER_CMD)


def _run_mcp_stdio(config: Config, request: dict) -> dict:
    """Send a JSON-RPC request to the MCP server over stdio and return the result.

    Starts the MCP server as a subprocess, performs the MCP initialization
    handshake, calls the specified tool, then shuts down.
    """
    server_cmd = _find_mcp_server()
    if not server_cmd:
        raise UserInputError(
            f"MCP server not found. Install it first:\n\n"
            f"  r7-cli vm export mcp install\n\n"
            f"Or manually: pip install {_MCP_PACKAGE}"
        )

    env = dict(os.environ)
    if config.api_key:
        env["RAPID7_API_KEY"] = config.api_key
    env["RAPID7_REGION"] = config.region

    proc = subprocess.Popen(
        [server_cmd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )

    try:
        # MCP initialization handshake
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "r7-cli", "version": "0.1.0"},
            },
        }
        _send_message(proc, init_request)
        _read_response(proc)  # init response

        # Send initialized notification
        initialized_notif = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        _send_message(proc, initialized_notif)

        # Send the actual tool call
        tool_request = {
            "jsonrpc": "2.0",
            "id": 2,
            **request,
        }
        _send_message(proc, tool_request)
        result = _read_response(proc)

        return result

    finally:
        proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _send_message(proc: subprocess.Popen, message: dict) -> None:
    """Send a JSON-RPC message using the MCP stdio transport format."""
    body = json.dumps(message)
    header = f"Content-Length: {len(body.encode())}\r\n\r\n"
    proc.stdin.write(header + body)
    proc.stdin.flush()


def _read_response(proc: subprocess.Popen) -> dict:
    """Read a JSON-RPC response from the MCP server's stdout."""
    # Read Content-Length header
    header_line = ""
    while True:
        ch = proc.stdout.read(1)
        if ch == "":
            stderr_output = proc.stderr.read()
            raise R7Error(
                f"MCP server closed unexpectedly. stderr: {stderr_output}",
                exit_code=2,
            )
        header_line += ch
        if header_line.endswith("\r\n\r\n"):
            break

    # Parse content length
    content_length = 0
    for line in header_line.strip().split("\r\n"):
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":", 1)[1].strip())
            break

    if content_length == 0:
        raise R7Error("Invalid MCP response: missing Content-Length", exit_code=2)

    # Read body
    body = proc.stdout.read(content_length)
    return json.loads(body)


def _call_tool(config: Config, tool_name: str, arguments: dict | None = None) -> str:
    """Call an MCP tool and return the text content from the response."""
    request = {
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments or {},
        },
    }
    result = _run_mcp_stdio(config, request)

    # Extract text content from MCP tool result
    if "error" in result:
        error = result["error"]
        raise R7Error(
            f"MCP tool error: {error.get('message', str(error))}",
            exit_code=2,
        )

    content_list = result.get("result", {}).get("content", [])
    texts = []
    for item in content_list:
        if isinstance(item, dict) and item.get("type") == "text":
            texts.append(item["text"])
    return "\n".join(texts) if texts else json.dumps(result.get("result", {}))


# ---------------------------------------------------------------------------
# Click group: vm export mcp
# ---------------------------------------------------------------------------

@click.group("mcp", cls=GlobalFlagHintGroup)
@click.pass_context
def mcp_group(ctx):
    """Rapid7 Bulk Export MCP server — install, configure, and query.

    \b
    The MCP server provides AI-powered analysis of Rapid7 bulk export data
    using a local DuckDB database. Use these commands to install the server,
    load data, and run SQL queries from the command line.

    \b
    Quick start:
      r7-cli vm export mcp install        # Install the MCP server
      r7-cli vm export mcp configure      # Write Kiro MCP config
      r7-cli vm export mcp start-export   # Kick off a vulnerability export
      r7-cli vm export mcp status --id X  # Check export progress
      r7-cli vm export mcp download --id X  # Download & load into DuckDB
      r7-cli vm export mcp query "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
    """
    pass


# ---------------------------------------------------------------------------
# mcp install
# ---------------------------------------------------------------------------

@mcp_group.command("install")
@click.option("--upgrade", is_flag=True, help="Upgrade if already installed.")
@click.pass_context
def mcp_install(ctx, upgrade):
    """Install the Rapid7 Bulk Export MCP server.

    \b
    Installs the rapid7-bulk-export-mcp package from GitHub using pip.
    After installation, the `rapid7-mcp-server` command will be available.

    \b
    Examples:
      r7-cli vm export mcp install
      r7-cli vm export mcp install --upgrade
    """
    existing = _find_mcp_server()
    if existing and not upgrade:
        click.echo(f"MCP server already installed: {existing}")
        click.echo("Use --upgrade to reinstall the latest version.")
        return

    click.echo("Installing rapid7-bulk-export-mcp from GitHub…", err=True)
    cmd = [sys.executable, "-m", "pip", "install"]
    if upgrade:
        cmd.append("--upgrade")
    cmd.append(_MCP_PACKAGE)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            click.echo(f"pip install failed:\n{result.stderr}", err=True)
            sys.exit(2)
        click.echo("✓ MCP server installed successfully.")
        # Verify
        server_path = _find_mcp_server()
        if server_path:
            click.echo(f"  Binary: {server_path}")
        else:
            click.echo(
                "  Warning: rapid7-mcp-server not found on PATH. "
                "You may need to restart your shell.",
                err=True,
            )
    except subprocess.TimeoutExpired:
        click.echo("Installation timed out.", err=True)
        sys.exit(2)


# ---------------------------------------------------------------------------
# mcp configure
# ---------------------------------------------------------------------------

@mcp_group.command("configure")
@click.option("--target", type=click.Choice(["kiro", "claude-desktop", "claude-code", "vscode"]),
              default="kiro", help="Target AI tool to configure (default: kiro).")
@click.pass_context
def mcp_configure(ctx, target):
    """Write MCP server configuration for your AI tool.

    \b
    Generates the MCP configuration JSON for the specified target tool.
    Uses your current API key and region settings.

    \b
    Examples:
      # Configure for Kiro (writes .kiro/settings/mcp.json)
      r7-cli vm export mcp configure

    \b
      # Configure for Claude Desktop (prints config to stdout)
      r7-cli vm export mcp configure --target claude-desktop

    \b
      # Configure for VS Code / GitHub Copilot
      r7-cli vm export mcp configure --target vscode
    """
    config = _get_config(ctx)

    mcp_config = {
        "mcpServers": {
            "rapid7-bulk-export": {
                "command": _MCP_SERVER_CMD,
                "args": [],
                "env": {
                    "RAPID7_API_KEY": config.api_key or "<your-api-key-here>",
                    "RAPID7_REGION": config.region,
                },
            }
        }
    }

    if target == "kiro":
        config_path = _KIRO_MCP_CONFIG
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Merge with existing config if present
        if config_path.exists():
            try:
                existing = json.loads(config_path.read_text())
                existing.setdefault("mcpServers", {})
                existing["mcpServers"]["rapid7-bulk-export"] = mcp_config["mcpServers"]["rapid7-bulk-export"]
                mcp_config = existing
            except (json.JSONDecodeError, KeyError):
                pass

        config_path.write_text(json.dumps(mcp_config, indent=2) + "\n")
        click.echo(f"✓ Wrote MCP config to {config_path}")
        if not config.api_key:
            click.echo("  Note: Replace <your-api-key-here> with your actual API key.", err=True)

    elif target == "claude-desktop":
        # Print the config for manual placement
        click.echo("Add this to your Claude Desktop config:")
        click.echo(f"  macOS: ~/Library/Application Support/Claude/claude_desktop_config.json")
        click.echo(f"  Windows: %APPDATA%\\Claude\\claude_desktop_config.json\n")
        click.echo(json.dumps(mcp_config, indent=2))

    elif target == "claude-code":
        click.echo("Add this to ~/.claude.json or .mcp.json:\n")
        click.echo(json.dumps(mcp_config, indent=2))

    elif target == "vscode":
        click.echo("Add this to .vscode/mcp.json:\n")
        click.echo(json.dumps(mcp_config, indent=2))


# ---------------------------------------------------------------------------
# mcp start-export
# ---------------------------------------------------------------------------

@mcp_group.command("start-export")
@click.option("--type", "export_type", type=click.Choice(_VALID_EXPORT_TYPES),
              default="vulnerability", help="Export type (default: vulnerability).")
@click.option("--start-date", default="", help="Start date YYYY-MM-DD (remediation only).")
@click.option("--end-date", default="", help="End date YYYY-MM-DD (remediation only).")
@click.pass_context
def mcp_start_export(ctx, export_type, start_date, end_date):
    """Start a Rapid7 bulk export via the MCP server.

    \b
    Kicks off an export job on the Rapid7 platform. The export processes
    in the background (typically 3-5 minutes). Use `mcp status` to check
    progress, then `mcp download` to load the data.

    \b
    If an export from today already exists, it will be reused.

    \b
    Examples:
      # Start a vulnerability export
      r7-cli vm export mcp start-export

    \b
      # Start a policy export
      r7-cli vm export mcp start-export --type policy

    \b
      # Start a remediation export with date range
      r7-cli vm export mcp start-export --type remediation --start-date 2026-03-01 --end-date 2026-04-01
    """
    config = _get_config(ctx)
    try:
        arguments: dict[str, Any] = {"export_type": export_type}
        if start_date:
            arguments["start_date"] = start_date
        if end_date:
            arguments["end_date"] = end_date

        result = _call_tool(config, "start_rapid7_export", arguments)
        click.echo(result)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# mcp status
# ---------------------------------------------------------------------------

@mcp_group.command("status")
@click.option("-j", "--id", "export_id", required=True, help="Export ID to check.")
@click.pass_context
def mcp_status(ctx, export_id):
    """Check the status of a Rapid7 export job.

    \b
    Examples:
      r7-cli vm export mcp status --id <EXPORT_ID>
    """
    config = _get_config(ctx)
    try:
        result = _call_tool(config, "check_rapid7_export_status", {"export_id": export_id})
        click.echo(result)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# mcp download
# ---------------------------------------------------------------------------

@mcp_group.command("download")
@click.option("-j", "--id", "export_id", required=True, help="Export ID to download.")
@click.option("--type", "export_type", type=click.Choice(_VALID_EXPORT_TYPES),
              default="vulnerability", help="Export type (default: vulnerability).")
@click.pass_context
def mcp_download(ctx, export_id, export_type):
    """Download a completed export and load into the local DuckDB database.

    \b
    Call this after `mcp status` confirms the export is COMPLETE.
    Downloads Parquet files and loads them into the local DuckDB for querying.

    \b
    Examples:
      r7-cli vm export mcp download --id <EXPORT_ID>
      r7-cli vm export mcp download --id <EXPORT_ID> --type policy
    """
    config = _get_config(ctx)
    try:
        result = _call_tool(config, "download_rapid7_export", {
            "export_id": export_id,
            "export_type": export_type,
        })
        click.echo(result)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# mcp query
# ---------------------------------------------------------------------------

@mcp_group.command("query")
@click.argument("sql")
@click.pass_context
def mcp_query(ctx, sql):
    """Execute a SQL query against the MCP DuckDB database.

    \b
    Queries the local DuckDB database populated by the MCP server.
    Supports all DuckDB SQL syntax.

    \b
    Tables available after loading data:
      - assets            (asset inventory)
      - vulnerabilities   (combined asset + vuln data)
      - policies          (compliance results)
      - vulnerability_remediation (remediation tracking)

    \b
    Examples:
      # Severity distribution
      r7-cli vm export mcp query "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity"

    \b
      # Top 10 critical vulns
      r7-cli vm export mcp query "SELECT title, cvssV3Score FROM vulnerabilities WHERE severity='Critical' ORDER BY cvssV3Score DESC LIMIT 10"

    \b
      # Assets with most vulns
      r7-cli vm export mcp query "SELECT hostName, COUNT(*) as cnt FROM vulnerabilities GROUP BY hostName ORDER BY cnt DESC LIMIT 10"

    \b
      # Policy failures
      r7-cli vm export mcp query "SELECT ruleTitle, COUNT(*) FROM policies WHERE finalStatus='fail' GROUP BY ruleTitle ORDER BY 2 DESC LIMIT 10"
    """
    config = _get_config(ctx)
    try:
        result = _call_tool(config, "query_rapid7", {"sql": sql})
        click.echo(result)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# mcp schema
# ---------------------------------------------------------------------------

@mcp_group.command("schema")
@click.pass_context
def mcp_schema(ctx):
    """Show the schema of all tables in the MCP DuckDB database.

    \b
    Examples:
      r7-cli vm export mcp schema
    """
    config = _get_config(ctx)
    try:
        result = _call_tool(config, "get_rapid7_schema")
        click.echo(result)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# mcp stats
# ---------------------------------------------------------------------------

@mcp_group.command("stats")
@click.pass_context
def mcp_stats(ctx):
    """Show summary statistics for all loaded tables.

    \b
    Examples:
      r7-cli vm export mcp stats
    """
    config = _get_config(ctx)
    try:
        result = _call_tool(config, "get_rapid7_stats")
        click.echo(result)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# mcp list-exports
# ---------------------------------------------------------------------------

@mcp_group.command("list-exports")
@click.option("-l", "--limit", type=int, default=10, help="Max exports to show (default: 10).")
@click.pass_context
def mcp_list_exports(ctx, limit):
    """List recent exports tracked by the MCP server.

    \b
    Examples:
      r7-cli vm export mcp list-exports
      r7-cli vm export mcp list-exports --limit 5
    """
    config = _get_config(ctx)
    try:
        result = _call_tool(config, "list_rapid7_exports", {"limit": limit})
        click.echo(result)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# mcp suggest
# ---------------------------------------------------------------------------

@mcp_group.command("suggest")
@click.argument("task", default="")
@click.pass_context
def mcp_suggest(ctx, task):
    """Get SQL query suggestions for common analysis tasks.

    \b
    Examples:
      r7-cli vm export mcp suggest
      r7-cli vm export mcp suggest "find critical vulns with exploits"
    """
    config = _get_config(ctx)
    try:
        result = _call_tool(config, "suggest_query", {"task": task})
        click.echo(result)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# mcp load-parquet
# ---------------------------------------------------------------------------

@mcp_group.command("load-parquet")
@click.argument("parquet_path", type=click.Path(exists=True))
@click.pass_context
def mcp_load_parquet(ctx, parquet_path):
    """Load local Parquet files into the MCP DuckDB database.

    \b
    Use this if you already have Parquet files downloaded (e.g. from
    `r7-cli vm export vulnerabilities --auto`) and want to load them
    into the MCP database for SQL querying.

    \b
    Note: Files must be within ~/.rapid7-mcp/imports/ for security.

    \b
    Examples:
      r7-cli vm export mcp load-parquet ~/.rapid7-mcp/imports/vuln-data/
    """
    config = _get_config(ctx)
    try:
        result = _call_tool(config, "load_rapid7_parquet", {"parquet_path": parquet_path})
        click.echo(result)
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
