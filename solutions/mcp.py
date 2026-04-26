"""MCP server integration for the Rapid7 Bulk Export MCP.

Provides `r7-cli vm export mcp` subcommands to install, configure, and
interact with the rapid7-bulk-export MCP server from the command line.
"""
from __future__ import annotations

import json
import os
import signal
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

# PID file for persistent server mode
_MCP_PID_DIR = Path.home() / ".r7-cli"
_MCP_PID_FILE = _MCP_PID_DIR / "mcp-server.pid"
_MCP_LOG_FILE = _MCP_PID_DIR / "mcp-server.log"

# Default timeout for reading MCP responses (seconds)
_MCP_READ_TIMEOUT = 30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_config(ctx: click.Context) -> Config:
    return ctx.obj["config"]


def _log_verbose(config: Config, msg: str) -> None:
    """Print a message to stderr when verbose mode is enabled."""
    if config.verbose or config.debug:
        click.echo(f"[mcp] {msg}", err=True)


def _log_debug(config: Config, msg: str) -> None:
    """Print a message to stderr when debug mode is enabled."""
    if config.debug:
        click.echo(f"[mcp:debug] {msg}", err=True)


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

    _log_verbose(config, f"Starting MCP server: {server_cmd}")

    env = dict(os.environ)
    if config.api_key:
        env["RAPID7_API_KEY"] = config.api_key
    env["RAPID7_REGION"] = config.region

    _log_debug(config, f"Region: {config.region}")
    _log_debug(config, f"API key: {'set (' + config.api_key[:4] + '…)' if config.api_key else 'NOT SET'}")

    timeout = config.timeout or _MCP_READ_TIMEOUT

    proc = subprocess.Popen(
        [server_cmd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )

    _log_verbose(config, f"Server process started (PID {proc.pid})")

    try:
        # MCP initialization handshake
        _log_verbose(config, "Sending initialize request…")
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
        _send_message(proc, init_request, config)
        init_response = _read_response(proc, config, timeout=timeout)
        _log_debug(config, f"Init response: {json.dumps(init_response, indent=2)}")
        _log_verbose(config, "Server initialized ✓")

        # Send initialized notification
        initialized_notif = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        _send_message(proc, initialized_notif, config)
        _log_debug(config, "Sent initialized notification")

        # Send the actual tool call
        tool_name = request.get("params", {}).get("name", "unknown")
        _log_verbose(config, f"Calling tool: {tool_name}")
        _log_debug(config, f"Tool arguments: {json.dumps(request.get('params', {}).get('arguments', {}))}")

        tool_request = {
            "jsonrpc": "2.0",
            "id": 2,
            **request,
        }
        _send_message(proc, tool_request, config)
        result = _read_response(proc, config, timeout=timeout)
        _log_verbose(config, f"Tool response received ✓")
        _log_debug(config, f"Response: {json.dumps(result, indent=2)}")

        # Capture and log any stderr from the server
        _drain_stderr(proc, config)

        return result

    except TimeoutError:
        _drain_stderr(proc, config)
        raise R7Error(
            f"MCP server did not respond within {timeout}s. "
            f"Use --timeout to increase, or check server logs with: "
            f"r7-cli vm export mcp server status",
            exit_code=2,
        )
    finally:
        proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
            _log_debug(config, "Server process terminated cleanly")
        except subprocess.TimeoutExpired:
            proc.kill()
            _log_debug(config, "Server process killed (did not terminate in 5s)")


def _drain_stderr(proc: subprocess.Popen, config: Config) -> None:
    """Read any available stderr from the process and log it."""
    try:
        # Non-blocking read of stderr
        import select
        if hasattr(select, "select") and proc.stderr:
            ready, _, _ = select.select([proc.stderr], [], [], 0.1)
            if ready:
                stderr_output = proc.stderr.read()
                if stderr_output and stderr_output.strip():
                    _log_debug(config, f"Server stderr: {stderr_output.strip()}")
    except (OSError, ValueError):
        pass


def _send_message(proc: subprocess.Popen, message: dict, config: Config) -> None:
    """Send a JSON-RPC message using the MCP stdio transport format."""
    body = json.dumps(message)
    header = f"Content-Length: {len(body.encode())}\r\n\r\n"
    _log_debug(config, f"→ Sending {len(body.encode())} bytes: method={message.get('method', 'N/A')}")
    proc.stdin.write(header + body)
    proc.stdin.flush()


def _read_response(proc: subprocess.Popen, config: Config, timeout: int = _MCP_READ_TIMEOUT) -> dict:
    """Read a JSON-RPC response from the MCP server's stdout.

    Raises TimeoutError if no response is received within the timeout period.
    """
    import select

    deadline = time.monotonic() + timeout
    _log_debug(config, f"← Waiting for response (timeout: {timeout}s)…")

    # Read Content-Length header
    header_line = ""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Timed out waiting for MCP response header after {timeout}s")

        # Use select for timeout on reads (Unix)
        if hasattr(select, "select"):
            ready, _, _ = select.select([proc.stdout], [], [], min(remaining, 1.0))
            if not ready:
                # Check if process is still alive
                if proc.poll() is not None:
                    stderr_output = proc.stderr.read() if proc.stderr else ""
                    raise R7Error(
                        f"MCP server exited unexpectedly (code {proc.returncode}). "
                        f"stderr: {stderr_output.strip() or '(empty)'}",
                        exit_code=2,
                    )
                continue

        ch = proc.stdout.read(1)
        if ch == "":
            stderr_output = proc.stderr.read() if proc.stderr else ""
            raise R7Error(
                f"MCP server closed unexpectedly. stderr: {stderr_output.strip() or '(empty)'}",
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

    _log_debug(config, f"← Reading {content_length} bytes…")

    # Read body with timeout
    body = ""
    while len(body.encode()) < content_length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Timed out reading MCP response body after {timeout}s")

        if hasattr(select, "select"):
            ready, _, _ = select.select([proc.stdout], [], [], min(remaining, 1.0))
            if not ready:
                if proc.poll() is not None:
                    stderr_output = proc.stderr.read() if proc.stderr else ""
                    raise R7Error(
                        f"MCP server exited while sending response (code {proc.returncode}). "
                        f"stderr: {stderr_output.strip() or '(empty)'}",
                        exit_code=2,
                    )
                continue

        chunk = proc.stdout.read(content_length - len(body.encode()))
        if chunk == "":
            raise R7Error("MCP server closed while sending response body", exit_code=2)
        body += chunk

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
# Server lifecycle helpers
# ---------------------------------------------------------------------------

def _read_pid_file() -> int | None:
    """Read the PID from the MCP server PID file, or None if not present."""
    if not _MCP_PID_FILE.exists():
        return None
    try:
        pid = int(_MCP_PID_FILE.read_text().strip())
        return pid
    except (ValueError, OSError):
        return None


def _is_process_running(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _write_pid_file(pid: int) -> None:
    """Write the server PID to the PID file."""
    _MCP_PID_DIR.mkdir(parents=True, exist_ok=True)
    _MCP_PID_FILE.write_text(str(pid))


def _remove_pid_file() -> None:
    """Remove the PID file."""
    try:
        _MCP_PID_FILE.unlink()
    except FileNotFoundError:
        pass


def _auto_configure_api_key(config: Config) -> None:
    """Write the API key and region into the Kiro MCP config file.

    Creates or updates .kiro/settings/mcp.json so the MCP server can
    authenticate without requiring env vars at runtime.
    """
    config_path = _KIRO_MCP_CONFIG
    config_path.parent.mkdir(parents=True, exist_ok=True)

    mcp_config: dict = {}
    if config_path.exists():
        try:
            mcp_config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            mcp_config = {}

    mcp_config.setdefault("mcpServers", {})
    mcp_config["mcpServers"]["rapid7-bulk-export"] = {
        "command": _MCP_SERVER_CMD,
        "args": [],
        "env": {
            "RAPID7_API_KEY": config.api_key,
            "RAPID7_REGION": config.region,
        },
    }

    config_path.write_text(json.dumps(mcp_config, indent=2) + "\n")
    click.echo(f"✓ API key configured in {config_path}", err=True)


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

    \b
    Server management:
      r7-cli vm export mcp server start   # Start persistent MCP server
      r7-cli vm export mcp server stop    # Stop the server
      r7-cli vm export mcp server status  # Check if server is running

    \b
    Debugging:
      r7-cli -v vm export mcp query ...   # Verbose: show request/response flow
      r7-cli --debug vm export mcp query ...  # Debug: full JSON payloads
    """
    pass


# ---------------------------------------------------------------------------
# mcp server (subgroup for lifecycle management)
# ---------------------------------------------------------------------------

@mcp_group.group("server", cls=GlobalFlagHintGroup)
@click.pass_context
def mcp_server_group(ctx):
    """Manage the MCP server process (start, stop, status).

    \b
    By default, each `mcp` command starts a fresh server subprocess,
    runs the request, and shuts it down. For repeated queries, you can
    start a persistent server that stays running in the background.

    \b
    Examples:
      r7-cli vm export mcp server start
      r7-cli vm export mcp server status
      r7-cli vm export mcp server stop
    """
    pass


@mcp_server_group.command("start")
@click.pass_context
def mcp_server_start(ctx):
    """Start the MCP server as a persistent background process.

    \b
    The server runs in the background and logs to ~/.r7-cli/mcp-server.log.
    Use `server status` to check if it's running, and `server stop` to shut it down.

    \b
    If the MCP server is not installed, it will be installed automatically.
    The API key from your current config is written to the Kiro MCP config
    so the server can authenticate on startup.

    \b
    Examples:
      r7-cli vm export mcp server start
      r7-cli -v vm export mcp server start
    """
    config = _get_config(ctx)

    server_cmd = _find_mcp_server()
    if not server_cmd:
        click.echo("MCP server is not installed. Installing now…", err=True)
        cmd = [sys.executable, "-m", "pip", "install", _MCP_PACKAGE]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                click.echo(f"Installation failed:\n{result.stderr}", err=True)
                sys.exit(2)
            click.echo("✓ MCP server installed.", err=True)
        except subprocess.TimeoutExpired:
            click.echo("Installation timed out.", err=True)
            sys.exit(2)
        server_cmd = _find_mcp_server()
        if not server_cmd:
            click.echo(
                "rapid7-mcp-server not found on PATH after install. "
                "You may need to restart your shell.",
                err=True,
            )
            sys.exit(2)

    # Auto-configure API key into the Kiro MCP config
    if config.api_key:
        _auto_configure_api_key(config)
    else:
        click.echo(
            "Warning: No API key set. The server may not be able to authenticate.\n"
            "  Set via: -k <key>, or R7_X_API_KEY env var.",
            err=True,
        )

    # Check if already running
    existing_pid = _read_pid_file()
    if existing_pid and _is_process_running(existing_pid):
        click.echo(f"MCP server is already running (PID {existing_pid}).")
        click.echo(f"  Log: {_MCP_LOG_FILE}")
        return

    # Build environment
    env = dict(os.environ)
    if config.api_key:
        env["RAPID7_API_KEY"] = config.api_key
    env["RAPID7_REGION"] = config.region

    _log_verbose(config, f"Starting persistent server: {server_cmd}")
    _log_debug(config, f"Region: {config.region}")
    _log_debug(config, f"Log file: {_MCP_LOG_FILE}")

    # Start the server in the background
    _MCP_PID_DIR.mkdir(parents=True, exist_ok=True)
    log_file = open(_MCP_LOG_FILE, "a")

    proc = subprocess.Popen(
        [server_cmd],
        stdin=subprocess.PIPE,
        stdout=log_file,
        stderr=log_file,
        env=env,
        start_new_session=True,  # Detach from terminal
    )

    # Give it a moment to start (or crash)
    time.sleep(1)
    if proc.poll() is not None:
        log_file.close()
        # Server exited immediately — read the log for clues
        recent_log = ""
        try:
            recent_log = _MCP_LOG_FILE.read_text()[-500:]
        except OSError:
            pass
        click.echo(f"MCP server failed to start (exit code {proc.returncode}).", err=True)
        if recent_log:
            click.echo(f"Recent log output:\n{recent_log}", err=True)
        sys.exit(2)

    _write_pid_file(proc.pid)
    log_file.close()

    click.echo(f"✓ MCP server started (PID {proc.pid})")
    click.echo(f"  Log: {_MCP_LOG_FILE}")
    click.echo(f"  Stop: r7-cli vm export mcp server stop")


@mcp_server_group.command("stop")
@click.pass_context
def mcp_server_stop(ctx):
    """Stop the persistent MCP server process.

    \b
    Sends SIGTERM to the server process. If it doesn't stop within 5 seconds,
    sends SIGKILL.

    \b
    Examples:
      r7-cli vm export mcp server stop
    """
    config = _get_config(ctx)

    pid = _read_pid_file()
    if pid is None:
        click.echo("No MCP server PID file found. Server may not be running.")
        _remove_pid_file()
        return

    if not _is_process_running(pid):
        click.echo(f"MCP server (PID {pid}) is not running. Cleaning up PID file.")
        _remove_pid_file()
        return

    _log_verbose(config, f"Stopping MCP server (PID {pid})…")

    try:
        os.kill(pid, signal.SIGTERM)
        # Wait for graceful shutdown
        for _ in range(50):  # 5 seconds in 100ms increments
            if not _is_process_running(pid):
                break
            time.sleep(0.1)
        else:
            # Force kill if still running
            _log_verbose(config, "Server did not stop gracefully, sending SIGKILL")
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
    except ProcessLookupError:
        pass

    _remove_pid_file()
    click.echo(f"✓ MCP server stopped (was PID {pid})")


@mcp_server_group.command("status")
@click.pass_context
def mcp_server_status(ctx):
    """Check if the MCP server is running.

    \b
    Shows the server PID, whether it's responsive, and the log file location.

    \b
    Examples:
      r7-cli vm export mcp server status
    """
    config = _get_config(ctx)

    # Check binary availability
    server_cmd = _find_mcp_server()
    if not server_cmd:
        click.echo("MCP server binary: NOT INSTALLED")
        click.echo(f"  Install with: r7-cli vm export mcp install")
        return

    click.echo(f"MCP server binary: {server_cmd}")

    # Check persistent server
    pid = _read_pid_file()
    if pid is None:
        click.echo("Persistent server: not started")
    elif _is_process_running(pid):
        click.echo(f"Persistent server: RUNNING (PID {pid})")
    else:
        click.echo(f"Persistent server: DEAD (stale PID {pid})")
        _remove_pid_file()

    # Show log file info
    if _MCP_LOG_FILE.exists():
        size = _MCP_LOG_FILE.stat().st_size
        click.echo(f"Log file: {_MCP_LOG_FILE} ({size} bytes)")
        # Show last few lines
        try:
            lines = _MCP_LOG_FILE.read_text().strip().split("\n")
            tail = lines[-5:] if len(lines) > 5 else lines
            if tail and tail[0]:
                click.echo("  Last log lines:")
                for line in tail:
                    click.echo(f"    {line}")
        except OSError:
            pass
    else:
        click.echo(f"Log file: {_MCP_LOG_FILE} (not created yet)")

    # Quick connectivity test (start a server, send init, shut down)
    click.echo("")
    click.echo("Testing server connectivity…")
    try:
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
        _send_message(proc, init_request, config)
        response = _read_response(proc, config, timeout=10)
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=5)

        server_info = response.get("result", {}).get("serverInfo", {})
        server_name = server_info.get("name", "unknown")
        server_version = server_info.get("version", "unknown")
        click.echo(f"  ✓ Server responds: {server_name} v{server_version}")
    except TimeoutError:
        click.echo("  ✗ Server did not respond within 10s (may be hanging on startup)")
        click.echo("    Check that RAPID7_API_KEY is set and valid")
    except R7Error as exc:
        click.echo(f"  ✗ Server error: {exc}")
    except Exception as exc:
        click.echo(f"  ✗ Could not connect: {exc}")
    finally:
        try:
            proc.kill()
        except Exception:
            pass


@mcp_server_group.command("logs")
@click.option("-n", "--lines", type=int, default=20, help="Number of lines to show (default: 20).")
@click.option("-f", "--follow", is_flag=True, help="Follow log output (like tail -f). Press Ctrl+C to stop.")
@click.pass_context
def mcp_server_logs(ctx, lines, follow):
    """Show MCP server log output.

    \b
    Examples:
      r7-cli vm export mcp server logs
      r7-cli vm export mcp server logs -n 50
      r7-cli vm export mcp server logs -f
    """
    if not _MCP_LOG_FILE.exists():
        click.echo(f"No log file found at {_MCP_LOG_FILE}")
        click.echo("Start the server first: r7-cli vm export mcp server start")
        return

    if follow:
        click.echo(f"Following {_MCP_LOG_FILE} (Ctrl+C to stop)…", err=True)
        try:
            with open(_MCP_LOG_FILE) as f:
                # Seek to end
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        click.echo(line, nl=False)
                    else:
                        time.sleep(0.2)
        except KeyboardInterrupt:
            pass
    else:
        content = _MCP_LOG_FILE.read_text()
        all_lines = content.strip().split("\n")
        tail = all_lines[-lines:] if len(all_lines) > lines else all_lines
        for line in tail:
            click.echo(line)


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
@click.option("--type", "export_type", type=click.Choice(("vulnerability", "policy", "remediation", "asset")),
              default=None, help="Download only this export type. Default: download all available.")
@click.option("--output-dir", type=click.Path(), default=None, help="Directory to save files (default: current dir).")
@click.pass_context
def mcp_download(ctx, export_type, output_dir):
    """Download available bulk exports and load into the MCP DuckDB database.

    \b
    By default, downloads ALL available export types (vulnerabilities,
    policies, assets, remediations). Use --type to limit to a single type.

    \b
    This is the equivalent of `r7-cli vm export vulnerabilities --auto` but
    routed through the MCP server for DuckDB loading.

    \b
    Examples:
      # Download everything available
      r7-cli vm export mcp download

    \b
      # Download only vulnerabilities
      r7-cli vm export mcp download --type vulnerability

    \b
      # Download only policies to a specific directory
      r7-cli vm export mcp download --type policy --output-dir ./exports
    """
    config = _get_config(ctx)

    # Determine which types to download
    if export_type:
        types_to_download = [export_type]
    else:
        types_to_download = ["vulnerability", "policy", "asset"]
        # Remediation requires date range — include it with a sensible default
        types_to_download.append("remediation")

    click.echo(f"Downloading all available exports: {', '.join(types_to_download)}", err=True)
    if output_dir:
        click.echo(f"Output directory: {output_dir}", err=True)

    results: list[tuple[str, str]] = []  # (type, status)

    for etype in types_to_download:
        click.echo(f"\n{'─' * 40}", err=True)
        click.echo(f"▶ Starting {etype} export…", err=True)

        try:
            # Start the export
            arguments: dict[str, Any] = {"export_type": etype}
            start_result = _call_tool(config, "start_rapid7_export", arguments)
            click.echo(f"  {start_result.splitlines()[0] if start_result else 'Export started'}", err=True)

            # Extract export ID from the response
            export_id = _extract_export_id_from_text(start_result)
            if not export_id:
                click.echo(f"  Could not extract export ID. Raw response:", err=True)
                click.echo(f"  {start_result}", err=True)
                results.append((etype, "FAILED (no ID)"))
                continue

            # Poll until complete
            click.echo(f"  Export ID: {export_id} — polling for completion…", err=True)
            poll_timeout = time.monotonic() + 600  # 10 minute max
            while time.monotonic() < poll_timeout:
                status_result = _call_tool(config, "check_rapid7_export_status", {"export_id": export_id})
                if "COMPLETE" in status_result.upper() or "SUCCEEDED" in status_result.upper():
                    click.echo(f"  ✓ Export complete.", err=True)
                    break
                elif "FAILED" in status_result.upper() or "ERROR" in status_result.upper():
                    click.echo(f"  ✗ Export failed: {status_result.splitlines()[0]}", err=True)
                    results.append((etype, "FAILED"))
                    break
                else:
                    _log_verbose(config, f"  Status: {status_result.splitlines()[0] if status_result else 'unknown'}")
                    time.sleep(10)
            else:
                click.echo(f"  ✗ Timed out waiting for {etype} export (10 min).", err=True)
                results.append((etype, "TIMEOUT"))
                continue

            # Download the completed export
            if results and results[-1][0] == etype:
                continue  # Already recorded a failure

            dl_args: dict[str, Any] = {"export_id": export_id, "export_type": etype}
            dl_result = _call_tool(config, "download_rapid7_export", dl_args)
            click.echo(f"  ✓ Downloaded: {dl_result.splitlines()[0] if dl_result else 'done'}", err=True)
            results.append((etype, "OK"))

        except R7Error as exc:
            click.echo(f"  ✗ Error: {exc}", err=True)
            results.append((etype, f"ERROR: {exc}"))

    # Summary
    click.echo(f"\n{'─' * 40}", err=True)
    click.echo("Download summary:", err=True)
    for etype, status in results:
        icon = "✓" if status == "OK" else "✗"
        click.echo(f"  {icon} {etype}: {status}", err=True)


def _extract_export_id_from_text(text: str) -> str | None:
    """Try to extract an export/job ID from MCP tool response text.

    Looks for common patterns: UUIDs, or key-value pairs like 'id: xxx'.
    """
    import re
    # Try UUID pattern first
    uuid_match = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text, re.IGNORECASE)
    if uuid_match:
        return uuid_match.group(0)
    # Try "id": "xxx" or id: xxx patterns
    id_match = re.search(r'["\']?(?:export_?)?id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)', text, re.IGNORECASE)
    if id_match:
        return id_match.group(1)
    return None


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
