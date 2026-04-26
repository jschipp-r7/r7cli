"""Natural language → r7-cli command translation.

Uses OpenAI, Anthropic (Claude), or Google Gemini to convert a plain-English
request into the appropriate r7-cli command, then optionally executes it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

import click
import httpx

from r7cli.config import Config
from r7cli.models import UserInputError


# ---------------------------------------------------------------------------
# System prompt shared across all providers
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert at the r7-cli command-line tool for the Rapid7 Command Platform.

Given a user's natural language request, respond with ONLY the r7-cli command \
that accomplishes their goal. Do not include any explanation, markdown formatting, \
or backticks — just the raw command string.

Available solutions: vm, siem, asm, drp, platform, appsec, cnapp, soar

Key commands:
- r7-cli validate — validate API key
- r7-cli vm health — VM health check
- r7-cli vm scans list [--days N] [--status S] [--all-pages] — list scans
- r7-cli vm assets list [--hostname H] [--ip I] [--os-family F] [--all-pages] — list assets
- r7-cli vm assets count — count assets
- r7-cli vm export vulnerabilities --auto — bulk export vulnerabilities
- r7-cli vm export policies --auto — bulk export policies
- r7-cli vm export remediations --auto — bulk export remediations
- r7-cli vm export list [--hostname H] [--severity S] [--has-exploits] — query local parquet
- r7-cli vm export mcp install — install MCP server
- r7-cli vm export mcp start-export [--type T] — start MCP export
- r7-cli vm export mcp query "SQL" — query MCP DuckDB
- r7-cli vm export mcp schema — show MCP table schemas
- r7-cli vm export mcp stats — show MCP statistics
- r7-cli vm vulns list [--severity S] [--all-pages] — list vulnerabilities
- r7-cli vm sites list — list sites
- r7-cli vm scan-engines list — list scan engines
- r7-cli siem health — SIEM health
- r7-cli siem logs query -n "LOG_NAME" [--time-range "Last N days"] — query logs
- r7-cli siem investigations list [--status S] [--all-pages] — list investigations
- r7-cli siem agents list [--all-pages] — list agents
- r7-cli asm queries list — list ASM queries
- r7-cli asm queries execute --query "CYPHER" — run Cypher query
- r7-cli asm connectors list — list connectors
- r7-cli drp alerts list [--severity S] [--days N] — list DRP alerts
- r7-cli drp risk-score — get risk score
- r7-cli platform products list — list licensed products
- r7-cli platform users list — list users
- r7-cli platform assets count — asset counts
- r7-cli platform compliance — export VM policies as SQL
- r7-cli platform compliance list [--vm|--siem|--asm|...] — CIS controls
- r7-cli platform matrix rapid7 [--reality] — coverage matrix
- r7-cli platform status — platform status
- r7-cli appsec apps list — list AppSec apps
- r7-cli cnapp findings list — list cloud findings
- r7-cli soar workflows list — list SOAR workflows

Global flags (must appear BEFORE the solution name):
- -r/--region REGION — set region (us, eu, ca, au, ap, us2, us3)
- -k/--api-key KEY — API key
- -o/--output FORMAT — json, table, csv, tsv, sql
- -s/--short — compact output
- -l/--limit N — limit results
- -c/--cache — use cached response
- -v/--verbose — verbose logging
- --search-fields FIELD — search for field name in response

If the request is ambiguous, pick the most likely command. \
If you truly cannot map the request to any r7-cli command, respond with: \
ERROR: <brief explanation of why>
"""


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

def _call_openai(api_key: str, user_message: str, timeout: int) -> str:
    """Call OpenAI Chat Completions API."""
    resp = httpx.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "temperature": 0,
            "max_tokens": 300,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


def _call_claude(api_key: str, user_message: str, timeout: int) -> str:
    """Call Anthropic Messages API."""
    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 300,
            "system": _SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": user_message},
            ],
            "temperature": 0,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    content = data.get("content", [])
    if content and isinstance(content[0], dict):
        return content[0].get("text", "").strip()
    return ""


def _call_gemini(api_key: str, user_message: str, timeout: int) -> str:
    """Call Google Gemini API."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
    resp = httpx.post(
        url,
        headers={"Content-Type": "application/json"},
        json={
            "system_instruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
            "contents": [
                {"parts": [{"text": user_message}]},
            ],
            "generationConfig": {"temperature": 0, "maxOutputTokens": 300},
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    candidates = data.get("candidates", [])
    if candidates:
        parts = candidates[0].get("content", {}).get("parts", [])
        if parts:
            return parts[0].get("text", "").strip()
    return ""


_PROVIDERS = {
    "openai": _call_openai,
    "claude": _call_claude,
    "gemini": _call_gemini,
}


# ---------------------------------------------------------------------------
# Click command
# ---------------------------------------------------------------------------

@click.command("ask")
@click.argument("question", nargs=-1, required=True)
@click.option("-x", "--execute", is_flag=True, help="Execute the generated command immediately.")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation when using --execute.")
@click.pass_context
def ask_cmd(ctx, question, execute, yes):
    """Translate a natural language request into an r7-cli command.

    \b
    Requires an LLM provider to be configured via:
      --llm openai|claude|gemini  (global flag, before 'ask')
      --llm-key YOUR_KEY          (or use env vars below)

    \b
    Environment variables:
      R7_LLM_PROVIDER    — openai, claude, or gemini
      OPENAI_API_KEY     — for OpenAI
      ANTHROPIC_API_KEY  — for Claude
      GEMINI_API_KEY     — for Gemini
      R7_LLM_API_KEY     — generic fallback for any provider

    \b
    Examples:
      # Get the command for listing critical vulnerabilities
      r7-cli --llm openai ask show me critical vulnerabilities

    \b
      # Execute directly
      r7-cli --llm claude ask -x list all open investigations

    \b
      # Using env vars (no --llm flag needed if R7_LLM_PROVIDER is set)
      export R7_LLM_PROVIDER=gemini
      export GEMINI_API_KEY=your-key
      r7-cli ask how many assets do I have
    """
    config: Config = ctx.obj["config"]

    if not config.llm_provider:
        click.echo(
            "Error: No LLM provider configured.\n\n"
            "Set one of:\n"
            "  --llm openai|claude|gemini  (global flag before 'ask')\n"
            "  R7_LLM_PROVIDER env var\n\n"
            "And provide the API key via --llm-key, or the provider's env var:\n"
            "  OPENAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY",
            err=True,
        )
        sys.exit(1)

    if not config.llm_api_key:
        click.echo(
            f"Error: No API key for '{config.llm_provider}'.\n\n"
            f"Provide via --llm-key flag or set the appropriate env var:\n"
            f"  openai  → OPENAI_API_KEY\n"
            f"  claude  → ANTHROPIC_API_KEY\n"
            f"  gemini  → GEMINI_API_KEY\n"
            f"  (any)   → R7_LLM_API_KEY",
            err=True,
        )
        sys.exit(1)

    user_message = " ".join(question)
    provider_fn = _PROVIDERS[config.llm_provider]

    try:
        command = provider_fn(config.llm_api_key, user_message, config.timeout)
    except httpx.HTTPStatusError as exc:
        click.echo(f"LLM API error ({exc.response.status_code}): {exc.response.text[:200]}", err=True)
        sys.exit(2)
    except httpx.RequestError as exc:
        click.echo(f"Network error calling {config.llm_provider}: {exc}", err=True)
        sys.exit(3)

    # Check for error response from the LLM
    if command.startswith("ERROR:"):
        click.echo(command, err=True)
        sys.exit(1)

    # Strip any accidental markdown backticks
    command = command.strip("`").strip()
    if command.startswith("bash\n"):
        command = command[5:].strip()

    click.echo(f"  {command}")

    if execute:
        if not yes:
            confirm = click.confirm("Execute this command?", default=True)
            if not confirm:
                click.echo("Aborted.", err=True)
                return

        # Execute the command
        try:
            result = subprocess.run(
                command,
                shell=True,
                text=True,
            )
            sys.exit(result.returncode)
        except KeyboardInterrupt:
            click.echo("\nAborted.", err=True)
            sys.exit(130)
