# Privacy Policy

## Overview

r7-cli is a command-line tool that communicates with Rapid7 Insight Platform APIs on your behalf. This document describes what data the CLI handles and where it goes.

## Data the CLI Sends

r7-cli sends requests to Rapid7 API endpoints using credentials you provide. The data sent depends on the command you run:

- **API keys and tokens** — sent as HTTP headers to Rapid7 APIs for authentication. Never logged or written to disk.
- **Command parameters** — query filters, search terms, JSON request bodies, and LEQL/Cypher queries are sent to the corresponding Rapid7 API endpoints.
- **Natural language prompts** (via `r7-cli ai`) — when you use the `ai` command, your prompt and a dynamically generated system prompt (describing available CLI commands) are sent to the LLM provider you configure (OpenAI, Anthropic, or Google). No API keys, credentials, or organization data are included in LLM requests.

## Data the CLI Stores Locally

All local storage is under `~/.r7-cli/` and the current working directory:

| Location | Contents | Sensitive? |
|----------|----------|------------|
| `~/.r7-cli/cache/` | SHA-256-keyed JSON files containing cached API responses | May contain asset names, IPs, vulnerability data |
| `~/.r7-cli/cache/log-queries/` | Cached log query results | May contain log event data |
| `~/.r7-cli/jobs.json` | Export job IDs and timestamps | No |
| `./*.parquet` (working dir) | Downloaded bulk export files | Yes — contains vulnerability, asset, or policy data |

### Clearing Local Data

```bash
# Remove all cached API responses
rm -rf ~/.r7-cli/cache/

# Remove job tracking
rm -f ~/.r7-cli/jobs.json

# Remove downloaded exports
rm -f *.parquet
```

## Data the CLI Does Not Collect

- r7-cli does not send telemetry, analytics, or usage data to any service.
- r7-cli does not phone home or check for updates.
- r7-cli does not store credentials on disk.
- r7-cli does not transmit data to any endpoint other than the Rapid7 APIs you invoke and (optionally) the LLM provider you configure.

## Third-Party Services

| Service | When Used | What Is Sent |
|---------|-----------|--------------|
| Rapid7 Insight Platform APIs | Every API command | API key (header) + request parameters |
| Rapid7 Statuspage (status.rapid7.com) | `r7-cli platform status` | Nothing (unauthenticated GET) |
| OpenAI / Anthropic / Google | `r7-cli ai` with `--llm` | Natural language prompt + CLI command tree description |

## Credential Handling

- Credentials are resolved at runtime from CLI flags or environment variables.
- `R7Client._redact()` strips API keys and tokens from all verbose/debug log output.
- Credentials are never written to local files by the CLI.
- If you use shell history, your API key may appear in `~/.bash_history` or equivalent when passed via `-k`. Using the `R7_X_API_KEY` environment variable avoids this.

## Recommendations

- Use environment variables (`R7_X_API_KEY`, `R7_DRP_TOKEN`) instead of CLI flags to keep credentials out of shell history and process listings.
- Periodically clear `~/.r7-cli/cache/` if you work with sensitive asset or vulnerability data.
- Review downloaded Parquet files and remove them when no longer needed — they contain full export data.
