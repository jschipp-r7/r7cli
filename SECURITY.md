# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in r7-cli, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email security findings to the project maintainers with:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested remediation

You should receive an acknowledgment within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Security Design

### Authentication

- API keys are resolved from CLI flags (`-k`) or the `R7_X_API_KEY` environment variable. They are never written to disk by the CLI itself.
- DRP tokens use a separate credential (`--drp-token` / `R7_DRP_TOKEN`).
- LLM API keys are resolved from provider-specific environment variables or the `--llm-key` flag.
- All credential values are redacted from verbose and debug log output via `R7Client._redact()`.

### Network

- All API communication uses HTTPS. Base URLs are hardcoded templates in `models.py` — no user-controlled scheme selection.
- HTTP requests go through `R7Client` (backed by `httpx`), which enforces timeouts and handles rate-limit retries.
- The MCP server integration communicates over local stdio (JSON-RPC), not over the network.

### Local Storage

- Response cache: `~/.r7-cli/cache/` — SHA-256-keyed JSON files. Contains API response data, not credentials.
- Job tracking: `~/.r7-cli/jobs.json` — export job IDs and timestamps.
- Parquet exports: downloaded to the current directory or a user-specified path.
- No credentials are persisted to disk by the CLI.

### Dependencies

Runtime dependencies are pinned to minimum versions and reviewed for known CVEs:

- `click` — CLI framework, no known CVEs
- `httpx` — HTTP client, no known CVEs at pinned version
- `tabulate` — table formatting, no known CVEs
- `pyarrow` — Parquet I/O, no known CVEs at pinned version
- `questionary` — interactive prompts, no known CVEs

Dev dependencies:

- `pytest>=9.0.3` — pinned above the tmp directory vulnerability fix
- `hypothesis>=6.0` — property-based testing, no known CVEs

Build tooling:

- `setuptools>=68.0`
- `wheel>=0.46.2` — pinned above the path traversal fix (CVE-2022-40898)

### Input Handling

- JSON request bodies are parsed via `json.loads()` / `json.load()` — no `eval()` or `exec()`.
- Parquet filter expressions (`--where`) use typed comparison parsing, not string interpolation.
- LEQL queries and Cypher queries are passed as-is to the respective APIs — the CLI does not construct query strings from user input via concatenation.

## Dependency Auditing

To check for known vulnerabilities in the dependency tree:

```bash
pip install pip-audit
pip-audit
```
