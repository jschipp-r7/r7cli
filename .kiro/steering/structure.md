# Project Structure

The workspace root is the `r7cli` Python package itself (mapped via `pyproject.toml`).

```
.                          # r7cli package root
├── main.py                # CLI entry point — top-level SolutionGroup, global options, lazy solution routing
├── cli_group.py           # GlobalFlagHintGroup — custom Click group that enforces global flag ordering
├── config.py              # Config dataclass + resolve_config() — merges CLI flags, env vars, defaults
├── models.py              # Shared constants (URLs, regions, solutions), GraphQL strings, exception hierarchy
├── client.py              # R7Client — HTTP wrapper with auth, caching, logging, rate-limit retry, error mapping
├── output.py              # format_output() — json/table/csv/tsv/sql formatting, field search, short mode
├── cache.py               # CacheStore — SHA-256-keyed JSON file cache in ~/.r7-cli/cache/
├── jobs.py                # JobStore — export job persistence in ~/.r7-cli/jobs.json
├── agents.py              # Cross-solution asset count command (platform assets count)
├── extensions.py          # Rapid7 Extension Library browser (no auth required)
├── compliance.py          # VM policy export → SQL dump pipeline + CIS controls list subcommand
├── matrix.py              # NIST CSF × CIS v8 coverage matrix with deployment-aware scoring
├── cis.py                 # CIS/NIST CSF controls lookup — shared by per-solution `cis` subcommands and compliance list
├── status.py              # Rapid7 platform status — fetches from status.rapid7.com (no auth required)
├── controls.csv           # Master controls CSV (CIS, NIST CSF, PCI DSS, HITRUST, MITRE) with Rapid7 product mappings
├── product-market.mappings # Market technology → Rapid7 product mapping (tab-delimited)
├── parquet_filter.py      # Parquet file resolution, schema detection, filtering, auto-join for local exports
├── ask.py                 # Natural language → CLI command translation via LLM (OpenAI, Claude, Gemini)
├── solutions/             # Per-product command modules
│   ├── __init__.py
│   ├── vm.py              # InsightVM — health, scans, engines, exports, assets, vulns, sites, cis
│   ├── siem.py            # InsightIDR — health, logs, agents, investigations, detections, cis
│   ├── asm.py             # Surface Command — Cypher queries, connectors, cis
│   ├── drp.py             # Digital Risk Protection — alerts, threats, takedowns, risk score, cis
│   ├── platform.py        # Platform — validate, search, users, orgs, products, roles, credentials
│   ├── appsec.py          # InsightAppSec — apps, scans, vulns, configs, templates, cis
│   ├── cnapp.py           # InsightCloudSec — IaC scans, AWS keys/roles/accounts, findings, cis
│   ├── soar.py            # InsightConnect — workflows, jobs, artifacts, snippets, cis
│   ├── mcp.py             # Rapid7 Bulk Export MCP server — install, configure, query via stdio
│   └── stub.py            # Stub group factory for not-yet-implemented solutions
├── tests/
│   ├── __init__.py
│   └── test_download_mkdir.py  # Hypothesis property-based tests for parquet download
├── docs/
│   └── REFERENCE.md       # CLI reference documentation
└── pyproject.toml         # Build config, dependencies, entry point
```

## Architecture Notes

- Each solution module defines a Click group (e.g. `vm`, `siem`) with subcommand groups and leaf commands
- Solution modules are lazily imported by `SolutionGroup.get_command()` in `main.py`
- `platform.py` registers cross-cutting subgroups: `assets`, `extensions`, `compliance`, `matrix`, `status`
- All solution commands follow the same pattern: get config from context → create R7Client → call API → format output
- Helper functions `_extract_items()`, `_extract_item_id()`, `_resolve_body()` are duplicated across solution modules (not shared)
- Interactive selection (`--auto` / `-a`) uses `questionary` for terminal prompts
- Polling mode (`--auto` with `-i`) tracks seen IDs and prints only new entries
- Every solution group registers a `cis` subcommand via `cis.make_cis_command()` for CIS/NIST CSF controls lookup
- `compliance.py` is a Click group (`invoke_without_command=True`): bare invocation runs the export pipeline, `list` subcommand queries CIS/NIST CSF controls
- `ask.py` uses LLM APIs (OpenAI, Claude, Gemini) to translate natural language into CLI commands; system prompt is dynamically generated from the Click command tree
- `solutions/mcp.py` communicates with the Rapid7 Bulk Export MCP server over stdio JSON-RPC; registered as `vm export mcp` subgroup
