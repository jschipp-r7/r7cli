---
inclusion: always
---

# Project Structure

Uses the standard Python `src` layout. The `r7cli` package lives under `src/r7cli/`, mapped via `pyproject.toml`.

```
.                              # Repository root
├── pyproject.toml             # Build config, dependencies, entry point
├── README.md                  # Project README
├── SECURITY.md                # Security policy and vulnerability reporting
├── PRIVACY.md                 # Privacy policy and data handling
├── LICENSE                    # License file
├── docs/
│   └── REFERENCE.md           # CLI reference documentation
├── tests/
│   ├── __init__.py
│   └── test_download_mkdir.py # Hypothesis property-based tests for parquet download
└── src/
    └── r7cli/                 # Main package
        ├── __init__.py
        ├── main.py            # CLI entry point — top-level SolutionGroup, global options, lazy solution routing
        ├── cli_group.py       # GlobalFlagHintGroup — custom Click group that enforces global flag ordering
        ├── config.py          # Config dataclass + resolve_config() — merges CLI flags, env vars, defaults
        ├── models.py          # Shared constants (URLs, regions, solutions), GraphQL strings, exception hierarchy
        ├── client.py          # R7Client — HTTP wrapper with auth, caching, logging, rate-limit retry, error mapping
        ├── output.py          # format_output() — json/table/csv/tsv/sql formatting, field search, short mode
        ├── helpers.py         # Shared helpers — get_config, extract_items, extract_item_id, resolve_body, parse_cmp_expr, emit, handle_errors, poll_loop, option decorators
        ├── cache.py           # CacheStore — SHA-256-keyed JSON file cache in ~/.r7-cli/cache/
        ├── jobs.py            # JobStore — export job persistence in ~/.r7-cli/jobs.json
        ├── progress.py        # ANSI progress bar utilities (progress_bar, spinner, pagination/download progress)
        ├── agents.py          # Cross-solution asset count command (platform assets count)
        ├── extensions.py      # Rapid7 Extension Library browser (no auth required)
        ├── compliance.py      # VM policy export → SQL dump pipeline + CIS controls list subcommand
        ├── matrix.py          # NIST CSF × CIS v8 coverage matrix with deployment-aware scoring
        ├── cis.py             # CIS/NIST CSF controls lookup — shared by per-solution `cis` subcommands and compliance list
        ├── status.py          # Rapid7 platform status — fetches from status.rapid7.com (no auth required)
        ├── ask.py             # Natural language → CLI command translation via LLM (OpenAI, Claude, Gemini)
        ├── parquet_filter.py  # Parquet file resolution, schema detection, filtering, auto-join for local exports
        ├── controls.csv       # Master controls CSV (CIS, NIST CSF, PCI DSS, HITRUST, MITRE) with Rapid7 product mappings
        ├── product-market.mappings # Market technology → Rapid7 product mapping (tab-delimited)
        └── solutions/         # Per-product command modules
            ├── __init__.py
            ├── vm.py          # InsightVM — health, scans, engines, sites, assets, vulns, exports, cis
            ├── siem.py        # InsightIDR — health, agents, logs, investigations, detections, collectors, event-sources, quarantine, cis
            ├── asm.py         # Surface Command — Cypher queries, connectors, cis
            ├── drp.py         # Digital Risk Protection — alerts, threats, takedowns, risk score, IOC sources, SSL threats, cis
            ├── platform.py    # Platform — validate, search, users, orgs, products, roles, api-keys, features, user-groups, credentials
            ├── appsec.py      # InsightAppSec — apps, scans, scan-configs, vulns, engines, engine-groups, schedules, blackouts, attack-templates, targets, modules, reports, tags, cis
            ├── cnapp.py       # InsightCloudSec — IaC scans, AWS keys/roles/accounts, findings, cis
            ├── soar.py        # InsightConnect — workflows, jobs, artifacts, snippets, plugins, cis
            ├── mcp.py         # Rapid7 Bulk Export MCP server — install, configure, query, schema, stats, clean via stdio
            └── stub.py        # Stub group factory for not-yet-implemented solutions
```

## Architecture Notes

- Each solution module defines a Click group (e.g. `vm`, `siem`) with subcommand groups and leaf commands
- Solution modules are lazily imported by `SolutionGroup.get_command()` in `main.py`
- `platform.py` registers cross-cutting subgroups: `assets`, `extensions`, `compliance`, `matrix`, `status`
- All solution commands follow the same pattern: get config from context → create R7Client → call API → format output
- Common helpers live in `helpers.py`: `get_config()`, `extract_items()`, `extract_item_id()`, `resolve_body()`, `parse_cmp_expr()`, `emit()`, `handle_errors()`, `poll_loop()`, `auto_poll_options`, `data_body_options`
- Solution modules import these shared helpers; some keep underscore aliases (e.g. `_get_config = get_config`) for internal consistency
- Interactive selection (`--auto` / `-a`) uses `questionary` for terminal prompts
- Polling mode (`--auto` with `-i`) uses `poll_loop()` from helpers or inline loops for custom cases
- Every solution group registers a `cis` subcommand via `cis.make_cis_command()` for CIS/NIST CSF controls lookup
- `compliance.py` is a Click group (`invoke_without_command=True`): bare invocation runs export, `list` subcommand queries controls
- `matrix.py` is a Click group with `matrix` (default) and `rapid7` (alias) subcommands; supports `--percent`, `--solution`, `--reality`, `--scoring`, `--json`
- `ask.py` uses LLM APIs (OpenAI, Claude, Gemini) to translate natural language into CLI commands; system prompt is dynamically generated from the Click command tree
- `solutions/mcp.py` communicates with the Rapid7 Bulk Export MCP server over stdio JSON-RPC; registered as `vm export mcp` subgroup
- `progress.py` provides ANSI progress bars, spinners, and pagination/download progress indicators (all output to stderr)
- `status.py` fetches from status.rapid7.com Statuspage API (no auth required); renders human-readable or JSON output
