---
inclusion: always
---

# Product Conventions

r7-cli is a CLI for the Rapid7 Command Platform. It wraps multiple security products behind a single `r7-cli SOLUTION SUBCOMMAND` interface.


## Solutions

| CLI name     | Product              | Auth        | Notes                                      |
|--------------|----------------------|-------------|--------------------------------------------|
| `vm`         | InsightVM            | API key     | Bulk exports produce Parquet files          |
| `siem`       | InsightIDR           | API key     | GraphQL for agents; REST for everything else|
| `asm`        | Surface Command      | API key     | Cypher query language                       |
| `drp`        | Digital Risk Prot.   | DRP token   | Separate token format (`user:key`)          |
| `platform`   | Platform admin       | API key     | Cross-cutting: hosts `assets`, `extensions`, `compliance`, `matrix`, `status` subgroups |
| `appsec`     | InsightAppSec        | API key     |                                             |
| `cnapp`      | InsightCloudSec      | API key     | Separate base URL (`insightcloudsec_url`)   |
| `soar`       | InsightConnect       | API key     |                                             |
| `compliance` | VM policy pipeline   | API key     | Registered under `platform`                 |
| `matrix`     | Coverage matrix      | none        | Offline NIST CSF × CIS v8 scoring           |
| `status`     | Platform status      | none        | Fetches from status.rapid7.com, no auth     |
| `extensions` | Extension Library    | none        | No auth required                            |

## Top-Level Utility Commands

| CLI name     | Purpose                                                    |
|--------------|------------------------------------------------------------|
| `validate`   | Validate API key against the Insight Platform              |
| `tldr`       | Show quick-reference examples for common commands          |
| `ask`        | Translate natural language into r7-cli commands via LLM    |
| `validate`   | Validate API key against the Insight Platform              |
| `tldr`       | Show quick-reference examples for common commands          |

## Market Technologies

`VALID_MARKET_TECHNOLOGIES` in `models.py` enumerates the supported market technology categories (e.g. `SIEM`, `EDR`, `VM`, `CNAPP`, `SOAR`). These map to Rapid7 products via `product-market.mappings` (tab-delimited: category → implementation products → supporting products). The CIS module (`cis.py`) uses the CSV columns "Implementation Market Technologies" and "Supporting Market Technologies" to tag each control with its relevant market categories.

## Command Patterns

Every solution command follows the same shape:

1. Retrieve `Config` from Click context via `_get_config(ctx)`.
2. Instantiate `R7Client(config)`.
3. Call the API (`client.get()` / `client.post()`), passing `solution=` and `subcommand=` for cache keying and logging.
4. Format with `format_output(result, config.output_format, config.limit, config.search, short=config.short)`.
5. Catch `R7Error` at the leaf command and `sys.exit(exc.exit_code)`.

When adding a new command, replicate this pattern exactly. Do not introduce alternative HTTP clients or output paths.

## Per-Module Helpers (Not Shared)

Each solution module re-defines these private helpers locally:

- `_get_config(ctx)` — extract `Config` from `ctx.obj["config"]`
- `_extract_items(data)` — normalize API response into a list of dicts
- `_extract_item_id(item)` — pull the best identifier from a dict (tries `id`, `rrn`, `key`, etc.)
- `_resolve_body(data_str, data_file)` — parse inline JSON or read from file for POST/PUT payloads

These are intentionally duplicated, not shared. Keep them private (underscore-prefixed) and co-located with their solution module.

## Global Options

Global flags must appear before the solution name on the command line. `GlobalFlagHintGroup` in `cli_group.py` enforces this and prints a corrective hint if violated.

Key globals: `-r/--region`, `-k/--api-key`, `-o/--output`, `-v/--verbose`, `--debug`, `-c/--cache`, `-l/--limit`, `-s/--short`, `-t/--timeout`, `--search-fields`, `--drp-token`, `--llm`, `--llm-key`.

## Authentication & Licensing

- Primary auth: `R7_X_API_KEY` env var or `-k` flag.
- DRP uses a separate token: `R7_DRP_TOKEN` or `--drp-token`.
- License checking runs once per invocation (cached in `ctx.obj["_licensed_codes"]`). It maps solution names to product codes (e.g. `vm` → `IVM`). Unlicensed solutions exit with code 1.
- License check is skipped for help requests, cache mode, and offline subcommands.

## Output Formats

Supported via `-o`: `json` (default), `table`, `csv`, `tsv`, `sql`.

- `--short` / `-s`: compact one-line-per-row JSON with field priority reordering (high-priority fields like `name`, `status`, `severity` first; low-priority like IDs and UUIDs last) and terminal-width truncation.
- `--search-fields`: recursive field-name search across the response, returns matching values with a count.
- `--limit`: truncates the largest top-level array in the response.

All formatting goes through `output.py:format_output()`. Do not bypass it.

## Interactive Selection & Polling

- `--auto` / `-a`: uses `questionary` to present an interactive picker when a command needs an entity ID.
- `--auto` combined with `--interval` / `-i`: polling mode that re-fetches on an interval, tracking seen IDs and printing only new entries.

## CIS & NIST CSF Controls Lookup

Every solution group (`vm`, `siem`, `asm`, `drp`, `appsec`, `cnapp`, `soar`) registers a `cis` subcommand via `cis.make_cis_command(solution)`. The `platform compliance list` command provides the same functionality with per-product flags.

Data source: `controls.csv` (bundled with the package) — the master controls spreadsheet with columns for Framework, Version, CIS Asset Type, NIST Category, Control ID, Control Description, Implementation Market Technologies, Rapid7 Implementation Products, Supporting Market Technologies, Rapid7 Supporting Products.

Product matching uses the "Rapid7 Implementation Products (Custom Script)" and "Rapid7 Supporting Products (Custom Script)" CSV columns. The `_SOLUTION_PRODUCTS` dict in `cis.py` maps CLI solution names to product strings:

| Flag / Solution | CSV Product Match |
|----------------|-------------------|
| `--vm` / `vm` | insightVM, Nexpose |
| `--siem` / `siem` | insightIDR |
| `--asm` / `asm` | Surface Command |
| `--drp` / `drp` | DRP, DRPS, Threat Command |
| `--appsec` / `appsec` | insightAppSec |
| `--cnapp` / `cnapp` | insightCloudSec |
| `--soar` / `soar` | insightConnect |
| `--dspm` | DSPM Add-On |
| `--grc` | Cyber GRC Add-On |
| `--patching` | Automox Add-On |

Framework filters:
- `--ig1`, `--ig2`, `--ig3` — filter CIS rows by Implementation Group (from the Framework field)
- `--csf` — switch to NIST CSF rows instead of CIS (uses "NIST Category" instead of "CIS Asset Type")
- `--other` — show controls not mapped to any Rapid7 product (excludes DSPM, GRC, and Patching)

Each result includes: Framework, Version, CIS Asset Type (or NIST Category for CSF), Control ID, Control Description, Solutions (array), Market Categories (array).

## Bulk Exports & Parquet

VM exports (vulnerabilities, policies, remediations) produce Parquet files downloaded to a local directory.

- `vm export list` operates offline on local Parquet files using `parquet_filter.py`.
- `parquet_filter.py` handles file resolution, schema detection, typed filtering (`--where` clauses), and auto-join of asset data.
- Export jobs are tracked in `~/.r7-cli/jobs.json` via `JobStore`.

## MCP Server Integration

The `vm export mcp` subgroup integrates the [Rapid7 Bulk Export MCP](https://github.com/rapid7/rapid7-bulk-export-mcp) server. It communicates over stdio using JSON-RPC (Model Context Protocol).

- `mcp install` — installs the `rapid7-bulk-export-mcp` package from GitHub
- `mcp configure` — writes MCP config for Kiro, Claude Desktop, VS Code, or Claude Code
- `mcp start-export` / `mcp status` / `mcp download` — manage exports via MCP tools
- `mcp query "SQL"` — execute SQL against the local DuckDB database
- `mcp schema` / `mcp stats` / `mcp list-exports` / `mcp suggest` — introspect loaded data
- The MCP server binary is `rapid7-mcp-server`; env vars `RAPID7_API_KEY` and `RAPID7_REGION` are passed from the CLI config

## Natural Language Commands (ask)

The `ask` top-level command translates natural language into r7-cli commands using an LLM.

- Requires `--llm openai|claude|gemini` global flag (or `R7_LLM_PROVIDER` env var)
- API key resolved from `--llm-key` flag, provider-specific env var (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`), or `R7_LLM_API_KEY`
- System prompt is dynamically generated by walking the Click command tree at runtime — always in sync
- `-x` / `--execute` runs the generated command; `-y` / `--yes` skips confirmation
- Implementation in `ask.py`; registered as a top-level command in `SolutionGroup.get_command()`

## Error Handling

Three exception classes under `R7Error`, each with a fixed exit code:

| Exception        | Exit code | When                                  |
|------------------|-----------|---------------------------------------|
| `UserInputError` | 1         | Bad flag, missing arg, invalid value  |
| `APIError`       | 2         | HTTP 4xx/5xx, API-level errors        |
| `NetworkError`   | 3         | Connection refused, timeout, DNS fail |

Always raise the appropriate subclass. Never use bare `sys.exit()` for error conditions that fit this hierarchy.

## Region Handling

Supported regions: `us`, `us2`, `us3`, `ca`, `eu`, `au`, `ap`, `me-central-1`, `ap-south-2`. Alias `us1` → `us`. Base URLs are templates formatted with `{region}` (defined in `models.py`).

## Code Style Rules

- Private helpers are underscore-prefixed (`_get_config`, `_extract_items`).
- Click decorators: use `@click.pass_context` on every command; use `GlobalFlagHintGroup` (or its subclass) as the `cls` for solution-level groups.
- All solution groups set `context_settings={"help_option_names": ["-h", "--help"]}`.
- Credential values must never appear in logs. `R7Client` uses `_redact()` to strip API keys and tokens from verbose/debug output.
- Imports of solution modules are lazy (inside `SolutionGroup.get_command()`). Do not add top-level imports for solution modules in `main.py`.
