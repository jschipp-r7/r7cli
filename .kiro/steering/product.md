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
| `platform`   | Platform admin       | API key     | Cross-cutting: hosts `agents`, `extensions`, `compliance`, `matrix` subgroups |
| `appsec`     | InsightAppSec        | API key     |                                             |
| `cnapp`      | InsightCloudSec      | API key     | Separate base URL (`insightcloudsec_url`)   |
| `soar`       | InsightConnect       | API key     |                                             |
| `compliance` | VM policy pipeline   | API key     | Registered under `platform`                 |
| `matrix`     | Coverage matrix      | none        | Offline NIST CSF × CIS v8 scoring           |
| `extensions` | Extension Library    | none        | No auth required                            |

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

Key globals: `-r/--region`, `-k/--api-key`, `-o/--output`, `-v/--verbose`, `--debug`, `-c/--cache`, `-l/--limit`, `-s/--short`, `-t/--timeout`, `--search-fields`, `--drp-token`.

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

## Bulk Exports & Parquet

VM exports (vulnerabilities, policies, remediations) produce Parquet files downloaded to a local directory.

- `vm export list` operates offline on local Parquet files using `parquet_filter.py`.
- `parquet_filter.py` handles file resolution, schema detection, typed filtering (`--where` clauses), and auto-join of asset data.
- Export jobs are tracked in `~/.r7-cli/jobs.json` via `JobStore`.

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
