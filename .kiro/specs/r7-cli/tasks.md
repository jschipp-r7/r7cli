# Implementation Plan: r7-cli

## Overview

Implement `r7-cli` as a Python package using Click for CLI dispatch, httpx for HTTP, pyarrow for Parquet, and tabulate for table output. Tasks are ordered from foundational infrastructure through solution-specific commands, with property-based and unit tests alongside each component.

## Tasks

- [x] 1. Project scaffold and package setup
  - Create `r7cli/` package with `__init__.py`, `solutions/` sub-package with `__init__.py`
  - Create `tests/` directory with `__init__.py` and empty test files for each module
  - Create `pyproject.toml` (or `setup.cfg`) declaring dependencies: `click`, `httpx`, `pyarrow`, `tabulate`, `hypothesis`, `pytest`
  - Create `r7cli/models.py` with `JobEntry` dataclass, exception hierarchy (`R7Error`, `UserInputError`, `APIError`, `NetworkError`), and all constants (`VALID_REGIONS`, `REGION_ALIASES`, `VALID_SOLUTIONS`, `STUB_SOLUTIONS`, `VALID_OUTPUT_FORMATS`, `VALID_SEARCH_TYPES`, exit code constants, GraphQL mutation/query strings)
  - _Requirements: 1a.2, 10.1–10.4, 17.1_

- [x] 2. Implement `config.py` — config resolution
  - Implement `Config` dataclass with fields: `region`, `api_key`, `drp_token`, `verbose`, `debug`, `output_format`, `use_cache`, `limit`
  - Implement `resolve_config()` applying priority order: flag → env → default for `api_key` and `region`; normalize `us1` → `us`; validate region against `VALID_REGIONS`; raise `UserInputError` for invalid region or missing API key
  - _Requirements: 1.2, 1.3, 1.4, 1.5, 17.1, 17.2_

  - [ ]* 2.1 Write property test for config resolution priority (Property 1)
    - **Property 1: Config Resolution Priority**
    - **Validates: Requirements 1.2, 1.3, 1.4**

  - [ ]* 2.2 Write property test for invalid region rejection (Property 3)
    - **Property 3: Invalid Region Rejects with Non-Zero Exit**
    - **Validates: Requirements 17.1, 17.2**

  - [ ]* 2.3 Write property test for short/long flag equivalence (Property 16)
    - **Property 16: Short/Long Flag Equivalence**
    - **Validates: Requirements 35.1, 35.2, 35.3**

  - [ ]* 2.4 Write unit tests for `config.py`
    - Test `us1` normalization, missing API key error, env var fallback, flag override
    - _Requirements: 1.2–1.5, 17.1–17.2_

- [x] 3. Implement `cache.py` — local response cache
  - Implement `cache_key(solution, subcommand, region, url, params) -> str` as SHA-256 hex digest
  - Implement `CacheStore` with `read(key) -> dict | None` and `write(key, body) -> None`; store files at `~/.r7-cli/cache/{key}.json`; catch `OSError` on write, print warning to stderr, continue
  - _Requirements: 37.1–37.7_

  - [ ]* 3.1 Write property test for cache key determinism (Property 12)
    - **Property 12: Cache Key Determinism**
    - **Validates: Requirements 37.2**

  - [ ]* 3.2 Write property test for cache round-trip (Property 13)
    - **Property 13: Cache Round-Trip**
    - **Validates: Requirements 37.3, 37.4**

  - [ ]* 3.3 Write unit tests for `cache.py`
    - Test read miss, read hit, write failure (OSError), key uniqueness for different params
    - _Requirements: 37.2–37.6_

- [x] 4. Implement `jobs.py` — job ID persistence
  - Implement `JobStore` backed by `~/.r7-cli/jobs.json` with `add(entry)`, `get_latest(export_type)`, `get_active(export_type)`, `remove(job_id)`, `mark_terminal(job_id, status)`
  - `get_latest` returns the entry with the most recent `created_at`; `mark_terminal` removes the entry from active jobs
  - _Requirements: 38.1–38.6_

  - [ ]* 4.1 Write property test for job store latest selection (Property 14)
    - **Property 14: Job Store Latest Selection**
    - **Validates: Requirements 38.2**

  - [ ]* 4.2 Write property test for job store terminal removal (Property 15)
    - **Property 15: Job Store Terminal Removal**
    - **Validates: Requirements 38.4**

  - [ ]* 4.3 Write unit tests for `jobs.py`
    - Test add/get/remove, interactive selection prompt when multiple active jobs, empty store error
    - _Requirements: 38.1–38.6_

- [x] 5. Implement `output.py` — output formatting
  - Implement `format_output(data, fmt, limit) -> str` supporting `json`, `table` (via tabulate), and `csv` formats; default to `json`
  - Implement `apply_limit(data, n) -> Any` that finds the largest top-level array field and truncates it to `n` items, leaving all other fields unchanged
  - _Requirements: 8.1–8.5, 36.1–36.6_

  - [ ]* 5.1 Write property test for output format round-trip (Property 5)
    - **Property 5: Output Format Round-Trip**
    - **Validates: Requirements 8.1, 8.2, 8.4**

  - [ ]* 5.2 Write property test for table output column headers (Property 6)
    - **Property 6: Table Output Contains Column Headers**
    - **Validates: Requirements 8.3**

  - [ ]* 5.3 Write property test for limit truncation (Property 10)
    - **Property 10: Limit Truncation**
    - **Validates: Requirements 36.3, 36.6**

  - [ ]* 5.4 Write property test for invalid limit rejection (Property 11)
    - **Property 11: Invalid Limit Rejects with Non-Zero Exit**
    - **Validates: Requirements 36.2**

  - [ ]* 5.5 Write unit tests for `output.py`
    - Test json/table/csv output, default format, limit truncation, empty data
    - _Requirements: 8.1–8.5, 36.1–36.6_

- [x] 6. Implement `client.py` — HTTP client wrapper
  - Implement `R7Client` wrapping `httpx`; inject `X-Api-Key` header; log `METHOD URL` to stderr before request and `STATUS timing_ms` after response when `verbose=True`; log full bodies when `debug=True`; redact API key and DRP token in all log output with `[REDACTED]`
  - Map `httpx.HTTPStatusError` (4xx/5xx) → `APIError(exit_code=2)` and `httpx.RequestError` → `NetworkError(exit_code=3)`
  - Integrate `CacheStore`: on every request write response to cache; when `use_cache=True` read from cache first and skip live call on hit; fall back to live call on miss
  - Handle HTTP 429 on IDR log endpoints: read `X-RateLimit-Reset` header and sleep before retry
  - _Requirements: 9.1–9.3, 10.1–10.4, 37.1–37.7_

  - [ ]* 6.1 Write property test for credential redaction (Property 7)
    - **Property 7: Credential Redaction in Verbose Output**
    - **Validates: Requirements 9.3, 18.6**

  - [ ]* 6.2 Write property test for exit code mapping (Property 8)
    - **Property 8: Exit Code Mapping**
    - **Validates: Requirements 10.1, 10.2, 10.3, 10.4**

  - [ ]* 6.3 Write unit tests for `client.py`
    - Test verbose logging, debug logging, key redaction, cache hit/miss, 429 retry, APIError/NetworkError mapping
    - _Requirements: 9.1–9.3, 10.3–10.4, 37.2–37.4_

- [x] 7. Checkpoint — Ensure all infrastructure tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Implement `main.py` — entry point and solution dispatch
  - Implement top-level Click group accepting `solution` positional argument plus global flags: `-r/--region`, `-v/--verbose`, `-k/--api-key`, `-o/--output` (default `json`), `-c/--cache`, `-l/--limit`, `--debug`, `--drp-token`
  - Dispatch to solution command groups: `vm`, `siem`, `drp`, `platform`; for `cnapp`/`asm`/`appsec` print stub message and exit 0; for unrecognized solution print help and exit 1; handle `help`/`-h`/`--help` as help triggers
  - Catch all `R7Error` subclasses at the top level, print message to stderr, call `sys.exit(error.exit_code)`
  - _Requirements: 1.1, 1a.1–1a.5, 10.1–10.5, 11.1–11.6_

  - [ ]* 8.1 Write property test for invalid solution rejection (Property 2)
    - **Property 2: Invalid Solution Rejects with Non-Zero Exit**
    - **Validates: Requirements 1a.4**

  - [ ]* 8.2 Write unit tests for `main.py`
    - Test stub solutions, unrecognized solution, missing API key, help output, region in help
    - _Requirements: 1a.1–1a.5, 11.1–11.6_

- [x] 9. Implement `solutions/stub.py` — stub command group
  - Implement a single Click group `stub` that prints "No commands are currently available for [solution]." and exits 0
  - Wire `cnapp`, `asm`, `appsec` to this stub in `main.py` dispatch
  - _Requirements: 1a.3_

- [x] 10. Implement `solutions/platform.py` — platform commands
  - Implement `platform validate`: GET `https://{region}.api.insight.rapid7.com/validate`, print auth result
  - Implement `platform search`: POST to search endpoint with `--type` (validate against `VALID_SEARCH_TYPES`), `--query`, `--sort-field`, `--sort-order`, `--from` (default 0), `--size` (default 100)
  - Implement `platform sc list-queries`: POST `MATCH (m:\`sys.cypher-query\`) RETURN m` to Surface Command graph API
  - Implement `platform sc execute`: POST Cypher query from `--query` or `--query-file`; error if both provided; error if neither provided
  - _Requirements: 1.6, 6.1–6.5, 7.1–7.5_

  - [ ]* 10.1 Write unit tests for `platform.py`
    - Test validate, search type validation, sc execute mutual exclusion, Surface Command error handling
    - _Requirements: 1.6, 6.1–6.5, 7.1–7.5_

- [x] 11. Implement `solutions/vm.py` — InsightVM commands
  - Implement `vm health`: GET `/vm/admin/health`, print `status`, exit non-zero if not `UP`
  - Implement `vm scans list`: GET `/vm/v4/integration/scan` with pagination; filter by `--days` (default 30) and `--status`
  - Implement `vm engines list`: GET `/vm/v4/integration/scan/engine` with pagination; filter by `--unhealthy`
  - Implement `vm export vulnerabilities`: POST `createVulnerabilityExport` GQL mutation; handle `FAILED_PRECONDITION` conflict by extracting in-progress `exportId` and polling it; support `--wait`, `--auto`, `--output-dir`; persist Job_ID to `JobStore`
  - Implement `vm export policies`: POST `createPolicyExport` GQL mutation; support `--wait`, `--auto`; persist Job_ID
  - Implement `vm export remediations`: POST `createVulnerabilityRemediationExport` with `--start-date` and `--end-date`; validate date order; support `--wait`, `--auto`; persist Job_ID
  - Implement `vm export external-assets`: trigger vuln export, download assets Parquet, filter non-RFC-1918 IPs, print filtered records; support `--output-dir`
  - Implement `vm job status`: GET export status via `GetExport` GQL; support `--job-id` (auto-select from `JobStore` if omitted); support `--poll` and `--poll-interval` (default 10s); remove terminal jobs from `JobStore`
  - _Requirements: 2.1–2.5, 3.1–3.4, 4.1–4.4, 5.1–5.5, 12.1–12.3, 13.1–13.5, 14.1–14.4, 15.1–15.4, 16.1–16.3, 38.1–38.6, 39.1–39.5_

  - [ ]* 11.1 Write property test for RFC-1918 IP filtering (Property 9)
    - **Property 9: RFC-1918 IP Filtering**
    - **Validates: Requirements 15.1**

  - [ ]* 11.2 Write property test for date range validation (Property 4)
    - **Property 4: Date Range Validation**
    - **Validates: Requirements 4.3**

  - [ ]* 11.3 Write unit tests for `vm.py`
    - Test health check degraded exit, scan/engine pagination, export mutation, conflict detection polling, `--auto` download, job status auto-select, date validation error
    - _Requirements: 2.1–2.5, 3.1–3.4, 4.1–4.4, 5.1–5.5, 12.1–12.3, 13.1–13.5, 14.1–14.4, 15.1–15.4, 16.1–16.3_

- [x] 12. Checkpoint — Ensure all VM tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 13. Implement `solutions/drp.py` — Digital Risk Protection commands
  - Implement DRP Basic auth helper using `R7_DRP_TOKEN` / `--drp-token`; raise `UserInputError` if absent; redact token in verbose output
  - Implement `drp validate`: HEAD `https://api.ti.insight.rapid7.com/public/v1/test-credentials`; exit non-zero on 401
  - Implement `drp api-version`: GET `/public/v1/api/version`
  - Implement `drp modules`: GET `/public/v1/account/system-modules`
  - Implement `drp assets list`: GET `/public/v2/data/assets`; print `_id`, `type`, `value`, `tags`, `addedOn`
  - Implement `drp ioc-sources list`: GET `/public/v1/iocs/sources`; support `--enabled-only`
  - Implement `drp alerts list`: GET alerts-list, then fetch detail per ID; support `--severity`, `--alert-type`, `--remediation-status`, `--days`; respect `--limit` to stop early
  - Implement `drp phishing-threats list`: GET threats-list, then fetch detail per ID; support `--active`, `--days`; respect `--limit`
  - Implement `drp takedowns list`: GET alerts-list with `remediationStatus=CompletedSuccessfully`, fetch details, filter `TakedownStatus=Resolved`; support `--days`; respect `--limit`
  - Implement `drp risk-score`: GET system-risk-score; support `--fail-above` threshold
  - Implement `drp reported-domains list`: GET alerts-list, fetch report-status per ID, filter entries with at least one `Sent` service; respect `--limit`
  - Implement `drp ssl-cert-threats list` and `drp ssl-issue-threats list`: GET threats-list then fetch detail per ID; respect `--limit`
  - _Requirements: 18.1–18.6, 19.1–19.3, 20.1–20.3, 21.1–21.4, 22.1–22.6, 23.1–23.4, 24.1–24.4, 25.1–25.2, 26.1–26.4, 27.1–27.3_

  - [ ]* 13.1 Write property test for risk score threshold exit code (Property 17)
    - **Property 17: Threshold Exit Code (Risk Score)**
    - **Validates: Requirements 25.2**

  - [ ]* 13.2 Write unit tests for `drp.py`
    - Test missing DRP token error, validate 401 handling, alerts list with limit early-stop, risk-score threshold, token redaction in verbose output
    - _Requirements: 18.1–18.6, 22.1–22.6, 25.1–25.2, 36.4_

- [x] 14. Implement `solutions/siem.py` — InsightIDR commands
  - Implement `idr health-metrics`: GET `/idr/v1/health-metrics` with pagination; support `--resource-type`
  - Implement `idr log-storage`: GET `/usage/organizations` with `from`/`to` date params (defaults: `2017-01-31` / today); sort most-recent-first; handle 429 with `X-RateLimit-Reset` sleep
  - Implement `idr log-retention`: GET `/management/organizations`; convert ms to days; support `--min-days` threshold
  - Implement `idr logsets list`: GET `/management/logsets`
  - Implement `idr logs query`: resolve logset name → Log_IDs, then per Log_ID POST async query, poll `links[].href` at ≤20s intervals; handle expiry error code `101056`; support `--time-range` (default `Last 30 days`), `--max-pages` (default 20)
  - Implement `idr event-sources list`: GET `/management/logs/{log_id}/event-sources`; support `--log-id` or `--logset-name` (resolve to IDs first)
  - Implement `idr quarantine-state`: POST `QuarantineState` GQL to IDR GQL endpoint; paginate via `pageInfo`; support `--state` filter; skip null agent/host nodes
  - _Requirements: 28.1–28.4, 29.1–29.3, 30.1–30.2, 31.1–31.2, 32.1–32.7, 33.1–33.3, 34.1–34.4_

  - [ ]* 14.1 Write property test for log retention threshold exit code (Property 18)
    - **Property 18: Threshold Exit Code (Log Retention)**
    - **Validates: Requirements 30.2**

  - [ ]* 14.2 Write unit tests for `siem.py`
    - Test health-metrics pagination, 429 retry on log-storage, log-retention threshold, quarantine-state pagination and null-node skip, logs query expiry handling
    - _Requirements: 28.1–28.4, 29.1–29.3, 30.1–30.2, 32.1–32.7, 34.1–34.4_

- [x] 15. Checkpoint — Ensure all solution tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 16. Wire everything together in `main.py` and validate integration
  - Register all solution Click groups (`vm`, `siem`, `drp`, `platform`, stub for `cnapp`/`asm`/`appsec`) in the top-level dispatcher
  - Ensure `Config` is built once per invocation and passed via Click context (`ctx.obj`) to all subcommands
  - Verify `--output`, `--limit`, `--cache`, `--verbose`, `--debug` flags propagate correctly to all subcommands
  - Verify help output includes all valid solutions, region codes, and required env var names
  - _Requirements: 1.1, 1a.1–1a.5, 8.1–8.5, 9.1–9.3, 11.1–11.6, 35.1–35.5, 36.1–36.6, 37.1–37.7_

  - [ ]* 16.1 Write integration tests for end-to-end CLI invocations
    - Use Click's `CliRunner` to test full invocations: missing API key, stub solution, invalid solution, `--output csv`, `--limit`, `--cache` flag propagation
    - _Requirements: 1.1, 1a.1–1a.5, 8.1–8.5, 36.1–36.6_

- [x] 17. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Property-based tests live in `tests/test_properties.py`; each `@given` test must include `@settings(max_examples=100)` and a comment referencing the property number
- Unit tests for each module live in the corresponding `tests/test_*.py` file
- All 18 correctness properties from the design document are covered across tasks 2–14
