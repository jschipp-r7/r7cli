# Requirements Document

## Introduction

`r7-cli` is a command-line tool for interacting with Rapid7's Insight Platform public APIs. It replaces a collection of ad-hoc bash scripts, JSON files, and GraphQL query files with a single, consistent CLI. The tool covers:

- **InsightVM (IVM)**: bulk export APIs (vulnerabilities, policies, remediations), the IVM v4 REST API (scans, scan engines, health, assets, sites, vulnerabilities), and external asset detection.
- **InsightIDR / SIEM**: agent health metrics, log storage and retention, logset and log queries, event source enumeration, agent quarantine state via GraphQL, investigations, comments, attachments, users, threats, collectors, saved queries, variables, detection rules, log management, pre-computed metrics, exports, notifications, and accounts/assets.
- **Digital Risk Protection (DRP)**: monitored assets, threat intelligence sources, alerts, phishing threats, domain takedowns, system risk score, reported domains, and SSL threats — all via a separate base URL with HTTP Basic auth.
- **Surface Command / ASM**: graph-based Cypher queries — list, get, and execute saved queries.
- **Insight Platform**: structured search, API key validation, user management, organizations, products, features, roles, API keys, user groups, and credentials.
- **InsightAppSec**: applications, scans, scan configs, vulnerabilities, vuln comments, engines, engine groups, schedules, blackouts, attack templates, targets, modules, reports, tags, and search.
- **InsightConnect / SOAR**: workflows (list, get, execute, activate, deactivate, export, import), jobs, artifacts, snippets, and plugins.
- **CNAPP / InsightCloudSec**: IaC scans, AWS keys, AWS roles, AWS accounts, and findings.

The CLI handles authentication via API keys (and DRP token), multi-region support, async job polling, pagination, output formatting, local response caching, request timeout configuration, and JSON field search.

## Glossary

- **CLI**: The `r7-cli` command-line tool being specified here.
- **Solution**: The required positional argument to `r7-cli` that selects which Rapid7 product's command group to invoke. Valid values: `siem`, `vm`, `cnapp`, `asm`, `appsec`, `drp`, `platform`, `soar`.
- **Insight_Platform**: Rapid7's cloud-hosted security platform, accessible at `{region}.api.insight.rapid7.com`.
- **API_Key**: A secret token used to authenticate requests to the Insight Platform, passed via the `X-Api-Key` HTTP header.
- **Region**: A geographic deployment identifier (e.g. `us`, `us1`, `eu`, `ap`, `us2`, `us3`, `ca`, `au`, `me-central-1`, `ap-south-2`) that determines the base URL for all API calls. `us1` is an alias for `us`.
- **IVM**: InsightVM — Rapid7's vulnerability management product, selected via the `vm` solution value.
- **IDR**: InsightIDR — Rapid7's detection and response (SIEM) product, selected via the `siem` solution value.
- **DRP**: Digital Risk Protection — Rapid7's threat intelligence and external monitoring product, accessible at `api.ti.insight.rapid7.com`, selected via the `drp` solution value.
- **DRP_Token**: An API token used to authenticate DRP requests via HTTP Basic auth (token as username, empty password).
- **ASM**: Attack Surface Management — graph-based asset discovery, selected via the `asm` solution value.
- **AppSec**: InsightAppSec — application security testing, selected via the `appsec` solution value.
- **SOAR**: InsightConnect — security orchestration, automation, and response, selected via the `soar` solution value.
- **CNAPP**: Cloud Native Application Protection Platform (InsightCloudSec), selected via the `cnapp` solution value.
- **Surface_Command**: A graph-based query interface within the Insight Platform, accessible at `{region}.api.insight.rapid7.com/surface`, available under the `asm` solution value.
- **Export_Job**: An asynchronous server-side job that produces a downloadable dataset.
- **Job_ID**: A server-assigned identifier returned when an Export_Job is created, used to poll for status and retrieve results.
- **Parquet**: A columnar binary file format used by Rapid7 bulk export APIs for large datasets.
- **GraphQL**: The query language used by the IVM bulk export, Surface Command, and IDR GQL APIs.
- **Output_Format**: The serialization format for CLI output, one of: `json`, `table`, or `csv`.

---

## Requirements

### Requirement 1: Authentication and Configuration

**User Story:** As a security engineer, I want to configure my API key, region, and timeout once, so that I don't have to pass credentials on every command.

#### Acceptance Criteria

1. THE CLI SHALL accept invocations in the form `r7-cli [GLOBAL OPTIONS] $SOLUTION SUBCOMMAND [FLAGS]`, where `$SOLUTION` is a required positional argument.
2. THE CLI SHALL read the API key from the `R7_X_API_KEY` environment variable when no explicit credential flag is provided.
3. THE CLI SHALL resolve the target region using the following priority order: (1) the `-r` flag, (2) the `R7_REGION` environment variable, (3) the default value `us`.
4. WHERE a `-k` / `--api-key` flag is provided, THE CLI SHALL use that value in preference to the `R7_X_API_KEY` environment variable.
5. THE CLI SHALL accept a `-t` / `--timeout` flag that takes an integer value in seconds, defaulting to 30 seconds.
6. THE CLI SHALL accept a `--search-fields` flag that takes a field name string for searching JSON responses.
7. WHEN the `validate` subcommand is invoked (either as `r7-cli validate` or `platform validate`), THE CLI SHALL send a request to `https://{region}.api.insight.rapid7.com/validate` and print whether the API key is authorized.

---

### Requirement 1a: Solution Dispatch

**User Story:** As a security engineer, I want to select a Rapid7 product by name as the first argument, so that the CLI routes my command to the correct product's command group.

#### Acceptance Criteria

1. THE CLI SHALL treat the first positional argument as the Solution value and route the invocation to the corresponding product command group.
2. THE CLI SHALL recognize the following Solution values and their product mappings:
   - `siem` → InsightIDR (SIEM)
   - `vm` → InsightVM
   - `cnapp` → Cloud Native Application Protection Platform (InsightCloudSec)
   - `asm` → Attack Surface Management (Surface Command)
   - `appsec` → InsightAppSec
   - `drp` → Digital Risk Protection
   - `platform` → Insight Platform (search, validate, users, orgs, products, roles, API keys, user groups, credentials)
   - `soar` → InsightConnect (SOAR)
3. ALL eight solution values SHALL route to fully implemented command groups; no solution values produce stub messages.
4. IF the provided Solution value does not match any recognized value, THEN THE CLI SHALL display the help menu listing all valid solution values and exit with a non-zero status code.
5. THE CLI SHALL treat `help`, `-h`, and `--help` as special solution values that trigger the help menu rather than routing to a product command group.

---

### Requirement 1b: Global Flag Hint Detection

**User Story:** As a CLI user, I want helpful error messages when I accidentally place global flags after a subcommand.

#### Acceptance Criteria

1. WHEN a global flag (e.g. `-v`, `-r`, `-o`, `-k`, `-t`, `--debug`, `--cache`, `--drp-token`, `--search-fields`) is detected after a subcommand, THE CLI SHALL print an error message explaining that the flag must appear before the subcommand, with an example of the correct invocation order, and exit with a non-zero status code.

---

### Requirement 2: IVM Vulnerability Export

#### Acceptance Criteria

1. WHEN `vm export vulnerabilities` is invoked, THE CLI SHALL send a `createVulnerabilityExport` GraphQL mutation and return the resulting Job_ID.
2. WHEN `--wait` is provided, THE CLI SHALL poll until the job reaches a terminal state.
3. WHEN the job reaches `SUCCEEDED`, THE CLI SHALL print the download URLs.
4. IF the job reaches `FAILED`, THE CLI SHALL print the failure reason and exit with a non-zero status code.
5. WHERE `--output-dir` is provided, THE CLI SHALL download all Parquet files to the specified directory.

---

### Requirement 3: IVM Policy Export

#### Acceptance Criteria

1. WHEN `vm export policies` is invoked, THE CLI SHALL send a `createPolicyExport` GraphQL mutation and return the resulting Job_ID.
2. WHEN `--wait` is provided, THE CLI SHALL poll until the job reaches a terminal state.
3. WHEN the job reaches `SUCCEEDED`, THE CLI SHALL print the download URLs.
4. IF the job reaches `FAILED`, THE CLI SHALL print the failure reason and exit with a non-zero status code.

---

### Requirement 4: IVM Vulnerability Remediation Export

#### Acceptance Criteria

1. WHEN `vm export remediations` is invoked with `--start-date` and `--end-date`, THE CLI SHALL send a `createVulnerabilityRemediationExport` GraphQL mutation and return the Job_ID.
2. IF `--start-date` or `--end-date` is missing, THE CLI SHALL print an error and exit with a non-zero status code.
3. IF `--start-date` is later than `--end-date`, THE CLI SHALL print an error and exit with a non-zero status code.
4. WHEN `--wait` is provided, THE CLI SHALL poll until the job reaches a terminal state.

---

### Requirement 5: Export Job Status Polling

#### Acceptance Criteria

1. WHEN `vm job status` is invoked with `--job-id`, THE CLI SHALL send a `GetExport` GraphQL query and print the job status and result URLs.
2. WHEN invoked WITHOUT `--job-id`, THE CLI SHALL read `~/.r7-cli/jobs.json` and auto-select the most recent Job_ID, or present an interactive menu if multiple active jobs exist.
3. WHEN `--poll` is provided, THE CLI SHALL repeatedly query at a configurable interval (default 10s via `--poll-interval`) until the job reaches a terminal state.

---

### Requirement 6: Insight Platform Search

#### Acceptance Criteria

1. WHEN `platform search` is invoked with `--type` and `--query`, THE CLI SHALL POST a JSON search request and print the results.
2. Supported search types: `VULNERABILITY`, `ASSET`, `SCAN`, `SCHEDULE`, `APP`.
3. Optional `--sort-field`, `--sort-order`, `--from`, and `--size` flags control sorting and pagination.

---

### Requirement 7: ASM / Surface Command Graph Queries

#### Acceptance Criteria

1. WHEN `asm list` is invoked, THE CLI SHALL POST the list-queries Cypher to the Surface Command graph API and print the results.
2. WHEN `asm get` is invoked with `--id` or `--auto`, THE CLI SHALL retrieve or interactively select a saved query.
3. WHEN `asm execute` is invoked with `--query`, `--query-file`, or `--auto`, THE CLI SHALL execute the Cypher query and print the results.
4. IF both `--query` and `--query-file` are provided, THE CLI SHALL print an error and exit with a non-zero status code.

---

### Requirement 8: Output Formatting

#### Acceptance Criteria

1. THE CLI SHALL support `-o` / `--output` flag values of `json`, `table`, and `csv`.
2. WHEN `--output json` is specified, THE CLI SHALL print raw JSON to stdout.
3. WHEN `--output table` is specified, THE CLI SHALL print a human-readable table with column headers.
4. WHEN `--output csv` is specified, THE CLI SHALL print comma-separated values with a header row.
5. THE CLI SHALL default to `json` output when the flag is absent.

---

### Requirement 8a: JSON Field Search

#### Acceptance Criteria

1. WHEN `--search-fields` is provided, THE CLI SHALL recursively traverse the JSON response, collect all values for keys matching the specified field name, and print the results as a JSON object with `matches` and `count` fields.
2. IF no matches are found, THE CLI SHALL print a JSON object with `count: 0` and a descriptive message.

---

### Requirement 9: Verbose and Debug Modes

#### Acceptance Criteria

1. WHERE `-v` / `--verbose` is provided, THE CLI SHALL print method+URL before each request and status+timing after each response to stderr.
2. WHERE `--debug` is provided, THE CLI SHALL additionally print full request/response bodies and an equivalent curl command to stderr.
3. THE CLI SHALL redact the API key and DRP token in all verbose and debug output, replacing each with `[REDACTED]`.

---

### Requirement 10: Error Handling and Exit Codes

#### Acceptance Criteria

1. Exit code `0` for success, `1` for user input error, `2` for API error (HTTP 4xx/5xx), `3` for network/timeout error.
2. WHEN any error occurs, THE CLI SHALL print a human-readable error message to stderr.
3. WHEN HTTP 401 is received, THE CLI SHALL print a specific message about missing or invalid API key.
4. WHEN a request times out, THE CLI SHALL suggest increasing the `-t` / `--timeout` value.

---

### Requirement 11: Help and Discoverability

#### Acceptance Criteria

1. THE CLI SHALL display the help menu when invoked with `-h` or `--help` or `help`.
2. THE CLI SHALL include all valid solution values, all available flags, supported regions, and required environment variables in the top-level help output.
3. WHEN any subcommand is invoked with `--help`, THE CLI SHALL display usage information and all available flags.

---

### Requirement 12: IVM v4 API Health Check

#### Acceptance Criteria

1. WHEN `vm health` is invoked, THE CLI SHALL GET the IVM health endpoint and print the status.
2. IF the status is not `UP`, THE CLI SHALL print a warning and exit with a non-zero status code.

---

### Requirement 13: IVM v4 Vulnerability Scans

#### Acceptance Criteria

1. WHEN `vm scans list` is invoked, THE CLI SHALL GET scans from the IVM v4 endpoint. Supports `--days`, `--status`, `--started` (comparison expression), `--all-pages`, and auto-polling.
2. WHEN `vm scans get` is invoked with `--id` or `--auto`, THE CLI SHALL retrieve a single scan or present interactive selection.
3. WHEN `vm scans start` is invoked with `--data` or `--data-file`, THE CLI SHALL POST to start a new scan.
4. WHEN `vm scans stop` is invoked with `--id` or `--auto`, THE CLI SHALL POST to stop the scan.

---

### Requirement 14: IVM v4 Scan Engines

#### Acceptance Criteria

1. WHEN `vm engines list` is invoked, THE CLI SHALL GET engines from the IVM v4 endpoint. Supports `--unhealthy`, `--all-pages`, and auto-polling.
2. WHEN `vm engines get` is invoked with `--id` or `--auto`, THE CLI SHALL retrieve a single engine or present interactive selection.
3. WHEN `vm engines update-config` is invoked with `--id` and `--data`/`--data-file`, THE CLI SHALL PUT to update the engine configuration.
4. WHEN `vm engines remove-config` is invoked with `--id`, THE CLI SHALL DELETE the engine configuration.

---

### Requirement 14a: IVM v4 Assets

#### Acceptance Criteria

1. WHEN `vm assets search` is invoked, THE CLI SHALL POST to the IVM v4 asset search endpoint. Supports `--size`, `--cursor`, `--asset-filter`, `--vuln-filter`, `--all-pages`, and auto-polling.
2. THE CLI SHALL support client-side filters: `--hostname`, `--ip`, `--os-family`, `--tag`, `--risk-score` (comparison expression), `--critical-vulns` (comparison expression).
3. WHEN `vm assets get` is invoked with `--id` or `--auto`, THE CLI SHALL retrieve a single asset or present interactive selection.

---

### Requirement 14b: IVM v4 Sites

#### Acceptance Criteria

1. WHEN `vm sites list` is invoked, THE CLI SHALL POST to the IVM v4 sites endpoint. Supports `--size`, `--cursor`, `--all-pages`, and auto-polling.
2. THE CLI SHALL support client-side filters: `--site-name` (substring match) and `--site-type`.

---

### Requirement 14c: IVM v4 Vulnerabilities

#### Acceptance Criteria

1. WHEN `vm vulns search` is invoked, THE CLI SHALL POST to the IVM v4 vulnerability endpoint. Supports `--size`, `--cursor`, `--asset-filter`, `--vuln-filter`, `--all-pages`, and auto-polling.
2. THE CLI SHALL support client-side filters: `--severity`, `--cvss-score` (comparison expression), `--categories`, `--published` (date comparison), `--cve`.

---

### Requirement 15: IVM External Vulnerability Scan Detection

#### Acceptance Criteria

1. WHEN `vm export external-assets` is invoked, THE CLI SHALL trigger a vulnerability bulk export, download the assets Parquet table, and filter to assets whose `ip` field does not match any RFC-1918 private address range.
2. IF no public-IP assets are found, THE CLI SHALL print an informational message and exit with status code `0`.

---

### Requirement 16: IVM Export Job Conflict Detection

#### Acceptance Criteria

1. WHEN a bulk export mutation returns `FAILED_PRECONDITION`, THE CLI SHALL extract the in-progress `exportId` and poll that existing job instead of failing.
2. IF `--wait` is not provided and a conflict is detected, THE CLI SHALL print the in-progress `exportId` and exit with a non-zero status code.
