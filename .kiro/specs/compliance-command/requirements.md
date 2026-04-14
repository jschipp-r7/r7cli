# Requirements Document

## Introduction

Add a top-level `compliance` command to the r7-cli tool, invoked as `r7-cli compliance`. The command reuses the existing VM policy export pipeline (GraphQL mutation, polling, Parquet download) and adds a processing step that reads the downloaded Parquet files and emits their contents as SQL INSERT statements, producing a full data dump suitable for loading into a relational database.

## Glossary

- **CLI**: The `r7-cli` Click-based command-line application whose entry point is the `SolutionGroup` multi-command in `main.py`.
- **Compliance_Command**: The new top-level Click command registered as `compliance` on the root `SolutionGroup`.
- **Policy_Export_Pipeline**: The existing sequence of operations in `solutions/vm.py` that creates a policy export via GraphQL mutation, polls for completion, and downloads the resulting Parquet files. Composed of `_submit_export`, `_poll_export`, and `_download_parquet_urls`.
- **Parquet_Processor**: A new module or function responsible for reading downloaded Parquet files and converting their row data into SQL INSERT statements.
- **SQL_Dump**: The textual output consisting of SQL INSERT statements that represent every row from the downloaded Parquet files.
- **Policy_Schema**: The known Parquet schema for VM policy exports, consisting of the following columns:
  - `benchmarkNaturalId` (varchar)
  - `profileNaturalId` (varchar)
  - `benchmarkVersion` (varchar)
  - `ruleNaturalId` (varchar)
  - `orgId` (varchar)
  - `assetId` (varchar)
  - `finalStatus` (varchar)
  - `proof` (varchar)
  - `lastAssessmentTimestamp` (timestamp)
  - `benchmarkTitle` (varchar)
  - `profileTitle` (varchar)
  - `publisher` (varchar)
  - `ruleTitle` (varchar)
  - `fixTexts` (varchar[] — array of strings)
  - `rationales` (varchar[] — array of strings)
- **Asset_Schema** (reference only — not processed by this command): The known Parquet schema for VM vulnerability/asset exports, consisting of the following columns:
  - `orgId` (varchar)
  - `assetId` (varchar)
  - `agentId` (varchar)
  - `awsInstanceId` (varchar)
  - `azureResourceId` (varchar)
  - `gcpObjectId` (varchar)
  - `mac` (varchar)
  - `ip` (varchar)
  - `hostName` (varchar)
  - `osArchitecture` (varchar)
  - `osFamily` (varchar)
  - `osProduct` (varchar)
  - `osVendor` (varchar)
  - `osVersion` (varchar)
  - `osType` (varchar)
  - `osDescription` (varchar)
  - `riskScore` (double)
  - `sites` (varchar[] — array of strings)
  - `assetGroups` (varchar[] — array of strings)
  - `tags` (struct("name" varchar, tagtype varchar)[] — array of structs)
- **R7Client**: The HTTP client class in `client.py` used for all API communication.
- **Config**: The resolved runtime configuration dataclass from `config.py`.
- **SolutionGroup**: The Click `MultiCommand` in `main.py` that dispatches to per-solution command groups and top-level commands.

## Requirements

### Requirement 1: Register the Compliance Command

**User Story:** As a CLI user, I want to invoke `r7-cli compliance` as a top-level command, so that I can generate a SQL dump of VM policy data without navigating the `vm export` subcommand tree.

#### Acceptance Criteria

1. THE SolutionGroup SHALL list `compliance` among its available commands.
2. WHEN a user invokes `r7-cli compliance`, THE CLI SHALL execute the Compliance_Command.
3. THE Compliance_Command SHALL accept the same global flags (region, api-key, verbose, debug, output, cache, limit, timeout) as other top-level commands.
4. WHEN a user invokes `r7-cli compliance --help`, THE CLI SHALL display usage information describing the command purpose and available options.

### Requirement 2: Download Policy Parquet Files

**User Story:** As a CLI user, I want the compliance command to automatically download VM policy export Parquet files, so that I do not need to run the export manually first.

The export API response contains a `result` array where each entry has a `prefix` (e.g. `"asset"`, `"asset_policy"`) and a `urls` array of S3 download links. The response also includes a top-level `timestamp` field (e.g. `"2026-04-07T12:36:15.094Z"`).

#### Acceptance Criteria

1. WHEN the Compliance_Command is executed, THE Compliance_Command SHALL create a policy export by sending the same GraphQL mutation used by `vm export policies --auto`.
2. WHEN a policy export is already in progress (FAILED_PRECONDITION), THE Compliance_Command SHALL reuse the in-progress export job ID and continue polling.
3. WHILE the export job status is not terminal, THE Compliance_Command SHALL poll the export status at a configurable interval (default 10 seconds).
4. WHEN the export job reaches SUCCEEDED status, THE Compliance_Command SHALL download all Parquet files from all result entries.
5. WHEN the export job reaches FAILED status, THE Compliance_Command SHALL print an error message to stderr and exit with code 2.
6. THE Compliance_Command SHALL accept an `--output-dir` option to specify where downloaded Parquet files are saved (default: current directory).
7. THE Compliance_Command SHALL name each downloaded file using the pattern `{prefix}.{timestamp}.parquet`, where `{prefix}` is the `prefix` field from the result entry and `{timestamp}` is the download time in short ISO 8601 format (e.g. `asset_policy.2026-04-07T10:00Z.parquet`).
8. WHEN a result entry contains multiple URLs, THE Compliance_Command SHALL append a zero-based index to the filename (e.g. `asset_policy.2026-04-07T10:00Z.0.parquet`, `asset_policy.2026-04-07T10:00Z.1.parquet`).

### Requirement 3: Cache — Reuse Previously Downloaded Parquet Files

**User Story:** As a CLI user, I want to reuse previously downloaded Parquet files when using the `--cache` flag, so that I can regenerate the SQL dump without waiting for a new export and download.

#### Acceptance Criteria

1. WHEN the global `--cache` flag is set AND the output directory already contains Parquet files matching the `asset_policy.*.parquet` pattern, THE Compliance_Command SHALL skip the export creation, polling, and download steps entirely.
2. WHEN `--cache` is set and cached files are reused, THE Compliance_Command SHALL print a message to stderr indicating which cached files are being used.
3. WHEN `--cache` is set but no matching Parquet files exist in the output directory, THE Compliance_Command SHALL fall back to the normal export/download flow.

### Requirement 4: Process Parquet Files into SQL

**User Story:** As a CLI user, I want the downloaded Parquet files converted into SQL INSERT statements, so that I can load the policy data into a relational database.

#### Acceptance Criteria

1. WHEN Parquet files have been downloaded (or reused from cache), THE Parquet_Processor SHALL read only the files with the `asset_policy` prefix and extract all rows according to the Policy_Schema.
2. THE Parquet_Processor SHALL generate one SQL INSERT statement per row, targeting a table named `policy_compliance` by default or a user-specified table name.
3. THE Compliance_Command SHALL accept a `--table-name` option to override the default target table name (default: `policy_compliance`).
4. THE Parquet_Processor SHALL map Parquet column names to SQL column names preserving the original names from the Policy_Schema.
5. THE Parquet_Processor SHALL properly escape string values in generated SQL to prevent malformed statements (single quotes escaped as two single quotes).
6. THE Parquet_Processor SHALL represent NULL Parquet values as SQL NULL literals.
7. THE Parquet_Processor SHALL serialize varchar columns as SQL string literals.
8. THE Parquet_Processor SHALL serialize the `lastAssessmentTimestamp` column as an ISO-8601 formatted SQL string literal.
9. THE Parquet_Processor SHALL serialize varchar[] columns (`fixTexts`, `rationales`) as SQL ARRAY literals (e.g., `ARRAY['val1','val2']`) or as a JSON string representation, preserving all array elements.

### Requirement 5: Output Formats

**User Story:** As a CLI user, I want to choose how the compliance data is formatted, so that I can use it with different tools and workflows.

#### Acceptance Criteria

1. THE Compliance_Command SHALL respect the global `-o/--output` flag and support the following formats: `sql` (default), `json`, `table`, `csv`, and `tsv`.
2. WHEN `--output sql` is used (or no `--output` is specified), THE Compliance_Command SHALL write SQL INSERT statements to stdout.
3. WHEN `--output json` is used, THE Compliance_Command SHALL output the Parquet data as JSON using the existing `format_output` function.
4. WHEN `--output table` is used, THE Compliance_Command SHALL output the Parquet data as a formatted table using the existing `format_output` function.
5. WHEN `--output csv` is used, THE Compliance_Command SHALL output the Parquet data as CSV using the existing `format_output` function.
6. WHEN `--output tsv` is used, THE Compliance_Command SHALL output the Parquet data as tab-separated values with a header row followed by one row per record.
7. THE Compliance_Command SHALL accept a `--sql-file` option to write the output to a specified file path instead of stdout (applicable to all formats).
8. WHEN `--sql-file` is provided, THE Compliance_Command SHALL write the complete output to the specified file and print the file path to stderr.
9. WHEN the output format is `sql`, THE output SHALL include a header comment with the export timestamp and number of rows processed.

### Requirement 6: Error Handling

**User Story:** As a CLI user, I want clear error messages when something goes wrong, so that I can diagnose and fix issues.

#### Acceptance Criteria

1. IF the API key is missing or unauthorized, THEN THE Compliance_Command SHALL display the same authentication error messages used by other CLI commands and exit with code 2.
2. IF a downloaded Parquet file is corrupt or unreadable, THEN THE Compliance_Command SHALL print a descriptive error to stderr identifying the file and exit with code 2.
3. IF a network error occurs during export creation, polling, or download, THEN THE Compliance_Command SHALL print the network error to stderr and exit with code 3.
4. IF the `--sql-file` path is not writable, THEN THE Compliance_Command SHALL print an error to stderr and exit with code 1.

### Requirement 7: Parquet Reading and SQL Serialization Round-Trip Integrity

**User Story:** As a developer, I want confidence that the Parquet-to-SQL conversion preserves data faithfully, so that the SQL dump accurately represents the source data.

#### Acceptance Criteria

1. THE Parquet_Processor SHALL produce SQL INSERT statements that, when parsed back, yield column names and values equivalent to the original Parquet row data.
2. FOR ALL valid Parquet rows containing supported column types, reading the row and generating an INSERT statement then parsing that INSERT statement SHALL produce values equivalent to the original row (round-trip property).
3. THE Parquet_Processor SHALL format timestamp values in ISO-8601 format within SQL string literals.


## Post-Implementation Changes

- Command moved from top-level `r7-cli compliance` to `r7-cli platform compliance`
- TSV format support added to `output.py` (shared across all commands)
- `pyarrow` added as a required dependency
- File naming uses `_short_iso_timestamp()` helper in `vm.py`'s `_download_parquet_urls`
