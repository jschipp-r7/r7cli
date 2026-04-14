# Requirements Document

## Introduction

The `vm export list` subcommand enables users to query locally downloaded Parquet files from the VM bulk export pipeline. It detects the schema of each file (asset, vulnerability, policy, or remediation), applies user-specified filters, optionally joins asset data for cross-table filtering, and outputs results in JSON, table, or CSV format. This command operates entirely offline against local files and does not make API calls.

## Glossary

- **CLI**: The `r7-cli` command-line application built with Click
- **Export_List_Command**: The `vm export list` subcommand that reads and filters local Parquet files
- **Parquet_Reader**: The component that reads Apache Parquet files from disk using pyarrow
- **Schema_Detector**: The component that identifies which schema a Parquet file belongs to based on its column names
- **Filter_Engine**: The component that applies user-specified filter predicates to Parquet row data
- **Auto_Joiner**: The component that joins asset data with other schemas on the assetId column
- **Output_Formatter**: The existing `output.py` module that serializes results to JSON, table, or CSV
- **Asset_Schema**: Parquet files containing columns such as hostName, ip, mac, osFamily, agentId
- **Vulnerability_Schema**: Parquet files containing columns such as vulnId, checkId, cvssScore, severity
- **Policy_Schema**: Parquet files containing columns such as benchmarkNaturalId, profileNaturalId, finalStatus
- **Remediation_Schema**: Parquet files containing columns such as remediationCount, lastRemoved, lastDetected
- **Cache_Mode**: The global `-c`/`--cache` flag that instructs the CLI to look for `*.parquet` files in the current directory
- **File_Mode**: The `--file` option that accepts a file path or glob pattern to locate Parquet files

## Requirements

### Requirement 1: File Source Resolution

**User Story:** As a CLI user, I want to specify where Parquet files are located so that the command knows which files to read.

#### Acceptance Criteria

1. WHEN the `--cache` global flag is set, THE Export_List_Command SHALL search the current working directory for files matching the `*.parquet` glob pattern
2. WHEN the `--file` option is provided, THE Export_List_Command SHALL resolve the provided path or glob pattern to locate matching Parquet files
3. WHEN both `--cache` and `--file` are provided, THE Export_List_Command SHALL use only the files matched by the `--file` option
4. IF neither `--cache` nor `--file` is provided, THEN THE Export_List_Command SHALL exit with a non-zero exit code and print a usage hint indicating that one of `--cache` or `--file` is required
5. IF the resolved file list is empty (no files matched), THEN THE Export_List_Command SHALL exit with a non-zero exit code and print a message stating that no Parquet files were found

### Requirement 2: Parquet File Reading

**User Story:** As a CLI user, I want the command to read Parquet files from disk so that I can query exported data without making API calls.

#### Acceptance Criteria

1. WHEN one or more Parquet files are resolved, THE Parquet_Reader SHALL read each file using pyarrow and convert rows to Python dictionaries
2. WHEN a Parquet file contains timestamp columns, THE Parquet_Reader SHALL convert timestamp values to ISO-8601 formatted strings
3. WHEN a Parquet file contains list-typed columns, THE Parquet_Reader SHALL convert list values to Python lists
4. IF a Parquet file cannot be read (corrupt or invalid format), THEN THE Parquet_Reader SHALL print an error message identifying the file and exit with a non-zero exit code

### Requirement 3: Schema Detection

**User Story:** As a CLI user, I want the command to automatically detect which type of data each Parquet file contains so that I can query mixed file sets without manual configuration.

#### Acceptance Criteria

1. WHEN a Parquet file contains the column `vulnId`, THE Schema_Detector SHALL classify the file as Vulnerability_Schema
2. WHEN a Parquet file contains the column `benchmarkNaturalId`, THE Schema_Detector SHALL classify the file as Policy_Schema
3. WHEN a Parquet file contains the column `remediationCount`, THE Schema_Detector SHALL classify the file as Remediation_Schema
4. WHEN a Parquet file contains the column `hostName` and does not match Vulnerability_Schema, Policy_Schema, or Remediation_Schema, THE Schema_Detector SHALL classify the file as Asset_Schema
5. IF a Parquet file does not match any known schema, THEN THE Schema_Detector SHALL print a warning identifying the file and skip the file
6. THE Schema_Detector SHALL classify each file by inspecting column names only, without reading row data

### Requirement 4: String Filtering

**User Story:** As a CLI user, I want to filter results by string fields so that I can narrow down results to specific hostnames, severities, or other text values.

#### Acceptance Criteria

1. WHEN a string filter option is provided (e.g. `--hostname`, `--severity`, `--ip`), THE Filter_Engine SHALL perform a case-insensitive substring match against the corresponding column value
2. WHEN multiple string filter options are provided, THE Filter_Engine SHALL apply all filters as a logical AND (rows must match all filters)
3. WHEN a filter references a column not present in the current schema, THE Filter_Engine SHALL ignore that filter and continue processing

### Requirement 5: Numeric Filtering

**User Story:** As a CLI user, I want to filter results by numeric fields with comparison operators so that I can find high-risk assets or critical vulnerabilities.

#### Acceptance Criteria

1. WHEN a numeric filter option is provided with a comparison operator (e.g. `--cvss-score '>=9.0'`), THE Filter_Engine SHALL parse the operator and threshold, then compare each row's column value using the specified operator
2. THE Filter_Engine SHALL support the comparison operators: `>=`, `<=`, `>`, `<`, `==`, and `=`
3. IF a numeric filter value cannot be parsed as a number, THEN THE Filter_Engine SHALL print an error message and exit with a non-zero exit code
4. WHEN a row's numeric column value is null, THE Filter_Engine SHALL exclude that row from the filtered results

### Requirement 6: Boolean Filtering

**User Story:** As a CLI user, I want to filter by boolean fields so that I can find assets with exploits or non-PCI-compliant vulnerabilities.

#### Acceptance Criteria

1. WHEN a boolean filter option is provided (e.g. `--has-exploits true`), THE Filter_Engine SHALL compare the row's column value against the boolean literal
2. THE Filter_Engine SHALL accept the string values `true` and `false` (case-insensitive) as boolean filter inputs

### Requirement 7: Date Filtering

**User Story:** As a CLI user, I want to filter by date fields so that I can find vulnerabilities discovered after a specific date.

#### Acceptance Criteria

1. WHEN a date filter option is provided with a comparison operator (e.g. `--first-found '>=2025-01-01'`), THE Filter_Engine SHALL parse the operator and date threshold, then compare each row's timestamp value using the specified operator
2. THE Filter_Engine SHALL accept date values in ISO-8601 format (YYYY-MM-DD or full ISO-8601 datetime)
3. IF a date filter value cannot be parsed, THEN THE Filter_Engine SHALL print an error message and exit with a non-zero exit code

### Requirement 8: Generic Where Filter

**User Story:** As a CLI user, I want a generic filter option so that I can filter on any column without needing a dedicated flag for each field.

#### Acceptance Criteria

1. WHEN the `--where` option is provided with a value in the format `column operator value`, THE Filter_Engine SHALL parse the column name, operator, and value, then apply the filter to matching rows
2. THE Filter_Engine SHALL support string, numeric, and date comparisons in `--where` based on the column's data type in the Parquet schema
3. WHEN multiple `--where` options are provided, THE Filter_Engine SHALL apply all conditions as a logical AND

### Requirement 9: Auto-Join on Asset Data

**User Story:** As a CLI user, I want to filter vulnerability, policy, or remediation data by asset fields (hostname, IP, OS) without manually joining files, so that I can quickly find vulnerabilities on specific hosts.

#### Acceptance Criteria

1. WHEN Asset_Schema files are present alongside Vulnerability_Schema, Policy_Schema, or Remediation_Schema files, THE Auto_Joiner SHALL join the asset data with the other schema data on the `assetId` column
2. WHEN the auto-join is active, THE Filter_Engine SHALL accept asset-specific filter options (e.g. `--hostname`, `--ip`, `--os-family`) when querying non-asset schemas
3. WHEN the auto-join is active, THE Export_List_Command SHALL include only the columns from the primary (non-asset) schema in the output, unless the user explicitly requests asset columns
4. IF no Asset_Schema files are present and an asset-specific filter is used on a non-asset schema, THEN THE Export_List_Command SHALL print a warning that asset files are needed for cross-table filtering and ignore the asset filter

### Requirement 10: Output Formatting

**User Story:** As a CLI user, I want the results formatted consistently with other CLI commands so that I can use the same output flags I already know.

#### Acceptance Criteria

1. THE Export_List_Command SHALL respect the global `-o`/`--output` flag and format results as JSON (default), table, or CSV
2. THE Export_List_Command SHALL respect the global `-s`/`--short` flag for compact single-line-per-row JSON output
3. THE Export_List_Command SHALL respect the global `--search-fields` flag to search for specific field names in the output
4. WHEN the global `-l`/`--limit` flag is provided, THE Export_List_Command SHALL return at most the specified number of rows

### Requirement 11: Command Registration

**User Story:** As a CLI user, I want to invoke the command as `r7-cli vm export list` so that it fits naturally within the existing export subgroup.

#### Acceptance Criteria

1. THE Export_List_Command SHALL be registered as a `list` subcommand under the existing `vm export` Click group
2. THE Export_List_Command SHALL display help text describing its purpose and usage examples when invoked with `--help`
3. THE Export_List_Command SHALL not require an API key or network connectivity since it operates on local files only


## Post-Implementation Changes

- `--file` renamed to `--files`
- `--only` column projection option added
- Policy-specific filters added: `--benchmark-title`, `--profile-title`, `--publisher`, `--rule-title`, `--benchmark-version`
- String matching updated to support glob patterns (`*`, `?`) via `fnmatch`
- Auto-search of current directory when no `--files` or `--cache` specified
- Schema detection uses `path.resolve()` for absolute paths
- Only most recent file per schema is used (avoids duplicates)
- Asset column validation for `--only` option
