# Requirements Document

## Introduction

Add a `--short` / `-s` global flag to r7-cli that provides a compact, single-line-per-object output mode for JSON array responses. When active, each JSON object is printed on one line with fields reordered to prioritize human-readable fields before IDs/UUIDs, and the line is truncated to the terminal width to prevent wrapping. This is a generic output formatting feature that applies to all commands producing JSON arrays.

## Glossary

- **CLI**: The r7-cli command-line tool, the top-level Click group defined in main.py
- **Config**: The runtime configuration dataclass in config.py that holds resolved flag values
- **Format_Output**: The `format_output()` function in output.py responsible for serializing data to the requested output format
- **Short_Mode**: The compact output mode activated by the `--short` / `-s` global flag
- **Terminal_Width**: The number of character columns available in the user's terminal, detected via `shutil.get_terminal_size()`
- **Field_Priority**: A heuristic ordering that places human-readable fields before machine-oriented identifiers
- **High_Priority_Fields**: name, title, status, type, severity, value, description, hostName, ip, domain, hostname, mac, product_code, organization_name, riskScore, risk_score, cvss, cvssScore, cvss_score
- **Medium_Priority_Fields**: dates/timestamps, counts, boolean flags, version strings
- **Low_Priority_Fields**: IDs, UUIDs, tokens, URLs, hashes, base64-encoded strings
- **JSON_Object**: A single dictionary item within a JSON array response
- **Global_Flag**: A CLI option parsed before the solution subcommand, defined on the top-level Click group

## Requirements

### Requirement 1: Global Flag Registration

**User Story:** As a CLI user, I want a `--short` / `-s` flag available on the top-level CLI group, so that I can request compact output for any command without modifying individual subcommands.

#### Acceptance Criteria

1. THE CLI SHALL accept a `--short` boolean flag with short alias `-s` on the top-level Click group, before any solution subcommand.
2. WHEN the `--short` flag is provided, THE Config SHALL store a `short` field set to `True`.
3. WHEN the `--short` flag is omitted, THE Config SHALL store a `short` field set to `False`.
4. THE CLI SHALL register `-s` and `--short` in the GLOBAL_BOOLEAN_FLAGS set in cli_group.py so that misplaced flag detection works correctly.

### Requirement 2: Compact Single-Line Formatting

**User Story:** As a CLI user, I want each JSON object printed on a single line when short mode is active, so that I can quickly scan list output without scrolling through multi-line pretty-printed JSON.

#### Acceptance Criteria

1. WHEN Short_Mode is active and the data contains a JSON array of objects, THE Format_Output function SHALL print each JSON_Object on a separate single line using compact JSON serialization (no indentation, no extra whitespace beyond JSON separators).
2. WHEN Short_Mode is active and the data is a dict containing a nested JSON array (the largest list field), THE Format_Output function SHALL extract that array and print each item on a separate single line.
3. WHEN Short_Mode is active and the data is a single dict (not containing a list field), THE Format_Output function SHALL print that single dict on one compact line.
4. WHEN Short_Mode is active and the output format is not `json`, THE Format_Output function SHALL ignore Short_Mode and format using the requested format (table, csv, tsv).

### Requirement 3: Field Reordering by Priority

**User Story:** As a CLI user, I want human-readable fields displayed before UUIDs and IDs in short output, so that the most useful information appears first within the truncated line.

#### Acceptance Criteria

1. WHEN Short_Mode is active, THE Format_Output function SHALL reorder each JSON_Object's fields so that High_Priority_Fields appear first, Medium_Priority_Fields appear second, and Low_Priority_Fields appear last.
2. THE Format_Output function SHALL classify fields as High_Priority_Fields when the field name exactly matches one of: name, title, status, type, severity, value, description, hostName, ip, domain, hostname, mac, product_code, organization_name, riskScore, risk_score, cvss, cvssScore, cvss_score (case-sensitive match).
3. THE Format_Output function SHALL classify fields as Low_Priority_Fields when the field name contains "id", "uuid", "token", "url", "hash", or "base64" as a case-insensitive substring, or when the field value matches a UUID pattern (8-4-4-4-12 hex format).
4. THE Format_Output function SHALL classify fields as Medium_Priority_Fields when the field name contains "date", "time", "timestamp", "count", "version", or "created", or when the field value is a boolean, as a case-insensitive substring match on the field name.
5. WITHIN each priority tier, THE Format_Output function SHALL preserve the original field order from the API response.

### Requirement 4: Terminal Width Truncation

**User Story:** As a CLI user, I want each output line truncated to my terminal width, so that lines do not wrap and the output remains scannable.

#### Acceptance Criteria

1. WHEN Short_Mode is active, THE Format_Output function SHALL detect the terminal width using `shutil.get_terminal_size()`.
2. WHEN a compact JSON line exceeds the Terminal_Width, THE Format_Output function SHALL truncate the line to Terminal_Width minus 1 character and append an ellipsis character (`…`) as the last character, making the total output line exactly Terminal_Width characters.
3. WHEN a compact JSON line fits within the Terminal_Width, THE Format_Output function SHALL print the line without truncation or modification.

### Requirement 5: Interaction with Existing Features

**User Story:** As a CLI user, I want short mode to work correctly alongside existing flags like `--limit` and `--search-fields`, so that I can combine features without unexpected behavior.

#### Acceptance Criteria

1. WHEN Short_Mode is active and `--limit` is also provided, THE Format_Output function SHALL apply the limit before formatting in short mode.
2. WHEN Short_Mode is active and `--search-fields` is also provided, THE Format_Output function SHALL apply the search and return search results without short mode formatting (search takes precedence).
3. WHEN Short_Mode is active and `--output table` or `--output csv` or `--output tsv` is provided, THE Format_Output function SHALL use the explicitly requested format and ignore Short_Mode.
