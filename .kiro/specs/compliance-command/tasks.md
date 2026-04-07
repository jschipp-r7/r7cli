# Implementation Plan: compliance-command

## Overview

Implement the `compliance` top-level CLI command that orchestrates a VM policy export pipeline, reads downloaded Parquet files, and emits SQL INSERT statements (or json/table/csv/tsv). The implementation adds a new `compliance.py` module, extends `output.py` with TSV support, updates `models.py` with new format constants, registers the command in `main.py`, and adds `pyarrow` as a dependency.

## Tasks

- [x] 1. Add dependencies and update constants
  - [x] 1.1 Add `pyarrow>=14.0` to `dependencies` in `pyproject.toml`
    - _Requirements: 2.1 (Parquet reading capability)_
  - [x] 1.2 Add `"tsv"` and `"sql"` to `VALID_OUTPUT_FORMATS` in `models.py`
    - _Requirements: 5.1_

- [x] 2. Add TSV format support to `output.py`
  - [x] 2.1 Implement `_format_tsv(data)` helper in `output.py`
    - Add a `_format_tsv` function that renders data as tab-separated values with a header row
    - Reuse the existing `_extract_rows` helper for row normalization
    - _Requirements: 5.6_
  - [x] 2.2 Update `format_output()` to handle `fmt="tsv"`
    - Add an `elif fmt == "tsv"` branch that calls `_format_tsv`
    - _Requirements: 5.6_
  - [ ]* 2.3 Write property test for TSV structure
    - **Property 5: TSV Structure**
    - **Validates: Requirements 5.6**

- [x] 3. Implement core `compliance.py` module — Parquet reading and SQL formatting
  - [x] 3.1 Create `compliance.py` with `_read_policy_parquet(paths)` function
    - Use `pyarrow.parquet.read_table` to read each file
    - Filter input paths to only those whose filename starts with `asset_policy`
    - Convert rows to list of dicts matching the Policy_Schema
    - Wrap `read_table` in try/except to produce descriptive error on corrupt files (exit code 2)
    - _Requirements: 4.1, 6.2_
  - [x] 3.2 Implement `_format_sql(rows, table_name, timestamp)` function
    - Generate one INSERT statement per row targeting the given table name
    - Escape single quotes in string values (double them)
    - Represent NULL values as SQL NULL literals
    - Serialize varchar columns as string literals, timestamp as ISO-8601 string literal
    - Serialize varchar[] columns (`fixTexts`, `rationales`) as `ARRAY['val1','val2']` literals
    - Include a header comment with timestamp and row count
    - _Requirements: 4.2, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 5.9_
  - [ ]* 3.3 Write property test for SQL round-trip
    - **Property 1: SQL Serialization Round-Trip**
    - **Validates: Requirements 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 7.1, 7.2, 7.3**
  - [ ]* 3.4 Write property test for one INSERT per row
    - **Property 2: One INSERT Per Row**
    - **Validates: Requirements 4.2**
  - [ ]* 3.5 Write property test for SQL header comment
    - **Property 6: SQL Header Comment**
    - **Validates: Requirements 5.9**
  - [ ]* 3.6 Write property test for asset policy file filtering
    - **Property 4: Asset Policy File Filtering**
    - **Validates: Requirements 4.1**

- [x] 4. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement file download, naming, and caching logic in `compliance.py`
  - [x] 5.1 Implement `_download_and_rename(client, export, output_dir)` function
    - Iterate over the export `result` array entries (each has `prefix` and `urls`)
    - Download each URL using `_download_parquet_urls` from `solutions/vm.py`
    - Rename files to `{prefix}.{timestamp}.parquet` pattern; append zero-based index for multi-URL entries
    - Use the export's `timestamp` field for the timestamp component
    - Return list of Path objects for all downloaded files
    - _Requirements: 2.4, 2.7, 2.8_
  - [x] 5.2 Implement `_find_cached_files(output_dir)` function
    - Glob for `asset_policy.*.parquet` in the output directory
    - Return list of matching Path objects
    - _Requirements: 3.1_
  - [ ]* 5.3 Write property test for file naming pattern
    - **Property 3: File Naming Pattern**
    - **Validates: Requirements 2.7, 2.8**

- [x] 6. Implement the Click command and wire everything together
  - [x] 6.1 Implement the `compliance` Click command function in `compliance.py`
    - Define `@click.command("compliance")` with options: `--output-dir`, `--table-name`, `--sql-file`, `--poll-interval`
    - Use `@click.pass_context` to access the global config
    - Override default output format to `sql` when user hasn't explicitly set `--output`
    - Implement cache check: if `--cache` is set and cached files exist, skip export and print cache message to stderr
    - If no cache, run export pipeline: import and call `_submit_export` and `_poll_export` from `solutions/vm.py`, then `_download_and_rename`
    - Handle FAILED export status (stderr message, exit code 2)
    - Call `_read_policy_parquet` on the downloaded/cached files
    - Route to `_format_sql`, `_format_tsv`, or `format_output` based on the output format
    - If `--sql-file` is provided, write output to file and print path to stderr; handle write errors (exit code 1)
    - Catch `R7Error` subclasses at the command level, print to stderr, exit with appropriate code
    - _Requirements: 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.2, 3.3, 5.1, 5.2, 5.3, 5.4, 5.5, 5.7, 5.8, 6.1, 6.2, 6.3, 6.4_
  - [x] 6.2 Register the `compliance` command in `main.py`
    - Add `"compliance"` to `SolutionGroup.list_commands()` return set
    - Add `if name == "compliance"` branch in `SolutionGroup.get_command()` that imports and returns the command
    - _Requirements: 1.1, 1.2_
  - [ ]* 6.3 Write unit tests for command registration and output formats
    - Verify `compliance` appears in `SolutionGroup.list_commands()`
    - Verify `--help` output contains expected description
    - Test each output format (json, table, csv, tsv, sql) with sample row data
    - Test `--table-name` override in SQL output
    - Test `--sql-file` writes to file and prints path to stderr
    - Test non-writable `--sql-file` produces exit code 1
    - Test corrupt Parquet file produces exit code 2
    - _Requirements: 1.1, 1.4, 4.3, 5.1, 5.7, 5.8, 6.2, 6.4_

- [x] 7. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- The implementation reuses `_submit_export`, `_poll_export`, and `_download_parquet_urls` from `solutions/vm.py`
