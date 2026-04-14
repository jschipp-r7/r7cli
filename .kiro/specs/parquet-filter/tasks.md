# Implementation Plan: parquet-filter

## Overview

Implement the `vm export list` command in a new `parquet_filter.py` module, then wire it into the existing Click command group in `solutions/vm.py`. Each task builds incrementally: core utilities first, then schema detection, reading, filtering, auto-join, CLI wiring, and finally integration.

## Tasks

- [x] 1. Create `parquet_filter.py` with file resolution and schema detection
  - [x] 1.1 Implement `resolve_files(use_cache, file_pattern)` function
    - Accept `use_cache` (bool) and `file_pattern` (str | None)
    - When `use_cache` is True, glob `*.parquet` in cwd
    - When `file_pattern` is provided, resolve the path/glob
    - `file_pattern` takes precedence over `use_cache`
    - Exit with code 1 if neither flag provided or no files found
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [x] 1.2 Implement `detect_schema(path)` function
    - Read only Parquet metadata (column names) via `pyarrow.parquet.read_schema`
    - Apply priority-ordered probe: `vulnId` → vulnerability, `benchmarkNaturalId` → policy, `remediationCount` → remediation, `hostName` → asset
    - Return `None` and print warning for unknown schemas
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

  - [ ]* 1.3 Write unit tests for file resolution and schema detection
    - Test `--cache` glob, `--file` glob, precedence, empty results, and exit codes
    - Test each schema probe column and priority ordering
    - Test unknown schema warning and skip behavior
    - _Requirements: 1.1–1.5, 3.1–3.6_

- [x] 2. Implement Parquet reading and type conversion
  - [x] 2.1 Implement `read_parquet_files(paths)` function
    - Read each file with `pyarrow.parquet.read_table`, convert to `list[dict]`
    - Convert timestamp columns to ISO-8601 strings
    - Convert list-typed columns to Python lists
    - Handle corrupt/unreadable files: print error, exit with code 2
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [ ]* 2.2 Write property test: Timestamp ISO-8601 conversion
    - **Property 1: Timestamp conversion produces valid ISO-8601**
    - Generate datetimes with `st.datetimes()`, write to Parquet, read back, verify ISO-8601 format
    - **Validates: Requirements 2.2**

  - [ ]* 2.3 Write unit tests for Parquet reading
    - Test row conversion, list column handling, corrupt file error
    - _Requirements: 2.1, 2.3, 2.4_

- [x] 3. Implement comparison parsing and filter engine
  - [x] 3.1 Implement `parse_comparison(expr)` function
    - Parse expressions like `>=9.0` into `(operator_func, "9.0")`
    - Support operators: `>=`, `<=`, `>`, `<`, `==`, `=`
    - _Requirements: 5.2_

  - [x] 3.2 Implement `apply_filters(rows, filters)` function
    - Apply string filters as case-insensitive substring match
    - Apply numeric filters with parsed comparison operators
    - Apply boolean filters (`true`/`false`, case-insensitive)
    - Apply date filters with ISO-8601 parsing and comparison
    - Exclude rows with null values for numeric columns
    - Ignore filters for columns not present in the schema
    - Compose all filters as logical AND
    - _Requirements: 4.1, 4.2, 4.3, 5.1, 5.3, 5.4, 6.1, 6.2, 7.1, 7.2, 7.3_

  - [x] 3.3 Implement `apply_where(rows, where_clauses, schema_columns)` function
    - Parse `column op value` syntax from each `--where` clause
    - Auto-detect column type from Parquet schema for correct comparison
    - Apply all `--where` clauses as logical AND
    - Exit with code 1 on invalid syntax
    - _Requirements: 8.1, 8.2, 8.3_

  - [ ]* 3.4 Write property test: String filter case-insensitive substring
    - **Property 2: String filter is case-insensitive substring match**
    - Generate random text values and filter substrings, verify inclusion iff `f.lower() in v.lower()`
    - **Validates: Requirements 4.1**

  - [ ]* 3.5 Write property test: Multiple filters compose as AND
    - **Property 3: Multiple filters compose as logical AND**
    - Generate rows and multiple filter predicates, verify row included iff all predicates pass
    - **Validates: Requirements 4.2, 8.3**

  - [ ]* 3.6 Write property test: Numeric comparison correctness
    - **Property 4: Numeric comparison filter correctness**
    - Generate floats for values and thresholds, sampled operators, verify `v op t` matches filter result
    - **Validates: Requirements 5.1, 5.2, 5.4**

  - [ ]* 3.7 Write property test: Date comparison correctness
    - **Property 5: Date comparison filter correctness**
    - Generate datetimes for values and thresholds, sampled operators, verify datetime comparison
    - **Validates: Requirements 7.1, 7.2**

  - [ ]* 3.8 Write property test: Comparison operator parsing round-trip
    - **Property 7: Comparison operator parsing round-trip**
    - Generate operator symbols and numeric strings, verify `parse_comparison` returns correct operator and value
    - **Validates: Requirements 5.2**

- [x] 4. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement auto-join logic
  - [x] 5.1 Implement `auto_join(primary_rows, asset_rows)` function
    - Build `assetId → asset_row` lookup from asset rows
    - Enrich primary rows with asset fields for filtering
    - Strip asset columns from final output
    - Print warning and ignore asset filters when no asset files present
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [ ]* 5.2 Write property test: Auto-join preserves matching primary rows
    - **Property 6: Auto-join preserves all matching primary rows**
    - Generate primary and asset row sets, verify join returns exactly matching primary rows enriched with asset fields
    - **Validates: Requirements 9.1**

  - [ ]* 5.3 Write unit tests for auto-join
    - Test asset column stripping from output
    - Test warning when asset files missing and asset filter used
    - _Requirements: 9.3, 9.4_

- [x] 6. Wire up the Click command in `solutions/vm.py`
  - [x] 6.1 Add `export list` command to the existing `export` group
    - Add all CLI options: `--file`, `--hostname`, `--ip`, `--os-family`, `--severity`, `--cvss-score`, `--risk-score`, `--has-exploits`, `--first-found`, `--status`, `--where`
    - Call `resolve_files`, `detect_schema`, `read_parquet_files`, `auto_join`, `apply_filters`, `apply_where`
    - Pass filtered rows to `format_output(data, fmt, limit, search, short)`
    - Respect global flags: `-o`/`--output`, `-s`/`--short`, `--search-fields`, `-l`/`--limit`, `-c`/`--cache`
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 11.1, 11.2, 11.3_

  - [ ]* 6.2 Write unit tests for command registration and help
    - Verify `vm export list --help` works
    - Verify no API key required
    - _Requirements: 11.1, 11.2, 11.3_

- [x] 7. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Property tests use Hypothesis (already in dev dependencies)
- The `parquet_filter.py` module is new; `solutions/vm.py` receives only the thin Click command addition
