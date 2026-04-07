# Implementation Plan: Short Output Mode

## Overview

Add a `--short` / `-s` global flag to r7-cli that provides compact, single-line-per-object output for JSON array responses with field reordering by priority and terminal-width truncation. Changes touch `cli_group.py`, `config.py`, `main.py`, and `output.py`.

## Tasks

- [x] 1. Register the `--short` / `-s` global flag and extend Config
  - [x] 1.1 Add `short: bool` field to the `Config` dataclass in `config.py` and add `short: bool = False` parameter to `resolve_config()`
    - Add `short: bool` field to `Config` (default `False`)
    - Add `short` keyword parameter to `resolve_config()` and pass it through to the `Config` constructor
    - _Requirements: 1.2, 1.3_

  - [x] 1.2 Add `-s` / `--short` to `GLOBAL_BOOLEAN_FLAGS` in `cli_group.py`
    - Add `"-s"` and `"--short"` to the `GLOBAL_BOOLEAN_FLAGS` set
    - _Requirements: 1.4_

  - [x] 1.3 Add the Click option to the `cli` group in `main.py` and wire it to `resolve_config()`
    - Add `@click.option("-s", "--short", is_flag=True, help="Compact single-line-per-object output.")` to the `cli` function
    - Pass `short=short` to `resolve_config()`
    - _Requirements: 1.1_

  - [ ]* 1.4 Write unit tests for flag registration and Config wiring
    - Test that `-s` and `--short` are in `GLOBAL_BOOLEAN_FLAGS`
    - Test `resolve_config(short=True).short == True` and default is `False`
    - Test CLI invocation with `-s` flag does not error
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [x] 2. Implement field classification and reordering in `output.py`
  - [x] 2.1 Add priority constants and `_classify_field(key, value)` function
    - Add `HIGH_PRIORITY_FIELDS` frozenset, `LOW_PRIORITY_SUBSTRINGS` tuple, `MEDIUM_PRIORITY_SUBSTRINGS` tuple, and `UUID_PATTERN` regex to `output.py`
    - Implement `_classify_field(key: str, value: Any) -> int` returning tier 0 (high), 1 (medium), 2 (low), or 3 (default) with precedence: high > low > medium > default
    - _Requirements: 3.2, 3.3, 3.4_

  - [ ]* 2.2 Write property test for field classification
    - **Property 3: Field classification correctness**
    - **Validates: Requirements 3.2, 3.3, 3.4**

  - [x] 2.3 Implement `_reorder_fields(obj: dict) -> dict`
    - Reorder dict keys: tier 0 first, then tier 1, then tier 3 (default), then tier 2 (low)
    - Preserve original insertion order within each tier
    - _Requirements: 3.1, 3.5_

  - [ ]* 2.4 Write property test for field reordering
    - **Property 4: Field reordering preserves tier order and within-tier stability**
    - **Validates: Requirements 3.1, 3.5**

- [x] 3. Implement short-mode formatting pipeline in `output.py`
  - [x] 3.1 Implement `_truncate_line(line, width)` helper
    - Return line unchanged if `len(line) <= width`
    - Otherwise return `line[:width-1] + "…"` (exactly `width` characters)
    - _Requirements: 4.2, 4.3_

  - [ ]* 3.2 Write property test for line truncation
    - **Property 5: Line truncation correctness**
    - **Validates: Requirements 4.2, 4.3**

  - [x] 3.3 Implement `_extract_short_rows(data)` and `_format_short(data, terminal_width)` functions
    - `_extract_short_rows`: extract list of dicts from top-level list, dict-with-nested-list, or single dict
    - `_format_short`: orchestrate the pipeline — extract rows → reorder fields → compact JSON serialize → truncate → join with newlines
    - Use `shutil.get_terminal_size().columns` for terminal width (called once)
    - _Requirements: 2.1, 2.2, 2.3, 4.1_

  - [x] 3.4 Update `format_output()` signature and integrate short mode
    - Add `short: bool = False` parameter to `format_output()`
    - When `short=True` and `fmt == "json"` and `search is None`: call `_format_short(data, terminal_width)`
    - When `short=True` and `fmt != "json"`: ignore short mode, use existing format path
    - When `short=True` and `search is not None`: ignore short mode, search takes precedence
    - _Requirements: 2.4, 5.2, 5.3_

  - [ ]* 3.5 Write property test for one-line-per-row output
    - **Property 1: Short mode produces one compact JSON line per row**
    - **Validates: Requirements 2.1, 2.2, 2.3**

  - [ ]* 3.6 Write property test for non-JSON formats ignoring short mode
    - **Property 2: Non-JSON formats ignore short mode**
    - **Validates: Requirements 2.4, 5.3**

- [x] 4. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Wire short mode through all call sites
  - [x] 5.1 Update all `format_output()` call sites to pass `config.short`
    - Update `_validate_cmd` in `main.py` and any other call sites across solution modules (`solutions/*.py`, `compliance.py`, `security_checklist.py`, `jobs.py`) to pass `short=config.short`
    - _Requirements: 1.1, 2.1_

  - [ ]* 5.2 Write property test for limit interaction with short mode
    - **Property 6: Limit is applied before short formatting**
    - **Validates: Requirements 5.1**

  - [ ]* 5.3 Write property test for search precedence over short mode
    - **Property 7: Search takes precedence over short mode**
    - **Validates: Requirements 5.2**

- [x] 6. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- The design uses Python, so all implementation tasks target Python
