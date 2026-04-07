# Implementation Plan: Security Checklist Command

## Overview

Implement the `security-checklist` top-level CLI command that fetches licensed Rapid7 products, evaluates coverage against a NIST CSF × CIS v8 matrix, and renders an ASCII grid table. The implementation is split into: static data constants, pure evaluation functions, Click command wiring, and registration on the SolutionGroup.

## Tasks

- [x] 1. Create `security_checklist.py` with static data constants and pure functions
  - [x] 1.1 Define module-level constants: `PRODUCT_CODE_MAP`, `NIST_STAGES`, `CIS_ASSET_TYPES`, and `CELL_MAPPING`
    - `PRODUCT_CODE_MAP` maps 11 product codes to canonical names per the design (SC, ICS, IVM, IDR, OPS, ICON, TC, AS, MDR, DSPM, CGRC)
    - `NIST_STAGES` = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
    - `CIS_ASSET_TYPES` = ["DEVICES", "SOFTWARE", "NETWORK", "USERS", "DATA", "DOCUMENTATION"]
    - `CELL_MAPPING` is a `dict[tuple[str, str], set[str] | None]` with all 36 entries per the design table
    - _Requirements: 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9_

  - [x] 1.2 Implement `resolve_product_codes(product_records: list[dict]) -> set[str]`
    - Extract `product_code` from each record, look up in `PRODUCT_CODE_MAP`, return set of canonical names
    - Unknown codes are silently skipped
    - _Requirements: 2.2, 2.3, 2.4_

  - [x] 1.3 Implement `evaluate_cell(required: set[str] | None, licensed: set[str]) -> str`
    - Return `"not_applicable"` if required is None
    - Return `"covered"` if intersection of required and licensed is non-empty
    - Return `"not_covered"` if required is non-empty and intersection is empty
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [x] 1.4 Implement `build_matrix(licensed: set[str]) -> list[list[str]]`
    - Iterate all 36 cells using `NIST_STAGES` and `CIS_ASSET_TYPES`
    - Map coverage status to display strings: ✅, 🚫, or `\033[1;37mN/A\033[0m`
    - Return list of rows, each row = [asset_type_label, cell_0, ..., cell_5]
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

  - [x] 1.5 Implement `render_matrix(rows: list[list[str]]) -> str`
    - Call `tabulate(rows, headers=["", *NIST_STAGES], tablefmt="grid")`
    - _Requirements: 6.6_

  - [ ]* 1.6 Write property test for product code resolution (Property 1)
    - **Property 1: Product Code Resolution**
    - Generate random lists of product records with mix of known/unknown codes, verify `resolve_product_codes` returns exactly the expected canonical names
    - **Validates: Requirements 2.2, 2.3, 2.4**

  - [ ]* 1.7 Write property test for coverage evaluation correctness (Property 2)
    - **Property 2: Coverage Evaluation Correctness**
    - Generate random required sets (or None) and random licensed sets, verify `evaluate_cell` returns the correct status based on set intersection
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 9.1, 9.2, 9.3**

  - [ ]* 1.8 Write property test for display symbol consistency (Property 3)
    - **Property 3: Display Symbol Consistency**
    - Generate random licensed product name sets, call `build_matrix`, verify each cell's display string matches its expected coverage status
    - **Validates: Requirements 6.3, 6.4, 6.5**

  - [ ]* 1.9 Write property test for code resolution round-trip (Property 4)
    - **Property 4: Code Resolution Round-Trip**
    - Generate random product code lists (known + unknown), resolve via `resolve_product_codes`, evaluate all 36 cells, compare against direct evaluation with manually computed canonical names
    - **Validates: Requirements 9.4**

- [x] 2. Checkpoint - Verify pure functions and properties
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Implement the Click command and register it on SolutionGroup
  - [x] 3.1 Add the `security_checklist` Click command in `security_checklist.py`
    - Decorate with `@click.command("security-checklist")`
    - Accept `ctx` via `@click.pass_context`, extract `config` from `ctx.obj["config"]`
    - Use `R7Client` to GET `ACCOUNT_BASE.format(region=config.region) + "/products"`
    - Validate response is a list; raise `APIError` if not
    - Call `resolve_product_codes` → `build_matrix` → `render_matrix` → `click.echo`
    - Catch `R7Error` subclasses, print to stderr, exit with appropriate code
    - _Requirements: 1.2, 1.3, 2.1, 6.7, 7.1, 7.2, 7.3, 8.1, 8.2, 8.3_

  - [x] 3.2 Register `security-checklist` in `main.py` SolutionGroup
    - Add `"security-checklist"` to `list_commands()` return set
    - Add import branch in `get_command()` for `name == "security-checklist"`
    - _Requirements: 1.1, 1.4_

  - [ ]* 3.3 Write unit tests for command registration and error handling
    - Verify `security-checklist` appears in `SolutionGroup.list_commands()`
    - Verify `--help` output contains expected description
    - Verify `PRODUCT_CODE_MAP` has 11 entries with correct values
    - Verify `CELL_MAPPING` has exactly 36 entries
    - Verify GOVERN column maps to {"Cyber GRC"} and RECOVER column maps to None
    - Verify auth error (mocked 401) produces exit code 2
    - Verify network error produces exit code 3
    - Verify non-array API response produces descriptive error and exit code 2
    - _Requirements: 1.1, 1.4, 3.1, 3.2, 4.1, 8.1, 8.2, 8.3_

- [x] 4. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Property tests use Hypothesis (already in dev dependencies)
- The command reuses existing `R7Client`, `Config`, and `ACCOUNT_BASE` — no new dependencies needed
- `tabulate` is called directly (not via `format_output`) since the matrix has a fixed non-standard shape
