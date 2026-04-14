# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Prefix with slash crashes with FileNotFoundError
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: Scope the property to prefixes containing `/` (e.g., `vulnerability_remediation/ivm`, `a/b/c`) with any valid timestamp and URL list
  - Write a property-based test that generates random prefixes containing at least one `/`, random timestamps, and 1-3 mock URLs
  - Call `_download_parquet_urls` with a mocked HTTP client and a temporary output directory
  - Assert that no `FileNotFoundError` is raised and all returned paths exist on disk
  - Bug condition from design: `isBugCondition(input) := "/" IN input.prefix`
  - Expected behavior from design: all parent directories created, files written successfully
  - Run test on UNFIXED code - expect FAILURE (`FileNotFoundError` because intermediate directories are not created)
  - **EXPECTED OUTCOME**: Test FAILS (this is correct - it proves the bug exists)
  - Document counterexamples found (e.g., `prefix="vulnerability_remediation/ivm"` raises `FileNotFoundError`)
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 2.1, 2.2_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Prefix without slash behavior unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - Observe behavior on UNFIXED code for flat prefixes (no `/`): e.g., `prefix="asset"`, `prefix="asset_policy"`, `prefix=None`
  - Observe: `prefix="asset"`, `timestamp="2026-04-07T20:33:00Z"`, 1 URL → file written as `asset.2026-04-07T20:33Z.parquet` directly in output dir
  - Observe: `prefix=None`, `timestamp=None` → filename extracted from URL, written directly in output dir
  - Observe: `prefix="asset"`, 3 URLs → files written as `asset.{ts}.0.parquet`, `asset.{ts}.1.parquet`, `asset.{ts}.2.parquet`
  - Write property-based test: for all prefixes NOT containing `/` (flat strings like `asset`, `asset_policy`, `asset_vulnerability`), with any valid timestamp and 1-3 URLs, files are written directly into the output directory and filenames match `{prefix}.{ts}.parquet` or `{prefix}.{ts}.{idx}.parquet`
  - Preservation condition from design: `NOT isBugCondition(input)` i.e., `"/" NOT IN input.prefix`
  - Verify tests PASS on UNFIXED code (confirms baseline behavior to preserve)
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3_

- [x] 3. Fix for FileNotFoundError when prefix contains slash

  - [x] 3.1 Implement the fix
    - In `solutions/vm.py`, function `_download_parquet_urls` (line ~133)
    - Add `dest.parent.mkdir(parents=True, exist_ok=True)` immediately before `dest.write_bytes(resp.content)`
    - This is a single-line change; no other modifications needed
    - When prefix has no `/`, `dest.parent` equals `out` which already exists — `exist_ok=True` makes this a no-op
    - When prefix has `/`, it creates the missing intermediate directories
    - _Bug_Condition: isBugCondition(input) where "/" IN input.prefix_
    - _Expected_Behavior: all parent directories created before write; no FileNotFoundError raised; all files written to disk_
    - _Preservation: flat prefixes (no "/") continue to write directly into output_dir without extra subdirectories_
    - _Requirements: 1.1, 1.2, 2.1, 2.2, 3.1, 3.2, 3.3_

  - [x] 3.2 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Prefix with slash downloads successfully
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior (no crash, files exist on disk)
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2_

  - [x] 3.3 Verify preservation tests still pass
    - **Property 2: Preservation** - Prefix without slash behavior unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all tests still pass after fix (no regressions)
    - _Requirements: 3.1, 3.2, 3.3_

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
