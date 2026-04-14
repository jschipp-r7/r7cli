# Export Download Mkdir Bugfix Design

## Overview

The `_download_parquet_urls` function in `solutions/vm.py` crashes with `FileNotFoundError` when the API returns a `prefix` containing a `/` (e.g., `vulnerability_remediation/ivm`). The constructed filename includes a subdirectory component, but only the top-level output directory is created via `out.mkdir()`. The fix is to ensure all parent directories of the destination file path exist before calling `dest.write_bytes()`.

## Glossary

- **Bug_Condition (C)**: The condition that triggers the bug — when the `prefix` parameter contains a `/` separator, causing the destination path to include an intermediate directory that does not exist.
- **Property (P)**: The desired behavior — all parent directories of the destination file are created before writing, so the download completes successfully regardless of prefix content.
- **Preservation**: Existing behavior for prefixes without `/` (e.g., `asset`, `asset_policy`) must remain unchanged — files are written directly into the output directory as before.
- **_download_parquet_urls**: The function in `solutions/vm.py` (line 107) that downloads parquet files from presigned URLs to a local output directory, constructing filenames from `prefix` and `timestamp`.
- **prefix**: A string returned by the API (e.g., `vulnerability_remediation/ivm` or `asset`) used to construct the local filename. When it contains `/`, the filename becomes a relative path with subdirectories.

## Bug Details

### Bug Condition

The bug manifests when the API returns a `prefix` containing a `/` separator. The function constructs `filename = f"{prefix}.{ts}.parquet"`, which produces a path like `vulnerability_remediation/ivm.2026-04-07T20:33Z.parquet`. When joined with the output directory via `dest = out / filename`, the resulting path includes an intermediate directory (`vulnerability_remediation/`) that was never created. The subsequent `dest.write_bytes()` call raises `FileNotFoundError`.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type DownloadInput  -- (prefix, timestamp, urls, output_dir)
  OUTPUT: boolean

  RETURN "/" IN input.prefix
END FUNCTION
```

### Examples

- **Single URL, prefix with `/`**: `prefix="vulnerability_remediation/ivm"`, `timestamp="2026-04-07T20:33:00Z"`, 1 URL → constructs `vulnerability_remediation/ivm.2026-04-07T20:33Z.parquet` → crashes with `FileNotFoundError` because `output_dir/vulnerability_remediation/` does not exist.
- **Multiple URLs, prefix with `/`**: `prefix="vulnerability_remediation/ivm"`, `timestamp="2026-04-07T20:33:00Z"`, 3 URLs → crashes on the first file, preventing all downloads.
- **Single URL, prefix without `/`**: `prefix="asset"`, `timestamp="2026-04-07T20:33:00Z"`, 1 URL → constructs `asset.2026-04-07T20:33Z.parquet` → writes directly into output directory → works correctly.
- **No prefix/timestamp**: `prefix=None`, `timestamp=None` → falls back to extracting filename from URL → writes directly into output directory → works correctly.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Downloads with a flat prefix (no `/`) must continue to write files directly into the output directory without creating extra subdirectories.
- Downloads with an explicitly specified `output_dir` and flat prefix must continue to create the output directory and write files into it.
- Downloads without `prefix`/`timestamp` must continue to fall back to extracting the filename from the URL.
- The filename construction logic (`{prefix}.{ts}.parquet` and `{prefix}.{ts}.{idx}.parquet`) must remain identical.
- The `click.echo` download confirmation messages must remain unchanged.

**Scope:**
All inputs where `prefix` does NOT contain a `/` should be completely unaffected by this fix. This includes:
- Prefixes like `asset`, `asset_policy`, `asset_vulnerability`
- `None` prefix (fallback path)
- Any prefix that is a simple flat string

## Hypothesized Root Cause

Based on the bug description, the root cause is straightforward:

1. **Missing intermediate directory creation**: The function calls `out.mkdir(parents=True, exist_ok=True)` to create the top-level output directory, but when `filename` contains a `/` (inherited from `prefix`), the resulting `dest` path has a parent directory that differs from `out`. For example, `out / "vulnerability_remediation/ivm.2026-04-07T20:33Z.parquet"` resolves to `out/vulnerability_remediation/ivm.2026-04-07T20:33Z.parquet`, and `out/vulnerability_remediation/` was never created.

2. **No validation of prefix content**: The function does not anticipate that `prefix` may contain path separators. It treats `prefix` as a flat filename component, but the API can return hierarchical prefixes.

The fix is a single line: `dest.parent.mkdir(parents=True, exist_ok=True)` before `dest.write_bytes(resp.content)`. This is safe because:
- When `prefix` has no `/`, `dest.parent` equals `out`, which already exists — `exist_ok=True` makes this a no-op.
- When `prefix` has `/`, it creates the missing intermediate directories.

## Correctness Properties

Property 1: Bug Condition - Prefix with slash downloads successfully

_For any_ input where the prefix contains a `/` separator (isBugCondition returns true), the fixed `_download_parquet_urls` function SHALL create all necessary parent directories and successfully write the downloaded file to disk without raising `FileNotFoundError`.

**Validates: Requirements 2.1, 2.2**

Property 2: Preservation - Prefix without slash behavior unchanged

_For any_ input where the prefix does NOT contain a `/` separator (isBugCondition returns false), the fixed `_download_parquet_urls` function SHALL produce the same result as the original function, preserving the existing download behavior where files are written directly into the output directory.

**Validates: Requirements 3.1, 3.2, 3.3**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `solutions/vm.py`

**Function**: `_download_parquet_urls` (line 107)

**Specific Changes**:
1. **Add parent directory creation before write**: Insert `dest.parent.mkdir(parents=True, exist_ok=True)` immediately before the `dest.write_bytes(resp.content)` line (currently around line 136).

That is the entire fix. No other changes are needed.

**Before:**
```python
        dest = out / filename
        # Use the underlying httpx client for raw download
        resp = client._http.get(url)
        dest.write_bytes(resp.content)
```

**After:**
```python
        dest = out / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Use the underlying httpx client for raw download
        resp = client._http.get(url)
        dest.write_bytes(resp.content)
```

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm that a prefix containing `/` causes `FileNotFoundError` on the unfixed code.

**Test Plan**: Write a test that calls `_download_parquet_urls` with a prefix containing `/` (e.g., `vulnerability_remediation/ivm`) using a mocked HTTP client. Run on UNFIXED code to observe the `FileNotFoundError`.

**Test Cases**:
1. **Slash prefix single URL**: Call with `prefix="vulnerability_remediation/ivm"`, 1 URL (will crash on unfixed code)
2. **Slash prefix multiple URLs**: Call with `prefix="vulnerability_remediation/ivm"`, 3 URLs (will crash on first file on unfixed code)
3. **Deeply nested prefix**: Call with `prefix="a/b/c"`, 1 URL (will crash on unfixed code)

**Expected Counterexamples**:
- `FileNotFoundError` raised at `dest.write_bytes()` because `output_dir/vulnerability_remediation/` does not exist
- Root cause confirmed: no `mkdir` call for intermediate directories

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  result := _download_parquet_urls'(input.client, input.urls, input.output_dir,
                                     prefix=input.prefix, timestamp=input.timestamp)
  ASSERT no FileNotFoundError raised
  ASSERT all returned paths exist on disk
  ASSERT parent directories were created
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT _download_parquet_urls(input) = _download_parquet_urls'(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain (various flat prefixes, timestamps, URL counts)
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for flat prefixes (no `/`), then write property-based tests capturing that behavior and verifying the fixed code produces identical results.

**Test Cases**:
1. **Flat prefix preservation**: Verify that `prefix="asset"` with various timestamps produces the same file paths and content before and after fix
2. **No prefix preservation**: Verify that `prefix=None` fallback behavior is identical before and after fix
3. **Multi-URL flat prefix preservation**: Verify that multiple URLs with flat prefix produce the same indexed filenames before and after fix

### Unit Tests

- Test `_download_parquet_urls` with slash prefix and single URL — file is created in subdirectory
- Test `_download_parquet_urls` with slash prefix and multiple URLs — all files created with index suffixes
- Test `_download_parquet_urls` with flat prefix — files created directly in output directory (unchanged)
- Test `_download_parquet_urls` with no prefix/timestamp — fallback filename extraction (unchanged)

### Property-Based Tests

- Generate random prefixes containing `/` with random timestamps and verify all files are written successfully (fix checking)
- Generate random flat prefixes (no `/`) with random timestamps and verify output matches original function behavior (preservation checking)
- Generate random combinations of prefix presence/absence and URL counts to verify no crashes across the input space

### Integration Tests

- Test full `vm export remediations --auto` flow with mocked API returning a slash prefix — verify files downloaded to correct subdirectory
- Test full export flow with flat prefix — verify no regression in existing behavior
- Test export flow with multiple result entries containing mixed prefix types
