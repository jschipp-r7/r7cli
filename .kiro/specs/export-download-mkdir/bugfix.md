# Bugfix Requirements Document

## Introduction

When exporting VM remediations via `r7-cli vm export remediations --auto`, the CLI crashes with a `FileNotFoundError` during the download phase. The API returns a `prefix` field containing a `/` (e.g., `vulnerability_remediation/ivm`), which causes the constructed filename to include a subdirectory path. The `_download_parquet_urls` function only creates the top-level output directory but not the intermediate parent directories implied by the prefix, so `dest.write_bytes()` fails because the parent directory does not exist.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN the API returns a `prefix` containing a `/` separator (e.g., `vulnerability_remediation/ivm`) THEN the system crashes with `FileNotFoundError: [Errno 2] No such file or directory` when attempting to write the downloaded parquet file, because the intermediate parent directory (e.g., `vulnerability_remediation/`) is not created.

1.2 WHEN multiple parquet URLs are downloaded and the `prefix` contains a `/` separator THEN the system crashes on the first file write attempt, preventing all subsequent downloads from completing.

### Expected Behavior (Correct)

2.1 WHEN the API returns a `prefix` containing a `/` separator (e.g., `vulnerability_remediation/ivm`) THEN the system SHALL create all necessary parent directories for the destination file path before writing, and the download SHALL complete successfully.

2.2 WHEN multiple parquet URLs are downloaded and the `prefix` contains a `/` separator THEN the system SHALL create the required parent directories and successfully download all files.

### Unchanged Behavior (Regression Prevention)

3.1 WHEN the API returns a `prefix` without a `/` separator (e.g., `asset` or `asset_policy`) THEN the system SHALL CONTINUE TO download files directly into the output directory without creating extra subdirectories.

3.2 WHEN `output_dir` is explicitly specified and the `prefix` has no `/` separator THEN the system SHALL CONTINUE TO create the output directory and download files into it as before.

3.3 WHEN neither `prefix` nor `timestamp` are provided THEN the system SHALL CONTINUE TO fall back to extracting the filename from the URL and downloading into the output directory.

---

### Bug Condition

```pascal
FUNCTION isBugCondition(X)
  INPUT: X of type DownloadInput  -- (prefix, timestamp, urls, output_dir)
  OUTPUT: boolean

  // The bug triggers when the prefix contains a path separator
  RETURN "/" IN X.prefix
END FUNCTION
```

### Fix Checking

```pascal
// Property: Fix Checking - Prefix with slash downloads successfully
FOR ALL X WHERE isBugCondition(X) DO
  result ← _download_parquet_urls'(X.client, X.urls, X.output_dir, prefix=X.prefix, timestamp=X.timestamp)
  ASSERT no_crash(result)
  ASSERT all files in result exist on disk
  ASSERT parent directories of each file were created
END FOR
```

### Preservation Checking

```pascal
// Property: Preservation Checking - Prefix without slash unchanged
FOR ALL X WHERE NOT isBugCondition(X) DO
  ASSERT _download_parquet_urls(X) = _download_parquet_urls'(X)
END FOR
```
