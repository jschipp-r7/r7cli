"""Bug condition exploration test for _download_parquet_urls.

The bug: when ``prefix`` contains a ``/`` (e.g. ``vulnerability_remediation/ivm``),
the constructed filename includes a subdirectory, but only the top-level output_dir
is created via ``mkdir``.  This causes ``FileNotFoundError`` on ``dest.write_bytes()``.

This test asserts the EXPECTED (correct) behaviour — files are created successfully.
On UNFIXED code it will FAIL with ``FileNotFoundError``, proving the bug exists.

**Validates: Requirements 1.1, 1.2, 2.1, 2.2**
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import hypothesis.strategies as st
from hypothesis import given, settings

from r7cli.solutions.vm import _download_parquet_urls


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Prefix that always contains at least one "/"
_segment = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz_"),
    min_size=1,
    max_size=12,
)
slash_prefix = st.tuples(_segment, _segment).map(lambda t: f"{t[0]}/{t[1]}")

# Valid ISO-8601 timestamps
iso_timestamp = st.datetimes(
    min_value=__import__("datetime").datetime(2020, 1, 1),
    max_value=__import__("datetime").datetime(2030, 12, 31),
).map(lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"))

# 1-3 dummy presigned URLs
dummy_urls = st.lists(
    st.text(alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789"), min_size=4, max_size=10).map(
        lambda s: f"https://s3.example.com/{s}.parquet?token=abc"
    ),
    min_size=1,
    max_size=3,
)


def _make_mock_client() -> MagicMock:
    """Return a mock R7Client whose ``_http.get()`` returns dummy bytes."""
    client = MagicMock()
    resp = MagicMock()
    resp.content = b"PARQUET_DUMMY_BYTES"
    client._http.get.return_value = resp
    return client


# ---------------------------------------------------------------------------
# Property 1: Bug Condition — prefix with "/" should not crash
# ---------------------------------------------------------------------------


@given(prefix=slash_prefix, timestamp=iso_timestamp, urls=dummy_urls)
@settings(max_examples=50, deadline=None)
def test_slash_prefix_creates_files_successfully(
    prefix: str, timestamp: str, urls: list[str]
) -> None:
    """For any prefix containing '/', all files must be written to disk.

    **Validates: Requirements 1.1, 1.2, 2.1, 2.2**
    """
    client = _make_mock_client()

    with tempfile.TemporaryDirectory() as tmpdir:
        saved = _download_parquet_urls(
            client, urls, tmpdir, prefix=prefix, timestamp=timestamp
        )

        # Every returned path must exist on disk
        assert len(saved) == len(urls)
        for p in saved:
            assert p.exists(), f"Expected file to exist: {p}"
            assert p.read_bytes() == b"PARQUET_DUMMY_BYTES"


# ---------------------------------------------------------------------------
# Property 2: Preservation — flat prefix (no "/") behaviour unchanged
# ---------------------------------------------------------------------------

# Flat prefix: alphanumeric + underscore, no "/"
_flat_prefix = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_"),
    min_size=1,
    max_size=12,
)


@given(prefix=_flat_prefix, timestamp=iso_timestamp, urls=dummy_urls.filter(lambda u: len(u) == 1))
@settings(max_examples=50, deadline=None)
def test_preservation_flat_prefix_single_url(
    prefix: str, timestamp: str, urls: list[str]
) -> None:
    """Flat prefix with a single URL writes one file directly into output dir.

    Expected filename: ``{prefix}.{short_ts}.parquet`` — no subdirectories.

    **Validates: Requirements 3.1, 3.2**
    """
    client = _make_mock_client()

    with tempfile.TemporaryDirectory() as tmpdir:
        saved = _download_parquet_urls(
            client, urls, tmpdir, prefix=prefix, timestamp=timestamp
        )

        from r7cli.solutions.vm import _short_iso_timestamp

        short_ts = _short_iso_timestamp(timestamp)
        expected_name = f"{prefix}.{short_ts}.parquet"

        assert len(saved) == 1
        p = saved[0]
        # File lives directly in the output directory (no subdirectories)
        assert p.parent == Path(tmpdir)
        assert p.name == expected_name
        assert p.exists()
        assert p.read_bytes() == b"PARQUET_DUMMY_BYTES"


@given(
    prefix=_flat_prefix,
    timestamp=iso_timestamp,
    urls=dummy_urls.filter(lambda u: 2 <= len(u) <= 3),
)
@settings(max_examples=50, deadline=None)
def test_preservation_flat_prefix_multiple_urls(
    prefix: str, timestamp: str, urls: list[str]
) -> None:
    """Flat prefix with 2-3 URLs writes indexed files directly into output dir.

    Expected filenames: ``{prefix}.{short_ts}.{idx}.parquet`` — no subdirectories.

    **Validates: Requirements 3.1, 3.2**
    """
    client = _make_mock_client()

    with tempfile.TemporaryDirectory() as tmpdir:
        saved = _download_parquet_urls(
            client, urls, tmpdir, prefix=prefix, timestamp=timestamp
        )

        from r7cli.solutions.vm import _short_iso_timestamp

        short_ts = _short_iso_timestamp(timestamp)

        assert len(saved) == len(urls)
        for idx, p in enumerate(saved):
            expected_name = f"{prefix}.{short_ts}.{idx}.parquet"
            # File lives directly in the output directory
            assert p.parent == Path(tmpdir)
            assert p.name == expected_name
            assert p.exists()
            assert p.read_bytes() == b"PARQUET_DUMMY_BYTES"


# ---------------------------------------------------------------------------
# Preservation — no prefix / no timestamp fallback
# ---------------------------------------------------------------------------


def test_no_prefix_no_timestamp_extracts_filename_from_url() -> None:
    """When prefix=None and timestamp=None, filename is extracted from the URL.

    The last path segment before ``?`` is used as the filename, and the file
    is written directly into the output directory.

    **Validates: Requirements 3.3**
    """
    client = _make_mock_client()
    urls = ["https://s3.example.com/part-00000-abc123.snappy.parquet?token=xyz"]

    with tempfile.TemporaryDirectory() as tmpdir:
        saved = _download_parquet_urls(client, urls, tmpdir)

        assert len(saved) == 1
        p = saved[0]
        assert p.parent == Path(tmpdir)
        assert p.name == "part-00000-abc123.snappy.parquet"
        assert p.exists()
        assert p.read_bytes() == b"PARQUET_DUMMY_BYTES"


# ---------------------------------------------------------------------------
# Verify follow_redirects=True is passed on every download request
# ---------------------------------------------------------------------------


@given(prefix=slash_prefix, timestamp=iso_timestamp, urls=dummy_urls)
@settings(max_examples=50, deadline=None)
def test_download_follows_redirects(
    prefix: str, timestamp: str, urls: list[str]
) -> None:
    """Every HTTP GET for a parquet download must use follow_redirects=True.

    S3 pre-signed URLs (path-style) can issue 307 redirects. Without
    follow_redirects=True, the response body is empty, producing 0-byte files.
    This was reported by a Windows customer using vm export --auto.
    """
    client = _make_mock_client()

    with tempfile.TemporaryDirectory() as tmpdir:
        _download_parquet_urls(client, urls, tmpdir, prefix=prefix, timestamp=timestamp)

        # Every call to _http.get() must have follow_redirects=True
        assert client._http.get.call_count == len(urls)
        for call in client._http.get.call_args_list:
            _, kwargs = call
            assert kwargs.get("follow_redirects") is True, (
                f"Expected follow_redirects=True in GET call, got: {kwargs}"
            )


def test_download_follows_redirects_no_prefix() -> None:
    """follow_redirects=True must also be set when prefix/timestamp are omitted."""
    client = _make_mock_client()
    urls = [
        "https://s3.us-west-2.amazonaws.com/bucket/part-00000.snappy.parquet?X-Amz-Token=abc",
        "https://s3.us-west-2.amazonaws.com/bucket/part-00001.snappy.parquet?X-Amz-Token=def",
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        _download_parquet_urls(client, urls, tmpdir)

        assert client._http.get.call_count == 2
        for call in client._http.get.call_args_list:
            _, kwargs = call
            assert kwargs.get("follow_redirects") is True


def test_download_calls_raise_for_status() -> None:
    """Every download response must have raise_for_status() called.

    This ensures HTTP errors (e.g. 403 expired token) are surfaced
    rather than silently writing error XML to disk.
    """
    client = _make_mock_client()
    urls = ["https://s3.example.com/file.parquet?token=abc"]

    with tempfile.TemporaryDirectory() as tmpdir:
        _download_parquet_urls(client, urls, tmpdir, prefix="test", timestamp="2026-05-07T13:50:56.086Z")

    resp_mock = client._http.get.return_value
    resp_mock.raise_for_status.assert_called()
