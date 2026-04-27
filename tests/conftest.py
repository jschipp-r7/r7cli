"""Shared pytest fixtures and configuration for r7-cli tests."""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from r7cli.config import Config


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def mock_config() -> Config:
    """Return a Config with safe defaults for testing (no real API key)."""
    return Config(
        region="us",
        api_key="test-key-do-not-use",
        drp_token="",
        verbose=False,
        debug=False,
        output_format="json",
        use_cache=False,
        limit=None,
        timeout=5,
        search=None,
        short=False,
        llm_provider="",
        llm_api_key="",
    )


@pytest.fixture
def mock_client():
    """Return a MagicMock that behaves like R7Client for unit tests."""
    client = MagicMock()
    resp = MagicMock()
    resp.content = b"MOCK_RESPONSE_BYTES"
    client._http.get.return_value = resp
    return client
