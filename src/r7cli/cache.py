"""Local response cache for r7-cli.

Stores JSON responses under ``~/.r7-cli/cache/{sha256_key}.json`` so that
repeated requests can be served from disk when ``--cache`` is active.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from r7cli.log import logger


CACHE_DIR = Path.home() / ".r7-cli" / "cache"


def cache_key(
    solution: str,
    subcommand: str,
    region: str,
    url: str,
    params: dict,
) -> str:
    """Return a deterministic SHA-256 hex digest for the logical request."""
    sorted_params_json = json.dumps(params, sort_keys=True)
    raw = f"{solution}|{subcommand}|{region}|{url}|{sorted_params_json}"
    return hashlib.sha256(raw.encode()).hexdigest()


class CacheStore:
    """Read/write JSON cache files keyed by SHA-256 hex digest."""

    CACHE_DIR = CACHE_DIR

    def read(self, key: str) -> dict | None:
        """Return parsed JSON for *key*, or ``None`` if the file is missing."""
        path = self.CACHE_DIR / f"{key}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def write(self, key: str, body: dict) -> None:
        """Write *body* as JSON to the cache.  Filesystem errors are non-fatal."""
        path = self.CACHE_DIR / f"{key}.json"
        try:
            self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(body), encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to write cache file %s: %s", path, exc)
