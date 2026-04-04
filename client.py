"""HTTP client wrapper for r7-cli.

Wraps :mod:`httpx` (synchronous) with auth injection, verbose/debug logging,
credential redaction, caching, rate-limit retry, and typed error mapping.
"""
from __future__ import annotations

import re
import sys
import time
from typing import Any

import httpx

from r7cli.cache import CacheStore, cache_key
from r7cli.config import Config
from r7cli.models import APIError, NetworkError


_REDACT_RE: re.Pattern[str] | None = None


def _build_redact_pattern(config: Config) -> re.Pattern[str] | None:
    """Compile a regex that matches literal api_key or drp_token values."""
    literals = []
    if config.api_key:
        literals.append(re.escape(config.api_key))
    if config.drp_token:
        literals.append(re.escape(config.drp_token))
    if not literals:
        return None
    return re.compile("|".join(literals))


def _redact(text: str, pattern: re.Pattern[str] | None) -> str:
    if pattern is None:
        return text
    return pattern.sub("[REDACTED]", text)


class R7Client:
    """Synchronous HTTP client with auth, logging, caching, and error mapping."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._http = httpx.Client(timeout=30.0)
        self._cache = CacheStore()
        self._redact_re = _build_redact_pattern(config)

    # -- convenience methods ------------------------------------------------

    def get(self, url: str, **kwargs: Any) -> dict:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> dict:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> dict:
        return self.request("HEAD", url, **kwargs)

    # -- core request -------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
        auth: tuple | None = None,
        headers: dict | None = None,
        solution: str = "",
        subcommand: str = "",
    ) -> dict:
        """Send an HTTP request with all cross-cutting concerns applied.

        Returns the parsed JSON response body as a dict.
        """
        # -- cache check (before live call) ---------------------------------
        ck = cache_key(solution, subcommand, self.config.region, url, params or {})
        if self.config.use_cache:
            cached = self._cache.read(ck)
            if cached is not None:
                return cached

        # -- build merged headers -------------------------------------------
        merged_headers = {
            "X-Api-Key": self.config.api_key,
            "Content-Type": "application/json",
        }
        if headers:
            merged_headers.update(headers)

        # -- verbose: log request -------------------------------------------
        if self.config.verbose:
            self._log(f"{method} {url}")

        # -- debug: log request body ----------------------------------------
        if self.config.debug and json is not None:
            import json as _json
            self._log(f">>> {_json.dumps(json)}")

        # -- execute --------------------------------------------------------
        response = self._send(method, url, json=json, params=params,
                              auth=auth, headers=merged_headers)

        # -- handle 429 rate-limit (retry once) -----------------------------
        if response.status_code == 429:
            reset = response.headers.get("X-RateLimit-Reset")
            if reset:
                try:
                    sleep_secs = int(reset)
                except ValueError:
                    sleep_secs = 1
                if self.config.verbose:
                    self._log(f"Rate limited — sleeping {sleep_secs}s")
                time.sleep(sleep_secs)
            response = self._send(method, url, json=json, params=params,
                                  auth=auth, headers=merged_headers)

        # -- verbose: log response ------------------------------------------
        elapsed_ms = int(response.elapsed.total_seconds() * 1000)
        if self.config.verbose:
            self._log(f"{response.status_code} {response.reason_phrase} {elapsed_ms}ms")

        # -- debug: log response body ---------------------------------------
        if self.config.debug:
            self._log(f"<<< {response.text}")

        # -- raise on HTTP errors -------------------------------------------
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise APIError(
                message=str(exc),
                status_code=response.status_code,
                body=response.text,
            ) from exc

        # -- parse body -----------------------------------------------------
        try:
            body = response.json()
        except Exception:
            body = {}

        # -- always write to cache ------------------------------------------
        self._cache.write(ck, body)

        return body

    # -- internal helpers ---------------------------------------------------

    def _send(
        self,
        method: str,
        url: str,
        *,
        json: dict | None,
        params: dict | None,
        auth: tuple | None,
        headers: dict,
    ) -> httpx.Response:
        """Execute the raw HTTP call, mapping connection errors."""
        try:
            return self._http.request(
                method,
                url,
                json=json,
                params=params,
                auth=auth,
                headers=headers,
            )
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc

    def _log(self, msg: str) -> None:
        """Print *msg* to stderr with credential redaction."""
        print(_redact(msg, self._redact_re), file=sys.stderr)
