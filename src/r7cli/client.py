"""HTTP client wrapper for r7-cli.

Wraps :mod:`httpx` (synchronous) with auth injection, verbose/debug logging,
credential redaction, caching, rate-limit retry, and typed error mapping.
"""
from __future__ import annotations

import sys
import time
from typing import Any

import httpx

from r7cli.cache import CacheStore, cache_key
from r7cli.config import Config
from r7cli.log import logger
from r7cli.models import APIError, NetworkError


class R7Client:
    """Synchronous HTTP client with auth, logging, caching, and error mapping."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._http = httpx.Client(timeout=float(config.timeout))
        self._cache = CacheStore()
        self._license_checked: set[str] = set()  # solutions already checked

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

        Handles license checking, response caching, verbose/debug logging,
        rate-limit retry with exponential backoff, and typed error mapping.

        Parameters
        ----------
        method : str
            HTTP method (``GET``, ``POST``, ``HEAD``, ``DELETE``, etc.).
        url : str
            Fully qualified URL.
        json : dict, optional
            JSON request body.
        params : dict, optional
            URL query parameters.
        auth : tuple, optional
            HTTP Basic auth ``(username, password)`` tuple.
        headers : dict, optional
            Additional headers to merge with the default auth headers.
        solution : str
            Solution name for cache keying and license checking.
        subcommand : str
            Subcommand name for cache keying.

        Returns
        -------
        dict
            Parsed JSON response body.

        Raises
        ------
        APIError
            On HTTP 4xx/5xx responses.
        NetworkError
            On connection failures or timeouts.
        """
        # -- license check (lazy, once per solution) ------------------------
        if solution and solution not in self._license_checked and solution != "platform":
            self._license_checked.add(solution)
            if not self.config.use_cache:
                self._check_solution_license(solution)

        # -- cache check (before live call) ---------------------------------
        ck = cache_key(solution, subcommand, self.config.region, url, params or {})
        if self.config.use_cache:
            cached = self._cache.read(ck)
            if cached is not None:
                cache_path = self._cache.CACHE_DIR / f"{ck}.json"
                logger.debug("Cache hit: %s", cache_path)
                return cached
            else:
                if self.config.debug:
                    cache_path = self._cache.CACHE_DIR / f"{ck}.json"
                    logger.debug("No cache file found: %s", cache_path)

        # -- build merged headers -------------------------------------------
        merged_headers = {
            "X-Api-Key": self.config.api_key,
            "Content-Type": "application/json",
        }
        if headers:
            merged_headers.update(headers)

        # -- verbose: log request -------------------------------------------
        if self.config.verbose:
            if params:
                from urllib.parse import urlencode
                logger.info("%s %s?%s", method, url, urlencode(params))
            else:
                logger.info("%s %s", method, url)

        # -- debug: log request body ----------------------------------------
        if self.config.debug and json is not None:
            import json as _json
            logger.debug(">>> %s", _json.dumps(json))

        # -- debug: print equivalent curl command ---------------------------
        if self.config.debug:
            curl_cmd = self._build_curl(method, url, merged_headers, json, params, auth)
            logger.debug("Example cURL: %s", curl_cmd)

        # -- execute --------------------------------------------------------
        response = self._send(method, url, json=json, params=params,
                              auth=auth, headers=merged_headers)

        # -- handle 429 rate-limit with exponential backoff -----------------
        max_retries = 3
        for attempt in range(max_retries):
            if response.status_code != 429:
                break
            reset = response.headers.get("X-RateLimit-Reset")
            if reset:
                try:
                    sleep_secs = int(reset)
                except ValueError:
                    sleep_secs = 2 ** attempt
            else:
                sleep_secs = min(2 ** attempt, 60)
            logger.info("Rate limited (429) — retry %d/%d, sleeping %ds",
                        attempt + 1, max_retries, sleep_secs)
            time.sleep(sleep_secs)
            response = self._send(method, url, json=json, params=params,
                                  auth=auth, headers=merged_headers)

        # -- verbose: log response ------------------------------------------
        elapsed_ms = int(response.elapsed.total_seconds() * 1000)
        logger.info("%s %s %dms", response.status_code, response.reason_phrase, elapsed_ms)

        # -- debug: log response body ---------------------------------------
        logger.debug("<<< %s", response.text)

        # -- raise on HTTP errors -------------------------------------------
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if response.status_code == 401:
                # Check if a key was even provided
                has_key = bool(self.config.api_key) or (auth is not None)
                if not has_key:
                    msg = (
                        "No API key provided. Set the R7_X_API_KEY environment variable "
                        "or use -k / --api-key to provide one."
                    )
                else:
                    msg = (
                        "The provided key is not authorized for this request. "
                        "Try checking permissions or generating a new platform key."
                    )
                if self.config.verbose:
                    msg += f"\n{exc}"
                raise APIError(
                    message=msg,
                    status_code=response.status_code,
                    body=response.text,
                ) from exc
            # Try to extract a human-readable message from the JSON body
            api_msg = str(exc)
            try:
                err_body = response.json()
                if isinstance(err_body, dict):
                    err_obj = err_body.get("error", err_body)
                    if isinstance(err_obj, dict) and "message" in err_obj:
                        api_msg = err_obj["message"]
                    elif "message" in err_body:
                        api_msg = err_body["message"]
            except Exception:
                pass
            if self.config.verbose:
                api_msg += f"\n{exc}"
            raise APIError(
                message=api_msg,
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
        except httpx.TimeoutException as exc:
            timeout_val = self.config.timeout
            raise NetworkError(
                f"Request timed out after {timeout_val}s. "
                f"The request is taking longer than expected, likely because "
                f"a large amount of data is being returned. "
                f"Try using -t / --timeout with a value greater than {timeout_val} (in seconds)."
            ) from exc
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc

    def _check_solution_license(self, solution: str) -> None:
        """Check if the user is licensed for the given solution. Exits if not."""
        from r7cli.main import _SOLUTION_LICENSE_MAP
        required_codes = _SOLUTION_LICENSE_MAP.get(solution)
        if not required_codes or not self.config.api_key:
            return
        try:
            from r7cli.models import ACCOUNT_BASE
            url = ACCOUNT_BASE.format(region=self.config.region) + "/products"
            resp = self._http.request(
                "GET", url,
                headers={"X-Api-Key": self.config.api_key, "Content-Type": "application/json"},
            )
            if resp.status_code != 200:
                return  # fail open
            data = resp.json()
            codes = {item.get("product_code", "") for item in data} if isinstance(data, list) else set()
            if codes and not any(code in codes for code in required_codes):
                _FRIENDLY = {
                    "vm": "InsightVM", "siem": "InsightIDR", "asm": "Surface Command",
                    "drp": "Digital Risk Protection", "appsec": "InsightAppSec",
                    "cnapp": "InsightCloudSec", "soar": "InsightConnect",
                }
                friendly = _FRIENDLY.get(solution, solution)
                logger.error(
                    "Your organization is not licensed for %s. "
                    "This command requires one of: %s.\n"
                    "Check your licensed products with: r7-cli platform products list",
                    friendly, ", ".join(required_codes),
                )
                sys.exit(1)
        except Exception:
            pass  # fail open on any error

    def _build_curl(
        self,
        method: str,
        url: str,
        headers: dict,
        json_body: dict | None,
        params: dict | None,
        auth: tuple | None,
    ) -> str:
        """Build an equivalent curl command string."""
        import json as _json
        import shlex
        from urllib.parse import urlencode

        parts = ["curl", "-s"]

        if method != "GET":
            parts.extend(["-X", method])

        # URL with query params
        full_url = url
        if params:
            full_url = f"{url}?{urlencode(params)}"
        parts.append(shlex.quote(full_url))

        # Headers — save X-Api-Key for last
        api_key_header = None
        for key, val in headers.items():
            if key == "X-Api-Key":
                api_key_header = (key, val)
                continue
            parts.extend(["-H", shlex.quote(f"{key}: {val}")])

        # Auth
        if auth:
            parts.extend(["-u", shlex.quote(f"{auth[0]}:{auth[1]}")])

        # Body
        if json_body is not None:
            parts.extend(["-d", shlex.quote(_json.dumps(json_body))])

        # API key last
        if api_key_header:
            parts.extend(["-H", shlex.quote(f"{api_key_header[0]}: {api_key_header[1]}")])

        return " ".join(parts)
