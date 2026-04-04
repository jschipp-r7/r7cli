"""Config resolution for r7-cli.

Priority order: CLI flag → environment variable → default value.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from r7cli.models import (
    REGION_ALIASES,
    VALID_REGIONS,
    UserInputError,
)


@dataclass
class Config:
    """Resolved runtime configuration."""

    region: str
    api_key: str
    drp_token: str
    verbose: bool
    debug: bool
    output_format: str  # "json" | "table" | "csv"
    use_cache: bool
    limit: Optional[int]
    timeout: int  # seconds, default 30


def resolve_config(
    *,
    region_flag: Optional[str] = None,
    api_key_flag: Optional[str] = None,
    drp_token_flag: Optional[str] = None,
    verbose: bool = False,
    debug: bool = False,
    output_format: str = "json",
    use_cache: bool = False,
    limit: Optional[int] = None,
    timeout: int = 30,
) -> Config:
    """Build a :class:`Config` by merging flags, env vars, and defaults.

    Raises :class:`UserInputError` when the resolved region is not in
    :data:`VALID_REGIONS`.

    Does **not** raise for a missing API key — that check is deferred to
    individual commands that require it.
    """

    # --- region: flag → env → default "us" ---
    region = region_flag or os.environ.get("R7_REGION") or "us"
    region = REGION_ALIASES.get(region, region)

    if region not in VALID_REGIONS:
        supported = ", ".join(sorted(VALID_REGIONS))
        raise UserInputError(
            f"Invalid region '{region}'. Supported regions: {supported}"
        )

    # --- api_key: flag → env → None (validation deferred to per-command) ---
    api_key = api_key_flag or os.environ.get("R7_X_API_KEY") or ""

    # --- drp_token: flag → env (not required globally) ---
    drp_token = drp_token_flag or os.environ.get("R7_DRP_TOKEN") or ""

    return Config(
        region=region,
        api_key=api_key,
        drp_token=drp_token,
        verbose=verbose,
        debug=debug,
        output_format=output_format,
        use_cache=use_cache,
        limit=limit,
    )
