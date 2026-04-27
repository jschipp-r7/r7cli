"""Config resolution for r7-cli.

Priority order: CLI flag → environment variable → default value.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from r7cli.models import (
    REGION_ALIASES,
    VALID_OUTPUT_FORMATS,
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
    search: Optional[str]  # field name to search for in JSON responses
    short: bool  # compact single-line output mode
    llm_provider: str  # "openai" | "claude" | "gemini" | ""
    llm_api_key: str  # API key for the chosen LLM provider


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
    search: Optional[str] = None,
    short: bool = False,
    llm_provider_flag: Optional[str] = None,
    llm_api_key_flag: Optional[str] = None,
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

    # --- validate output format ---
    if output_format not in VALID_OUTPUT_FORMATS:
        supported = ", ".join(sorted(VALID_OUTPUT_FORMATS))
        raise UserInputError(
            f"Unsupported output format '{output_format}'. Supported formats: {supported}"
        )

    # --- LLM provider: flag → env → "" ---
    llm_provider = llm_provider_flag or os.environ.get("R7_LLM_PROVIDER") or ""
    llm_provider = llm_provider.lower()
    if llm_provider and llm_provider not in ("openai", "claude", "gemini"):
        raise UserInputError(
            f"Unsupported LLM provider '{llm_provider}'. "
            f"Supported: openai, claude, gemini"
        )

    # --- LLM API key: flag → provider-specific env → generic env → "" ---
    llm_api_key = llm_api_key_flag or ""
    if not llm_api_key:
        if llm_provider == "openai":
            llm_api_key = os.environ.get("OPENAI_API_KEY") or ""
        elif llm_provider == "claude":
            llm_api_key = os.environ.get("ANTHROPIC_API_KEY") or ""
        elif llm_provider == "gemini":
            llm_api_key = os.environ.get("GEMINI_API_KEY") or ""
        if not llm_api_key:
            llm_api_key = os.environ.get("R7_LLM_API_KEY") or ""

    return Config(
        region=region,
        api_key=api_key,
        drp_token=drp_token,
        verbose=verbose,
        debug=debug,
        output_format=output_format,
        use_cache=use_cache,
        limit=limit,
        timeout=timeout,
        search=search,
        short=short,
        llm_provider=llm_provider,
        llm_api_key=llm_api_key,
    )
