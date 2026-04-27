"""Logging configuration for r7-cli.

Provides a pre-configured logger that writes to stderr with credential
redaction.  Log level is controlled by the ``--verbose`` and ``--debug``
CLI flags:

- Default: WARNING (only warnings and errors)
- ``--verbose``: INFO (request/response summaries)
- ``--debug``: DEBUG (full request/response bodies, curl commands)

All output goes to stderr so it never pollutes structured data on stdout.
"""
from __future__ import annotations

import logging
import re
import sys


_LOG_NAME = "r7cli"

logger: logging.Logger = logging.getLogger(_LOG_NAME)


class _RedactingFormatter(logging.Formatter):
    """Formatter that strips credential values from log messages."""

    _pattern: re.Pattern[str] | None = None

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if self._pattern is not None:
            msg = self._pattern.sub("[REDACTED]", msg)
        return msg


_formatter = _RedactingFormatter("%(message)s")
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(_formatter)
logger.addHandler(_handler)
logger.setLevel(logging.WARNING)  # default until configure_logging() is called


def configure_logging(
    *,
    verbose: bool = False,
    debug: bool = False,
    api_key: str = "",
    drp_token: str = "",
) -> None:
    """Set the log level and credential redaction pattern.

    Called once during CLI startup after config resolution.

    Parameters
    ----------
    verbose:
        If True, set level to INFO.
    debug:
        If True, set level to DEBUG (overrides verbose).
    api_key:
        API key value to redact from all log output.
    drp_token:
        DRP token value to redact from all log output.
    """
    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    # Build redaction pattern from credential values
    literals: list[str] = []
    if api_key:
        literals.append(re.escape(api_key))
    if drp_token:
        literals.append(re.escape(drp_token))
    if literals:
        _formatter._pattern = re.compile("|".join(literals))
    else:
        _formatter._pattern = None
