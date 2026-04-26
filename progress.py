"""ANSI progress bar utilities for r7-cli.

All progress output goes to stderr so it never pollutes structured data on stdout.
"""
from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager

import click


def progress_bar(
    progress: float,
    label: str = "",
    width: int = 30,
) -> None:
    """Print an ANSI progress bar that overwrites the current line on stderr.

    Args:
        progress: Float between 0.0 and 1.0 (clamped).
        label: Status text to show after the bar.
        width: Character width of the bar (default 30).
    """
    progress = max(0.0, min(1.0, progress))
    filled = int(width * progress)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(progress * 100)
    # Truncate label to keep line reasonable
    max_label = 40
    if len(label) > max_label:
        label = label[: max_label - 1] + "…"
    line = f"\r  [{bar}] {pct:3d}% {label}"
    click.echo(line, nl=False, err=True)


def progress_done(message: str = "") -> None:
    """Clear the progress bar line and optionally print a completion message to stderr."""
    # Overwrite the bar line with spaces, then print message
    click.echo("\r" + " " * 80 + "\r", nl=False, err=True)
    if message:
        click.echo(f"  {message}", err=True)


def progress_pages(current: int, total: int | None, records: int) -> None:
    """Show pagination progress on stderr.

    When *total* is known, displays a filling bar. Otherwise shows an
    indeterminate counter.
    """
    if total is not None and total > 0:
        frac = min(current / total, 1.0)
        progress_bar(frac, f"page {current}/{total} ({records} records)")
    else:
        # Indeterminate — just show page count
        progress_bar(0.0, f"page {current} ({records} records)")


def progress_download(current: int, total: int, filename: str = "") -> None:
    """Show file download progress on stderr."""
    if total > 0:
        frac = current / total
        label = f"file {current}/{total}"
        if filename:
            # Show just the basename
            short = filename.rsplit("/", 1)[-1] if "/" in filename else filename
            if len(short) > 20:
                short = short[:19] + "…"
            label += f" {short}"
        progress_bar(frac, label)


@contextmanager
def spinner(label: str = "Working"):
    """Context manager that shows an animated spinner on stderr while blocking.

    Usage:
        with spinner("Downloading"):
            slow_blocking_call()

    The spinner runs in a daemon thread and is cleaned up when the block exits.
    """
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    stop_event = threading.Event()

    def _spin():
        idx = 0
        while not stop_event.is_set():
            frame = frames[idx % len(frames)]
            click.echo(f"\r  {frame} {label}…", nl=False, err=True)
            idx += 1
            stop_event.wait(0.1)

    t = threading.Thread(target=_spin, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop_event.set()
        t.join(timeout=1.0)
        # Clear the spinner line
        click.echo("\r" + " " * (len(label) + 10) + "\r", nl=False, err=True)
