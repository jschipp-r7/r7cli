"""Custom Click group that hints when global flags are used after subcommands."""
from __future__ import annotations

import click

# Global flags that must appear before the solution/subcommand
GLOBAL_VALUE_FLAGS = {
    "-r", "--region",
    "-k", "--api-key",
    "-o", "--output",
    "-l", "--limit",
    "-t", "--timeout",
    "--drp-token",
    "--search-fields",
}

GLOBAL_BOOLEAN_FLAGS = {
    "-v", "--verbose",
    "-c", "--cache",
    "-s", "--short",
    "--debug",
}

GLOBAL_FLAGS = GLOBAL_VALUE_FLAGS | GLOBAL_BOOLEAN_FLAGS


class GlobalFlagHintGroup(click.Group):
    """Click Group that gives a helpful error when global flags are used
    after a subcommand instead of before it."""

    def __init__(self, *args, **kwargs):
        # Ensure -h works as --help on all subcommand groups
        context_settings = kwargs.get("context_settings", {})
        context_settings.setdefault("help_option_names", ["-h", "--help"])
        kwargs["context_settings"] = context_settings
        super().__init__(*args, **kwargs)

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        for arg in args:
            flag = arg.split("=")[0] if "=" in arg else arg
            if flag in GLOBAL_FLAGS:
                val_hint = " <value>" if flag in GLOBAL_VALUE_FLAGS else ""
                click.echo(
                    f"Error: '{flag}' is a global option and must appear "
                    f"before the subcommand.\n\n"
                    f"  r7-cli [GLOBAL OPTIONS] SOLUTION SUBCOMMAND ...\n\n"
                    f"Example:\n"
                    f"  r7-cli {flag}{val_hint} vm engines list",
                    err=True,
                )
                ctx.exit(1)
        return super().parse_args(ctx, args)
