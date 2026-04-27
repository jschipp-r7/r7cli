"""Stub solution groups for not-yet-implemented solutions (cnapp, asm, appsec)."""
from __future__ import annotations

import click


def create_stub_group(solution_name: str) -> click.Group:
    """Create a Click group that prints a stub message and exits 0."""

    @click.group(name=solution_name, invoke_without_command=True)
    @click.pass_context
    def stub(ctx):
        if ctx.invoked_subcommand is None:
            click.echo(f"No commands are currently available for {solution_name}.")

    return stub
