# Tech Stack & Build

## Language & Runtime
- Python 3.10+
- Package: `r7-cli` (installed as `r7cli` namespace)

## Build System
- setuptools + wheel (`pyproject.toml`)
- Editable install: `pip install -e .`
- Dev install: `pip install -e ".[dev]"`

## Core Dependencies
- `click` — CLI framework (groups, commands, options, context passing)
- `httpx` — Synchronous HTTP client
- `tabulate` — Table output formatting
- `pyarrow` — Parquet file reading/writing for bulk exports
- `questionary` — Interactive terminal prompts for `--auto` selection

## Dev Dependencies
- `pytest` — Test runner
- `hypothesis` — Property-based testing

## Entry Point
- CLI entry: `r7-cli` → `r7cli.main:cli`
- The workspace root IS the `r7cli` package (via `tool.setuptools.package-dir`)

## Common Commands
```bash
# Install
pip install -e ".[dev]"

# Run tests
pytest

# Run CLI
r7-cli --help
r7-cli <solution> <subcommand> [options]
```

## Key Patterns
- All HTTP goes through `R7Client` (`client.py`) which handles auth, caching, logging, rate-limits, and error mapping
- Config resolution: CLI flag → env var → default (`config.py`)
- Output formatting is centralized in `output.py` via `format_output()`
- Response caching lives in `~/.r7-cli/cache/` as SHA-256-keyed JSON files
- Job persistence in `~/.r7-cli/jobs.json`
- Custom Click group `GlobalFlagHintGroup` enforces global flags before subcommands
- `SolutionGroup` in `main.py` lazily imports solution modules
- Error hierarchy: `R7Error` → `UserInputError` (exit 1), `APIError` (exit 2), `NetworkError` (exit 3)
- Tests use Hypothesis property-based testing with `@given` decorators
- CIS/NIST CSF controls loaded from `controls.csv` (bundled as package data) by `cis.py`
- Per-solution `cis` subcommand registered via `cis.make_cis_command()` in each solution module
- `compliance` is a Click group (`invoke_without_command=True`): bare invocation runs export, `list` subcommand queries controls
