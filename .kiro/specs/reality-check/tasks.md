# Implementation Plan: reality-check

## Overview

Extend the `matrix rapid7` command in `security_checklist.py` with a `--reality` / `--deployment` flag that queries Rapid7 deployment APIs, reduces cell percentages for missing infrastructure components, and prints action items. All changes are in `security_checklist.py` — no new modules needed.

## Tasks

- [x] 1. Add static data constants and pure reduction functions
  - [x] 1.1 Add the `REDUCTION_RULES` table and `ACTION_ITEM_MESSAGES` dict to `security_checklist.py`
    - Define `REDUCTION_RULES` as a list of `(component_key, product, stage_scope, reduction)` tuples per the design
    - Define `ACTION_ITEM_MESSAGES` dict mapping component keys to exact message strings
    - _Requirements: 7.1, 8.1, 9.1, 10.1, 11.1, 13.2, 13.3, 13.4, 13.5, 13.6_

  - [x] 1.2 Implement `compute_reductions(status: dict[str, bool]) -> list[tuple[str, str | None, int]]`
    - Iterate `REDUCTION_RULES`, include rule only when `status[component_key]` is False
    - Return list of `(product, stage_scope, reduction_percent)` tuples
    - _Requirements: 7.1, 8.1, 9.1, 10.1, 11.1_

  - [x] 1.3 Implement `apply_reductions(mapping, reductions) -> adjusted_mapping`
    - Deep-copy the input mapping
    - For each cell, sum applicable reductions per product (match product name and stage scope)
    - Subtract total reduction from each product's percentage, clamp to `max(0, ...)`
    - Return the new mapping
    - _Requirements: 7.2, 8.2, 9.2, 10.2, 11.2, 12.1, 12.2_

  - [ ]* 1.4 Write property test for reduction correctness (Property 1)
    - **Property 1: Reduction Correctness**
    - Generate random deployment status dicts (5 booleans) via Hypothesis
    - For each cell and product, verify adjusted percentage equals `max(0, original - sum_of_applicable_reductions)`
    - **Validates: Requirements 7.1, 7.2, 8.1, 8.2, 9.1, 9.2, 10.1, 10.2, 11.1, 11.2, 12.1**

  - [ ]* 1.5 Write property test for product contribution floor (Property 2)
    - **Property 2: Product Contribution Floor**
    - Generate random mapping-shaped dicts with percentages 0–200 and random deployment statuses
    - Verify every product percentage in the result is >= 0
    - **Validates: Requirements 12.2**

- [x] 2. Implement `build_action_items` and cell total bounds
  - [x] 2.1 Implement `build_action_items(status: dict[str, bool]) -> str`
    - If all values are True, return empty string
    - Otherwise return "Action Items to Improve Coverage:" header followed by one line per missing component using `ACTION_ITEM_MESSAGES`
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7_

  - [ ]* 2.2 Write property test for action items completeness (Property 4)
    - **Property 4: Action Items Completeness**
    - Generate random deployment status dicts
    - Verify each missing component has exactly one action item line, present components have none, all-True produces empty string
    - **Validates: Requirements 13.1, 13.7**

  - [x] 2.3 Modify `build_matrix` to accept optional `adjusted_mapping` parameter
    - Add `adjusted_mapping` keyword argument defaulting to `None`
    - When `adjusted_mapping` is provided and `percent=True`, use it instead of `CELL_PERCENT_MAPPING`
    - Existing behavior unchanged when `adjusted_mapping` is None
    - _Requirements: 14.1_

  - [ ]* 2.4 Write property test for cell total bounds (Property 3)
    - **Property 3: Cell Total Bounds**
    - Generate random adjusted mappings and random licensed product sets
    - Call `evaluate_cell_percent` for every cell and verify result is in [0, 100] or "N/A"
    - **Validates: Requirements 12.3**

- [x] 3. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement deployment checks and wire into the CLI command
  - [x] 4.1 Implement `check_deployments(client, config) -> dict[str, bool]`
    - Query `GET {IVM_V4_BASE}/integration/scan/engine` — count items in `data` array, True if > 0
    - Query `GET {IDR_V1_BASE}/health-metrics` with `resourceTypes` param for each of: `collectors`, `network_sensors`, `honeypots`, `orchestrator`
    - Wrap each call in try/except for `R7Error`, log warning to stderr, default to False on failure
    - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 5.1, 5.2, 5.3, 6.1, 6.2, 6.3_

  - [x] 4.2 Register `--reality` / `--deployment` flag on the `rapid7` command
    - Add `--reality/--no-reality` and `--deployment/--no-deployment` as Click flag aliases for a single `reality` boolean parameter
    - Add mutual exclusivity check: `--reality` + `--solution` → error to stderr, exit 1
    - When `reality` is True and `percent` is False, implicitly set `percent = True`
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

  - [x] 4.3 Wire the full pipeline in the `rapid7` command handler
    - When `reality` is True: call `check_deployments`, `compute_reductions`, `apply_reductions`, pass `adjusted_mapping` to `build_matrix`
    - Print deployment-adjusted header to stderr
    - After rendering the matrix, call `build_action_items` and print to stderr if non-empty
    - Ensure `build_recommendations` still runs with the adjusted context
    - _Requirements: 14.1, 14.2, 13.1_

  - [ ]* 4.4 Write unit tests for CLI flag behavior and full pipeline
    - Test `--reality` flag is recognized
    - Test `--deployment` behaves identically to `--reality`
    - Test `--reality` without `--percent` implicitly enables percent mode
    - Test `--reality` + `--solution` produces mutual exclusivity error
    - Test full pipeline with mocked APIs: all deployed → matches standard `--percent` output
    - Test full pipeline with mocked APIs: all missing → maximum reductions applied
    - Test API failure → warning logged, component treated as missing
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.3, 3.3, 4.3, 5.3, 6.3_

- [x] 5. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- All changes are confined to `security_checklist.py` — no new modules
- Property tests use Hypothesis (already in dev dependencies)
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
