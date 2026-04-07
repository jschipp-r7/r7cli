# Implementation Plan: siem-agents-list

## Overview

Implement the `siem agents list` command by adding the GQL query string to `models.py`, then building the org resolver, node flattener, filters, pagination, auto-poll, and CLI wiring in `solutions/siem.py`. Each task builds incrementally on the previous one, ending with full integration.

## Tasks

- [x] 1. Add GQL_AGENTS_LIST query string to models.py
  - Add the `GQL_AGENTS_LIST` GraphQL query string constant alongside `GQL_QUARANTINE_STATE`
  - Include all required fields: `agent`, `host`, `publicIpAddress`, `sysArch`, `endpointPrevention`, `bootstrap`
  - Include `pageInfo { endCursor hasNextPage }` for cursor pagination
  - Use `$orgId: String!`, `$first: Int!`, `$cursor: String` as query variables
  - _Requirements: 2.1, 2.2_

- [x] 2. Implement org resolver and agent node flattener
  - [x] 2.1 Implement `_resolve_org_id(client, config)` in `solutions/siem.py`
    - Call `GET ACCOUNT_BASE.format(region=config.region) + "/organizations"`
    - Iterate orgs, normalize each org's `region` via `REGION_ALIASES`
    - Return the `id` of the first org whose normalized region matches `config.region`
    - Raise `UserInputError` if no match found
    - Import `ACCOUNT_BASE` and `REGION_ALIASES` from `models.py`
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

  - [ ]* 2.2 Write property test for org resolution matching (Property 1)
    - **Property 1: Org resolution matches correct organization with region normalization**
    - **Validates: Requirements 1.2, 1.3**

  - [ ]* 2.3 Write property test for org resolution error (Property 2)
    - **Property 2: Org resolution raises error when no organization matches**
    - **Validates: Requirements 1.4**

  - [x] 2.4 Implement `_flatten_agent_node(node)` in `solutions/siem.py`
    - Convert nested GQL node into flat `Agent_Record` dict with all fields from the design
    - Extract velociraptor state/version from `bootstrap.components` where `name == "velociraptor"`
    - Use safe `.get()` chains for nullable fields
    - _Requirements: 2.3, 8.1_

  - [ ]* 2.5 Write property test for node flattening (Property 4)
    - **Property 4: Agent node flattening preserves all source data**
    - **Validates: Requirements 2.3, 8.1**

- [x] 3. Implement agent filters
  - [x] 3.1 Implement `_apply_agent_filters(records, ngav_status, velociraptor_status)` in `solutions/siem.py`
    - If `ngav_status` is set: keep only records where `ngav_status` matches (case-sensitive)
    - If `velociraptor_status` is `RUNNING`: keep only records where `velociraptor_state == "RUNNING"`
    - If `velociraptor_status` is `NOT_RUNNING`: keep records where `velociraptor_state != "RUNNING"` (including `None`)
    - _Requirements: 6.1, 6.2, 6.3, 7.1, 7.2, 7.3_

  - [ ]* 3.2 Write property test for NGAV status filter (Property 5)
    - **Property 5: NGAV status filter retains only matching agents**
    - **Validates: Requirements 6.2**

  - [ ]* 3.3 Write property test for velociraptor status filter (Property 6)
    - **Property 6: Velociraptor status filter correctly partitions agents**
    - **Validates: Requirements 7.2, 7.3**

- [x] 4. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement the `agents` group and `list` command with pagination and auto-poll
  - [x] 5.1 Register the `agents` Click group under `siem` and the `list` command under `agents`
    - Add `@siem.group("agents")` and `@agents.command("list")` with all CLI options: `--limit`, `--all-pages`, `--auto`, `--interval`, `--ngav-status`, `--velociraptor-status`
    - Follow the existing pattern from `quarantine_state` and `health_metrics` commands
    - _Requirements: 10.1, 10.2, 10.3, 4.1, 4.2_

  - [x] 5.2 Implement single-page and `--all-pages` cursor pagination in the `list` command body
    - Resolve org ID via `_resolve_org_id`
    - Build and send GQL query to `IDR_GQL` with org ID and limit
    - Check for GQL `errors` array before processing — raise `APIError` with first error message
    - Extract edges, flatten nodes via `_flatten_agent_node`, apply filters via `_apply_agent_filters`
    - When `--all-pages`: loop while `hasNextPage`, passing `endCursor` as cursor
    - When not `--all-pages`: return only first page
    - Output via `format_output()` respecting global flags
    - _Requirements: 2.1, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 8.2, 8.3_

  - [x] 5.3 Implement `--auto` polling loop with deduplication
    - Track seen agent IDs across polls
    - Only output newly discovered agents on each poll cycle
    - Sleep for `--interval` seconds between polls
    - Catch `KeyboardInterrupt` and print "Stopped polling." to stderr
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [ ]* 5.4 Write property test for cursor pagination accumulation (Property 3)
    - **Property 3: Cursor pagination accumulates all edges across pages**
    - **Validates: Requirements 3.1, 3.2, 3.3**

  - [ ]* 5.5 Write property test for auto-poll deduplication (Property 7)
    - **Property 7: Auto-poll deduplication emits only new agents**
    - **Validates: Requirements 5.3**

  - [ ]* 5.6 Write property test for GQL error response extraction (Property 8)
    - **Property 8: GraphQL error response extraction**
    - **Validates: Requirements 2.4, 9.3**

- [x] 6. Wire error handling and add the `agents` group import to `siem` module
  - Wrap the command body in `try/except R7Error` and `except KeyboardInterrupt`, matching existing command patterns
  - Ensure `NetworkError` exits with code 3, `APIError` exits with code 2, `UserInputError` exits with code 1
  - Verify the `agents` group is importable and registered under `siem`
  - _Requirements: 9.1, 9.2, 9.3, 9.4_

- [x] 7. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Property tests use Hypothesis with `@settings(max_examples=100)`
- All code goes in `solutions/siem.py` and `models.py` — no new files needed
