# Requirements Document

## Introduction

Add a `siem agents list` subcommand to r7-cli that queries the Rapid7 InsightIDR GraphQL API to list agents with their host information, NGAV (endpoint prevention) status, and velociraptor bootstrap status. The command resolves the organization ID automatically by matching the configured region against the platform orgs API, then uses cursor-based pagination to fetch agent data from the GraphQL endpoint.

## Glossary

- **CLI**: The r7-cli Click-based command-line tool
- **Agents_List_Command**: The `siem agents list` Click command that fetches and displays agent data
- **GraphQL_Client**: The component that sends GraphQL queries to the IDR GQL endpoint via R7Client
- **Org_Resolver**: The component that determines the organization ID by calling the platform orgs API and matching on region
- **NGAV_Status**: The `endpointPrevention.status.health` field representing the endpoint prevention health state of an agent
- **Velociraptor_Status**: The state of the velociraptor bootstrap component, derived from the `bootstrap.components` array where `name` equals `"velociraptor"`
- **Cursor_Paginator**: The component that handles cursor-based pagination using `pageInfo.endCursor` and `pageInfo.hasNextPage` from the GraphQL response
- **Agent_Record**: A flattened dictionary representing a single agent with fields extracted from the nested GraphQL response

## Requirements

### Requirement 1: Organization ID Resolution

**User Story:** As a CLI user, I want the command to automatically resolve my organization ID from the configured region, so that I do not need to provide it manually.

#### Acceptance Criteria

1. WHEN the `siem agents list` command is invoked, THE Org_Resolver SHALL call the platform orgs API (GET `ACCOUNT_BASE/organizations`) to retrieve the list of organizations
2. WHEN the orgs API returns a list of organizations, THE Org_Resolver SHALL match the organization whose `region` field equals the configured region, applying `us1` to `us` normalization via REGION_ALIASES
3. WHEN a matching organization is found, THE Org_Resolver SHALL use that organization's `id` field as the organization ID in the GraphQL query
4. IF no organization matches the configured region, THEN THE Org_Resolver SHALL raise a UserInputError with a message indicating no organization was found for the region

### Requirement 2: GraphQL Agent Query

**User Story:** As a CLI user, I want to query agent data from the InsightIDR GraphQL API, so that I can see agent status, host info, NGAV status, and velociraptor status.

#### Acceptance Criteria

1. WHEN the organization ID is resolved, THE GraphQL_Client SHALL send a POST request to the IDR_GQL endpoint with the agent query containing the organization ID and the requested limit
2. THE GraphQL_Client SHALL include the `agent`, `host`, `publicIpAddress`, `sysArch`, `endpointPrevention`, and `bootstrap` fields in the query
3. WHEN the GraphQL API returns a successful response, THE Agents_List_Command SHALL extract agent records from `data.organization.assets.edges`
4. WHEN the GraphQL API returns a response containing an `errors` array, THE Agents_List_Command SHALL raise an APIError with the first error message from the array
5. IF the GraphQL API returns a non-2xx HTTP status code, THEN THE GraphQL_Client SHALL raise an APIError with the status code and response body

### Requirement 3: Cursor-Based Pagination

**User Story:** As a CLI user, I want to paginate through large result sets, so that I can retrieve all agents beyond the per-page limit.

#### Acceptance Criteria

1. WHEN `--all-pages` is specified, THE Cursor_Paginator SHALL check `pageInfo.hasNextPage` after each response
2. WHILE `pageInfo.hasNextPage` is true, THE Cursor_Paginator SHALL send a subsequent query using `pageInfo.endCursor` as the `after` argument in the `assets` field
3. WHEN `--all-pages` is specified, THE Cursor_Paginator SHALL accumulate all edges from every page into a single result list
4. WHEN `--all-pages` is not specified, THE Agents_List_Command SHALL return only the first page of results

### Requirement 4: Limit Option

**User Story:** As a CLI user, I want to control how many agents are returned per page, so that I can manage response size.

#### Acceptance Criteria

1. THE Agents_List_Command SHALL accept a `--limit` / `-l` option of type integer with a default value of 10
2. WHEN `--limit` is provided, THE GraphQL_Client SHALL use the limit value as the `first` argument in the `assets(first: N)` field of the GraphQL query

### Requirement 5: Auto-Poll Mode

**User Story:** As a CLI user, I want to continuously poll for new agents, so that I can monitor newly appearing assets.

#### Acceptance Criteria

1. THE Agents_List_Command SHALL accept an `--auto` / `-a` flag
2. WHEN `--auto` is specified, THE Agents_List_Command SHALL repeatedly query the GraphQL API at a regular interval
3. WHILE polling, THE Agents_List_Command SHALL track previously seen agent IDs and only output newly discovered agents
4. WHEN the user sends a keyboard interrupt (Ctrl+C), THE Agents_List_Command SHALL stop polling and print a "Stopped polling." message to stderr

### Requirement 6: NGAV Status Filter

**User Story:** As a CLI user, I want to filter agents by their NGAV health status, so that I can focus on agents with specific endpoint prevention states.

#### Acceptance Criteria

1. THE Agents_List_Command SHALL accept an `--ngav-status` option of type string
2. WHEN `--ngav-status` is provided, THE Agents_List_Command SHALL include only agents whose `endpointPrevention.status.health` value matches the provided value (case-sensitive)
3. THE Agents_List_Command SHALL accept the following valid values for `--ngav-status`: `GOOD`, `POOR`, `N/A`, `Not Monitored`

### Requirement 7: Velociraptor Status Filter

**User Story:** As a CLI user, I want to filter agents by their velociraptor component state, so that I can identify agents where velociraptor is or is not running.

#### Acceptance Criteria

1. THE Agents_List_Command SHALL accept a `--velociraptor-status` option of type string
2. WHEN `--velociraptor-status` is `RUNNING`, THE Agents_List_Command SHALL include only agents that have a bootstrap component with `name` equal to `"velociraptor"` and `state` equal to `"RUNNING"`
3. WHEN `--velociraptor-status` is `NOT_RUNNING`, THE Agents_List_Command SHALL include only agents whose velociraptor bootstrap component has a `state` value not equal to `"RUNNING"`, or agents that have no velociraptor bootstrap component

### Requirement 8: Output Formatting

**User Story:** As a CLI user, I want the agent data formatted consistently with other r7-cli commands, so that I can use familiar output options.

#### Acceptance Criteria

1. THE Agents_List_Command SHALL flatten each agent node into a single-level dictionary (Agent_Record) with key fields from the nested GraphQL response
2. THE Agents_List_Command SHALL pass the result list to the `format_output()` function, respecting the global `-o`/`--output`, `-s`/`--short`, `--limit`, and `--search-fields` flags
3. WHEN the result set is empty, THE Agents_List_Command SHALL output an empty list in the configured format

### Requirement 9: Error Handling

**User Story:** As a CLI user, I want clear error messages when something goes wrong, so that I can diagnose and fix issues.

#### Acceptance Criteria

1. IF a network error occurs during the GraphQL request, THEN THE Agents_List_Command SHALL catch the NetworkError and print the error message to stderr with exit code 3
2. IF the orgs API or GraphQL API returns an authentication error (HTTP 401), THEN THE Agents_List_Command SHALL print a message about the invalid or missing API key to stderr with exit code 2
3. IF the GraphQL response contains an `errors` array, THEN THE Agents_List_Command SHALL print the first error message to stderr with exit code 2
4. THE Agents_List_Command SHALL catch all R7Error exceptions and print the error message to stderr, exiting with the exception's exit code

### Requirement 10: Command Registration

**User Story:** As a CLI user, I want to invoke the command as `r7-cli siem agents list`, so that it follows the existing CLI hierarchy.

#### Acceptance Criteria

1. THE CLI SHALL register an `agents` Click group under the existing `siem` group
2. THE CLI SHALL register a `list` command under the `agents` group
3. WHEN `r7-cli siem agents list` is invoked with `--help`, THE Agents_List_Command SHALL display usage information including all available options


## Post-Implementation Changes

- Command moved from `r7-cli siem agents list` to also be available as `r7-cli platform assets list` (via `agents.py`)
- GQL query simplified: removed host, endpointPrevention, bootstrap fields; now uses agent (id, agentStatus, agentSemanticVersion, deployTime, agentLastUpdateTime), publicIpAddress, platform
- `--ngav-status` and `--velociraptor-status` filters removed
- `-l/--limit` renamed to `--size` to avoid conflict with global `-l`
- `assets count` subcommand added with `--vm`, `--siem`, `--asm`, `--appsec`, `--drp` options
- Org ID resolution via `_resolve_org_id` helper
