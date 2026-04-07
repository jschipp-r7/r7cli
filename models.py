"""Shared constants, dataclasses, and exception hierarchy for r7-cli."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Regions
# ---------------------------------------------------------------------------
VALID_REGIONS: frozenset[str] = frozenset({
    "us", "us2", "us3", "ca", "eu", "au", "ap", "me-central-1", "ap-south-2",
})
REGION_ALIASES: dict[str, str] = {"us1": "us"}

# ---------------------------------------------------------------------------
# Solutions
# ---------------------------------------------------------------------------
VALID_SOLUTIONS: frozenset[str] = frozenset({
    "siem", "vm", "cnapp", "asm", "appsec", "drp", "platform", "soar",
})
STUB_SOLUTIONS: frozenset[str] = frozenset()

# ---------------------------------------------------------------------------
# Output / search
# ---------------------------------------------------------------------------
VALID_OUTPUT_FORMATS: frozenset[str] = frozenset({"json", "table", "csv", "tsv", "sql"})
VALID_SEARCH_TYPES: frozenset[str] = frozenset({
    "VULNERABILITY", "ASSET", "SCAN", "SCHEDULE", "APP",
})

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
EXIT_SUCCESS = 0
EXIT_USER_ERROR = 1
EXIT_API_ERROR = 2
EXIT_NETWORK_ERROR = 3

# ---------------------------------------------------------------------------
# Base URLs (templates — format with region)
# ---------------------------------------------------------------------------
INSIGHT_BASE = "https://{region}.api.insight.rapid7.com"
IVM_BULK_GQL = "https://{region}.api.insight.rapid7.com/export/graphql"
IVM_V4_BASE = "https://{region}.api.insight.rapid7.com/vm/v4"
IDR_V1_BASE = "https://{region}.api.insight.rapid7.com/idr/v1"
IDR_LOGS_BASE = "https://{region}.rest.logs.insight.rapid7.com"
IDR_GQL = "https://{region}.api.insight.rapid7.com/graphql"
SC_BASE = "https://{region}.api.insight.rapid7.com/surface"
DRP_BASE = "https://api.ti.insight.rapid7.com"
IAS_V1_BASE = "https://{region}.api.insight.rapid7.com/ias/v1"
ACCOUNT_BASE = "https://{region}.api.insight.rapid7.com/account/api/1"
CREDMGMT_BASE = "https://{region}.api.insight.rapid7.com/credential-management/v1"
CONNECT_V1_BASE = "https://{region}.api.insight.rapid7.com/connect/v1"
CONNECT_V2_BASE = "https://{region}.api.insight.rapid7.com/connect/v2"
CLOUDSEC_V4_BASE = "https://{insightcloudsec_url}/v4"

# ---------------------------------------------------------------------------
# GraphQL strings
# ---------------------------------------------------------------------------
GQL_CREATE_VULN_EXPORT = (
    '{"query": "mutation CreateVulnerabilityExport '
    '{ createVulnerabilityExport(input:{}) {id}}"}'
)

GQL_CREATE_POLICY_EXPORT = (
    '{"query": "mutation CreatePolicyExport '
    '{ createPolicyExport(input:{}) {id}}"}'
)

GQL_GET_EXPORT = (
    'query GetExport($id: String!) '
    '{ export(id: $id) { id status dataset timestamp result { prefix urls } } }'
)

GQL_QUARANTINE_STATE = """
query QuarantineState($cursor: String) {
  organization {
    assets(first: 10000, after: $cursor) {
      pageInfo { endCursor hasNextPage }
      edges {
        node {
          agent {
            id agentStatus
            quarantineState { currentState }
            beaconTime agentLastUpdateTime
          }
          host {
            hostNames { name }
            primaryAddress { ip mac }
            alternateAddresses { ip mac }
          }
        }
        cursor
      }
    }
  }
}
"""

GQL_AGENTS_LIST = """
query AgentsList($orgId: String!, $first: Int!, $cursor: String) {
  organization(id: $orgId) {
    assets(first: $first, after: $cursor) {
      pageInfo { endCursor hasNextPage }
      edges {
        node {
          agent {
            id agentStatus
            quarantineState { currentState }
            beaconTime agentLastUpdateTime
          }
          host {
            hostNames { name }
            primaryAddress { ip mac }
            alternateAddresses { ip mac }
          }
        }
        cursor
      }
    }
  }
}
"""

GQL_SC_LIST_QUERIES = (
    '{"query": "MATCH (m:`sys.cypher-query`) RETURN m"}'
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class R7Error(Exception):
    """Base exception — carries an exit code."""
    exit_code: int = EXIT_USER_ERROR

    def __init__(self, message: str, exit_code: Optional[int] = None) -> None:
        super().__init__(message)
        if exit_code is not None:
            self.exit_code = exit_code


class UserInputError(R7Error):
    """Bad flag, missing argument, invalid value — exit 1."""
    exit_code = EXIT_USER_ERROR


class APIError(R7Error):
    """HTTP 4xx/5xx or API-level error — exit 2."""
    exit_code = EXIT_API_ERROR

    def __init__(
        self,
        message: str,
        status_code: int = 0,
        body: str = "",
    ) -> None:
        super().__init__(message, EXIT_API_ERROR)
        self.status_code = status_code
        self.body = body


class NetworkError(R7Error):
    """Connection refused, timeout, DNS failure — exit 3."""
    exit_code = EXIT_NETWORK_ERROR


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class JobEntry:
    job_id: str
    export_type: str        # "vulnerabilities" | "policies" | "remediations"
    created_at: str         # ISO-8601 timestamp
    status: str = "ACTIVE"  # "ACTIVE" | "SUCCEEDED" | "FAILED"
