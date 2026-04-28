"""Developer information commands — API registry and introspection.

Provides ``r7-cli dev api list`` to enumerate all API endpoints used by the CLI,
filterable by solution and HTTP method, with optional curl examples.
"""
from __future__ import annotations

import json
from typing import Any

import click

from r7cli.cli_group import GlobalFlagHintGroup
from r7cli.output import format_output


# ---------------------------------------------------------------------------
# API Registry — every API call the CLI makes
# ---------------------------------------------------------------------------

_API_REGISTRY: list[dict[str, str]] = [
    # -- Platform --
    {"solution": "platform", "method": "GET",    "endpoint": "/validate",                                "subcommand": "validate",           "description": "Validate API key"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/products",                  "subcommand": "products-list",      "description": "List licensed products"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/products/{product_token}",  "subcommand": "products-get",       "description": "Get product by token"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/users",                     "subcommand": "users-list",         "description": "List users"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/users/{user_id}",           "subcommand": "users-get",          "description": "Get user by ID"},
    {"solution": "platform", "method": "POST",   "endpoint": "/account/api/1/users",                     "subcommand": "users-create",       "description": "Create a user"},
    {"solution": "platform", "method": "DELETE", "endpoint": "/account/api/1/users/{user_id}",           "subcommand": "users-delete",       "description": "Delete a user"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/organizations",             "subcommand": "orgs-list",          "description": "List organizations"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/managed-organizations",     "subcommand": "orgs-managed",       "description": "List managed organizations"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/roles",                     "subcommand": "roles-list",         "description": "List roles"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/roles/{role_id}",           "subcommand": "roles-get",          "description": "Get role by ID"},
    {"solution": "platform", "method": "POST",   "endpoint": "/account/api/1/roles",                     "subcommand": "roles-create",       "description": "Create a role"},
    {"solution": "platform", "method": "DELETE", "endpoint": "/account/api/1/roles/{role_id}",           "subcommand": "roles-delete",       "description": "Delete a role"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/api-keys",                  "subcommand": "api-keys-list",      "description": "List API keys"},
    {"solution": "platform", "method": "POST",   "endpoint": "/account/api/1/api-keys",                  "subcommand": "api-keys-create",    "description": "Generate an API key"},
    {"solution": "platform", "method": "DELETE", "endpoint": "/account/api/1/api-keys/{apikey_id}",      "subcommand": "api-keys-delete",    "description": "Delete an API key"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/features",                  "subcommand": "features-list",      "description": "List features"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/user-groups",               "subcommand": "user-groups-list",   "description": "List user groups"},
    {"solution": "platform", "method": "GET",    "endpoint": "/account/api/1/user-groups/{group_id}",    "subcommand": "user-groups-get",    "description": "Get user group by ID"},
    {"solution": "platform", "method": "POST",   "endpoint": "/account/api/1/user-groups",               "subcommand": "user-groups-create", "description": "Create a user group"},
    {"solution": "platform", "method": "DELETE", "endpoint": "/account/api/1/user-groups/{group_id}",    "subcommand": "user-groups-delete", "description": "Delete a user group"},
    {"solution": "platform", "method": "POST",   "endpoint": "/idr/v1/search",                           "subcommand": "search",            "description": "Search the Insight Platform"},
    {"solution": "platform", "method": "GET",    "endpoint": "/credential-management/v1/credentials/organization/{org_id}", "subcommand": "credentials-list",  "description": "List credentials for an org"},
    {"solution": "platform", "method": "GET",    "endpoint": "/credential-management/v1/credentials/{rrn}",               "subcommand": "credentials-get",    "description": "Get credential by RRN"},
    {"solution": "platform", "method": "POST",   "endpoint": "/credential-management/v1/credentials",                     "subcommand": "credentials-create", "description": "Create a credential"},
    {"solution": "platform", "method": "DELETE", "endpoint": "/credential-management/v1/credentials/{rrn}",               "subcommand": "credentials-delete", "description": "Delete a credential"},

    # -- VM --
    {"solution": "vm", "method": "GET",  "endpoint": "/vm/admin/health",                    "subcommand": "health",            "description": "Check VM API health"},
    {"solution": "vm", "method": "POST", "endpoint": "/vm/v4/integration/assets",           "subcommand": "assets-list",       "description": "List/search assets"},
    {"solution": "vm", "method": "GET",  "endpoint": "/vm/v4/integration/assets/{asset_id}","subcommand": "assets-get",        "description": "Get asset by ID"},
    {"solution": "vm", "method": "GET",  "endpoint": "/vm/v4/integration/scan",             "subcommand": "scans-list",        "description": "List scans"},
    {"solution": "vm", "method": "GET",  "endpoint": "/vm/v4/integration/scan/{scan_id}",   "subcommand": "scans-get",         "description": "Get scan by ID"},
    {"solution": "vm", "method": "POST", "endpoint": "/vm/v4/integration/scan",             "subcommand": "scans-start",       "description": "Start a scan"},
    {"solution": "vm", "method": "GET",  "endpoint": "/vm/v4/integration/scan/engine",      "subcommand": "scan-engines-list", "description": "List scan engines"},
    {"solution": "vm", "method": "GET",  "endpoint": "/vm/v4/integration/scan/engine/{id}", "subcommand": "scan-engines-get",  "description": "Get scan engine by ID"},
    {"solution": "vm", "method": "GET",  "endpoint": "/vm/v4/integration/sites",            "subcommand": "sites-list",        "description": "List sites"},
    {"solution": "vm", "method": "GET",  "endpoint": "/vm/v4/integration/sites/{site_id}",  "subcommand": "sites-get",         "description": "Get site by ID"},
    {"solution": "vm", "method": "POST", "endpoint": "/vm/v4/integration/vulnerabilities",  "subcommand": "vulns-list",        "description": "List vulnerabilities"},
    {"solution": "vm", "method": "GET",  "endpoint": "/vm/v4/integration/vulnerabilities/{id}", "subcommand": "vulns-get",     "description": "Get vulnerability by ID"},
    {"solution": "vm", "method": "POST", "endpoint": "/export/graphql",                     "subcommand": "export-vulnerabilities", "description": "Start vulnerability bulk export (GraphQL)"},
    {"solution": "vm", "method": "POST", "endpoint": "/export/graphql",                     "subcommand": "export-policies",   "description": "Start policy bulk export (GraphQL)"},
    {"solution": "vm", "method": "POST", "endpoint": "/export/graphql",                     "subcommand": "job-status",        "description": "Poll export job status (GraphQL)"},

    # -- SIEM --
    {"solution": "siem", "method": "GET",  "endpoint": "/idr/v1/health-metrics",                    "subcommand": "health-metrics",      "description": "Agent/sensor health metrics"},
    {"solution": "siem", "method": "GET",  "endpoint": "/rest.logs.insight.rapid7.com/management/logsets", "subcommand": "logsets-list",  "description": "List logsets"},
    {"solution": "siem", "method": "GET",  "endpoint": "/rest.logs.insight.rapid7.com/query/logs/{log_id}", "subcommand": "logs-query",  "description": "Query log entries"},
    {"solution": "siem", "method": "GET",  "endpoint": "/rest.logs.insight.rapid7.com/usage/organizations", "subcommand": "log-storage", "description": "Log storage usage"},
    {"solution": "siem", "method": "GET",  "endpoint": "/rest.logs.insight.rapid7.com/management/organizations", "subcommand": "log-retention", "description": "Log retention settings"},
    {"solution": "siem", "method": "POST", "endpoint": "/graphql",                                  "subcommand": "agents-list",         "description": "List agents (GraphQL)"},
    {"solution": "siem", "method": "POST", "endpoint": "/graphql",                                  "subcommand": "quarantine-state",    "description": "Agent quarantine state (GraphQL)"},
    {"solution": "siem", "method": "GET",  "endpoint": "/idr/v1/investigations",                    "subcommand": "investigations-list", "description": "List investigations"},
    {"solution": "siem", "method": "GET",  "endpoint": "/idr/v1/investigations/{id}",               "subcommand": "investigations-get",  "description": "Get investigation by ID"},
    {"solution": "siem", "method": "POST", "endpoint": "/idr/v1/investigations",                    "subcommand": "investigations-create", "description": "Create an investigation"},
    {"solution": "siem", "method": "PATCH","endpoint": "/idr/v1/investigations/{id}",               "subcommand": "investigations-update", "description": "Update an investigation"},
    {"solution": "siem", "method": "GET",  "endpoint": "/idr/v1/detections",                        "subcommand": "detections-list",     "description": "List detection rules"},
    {"solution": "siem", "method": "GET",  "endpoint": "/idr/v1/collectors",                        "subcommand": "collectors-list",     "description": "List collectors"},
    {"solution": "siem", "method": "GET",  "endpoint": "/idr/v1/health-metrics?resourceTypes=event_sources", "subcommand": "event-sources-list", "description": "List event sources"},

    # -- ASM --
    {"solution": "asm", "method": "POST", "endpoint": "/surface/graph-api/objects/table",   "subcommand": "queries-list",    "description": "List saved Cypher queries"},
    {"solution": "asm", "method": "POST", "endpoint": "/surface/graph-api/objects/table",   "subcommand": "queries-execute", "description": "Execute a Cypher query"},
    {"solution": "asm", "method": "POST", "endpoint": "/surface/graph-api/objects/table",   "subcommand": "connectors-list", "description": "List connectors"},

    # -- DRP --
    {"solution": "drp", "method": "HEAD", "endpoint": "https://api.ti.insight.rapid7.com/public/v1/test-credentials", "subcommand": "validate",          "description": "Validate DRP credentials"},
    {"solution": "drp", "method": "GET",  "endpoint": "https://api.ti.insight.rapid7.com/public/v1/api/version",      "subcommand": "api-version",       "description": "Get DRP API version"},
    {"solution": "drp", "method": "GET",  "endpoint": "https://api.ti.insight.rapid7.com/public/v1/account/system-modules", "subcommand": "modules",    "description": "List account modules"},
    {"solution": "drp", "method": "GET",  "endpoint": "https://api.ti.insight.rapid7.com/public/v1/data/assets/list", "subcommand": "assets-list",       "description": "List DRP assets"},
    {"solution": "drp", "method": "GET",  "endpoint": "https://api.ti.insight.rapid7.com/public/v1/data/alerts/get-complete-alert/{id}", "subcommand": "alerts-get", "description": "Get alert by ID"},
    {"solution": "drp", "method": "GET",  "endpoint": "https://api.ti.insight.rapid7.com/public/v1/data/alerts/alerts-list", "subcommand": "alerts-list", "description": "List DRP alerts"},
    {"solution": "drp", "method": "GET",  "endpoint": "https://api.ti.insight.rapid7.com/public/v1/data/phishing/get-phishing-threats", "subcommand": "phishing-threats-list", "description": "List phishing threats"},
    {"solution": "drp", "method": "GET",  "endpoint": "https://api.ti.insight.rapid7.com/public/v1/data/takedowns/takedowns-list", "subcommand": "takedowns-list", "description": "List takedowns"},
    {"solution": "drp", "method": "GET",  "endpoint": "https://api.ti.insight.rapid7.com/public/v1/data/iocs/ioc-sources", "subcommand": "ioc-sources-list", "description": "List IOC sources"},
    {"solution": "drp", "method": "GET",  "endpoint": "https://api.ti.insight.rapid7.com/public/v1/data/ssl-cert-threats/ssl-cert-threats-list", "subcommand": "ssl-cert-threats-list", "description": "List SSL certificate threats"},

    # -- AppSec --
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/apps",                          "subcommand": "apps-list",          "description": "List applications"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/apps/{id}",                     "subcommand": "apps-get",           "description": "Get application by ID"},
    {"solution": "appsec", "method": "POST",   "endpoint": "/ias/v1/apps",                          "subcommand": "apps-create",        "description": "Create an application"},
    {"solution": "appsec", "method": "DELETE", "endpoint": "/ias/v1/apps/{id}",                     "subcommand": "apps-delete",        "description": "Delete an application"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/scans",                         "subcommand": "scans-list",         "description": "List scans"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/scans/{id}",                    "subcommand": "scans-get",          "description": "Get scan by ID"},
    {"solution": "appsec", "method": "POST",   "endpoint": "/ias/v1/scans",                         "subcommand": "scans-submit",       "description": "Submit a scan"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/scan-configs",                  "subcommand": "scan-configs-list",  "description": "List scan configs"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/scan-configs/{id}",             "subcommand": "scan-configs-get",   "description": "Get scan config by ID"},
    {"solution": "appsec", "method": "POST",   "endpoint": "/ias/v1/scan-configs",                  "subcommand": "scan-configs-create","description": "Create a scan config"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/vulnerabilities",               "subcommand": "vulns-list",         "description": "List vulnerabilities"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/vulnerabilities/{id}",          "subcommand": "vulns-get",          "description": "Get vulnerability by ID"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/engines",                       "subcommand": "engines-list",       "description": "List scan engines"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/engine-groups",                 "subcommand": "engine-groups-list", "description": "List engine groups"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/schedules",                     "subcommand": "schedules-list",     "description": "List schedules"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/blackouts",                     "subcommand": "blackouts-list",     "description": "List blackout windows"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/attack-templates",              "subcommand": "attack-templates-list", "description": "List attack templates"},
    {"solution": "appsec", "method": "GET",    "endpoint": "/ias/v1/modules",                       "subcommand": "modules-list",       "description": "List scan modules"},

    # -- CNAPP --
    {"solution": "cnapp", "method": "GET",    "endpoint": "/v4/iac/scans",                          "subcommand": "iac-scans-list",     "description": "List IaC scans"},
    {"solution": "cnapp", "method": "GET",    "endpoint": "/v4/iac/scans/{scan_id}",                "subcommand": "iac-scans-get",      "description": "Get IaC scan by ID"},
    {"solution": "cnapp", "method": "GET",    "endpoint": "/v4/iac/scans/{scan_id}/report",         "subcommand": "iac-scans-report",   "description": "Get IaC scan SARIF report"},
    {"solution": "cnapp", "method": "GET",    "endpoint": "/v4/configs/aws/accesskeys",             "subcommand": "aws-keys-list",      "description": "List AWS access keys"},
    {"solution": "cnapp", "method": "POST",   "endpoint": "/v4/configs/aws/accesskeys",             "subcommand": "aws-keys-create",    "description": "Create AWS access key"},
    {"solution": "cnapp", "method": "DELETE", "endpoint": "/v4/configs/aws/accesskeys/{key_id}",    "subcommand": "aws-keys-delete",    "description": "Delete AWS access key"},
    {"solution": "cnapp", "method": "GET",    "endpoint": "/v4/configs/aws/roles",                  "subcommand": "aws-roles-list",     "description": "List AWS roles"},
    {"solution": "cnapp", "method": "POST",   "endpoint": "/v4/configs/aws/roles",                  "subcommand": "aws-roles-create",   "description": "Create AWS role"},
    {"solution": "cnapp", "method": "DELETE", "endpoint": "/v4/configs/aws/roles/{role_id}",        "subcommand": "aws-roles-delete",   "description": "Delete AWS role"},
    {"solution": "cnapp", "method": "GET",    "endpoint": "/v4/configs/aws/accounts/{org_service_id}", "subcommand": "aws-accounts-get","description": "Get AWS account config"},
    {"solution": "cnapp", "method": "GET",    "endpoint": "/v4/insights/findings-per-cloud/{org_service_id}", "subcommand": "findings-list", "description": "List findings for cloud account"},

    # -- SOAR --
    {"solution": "soar", "method": "GET",    "endpoint": "/connect/v2/workflows",                   "subcommand": "workflows-list",     "description": "List workflows"},
    {"solution": "soar", "method": "GET",    "endpoint": "/connect/v2/workflows/{id}",              "subcommand": "workflows-get",      "description": "Get workflow by ID"},
    {"solution": "soar", "method": "POST",   "endpoint": "/connect/v2/workflows/{id}/execute",      "subcommand": "workflows-execute",  "description": "Execute a workflow"},
    {"solution": "soar", "method": "GET",    "endpoint": "/connect/v1/jobs",                        "subcommand": "jobs-list",          "description": "List jobs"},
    {"solution": "soar", "method": "GET",    "endpoint": "/connect/v1/jobs/{id}",                   "subcommand": "jobs-get",           "description": "Get job by ID"},
    {"solution": "soar", "method": "GET",    "endpoint": "/connect/v1/global_artifacts",            "subcommand": "artifacts-list",     "description": "List global artifacts"},
    {"solution": "soar", "method": "POST",   "endpoint": "/connect/v1/global_artifacts",            "subcommand": "artifacts-create",   "description": "Create a global artifact"},
    {"solution": "soar", "method": "DELETE", "endpoint": "/connect/v1/global_artifacts/{id}",       "subcommand": "artifacts-delete",   "description": "Delete a global artifact"},

    # -- Status (no auth) --
    {"solution": "status", "method": "GET", "endpoint": "https://status.rapid7.com/api/v2/status.json",               "subcommand": "status",     "description": "Platform status summary"},
    {"solution": "status", "method": "GET", "endpoint": "https://status.rapid7.com/api/v2/incidents/unresolved.json",  "subcommand": "incidents",  "description": "Unresolved incidents"},
    {"solution": "status", "method": "GET", "endpoint": "https://status.rapid7.com/api/v2/components.json",            "subcommand": "components", "description": "Platform components"},
]


# ---------------------------------------------------------------------------
# Curl example builder
# ---------------------------------------------------------------------------

_BASE_URL = "https://{region}.api.insight.rapid7.com"


def _build_curl(entry: dict[str, str], region: str = "us") -> str:
    """Build a curl example for an API registry entry.

    Parameters
    ----------
    entry : dict
        A single entry from ``_API_REGISTRY``.
    region : str
        Region code to substitute into URL templates.

    Returns
    -------
    str
        A curl command string with placeholder API key.
    """
    endpoint = entry["endpoint"]
    method = entry["method"]

    # Build full URL
    if endpoint.startswith("https://"):
        url = endpoint
    elif "rest.logs" in endpoint:
        # Log management endpoints use a different base
        path = endpoint.split("rest.logs.insight.rapid7.com", 1)[1]
        url = f"https://{region}.rest.logs.insight.rapid7.com{path}"
    else:
        url = f"{_BASE_URL.format(region=region)}{endpoint}"

    parts = [f"curl -s"]
    if method != "GET":
        parts.append(f"-X {method}")
    parts.append(f"'{url}'")
    parts.append("-H 'Content-Type: application/json'")

    # Auth header — DRP uses basic auth, everything else uses X-Api-Key
    if entry["solution"] == "drp":
        parts.append("-u '$R7_DRP_TOKEN:'")
    elif entry["solution"] != "status":
        parts.append("-H 'X-Api-Key: $R7_X_API_KEY'")

    return " \\\n  ".join(parts)


# ---------------------------------------------------------------------------
# Click commands
# ---------------------------------------------------------------------------

@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def dev(ctx):
    """Developer information."""
    pass


@dev.group(cls=GlobalFlagHintGroup)
@click.pass_context
def api(ctx):
    """API endpoint introspection."""
    pass


@api.command("list")
@click.option("--solution", "-s", "filter_solution", default=None,
              help="Filter by solution name (e.g. vm, siem, drp, platform).")
@click.option("--method", "-m", "filter_method", default=None,
              help="Filter by HTTP method (e.g. GET, POST, DELETE).")
@click.option("--curl", "--example", "show_curl", is_flag=True,
              help="Show curl examples for each API call.")
@click.pass_context
def api_list(ctx, filter_solution, filter_method, show_curl):
    """List all supported API calls within the tool.

    \b
    Examples:
      r7-cli dev api list                        # list all APIs
      r7-cli dev api list --solution vm           # only VM APIs
      r7-cli dev api list --method POST           # only POST endpoints
      r7-cli dev api list --solution siem --curl  # SIEM APIs with curl examples
    """
    config = ctx.obj["config"]
    entries = list(_API_REGISTRY)

    if filter_solution:
        sol = filter_solution.lower()
        entries = [e for e in entries if e["solution"] == sol]

    if filter_method:
        meth = filter_method.upper()
        entries = [e for e in entries if e["method"] == meth]

    if not entries:
        click.echo("No matching API endpoints found.", err=True)
        return

    if show_curl:
        region = config.region if config else "us"
        for entry in entries:
            click.echo(f"# {entry['solution']} — {entry['description']}")
            click.echo(f"# Subcommand: {entry['subcommand']}")
            click.echo(_build_curl(entry, region=region))
            click.echo()
        return

    # Default: structured output via format_output
    output = []
    for entry in entries:
        output.append({
            "solution": entry["solution"],
            "method": entry["method"],
            "endpoint": entry["endpoint"],
            "subcommand": entry["subcommand"],
            "description": entry["description"],
        })

    click.echo(format_output(output, config.output_format, config.limit, config.search, short=config.short))
