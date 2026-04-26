# r7-cli

A command-line interface for the Rapid7 Insight Platform. Query and manage InsightVM, InsightIDR, Surface Command, Digital Risk Protection, InsightCloudSec, InsightAppSec, and InsightConnect from your terminal.

## Installation

```bash
git clone <repo-url> r7cli
cd r7cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For development (includes pytest and hypothesis):

```bash
pip install -e ".[dev]"
```

Verify the install:

```bash
r7-cli --help
```

## Requirements

- Python 3.10+
- Dependencies: `click`, `httpx`, `tabulate`, `pyarrow`, `questionary`

## Configuration

Set your API key as an environment variable:

```bash
export R7_X_API_KEY="your-api-key-here"
```

Optionally set a default region (defaults to `us`):

```bash
export R7_REGION="us"
```

For Digital Risk Protection commands, set the DRP token:

```bash
export R7_DRP_TOKEN="user:key"
```

For InsightCloudSec commands, set the CloudSec URL:

```bash
export R7_CLOUDSEC_URL="my.insightcloudsec.com"
```

Supported regions: `us`, `us1`, `us2`, `us3`, `ca`, `eu`, `au`, `ap`, `me-central-1`, `ap-south-2`

## Global Options

| Flag | Description |
|------|-------------|
| `-r, --region` | Region code (default: us) |
| `-k, --api-key` | API key (overrides env var) |
| `-o, --output` | Output format: `json`, `table`, `csv`, `tsv` |
| `-v, --verbose` | Log request URLs and response info to stderr |
| `--debug` | Log full request/response bodies |
| `-c, --cache` | Use cached responses (skips API calls, skips license check) |
| `-l, --limit` | Limit the largest array in output |
| `-s, --short` | Compact single-line-per-object output with field priority reordering |
| `-t, --timeout` | Request timeout in seconds (default: 30) |
| `--search-fields` | Search JSON response for a field name and print matching values |
| `--drp-token` | DRP API token in `user:key` format |
| `--llm` | LLM provider for natural language commands (`openai`, `claude`, `gemini`) |
| `--llm-key` | API key for the LLM provider |
| `--tldr` | Show quick-reference examples |

## License Checking

On first API call per session, r7-cli validates your organization's product licenses against the Insight Platform Account API (`/account/api/1/products`). If the required license is missing, the command exits with code 1.

License checks are skipped for:
- Help requests (`-h`, `--help`)
- Cache mode (`-c`)
- Offline commands (`vm export list`)
- Platform commands (no license required)
- Commands where required options are missing (error shown before license check)

| Solution | Required License Codes |
|----------|----------------------|
| vm | IVM |
| siem | IDR or OPS |
| asm | SC |
| drp | TC or IH |
| appsec | AS |
| cnapp | ICS |
| soar | ICON |

## Error Handling

| Exception | Exit Code | When |
|-----------|-----------|------|
| `UserInputError` | 1 | Bad flag, missing argument, invalid value |
| `APIError` | 2 | HTTP 4xx/5xx, API-level errors |
| `NetworkError` | 3 | Connection refused, timeout, DNS failure |

## Caching

All API responses are cached locally in `~/.r7-cli/cache/` as SHA-256-keyed JSON files. Use `-c` to return cached data instead of making live API calls. Export jobs are tracked in `~/.r7-cli/jobs.json`.

---

## Solutions & API Reference

### `r7-cli validate`

Validate your API key against the Insight Platform.

| Command | Method | API Endpoint |
|---------|--------|-------------|
| `validate` | GET | `https://{region}.api.insight.rapid7.com/validate` |

```bash
r7-cli validate
```

---

### `r7-cli ai` — Natural Language Commands

Translates a natural language request into the appropriate r7-cli command using an LLM (OpenAI, Claude, or Gemini). The system prompt is dynamically generated from the CLI's command tree, so it always stays in sync with available commands.

| Option | Description |
|--------|-------------|
| `-x, --execute` | Execute the generated command immediately |
| `-y, --yes` | Skip confirmation when using `--execute` |

Requires `--llm` global flag (or `R7_LLM_PROVIDER` env var) and an API key for the chosen provider.

| Provider | Env Var |
|----------|---------|
| `openai` | `OPENAI_API_KEY` |
| `claude` | `ANTHROPIC_API_KEY` |
| `gemini` | `GEMINI_API_KEY` |
| (any) | `R7_LLM_API_KEY` (generic fallback) |

```bash
# Show the command (doesn't execute)
r7-cli --llm openai ai show me critical vulnerabilities

# Execute directly
r7-cli --llm claude ai -x list all open investigations

# Using env vars
export R7_LLM_PROVIDER=gemini
export GEMINI_API_KEY=your-key
r7-cli ai how many assets do I have

# Auto-execute without confirmation
r7-cli --llm openai ai -x -y check VM health
```

---

### `r7-cli vm` — InsightVM

Manages vulnerability scans, assets, engines, sites, vulnerabilities, and bulk exports via the IVM v4 Integration API and the Bulk Export GraphQL API.

| Command | Method | API Endpoint | Description |
|---------|--------|-------------|-------------|
| `vm health` | GET | `/vm/admin/health` | Check IVM API health status |
| `vm scans list` | GET | `/v4/integration/scan` | List vulnerability scans |
| `vm scans get` | GET | `/v4/integration/scan/{id}` | Get a single scan |
| `vm scans start` | POST | `/v4/integration/scan` | Start a new scan |
| `vm scans stop` | POST | `/v4/integration/scan/{id}/stop` | Stop a running scan |
| `vm assets list` | POST | `/v4/integration/assets` | Search/list assets |
| `vm assets count` | POST | `/v4/integration/assets` | Get total asset count |
| `vm assets get` | GET | `/v4/integration/assets/{id}` | Get a single asset |
| `vm scan-engines list` | GET | `/v4/integration/scan/engine` | List scan engines |
| `vm scan-engines get` | GET | `/v4/integration/scan/engine/{id}` | Get a single engine |
| `vm scan-engines update-config` | POST | `/v4/integration/scan/engine/{id}/configuration` | Update engine config |
| `vm scan-engines remove-config` | DELETE | `/v4/integration/scan/engine/{id}/configuration` | Remove engine config |
| `vm sites list` | GET | `/v4/integration/sites` | List sites |
| `vm vulns list` | POST | `/v4/integration/vulnerabilities` | Search vulnerabilities |
| `vm export vulnerabilities` | POST | `/export/graphql` (GQL mutation) | Start vulnerability export |
| `vm export policies` | POST | `/export/graphql` (GQL mutation) | Start policy export |
| `vm export remediations` | POST | `/export/graphql` (GQL mutation) | Start remediation export |
| `vm export list` | — | Local filesystem | Filter downloaded Parquet files |
| `vm export schema` | POST | `/export/graphql` (GQL query) | Inspect export schema |
| `vm export job status` | POST | `/export/graphql` (GQL query) | Poll export job status |
| `vm export mcp install` | — | — | Install the Rapid7 Bulk Export MCP server |
| `vm export mcp configure` | — | — | Write MCP config for AI tools |
| `vm export mcp start-export` | MCP | `start_rapid7_export` tool | Start export via MCP server |
| `vm export mcp status` | MCP | `check_rapid7_export_status` tool | Check MCP export status |
| `vm export mcp download` | MCP | `download_rapid7_export` tool | Download & load into DuckDB |
| `vm export mcp query` | MCP | `query_rapid7` tool | Execute SQL against DuckDB |
| `vm export mcp schema` | MCP | `get_rapid7_schema` tool | Show DuckDB table schemas |
| `vm export mcp stats` | MCP | `get_rapid7_stats` tool | Show summary statistics |
| `vm export mcp list-exports` | MCP | `list_rapid7_exports` tool | List tracked exports |
| `vm export mcp suggest` | MCP | `suggest_query` tool | Get SQL query suggestions |
| `vm export mcp load-parquet` | MCP | `load_rapid7_parquet` tool | Load local Parquet files |

Base URLs:
- IVM v4: `https://{region}.api.insight.rapid7.com/vm/v4`
- Bulk Export GraphQL: `https://{region}.api.insight.rapid7.com/export/graphql`

```bash
r7-cli vm health
r7-cli vm scans list --days 7
r7-cli vm scans list --status Success --all-pages
r7-cli vm assets list --hostname 'webserver' --all-pages
r7-cli vm assets list --risk-score '>=100000' --all-pages --force
r7-cli vm assets count
r7-cli vm scan-engines list
r7-cli vm scan-engines list --unhealthy
r7-cli vm sites list --all-pages
r7-cli vm vulns list --severity Critical --all-pages
r7-cli vm export vulnerabilities --auto
r7-cli vm export policies --auto
r7-cli vm export remediations --month january --year 2026 --auto
r7-cli vm export list --severity Critical --has-exploits true
r7-cli vm export list --hostname '*.prod.*' --where 'cvssScore>=9.0'
r7-cli vm export job status --id <JOB_ID> --poll

# MCP server commands
r7-cli vm export mcp install
r7-cli vm export mcp configure
r7-cli vm export mcp start-export
r7-cli vm export mcp start-export --type policy
r7-cli vm export mcp status --id <EXPORT_ID>
r7-cli vm export mcp download --id <EXPORT_ID>
r7-cli vm export mcp query "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
r7-cli vm export mcp schema
r7-cli vm export mcp stats
r7-cli vm export mcp list-exports
r7-cli vm export mcp suggest "find critical vulns with exploits"
```

---

### `r7-cli siem` — InsightIDR

Manages health metrics, log queries, agents, investigations, detection rules, collectors, event sources, and more via the IDR v1 REST API, the Log Search REST API, and the IDR GraphQL API.

| Command | Method | API Endpoint | Description |
|---------|--------|-------------|-------------|
| `siem health` | GET | `/idr/v1/health-metrics` | Health metrics (agents, collectors, event sources) |
| `siem agents list` | POST | `/graphql` (GQL query) | List agents via GraphQL |
| `siem agents count` | GET | `/idr/v1/health-metrics` | Get agent count from health metrics |
| `siem logs logsets list` | GET | `/management/logsets` | List logsets |
| `siem logs query` | GET | `/query/logsets`, `/query/logs/{id}` | Query logs by logset name |
| `siem logs keys` | GET | `/query/logs/{id}/keys` | Get log keys |
| `siem logs usage` | GET | `/query/logs/{id}/usage` | Get storage usage for a log |
| `siem logs storage` | GET | `/usage/organizations` | Log storage usage over time |
| `siem logs retention` | GET | `/management/organizations` | Log retention settings |
| `siem logs mgmt list` | GET | `/management/logs` | List individual logs |
| `siem logs mgmt get` | GET | `/management/logs/{id}` | Get a single log |
| `siem logs mgmt delete` | DELETE | `/management/logs/{id}` | Delete a log |
| `siem event-sources list` | GET | `/idr/v1/health-metrics?resourceTypes=event_sources` | List event sources |
| `siem collectors list` | GET | `/idr/v1/health-metrics?resourceTypes=collectors` | List collectors |
| `siem collectors create` | POST | `/idr/v1/collectors` | Create a collector |
| `siem investigations list` | GET | `/idr/v1/investigations` | List investigations |
| `siem investigations set-status` | PUT | `/idr/v1/investigations/{id}/status/{status}` | Update investigation status |
| `siem investigations close-bulk` | POST | `/idr/v1/investigations/bulk_close` | Bulk close investigations |
| `siem investigations assign` | PUT | `/idr/v1/investigations/{id}/assignee` | Assign investigation |
| `siem investigations comments list` | GET | `/idr/v1/comments` | List investigation comments |
| `siem investigations comments create` | POST | `/idr/v1/comments` | Create a comment |
| `siem investigations comments get` | GET | `/idr/v1/comments/{rrn}` | Get a comment |
| `siem investigations comments update` | PUT | `/idr/v1/comments/{rrn}/{visibility}` | Update comment visibility |
| `siem investigations comments delete` | DELETE | `/idr/v1/comments/{rrn}` | Delete a comment |
| `siem investigations attachments list` | GET | `/idr/v1/attachments` | List attachments |
| `siem investigations attachments get` | GET | `/idr/v1/attachments/{rrn}/metadata` | Get attachment metadata |
| `siem investigations attachments delete` | DELETE | `/idr/v1/attachments/{rrn}` | Delete an attachment |
| `siem users list` | POST | `/idr/v1/users/_search` | Search IDR users |
| `siem users get` | GET | `/idr/v1/users/{rrn}` | Get a user by RRN |
| `siem accounts search` | POST | `/idr/v1/accounts/_search` | Search accounts |
| `siem accounts get` | GET | `/idr/v1/accounts/{rrn}` | Get an account |
| `siem accounts assets search` | POST | `/idr/v1/assets/_search` | Search IDR assets |
| `siem accounts assets get` | GET | `/idr/v1/assets/{rrn}` | Get an IDR asset |
| `siem accounts assets local-account` | GET | `/idr/v1/assets/local-accounts/{rrn}` | Get local account |
| `siem accounts assets search-local-accounts` | POST | `/idr/v1/assets/local-accounts/_search` | Search local accounts |
| `siem detections threats create` | POST | `/idr/v1/customthreats` | Create custom threat |
| `siem detections threats add-indicators` | POST | `/idr/v1/customthreats/key/{key}/indicators/add` | Add threat indicators |
| `siem detections threats replace-indicators` | POST | `/idr/v1/customthreats/key/{key}/indicators/replace` | Replace indicators |
| `siem detections threats delete` | POST | `/idr/v1/customthreats/key/{key}/delete` | Delete custom threat |
| `siem queries saved-queries list` | GET | `/query/saved_queries` | List saved queries |
| `siem queries saved-queries get` | GET | `/query/saved_queries/{id}` | Get a saved query |
| `siem queries saved-queries create` | POST | `/query/saved_queries` | Create a saved query |
| `siem queries saved-queries update` | PUT | `/query/saved_queries/{id}` | Update a saved query |
| `siem queries saved-queries delete` | DELETE | `/query/saved_queries/{id}` | Delete a saved query |
| `siem queries variables list` | GET | `/query/variables` | List log search variables |
| `siem queries variables get` | GET | `/query/variables/{id}` | Get a variable |
| `siem queries variables update` | PUT | `/variables/{id}` | Update a variable |
| `siem queries variables delete` | DELETE | `/variables/{id}` | Delete a variable |
| `siem detections detection-rules list` | GET | `/management/tags` | List detection rules |
| `siem detections detection-rules get` | GET | `/management/tags/{id}` | Get a detection rule |
| `siem detections detection-rules create` | POST | `/management/tags` | Create a detection rule |
| `siem detections detection-rules delete` | DELETE | `/management/tags/{id}` | Delete a detection rule |
| `siem detections notifications list` | GET | `/query/notifications` | List notifications |
| `siem detections notifications get` | GET | `/query/notifications/{id}` | Get a notification |
| `siem detections notif-targets list` | GET | `/query/notification-targets` | List notification targets |
| `siem detections notif-targets get` | GET | `/query/notification-targets/{id}` | Get a notification target |
| `siem queries pre-computed list` | GET | `/query/pre-computed-metrics` | List pre-computed metrics |
| `siem queries pre-computed get` | GET | `/query/pre-computed-metrics/{id}` | Get a metric |
| `siem queries pre-computed results` | GET | `/query/pre-computed-metrics/{id}/results` | Get metric results |
| `siem queries pre-computed create` | POST | `/query/pre-computed-metrics` | Create a metric |
| `siem queries pre-computed delete` | DELETE | `/query/pre-computed-metrics/{id}` | Delete a metric |
| `siem exports list` | GET | `/query/exports` | List log exports |
| `siem exports get` | GET | `/query/exports/{id}` | Get an export |
| `siem exports delete` | DELETE | `/query/exports/{id}` | Delete an export |
| `siem quarantine-state` | POST | `/graphql` (GQL query) | Query agent quarantine state |

Base URLs:
- IDR v1 REST: `https://{region}.api.insight.rapid7.com/idr/v1`
- Log Search: `https://{region}.rest.logs.insight.rapid7.com`
- IDR GraphQL: `https://{region}.api.insight.rapid7.com/graphql`

```bash
r7-cli siem health
r7-cli siem agents list --all-pages
r7-cli siem agents count
r7-cli siem logs logsets list --name
r7-cli siem logs logsets list --ids
r7-cli siem logs query -n "Asset Authentication" --time-range "Last 7 days"
r7-cli siem logs query -n "DNS Query" --from 2026-01-01T00:00:00Z --to 2026-01-31T23:59:59Z
r7-cli siem logs query -n "Firewall Activity" -q "where(action=DENY)" -p 5
r7-cli -c siem logs query -n "DNS Query"  # return cached results
r7-cli siem investigations list --status OPEN --all-pages
r7-cli siem investigations set-status -j <ID> CLOSED
r7-cli siem collectors list
r7-cli siem event-sources list --issues-only
r7-cli siem detections detection-rules list --type UBA --priority HIGH
```

---

### `r7-cli asm` — Surface Command

Executes Cypher queries against the Surface Command graph API and manages connectors.

| Command | Method | API Endpoint | Description |
|---------|--------|-------------|-------------|
| `asm queries list` | POST | `/surface/graph-api/objects/table` | List saved Cypher queries |
| `asm queries execute` | POST | `/surface/graph-api/objects/table` | Execute a Cypher query |
| `asm queries get` | POST | `/surface/graph-api/objects/table` | Get a saved query by ID |
| `asm connectors list` | POST | `/surface/graph-api/objects/table` | List connectors |

Base URL: `https://{region}.api.insight.rapid7.com/surface`

```bash
r7-cli asm queries list
r7-cli asm queries execute --query 'MATCH (a:Asset) RETURN a LIMIT 10'
r7-cli asm queries execute --query-file my-query.cypher
r7-cli asm connectors list
```

---

### `r7-cli drp` — Digital Risk Protection

Manages alerts, threats, takedowns, risk scores, and monitored assets via the Threat Command API. Uses separate authentication (`R7_DRP_TOKEN` or `--drp-token` in `user:key` format).

| Command | Method | API Endpoint | Description |
|---------|--------|-------------|-------------|
| `drp validate` | HEAD | `/public/v1/test-credentials` | Validate DRP credentials |
| `drp api-version` | GET | `/public/v1/api/version` | Get API version |
| `drp modules` | GET | `/public/v1/account/system-modules` | List account modules |
| `drp assets list` | GET | `/public/v2/data/assets` | List monitored assets |
| `drp assets count` | GET | `/public/v2/data/assets` | Count monitored assets |
| `drp ioc-sources list` | GET | `/public/v1/iocs/sources` | List IOC sources |
| `drp alerts list` | GET | `/public/v2/data/alerts/alerts-list` | List alerts |
| `drp alerts get` | GET | `/public/v1/data/alerts/get-complete-alert/{id}` | Get alert details |
| `drp phishing-threats list` | GET | `/public/v1/data/phishing-domains-threats/threats-list` | List phishing threats |
| `drp phishing-threats get` | GET | `/public/v1/data/phishing-domains-threats/get-complete-threat/{id}` | Get phishing threat |
| `drp ssl-cert-threats list` | GET | `/public/v1/data/ssl-certificate-threats/threats-list` | List SSL cert threats |
| `drp ssl-issue-threats list` | GET | `/public/v1/data/ssl-issues-threats/threats-list` | List SSL issue threats |
| `drp reported-domains list` | GET | `/public/v1/data/reported-domains/domains-list` | List reported domains |
| `drp takedowns list` | GET | `/public/v2/data/alerts/alerts-list` | List completed takedowns |
| `drp takedowns report` | GET | `/public/v1/data/alerts/report-status/{id}` | Get takedown report |
| `drp risk-score` | GET | `/public/v1/data/alerts/system-risk-score` | Get system risk score |

Base URL: `https://api.ti.insight.rapid7.com`

```bash
r7-cli drp validate
r7-cli drp alerts list --severity High --days 30
r7-cli drp alerts get -j <ALERT_ID>
r7-cli drp assets list
r7-cli drp risk-score
r7-cli drp risk-score --fail-above 7
r7-cli drp phishing-threats list --days 14
r7-cli drp takedowns list
```

---

### `r7-cli platform` — Platform Administration

Manages users, organizations, products, roles, API keys, features, user groups, credentials, and hosts cross-cutting subcommands (assets, extensions, compliance, matrix).

| Command | Method | API Endpoint | Description |
|---------|--------|-------------|-------------|
| `platform validate` | GET | `/validate` | Validate API key |
| `platform status` | GET | `status.rapid7.com` | Show platform operational status |
| `platform search` | POST | `/idr/v1/search` | Search the Insight Platform |
| `platform users list` | GET | `/account/api/1/users` | List users |
| `platform users get` | GET | `/account/api/1/users/{id}` | Get a user |
| `platform users create` | POST | `/account/api/1/users` | Create a user |
| `platform users delete` | DELETE | `/account/api/1/users/{id}` | Delete a user |
| `platform orgs list` | GET | `/account/api/1/organizations` | List organizations |
| `platform orgs managed` | GET | `/account/api/1/managed-organizations` | List managed orgs |
| `platform products list` | GET | `/account/api/1/products` | List licensed products |
| `platform products get` | GET | `/account/api/1/products/{token}` | Get a product |
| `platform roles list` | GET | `/account/api/1/roles` | List roles |
| `platform roles get` | GET | `/account/api/1/roles/{id}` | Get a role |
| `platform roles create` | POST | `/account/api/1/roles` | Create a role |
| `platform roles delete` | DELETE | `/account/api/1/roles/{id}` | Delete a role |
| `platform api-keys list` | GET | `/account/api/1/api-keys` | List API keys |
| `platform api-keys create` | POST | `/account/api/1/api-keys` | Create an API key |
| `platform api-keys delete` | DELETE | `/account/api/1/api-keys/{id}` | Delete an API key |
| `platform features list` | GET | `/account/api/1/features` | List features |
| `platform user-groups list` | GET | `/account/api/1/user-groups` | List user groups |
| `platform user-groups get` | GET | `/account/api/1/user-groups/{id}` | Get a user group |
| `platform user-groups create` | POST | `/account/api/1/user-groups` | Create a user group |
| `platform user-groups delete` | DELETE | `/account/api/1/user-groups/{id}` | Delete a user group |
| `platform credentials list` | GET | `/credential-management/v1/credentials/organization/{org_id}` | List credentials |
| `platform credentials get` | GET | `/credential-management/v1/credentials/{rrn}` | Get a credential |
| `platform credentials create` | POST | `/credential-management/v1/credentials` | Create a credential |
| `platform credentials delete` | DELETE | `/credential-management/v1/credentials/{rrn}` | Delete a credential |

Base URLs:
- Insight Platform: `https://{region}.api.insight.rapid7.com`
- Account API: `https://{region}.api.insight.rapid7.com/account/api/1`
- Credential Management: `https://{region}.api.insight.rapid7.com/credential-management/v1`

```bash
r7-cli platform validate
r7-cli platform products list
r7-cli platform users list
r7-cli platform orgs list
r7-cli platform roles list
r7-cli platform api-keys list
r7-cli platform credentials list --org-id <ORG_ID>
r7-cli platform status
```

---

### `r7-cli platform status` — Platform Operational Status

Shows Rapid7 platform operational status from status.rapid7.com. No authentication required.

| Command | Method | Source | Description |
|---------|--------|--------|-------------|
| `platform status` | GET | `status.rapid7.com` | Show platform health, degraded services, and active incidents |

Options:
- `--json` — Output raw JSON instead of human-readable format

```bash
r7-cli platform status
r7-cli platform status --json
```

---

### `r7-cli platform assets` — Cross-Platform Asset Counts

Queries asset counts across multiple Rapid7 products via their respective APIs.

| Flag | Product | API Used |
|------|---------|----------|
| `--vm` | InsightVM | POST `/v4/integration/assets` |
| `--siem` | InsightIDR | GET `/idr/v1/health-metrics` |
| `--asm` | Surface Command | POST `/surface/graph-api/objects/table` (Cypher) |
| `--appsec` | InsightAppSec | GET `/ias/v1/apps` |
| `--drp` | DRP | GET `/public/v2/data/assets` |

```bash
r7-cli platform assets count
r7-cli platform assets count --vm
r7-cli platform assets count --siem --asm
```

---

### `r7-cli platform extensions` — Extension Library

Browses the Rapid7 Extension Library. No API key required.

| Command | Method | API Endpoint | Description |
|---------|--------|-------------|-------------|
| `extensions {product} list` | GET | `/v2/public/extensions` | List extensions by product |
| `extensions get` | GET | `/v2/public/extensions/{slug}` | Get extension details |
| `extensions version` | GET | `/v2/public/extensions/{slug}/versions/{ver}` | Get specific version |
| `extensions help` | GET | `/v2/public/extensions/{slug}/help` | Get extension help |
| `extensions count` | GET | `/v2/public/extensions` | Count extensions by product/type |
| `extensions leaderboard` | GET | `/v2/public/extensions` | Top extensions by installs |
| `extensions types` | — | — | List supported extension types |

Base URL: `https://extensions-api.rapid7.com`

Product subgroups: `asm` (SC), `soar` (ICON), `siem` (IDR), `vm` (IVM), `appsec` (AS)

```bash
r7-cli platform extensions soar list
r7-cli platform extensions siem list --sort updated -l 10
r7-cli platform extensions get -j rapid7-insightconnect-plugin-for-jira
r7-cli platform extensions count
r7-cli platform extensions leaderboard --group soar
```

---

### `r7-cli platform compliance` — VM Policy Compliance Export

Downloads VM policy compliance data via the Bulk Export GraphQL API, reads the Parquet files with pyarrow, and outputs as SQL INSERT statements (default), JSON, table, CSV, or TSV.

| Step | Method | API Endpoint | Description |
|------|--------|-------------|-------------|
| Submit export | POST | `/export/graphql` (GQL mutation) | CreatePolicyExport |
| Poll status | POST | `/export/graphql` (GQL query) | GetExport |
| Download files | GET | Presigned S3 URLs | Download Parquet files |

```bash
r7-cli platform compliance
r7-cli platform compliance --sql-file policy_dump.sql
r7-cli -o tsv platform compliance
r7-cli -c platform compliance  # reuse cached parquet files
```

---

### `r7-cli platform matrix` — NIST CSF × CIS v8 Coverage Matrix

Generates a NIST CSF × CIS v8 defender coverage matrix based on licensed Rapid7 products. Supports deployment-aware scoring that checks actual infrastructure state.

Running `r7-cli platform matrix` directly executes the matrix (the `rapid7` subcommand is retained as an alias for backward compatibility).

| Command | API Used (with `--reality`) |
|---------|---------------------------|
| `matrix` / `matrix rapid7` | GET `/idr/v1/health-metrics` (collectors, event sources, agents) |
| | POST `/surface/graph-api/objects/table` (SC connectors) |
| | GET `/idr/v1/health-metrics?resourceTypes=collectors` |

Options:
- `-p, --percent` — Show coverage percentages instead of checkmarks
- `--solution` — Show Rapid7 solution names mapped to each cell
- `--reality` / `--deployment` — Adjust percentages based on actual deployment state
- `--scoring` — Print the scoring rules and exit
- `--json` — Output the matrix as JSON

```bash
r7-cli platform matrix                    # default checkmark mode
r7-cli platform matrix -p                 # percentage mode
r7-cli platform matrix --solution         # show product mappings
r7-cli platform matrix --reality          # adjust for deployment state
r7-cli platform matrix --scoring          # view scoring rules
r7-cli platform matrix --json             # JSON output
r7-cli platform matrix rapid7             # alias (same as bare invocation)
```

---

### `r7-cli appsec` — InsightAppSec

Manages applications, scans, scan configs, vulnerabilities, engines, and engine groups via the IAS v1 API.

| Command | Method | API Endpoint | Description |
|---------|--------|-------------|-------------|
| `appsec apps list` | GET | `/ias/v1/apps` | List applications |
| `appsec apps get` | GET | `/ias/v1/apps/{id}` | Get an application |
| `appsec apps create` | POST | `/ias/v1/apps` | Create an application |
| `appsec apps update` | PUT | `/ias/v1/apps/{id}` | Update an application |
| `appsec apps delete` | DELETE | `/ias/v1/apps/{id}` | Delete an application |
| `appsec apps count` | GET | `/ias/v1/apps` | Count applications |
| `appsec scans list` | GET | `/ias/v1/scans` | List scans |
| `appsec scans get` | GET | `/ias/v1/scans/{id}` | Get a scan |
| `appsec scans start` | POST | `/ias/v1/scans` | Start a scan |
| `appsec scans stop` | PUT | `/ias/v1/scans/{id}/action` | Stop a scan |
| `appsec scans details` | GET | `/ias/v1/scans/{id}/execution-details` | Get scan execution details |
| `appsec scans delete` | DELETE | `/ias/v1/scans/{id}` | Delete a scan |
| `appsec scans engine-events` | GET | `/ias/v1/scans/{id}/engine-events` | Get scan engine events |
| `appsec scans platform-events` | GET | `/ias/v1/scans/{id}/platform-events` | Get scan platform events |
| `appsec scan-configs list` | GET | `/ias/v1/scan-configs` | List scan configurations |
| `appsec scan-configs get` | GET | `/ias/v1/scan-configs/{id}` | Get a scan config |
| `appsec scan-configs create` | POST | `/ias/v1/scan-configs` | Create a scan config |
| `appsec scan-configs options` | GET | `/ias/v1/scan-configs/{id}/options` | Get scan config options |
| `appsec scan-configs update` | PUT | `/ias/v1/scan-configs/{id}` | Update a scan config |
| `appsec scan-configs delete` | DELETE | `/ias/v1/scan-configs/{id}` | Delete a scan config |
| `appsec vulns list` | GET | `/ias/v1/vulnerabilities` | List vulnerabilities |
| `appsec vulns get` | GET | `/ias/v1/vulnerabilities/{id}` | Get a vulnerability |
| `appsec vulns discoveries` | GET | `/ias/v1/vulnerabilities/{id}/discoveries` | Get discoveries |
| `appsec vulns history` | GET | `/ias/v1/vulnerabilities/{id}/history` | Get vuln history |
| `appsec vulns update` | PUT | `/ias/v1/vulnerabilities/{id}` | Update a vulnerability |
| `appsec vulns comments list` | GET | `/ias/v1/vulnerabilities/{id}/comments` | List vuln comments |
| `appsec vulns comments create` | POST | `/ias/v1/vulnerabilities/{id}/comments` | Create a comment |
| `appsec vulns comments delete` | DELETE | `/ias/v1/vulnerabilities/{id}/comments/{cid}` | Delete a comment |
| `appsec engines list` | GET | `/ias/v1/engines` | List scan engines |
| `appsec engines get` | GET | `/ias/v1/engines/{id}` | Get an engine |
| `appsec engines create` | POST | `/ias/v1/engines` | Create an engine |
| `appsec engines update` | PUT | `/ias/v1/engines/{id}` | Update an engine |
| `appsec engines delete` | DELETE | `/ias/v1/engines/{id}` | Delete an engine |
| `appsec engine-groups list` | GET | `/ias/v1/engine-groups` | List engine groups |
| `appsec engine-groups get` | GET | `/ias/v1/engine-groups/{id}` | Get an engine group |
| `appsec engine-groups create` | POST | `/ias/v1/engine-groups` | Create an engine group |

Base URL: `https://{region}.api.insight.rapid7.com/ias/v1`

```bash
r7-cli appsec apps list
r7-cli appsec apps count
r7-cli appsec scans list --all-pages
r7-cli appsec vulns list --severity HIGH
r7-cli appsec scan-configs list
```

---

### `r7-cli soar` — InsightConnect

Manages workflows, jobs, global artifacts, and snippets via the Connect v1 and v2 APIs.

| Command | Method | API Endpoint | Description |
|---------|--------|-------------|-------------|
| `soar workflows list` | GET | `/connect/v2/workflows` | List workflows |
| `soar workflows get` | GET | `/connect/v2/workflows/{id}` | Get a workflow |
| `soar workflows execute` | POST | `/connect/v1/execute/async/workflows/{id}` | Execute a workflow |
| `soar workflows jobs` | GET | `/connect/v2/workflows/{id}/jobs` | List workflow jobs |
| `soar workflows delete` | DELETE | `/connect/v2/workflows/{id}` | Delete a workflow |
| `soar workflows import` | POST | `/connect/v2/workflows/import` | Import a workflow |
| `soar jobs list` | GET | `/connect/v1/jobs` | List all jobs |
| `soar jobs get` | GET | `/connect/v1/jobs/{id}` | Get a job |
| `soar jobs cancel` | POST | `/connect/v1/jobs/{id}/cancel` | Cancel a job |
| `soar artifacts list` | GET | `/connect/v1/globalArtifacts` | List global artifacts |
| `soar artifacts get` | GET | `/connect/v1/globalArtifacts/{id}` | Get an artifact |
| `soar artifacts create` | POST | `/connect/v1/globalArtifacts` | Create an artifact |
| `soar artifacts update` | PUT | `/connect/v1/globalArtifacts/{id}` | Update an artifact |
| `soar artifacts delete` | DELETE | `/connect/v1/globalArtifacts/{id}` | Delete an artifact |
| `soar snippets export` | GET | `/connect/v2/snippets/{id}/export` | Export a snippet |
| `soar snippets import` | POST | `/connect/v2/snippets/import` | Import a snippet |
| `soar plugins import` | POST | `/connect/v1/customPlugins/import` | Import a custom plugin |

Base URLs:
- Connect v1: `https://{region}.api.insight.rapid7.com/connect/v1`
- Connect v2: `https://{region}.api.insight.rapid7.com/connect/v2`

```bash
r7-cli soar workflows list
r7-cli soar workflows execute -j <WORKFLOW_ID>
r7-cli soar jobs list --all-pages
r7-cli soar artifacts list
```

---

### `r7-cli cnapp` — InsightCloudSec

Manages IaC scans, AWS access keys, AWS roles, AWS accounts, and findings via the InsightCloudSec v4 API.

| Command | Method | API Endpoint | Description |
|---------|--------|-------------|-------------|
| `cnapp iac-scans list` | GET | `/v4/iac/scans` | List IaC scans |
| `cnapp iac-scans get` | GET | `/v4/iac/scans/{id}` | Get an IaC scan |
| `cnapp iac-scans report` | GET | `/v4/iac/scans/{id}/report` | Get scan report |
| `cnapp aws-keys list` | GET | `/v4/configs/aws/accesskeys` | List AWS access keys |
| `cnapp aws-keys create` | POST | `/v4/configs/aws/accesskeys` | Create an access key |
| `cnapp aws-keys delete` | DELETE | `/v4/configs/aws/accesskeys/{id}` | Delete an access key |
| `cnapp aws-roles list` | GET | `/v4/configs/aws/roles` | List AWS roles |
| `cnapp aws-roles create` | POST | `/v4/configs/aws/roles` | Create a role |
| `cnapp aws-roles get` | GET | `/v4/configs/aws/roles/{id}` | Get a role |
| `cnapp aws-roles delete` | DELETE | `/v4/configs/aws/roles/{id}` | Delete a role |
| `cnapp aws-accounts get` | GET | `/v4/configs/aws/accounts/{org_service_id}` | Get AWS account |
| `cnapp aws-accounts delete` | DELETE | `/v4/configs/aws/accounts/{org_service_id}` | Delete AWS account |
| `cnapp findings list` | GET | `/v4/insights/findings-per-cloud/{org_service_id}` | List findings |

Base URL: `https://{R7_CLOUDSEC_URL}/v4` (default: `https://my.insightcloudsec.com/v4`)

```bash
r7-cli cnapp iac-scans list
r7-cli cnapp aws-keys list
r7-cli cnapp aws-roles list
r7-cli cnapp findings list -j <ORG_SERVICE_ID>
```

---

## Parquet Export & Local Filtering

The `vm export` commands download bulk data as Parquet files. The `vm export list` command operates entirely offline on local files — no API key needed.

Supported schemas: `asset`, `vulnerability`, `policy`, `remediation`

Features:
- Auto-detection of Parquet schema type
- Auto-join of asset data when vulnerability/policy files are present
- Glob pattern matching for string filters (`*`, `?` via fnmatch)
- Typed `--where` clauses with comparison operators (`>=`, `<=`, `>`, `<`, `=`, `!=`)
- `--only` to select specific columns

```bash
# Download vulnerability export
r7-cli vm export vulnerabilities --auto

# Filter locally
r7-cli vm export list --severity Critical --has-exploits true
r7-cli vm export list --hostname '*.prod.*' --where 'cvssScore>=9.0'
r7-cli vm export list --where 'riskScore>5000' --only hostname,ip,riskScore
r7-cli vm export list --files './exports/*.parquet'

# Policy-specific filters
r7-cli vm export list --benchmark-title 'CIS*' --rule-title '*password*'
```

## Output Formatting

```bash
# JSON (default)
r7-cli platform products list

# Table output
r7-cli -o table platform products list

# CSV / TSV
r7-cli -o csv vm scan-engines list
r7-cli -o tsv vm scan-engines list

# Compact single-line JSON (field priority reordering, terminal-width truncation)
r7-cli -s platform products list

# Limit results
r7-cli -l 5 vm scans list

# Search for a specific field across the response
r7-cli --search-fields status vm scans list
```

## Interactive Selection

Many commands support `-a`/`--auto` for interactive selection using terminal prompts (powered by questionary):

```bash
r7-cli vm scans get --auto
r7-cli vm scan-engines get --auto
r7-cli siem users get --auto
r7-cli appsec apps get --auto
```

## Polling Mode

Commands with `-a`/`--auto` combined with `-i`/`--interval` enter polling mode, re-fetching on an interval and printing only new entries:

```bash
r7-cli vm scans list -a -i 30
r7-cli siem investigations list -a -i 60
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests use Hypothesis property-based testing for the Parquet download logic.

## Project Structure

```
r7cli/                     # Package root (workspace root)
├── main.py                # CLI entry point, SolutionGroup, global options
├── cli_group.py           # GlobalFlagHintGroup (enforces global flag ordering)
├── config.py              # Config dataclass + resolve_config()
├── models.py              # Constants, URLs, GraphQL strings, exceptions
├── client.py              # R7Client (HTTP, auth, caching, rate-limit, logging)
├── output.py              # format_output() (json/table/csv/tsv/sql, short mode)
├── cache.py               # CacheStore (SHA-256-keyed JSON file cache)
├── jobs.py                # JobStore (export job persistence)
├── ask.py                 # Natural language → CLI command translation (LLM)
├── agents.py              # Cross-platform asset count command
├── extensions.py          # Extension Library browser (no auth)
├── compliance.py          # VM policy export → SQL dump pipeline
├── matrix.py              # NIST CSF × CIS v8 coverage matrix
├── cis.py                 # CIS/NIST CSF controls lookup (shared by per-solution cis subcommands)
├── controls.csv           # Master controls CSV (CIS, NIST CSF, PCI DSS, HITRUST, MITRE)
├── parquet_filter.py      # Parquet file resolution, filtering, auto-join
├── solutions/
│   ├── vm.py              # InsightVM
│   ├── siem.py            # InsightIDR
│   ├── asm.py             # Surface Command
│   ├── drp.py             # Digital Risk Protection
│   ├── platform.py        # Platform admin
│   ├── appsec.py          # InsightAppSec
│   ├── cnapp.py           # InsightCloudSec
│   ├── soar.py            # InsightConnect
│   ├── mcp.py             # Rapid7 Bulk Export MCP server integration
│   └── stub.py            # Stub group factory
├── tests/
│   └── test_download_mkdir.py
└── pyproject.toml
```

## License

See LICENSE file.
