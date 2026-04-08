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

Verify the install:

```bash
r7-cli --help
```

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

Supported regions: `us`, `us1`, `us2`, `us3`, `ca`, `eu`, `au`, `ap`, `me-central-1`, `ap-south-2`

## Global Options

| Flag | Description |
|------|-------------|
| `-r, --region` | Region code (default: us) |
| `-k, --api-key` | API key (overrides env var) |
| `-o, --output` | Output format: `json`, `table`, `csv`, `tsv` |
| `-v, --verbose` | Log request/response info to stderr |
| `--debug` | Log full request/response bodies |
| `-c, --cache` | Use cached responses |
| `-l, --limit` | Limit the largest array in output |
| `-s, --short` | Compact single-line-per-object output |
| `-t, --timeout` | Request timeout in seconds (default: 30) |
| `--search-fields` | Search JSON response for a field name |

## Solutions

| Command | Description |
|---------|-------------|
| `vm` | InsightVM — health, scans, engines, exports, assets, vulns, sites |
| `siem` | InsightIDR — health, logs, agents, investigations, detections |
| `asm` | Surface Command — queries, connectors, execute |
| `drp` | Digital Risk Protection — alerts, threats, takedowns, risk score |
| `platform` | Platform — validate, search, users, orgs, products, roles |
| `cnapp` | InsightCloudSec |
| `appsec` | InsightAppSec |
| `soar` | InsightConnect — workflows, jobs, artifacts |
| `compliance` | VM policy export → SQL dump |
| `matrix` | NIST CSF × CIS v8 coverage matrix |

## Examples

### Validate your API key

```bash
r7-cli validate
```

### InsightVM

```bash
# Check VM health
r7-cli vm health

# List scan engines
r7-cli vm engines list

# List recent scans
r7-cli vm scans list --days 7

# Download all policy compliance data as SQL
r7-cli compliance
r7-cli compliance --sql-file policy_dump.sql
r7-cli -c compliance  # reuse cached parquet files

# Download policy data as TSV
r7-cli -o tsv compliance
```

### InsightIDR / SIEM

```bash
# Check IDR health metrics
r7-cli siem health

# List collectors
r7-cli siem collectors list

# List agents (via GraphQL)
r7-cli siem agents list
r7-cli siem agents list -l 50 --all-pages
r7-cli siem agents list -a -i 30  # poll for new agents

# List investigations
r7-cli siem investigations list --status OPEN --all-pages

# Query logs
r7-cli siem logs query -n "Asset Authentication"
```

### Surface Command / ASM

```bash
# List saved queries
r7-cli asm list

# Execute a Cypher query
r7-cli asm execute --query 'MATCH (a:Asset) RETURN a LIMIT 10'

# List connectors
r7-cli asm connectors list
```

### Digital Risk Protection

```bash
# Validate DRP credentials
r7-cli drp validate

# List alerts
r7-cli drp alerts list --severity High --days 30

# Check risk score
r7-cli drp risk-score --fail-above 7
```

### Platform

```bash
# List organizations
r7-cli platform orgs list

# List licensed products
r7-cli platform products list

# List users
r7-cli platform users list
```

### Security Coverage Matrix

```bash
# Show coverage matrix (checkmarks)
r7-cli matrix rapid7

# Show coverage percentages
r7-cli matrix rapid7 -p

# Show which products map to each cell
r7-cli matrix rapid7 --solution

# Adjust for actual deployment state
r7-cli matrix rapid7 --reality

# View scoring rules
r7-cli matrix rapid7 --scoring
```

### Output Formatting

```bash
# Table output
r7-cli -o table platform products list

# CSV output
r7-cli -o csv vm engines list

# Compact single-line JSON (truncated to terminal width)
r7-cli -s platform products list

# Limit results
r7-cli -l 5 vm scans list

# Search for a specific field
r7-cli --search-fields status vm scans list
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

See LICENSE file.
