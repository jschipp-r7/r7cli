# Product Requirements Document: Cyber Matrix

## Overview

The Cyber Matrix is a feature of `r7-cli` that generates a **NIST CSF × CIS v8 defender coverage matrix** based on the Rapid7 products an organization is licensed for. It provides security teams with a visual representation of their cybersecurity coverage across six NIST Cybersecurity Framework stages and six CIS v8 asset types, identifying gaps and recommending products to improve posture.

The command is accessible at `r7-cli platform matrix`.

---

## Problem Statement

Security teams using multiple Rapid7 products lack a unified view of how their licensed toolset maps to industry-standard frameworks (NIST CSF and CIS v8). Without this visibility:

- Teams cannot quickly identify coverage gaps across their security program.
- Purchasing decisions for new products lack data-driven justification.
- Deployment deficiencies (missing collectors, sensors, etc.) silently degrade effective coverage without anyone noticing.
- There is no single command that answers "how well are we covered?" across the entire Rapid7 portfolio.

---

## Goals

1. **Visualize coverage**: Render a grid showing which NIST CSF stages × CIS v8 asset types are covered by the organization's licensed Rapid7 products.
2. **Quantify coverage**: Provide percentage-based scoring that reflects how much of each cell is addressed by licensed products.
3. **Reflect reality**: Optionally adjust scores based on actual deployment state (are collectors running? are sensors deployed?).
4. **Guide investment**: Recommend unlicensed products ranked by the coverage improvement they would provide.
5. **Drive remediation**: Surface actionable items for deployment gaps that reduce effective coverage.

---

## Users

| Persona | Use Case |
|---------|----------|
| Security Operations Manager | Assess overall program coverage, justify budget requests |
| CISO / Security Leader | Board-level reporting on framework alignment |
| Security Engineer | Identify deployment gaps degrading coverage |
| Compliance Analyst | Map licensed products to NIST CSF and CIS v8 controls |
| Sales Engineer / CSM | Demonstrate coverage value of Rapid7 portfolio to prospects/customers |

---

## Matrix Structure

### Axes

| Axis | Values |
|------|--------|
| **X-axis (columns)** — NIST CSF Stages | GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER |
| **Y-axis (rows)** — CIS v8 Asset Types | DEVICES, SOFTWARE, NETWORK, USERS, DATA, DOCUMENTATION |

### Cell Semantics

Each cell in the 6×6 grid maps to a set of Rapid7 products that provide coverage for that intersection. A cell can be:

- **Covered** — at least one mapped product is licensed
- **Not Covered** — products exist for this cell but none are licensed
- **Not Applicable** — no Rapid7 product maps to this cell (e.g., RECOVER stage)

---

## Product-to-Cell Mapping

The following Rapid7 products are mapped across the matrix:

| Product | License Code | Primary Coverage Areas |
|---------|-------------|----------------------|
| Surface Command | SC | IDENTIFY (devices, software, network, users), PROTECT (software, users) |
| insightVM | IVM | IDENTIFY (devices, software, network), PROTECT (devices, software, network, users) |
| insightIDR | IDR / OPS | IDENTIFY (devices, users), DETECT (all), RESPOND (all) |
| insightCloudSec | ICS | IDENTIFY (devices, software, users), PROTECT (devices, software, network, users, data) |
| insightAppSec | AS | IDENTIFY (software), PROTECT (software) |
| SOAR (InsightConnect) | ICON | RESPOND (all) |
| DRP (Threat Command) | TC / IH | DETECT (devices, software, network, users, data), RESPOND (network) |
| MDR | MDR | DETECT (all), RESPOND (all) |
| Cyber GRC | CGRC | GOVERN (all), PROTECT (documentation), DETECT (documentation), RESPOND (documentation) |
| DSPM | DSPM | IDENTIFY (data), PROTECT (data) |
| Vector Command | CAS | (mapped in PROTECT software) |

Each product carries a **percentage weight** per cell reflecting its contribution depth. Percentages are summed for licensed products and capped at 100%.

---

## Display Modes

### Default Mode (Checkmarks)

Shows ✅ for covered cells, 🚫 for uncovered cells, and N/A for cells with no product mapping.

```
r7-cli platform matrix
```

### Percentage Mode (`--percent` / `-p`)

Shows the summed coverage percentage for each cell based on licensed products.

```
r7-cli platform matrix -p
```

### Solution Mode (`--solution`)

Shows the Rapid7 product names mapped to each cell regardless of licensing.

```
r7-cli platform matrix --solution
```

### Reality Mode (`--reality` / `--deployment`)

Adjusts percentages based on actual deployment state by querying Rapid7 APIs. Implies `--percent`.

```
r7-cli platform matrix --reality
```

### JSON Output (`--json`)

Outputs the matrix as a JSON array for programmatic consumption.

```
r7-cli platform matrix --json
```

### Scoring Rules (`--scoring`)

Prints the complete scoring methodology and exits.

```
r7-cli platform matrix --scoring
```

---

## Deployment-Aware Scoring (Reality Mode)

When `--reality` is enabled, the command queries live APIs to determine which infrastructure components are actually deployed, then applies percentage reductions to products with missing components.

### Deployment Checks

| Component | API Queried | Product Affected | Reduction if Missing |
|-----------|-------------|-----------------|---------------------|
| Scan engines | `GET /vm/v4/integration/scan/engine` | insightVM | -25% (all cells) |
| Collectors | `GET /idr/v1/health-metrics?resourceTypes=collectors` | insightIDR | -50% (all cells) |
| Network sensors | `GET /idr/v1/health-metrics?resourceTypes=network_sensors` | insightIDR | -25% (all cells) |
| Honeypots | `GET /idr/v1/health-metrics?resourceTypes=honeypots` | insightIDR | -10% (all cells) |
| Orchestrator | `GET /idr/v1/health-metrics?resourceTypes=orchestrator` | insightIDR | -10% (DETECT only) |
| Event sources (0) | `GET /idr/v1/health-metrics?resourceTypes=event_sources` | insightIDR | -75% (all cells) |
| Event sources (<5) | `GET /idr/v1/health-metrics?resourceTypes=event_sources` | insightIDR | -50% (all cells) |
| SC connectors (<5 third-party) | `POST /surface/graph-api/objects/table` (Cypher) | Surface Command | -50% (all cells) |
| Stale/offline agents | `GET /idr/v1/health-metrics` (agent summary) | insightIDR | -10% per 10% unhealthy |
| No active ICON workflows | `GET /connect/v2/workflows?state=active` | insightIDR | -10% (DETECT only) |

### Reduction Rules

- Reductions are applied at the **product level** before summing across products in a cell.
- Multiple reductions for the same product **stack additively**.
- Product contributions are **floored at 0%**.
- Cell totals are **clamped to [0%, 100%]**.
- If an API check fails, the component is treated as missing (conservative approach) and a warning is logged to stderr.

### Connector Exclusions

When counting Surface Command connectors, the following are excluded (case-insensitive): "Built-in", "Rapid7", "EASM". Only third-party connectors count toward the threshold of 5.

### Agent Health Calculation

The stale/offline agent reduction is dynamic: for every 10% of total agents that are stale or offline, insightIDR coverage is reduced by 10% across all cells.

---

## Recommendations Engine

After rendering the matrix, the command outputs product recommendations for unlicensed products that would improve coverage:

- **In default mode**: Products are ranked by the number of new cells they would flip from 🚫 to ✅.
- **In percent mode**: Products are ranked by total percentage points they would add across all cells.

Only products that would produce a non-zero improvement are shown.

---

## Action Items

When `--reality` is enabled and deployment gaps are detected, the command prints an "Action Items to Improve Coverage" section listing specific remediation steps:

| Missing Component | Action Item |
|-------------------|-------------|
| Scan engines | Deploy scan engines to increase insightVM coverage by 25% |
| Collectors | Deploy collectors to increase insightIDR coverage by 50% |
| Network sensors | Deploy network sensors to increase insightIDR coverage by 25% |
| Honeypots | Deploy honeypots to increase insightIDR coverage by 10% |
| Orchestrator | Deploy orchestrator to increase insightIDR DETECT coverage by 10% |
| SC connectors | Deploy at least 5 third-party connectors in Surface Command to increase coverage by 50% |
| No event sources | Enable event sources in InsightIDR to increase coverage by 75% |
| Few event sources | Enable at least 5 event sources in InsightIDR to increase coverage by 50% |
| Stale/offline agents | Remediate stale/offline agents to increase insightIDR coverage |
| No active workflows | Enable active workflows in InsightConnect to increase insightIDR DETECT coverage by 10% |

---

## Functional Requirements

### FR-1: License Resolution

The command SHALL query `GET /account/api/1/products` to retrieve the organization's licensed product codes and resolve them to canonical product names using the product code mapping.

### FR-2: Matrix Rendering

The command SHALL render a 6×6 grid with NIST CSF stages as columns and CIS v8 asset types as rows, using the `tabulate` library in grid format.

### FR-3: Mutual Exclusivity

- `--percent` and `--solution` are mutually exclusive.
- `--reality` and `--solution` are mutually exclusive.
- `--reality` implies `--percent`.

### FR-4: Deployment Checks (Reality Mode)

When `--reality` is enabled, the command SHALL query each deployment API, record presence/absence of each component, compute reductions, and apply them to the percentage mapping before rendering.

### FR-5: Graceful Degradation

If any deployment API call fails, the command SHALL log a warning to stderr and treat the component as missing (conservative scoring). The matrix SHALL still render.

### FR-6: Recommendations

After the matrix, the command SHALL compute and display product recommendations for unlicensed products that would improve coverage, ranked by impact.

### FR-7: Action Items

When `--reality` detects missing components, the command SHALL print actionable remediation items after the matrix and recommendations.

### FR-8: JSON Output

When `--json` is passed, the command SHALL output the matrix as a JSON array of objects (one per row) with keys for `asset_type` and each NIST stage in lowercase.

### FR-9: Scoring Documentation

When `--scoring` is passed, the command SHALL print the complete scoring methodology and exit without querying any APIs.

---

## Non-Functional Requirements

### NFR-1: Performance

- Default and percent modes require a single API call (products list).
- Reality mode requires up to 7 additional API calls (scan engines, 4× health-metrics, SC connectors, ICON workflows).
- All API calls use the shared `R7Client` with timeout, retry, and caching support.

### NFR-2: Output Consistency

- Matrix output goes to stdout.
- Descriptive headers, action items, and warnings go to stderr.
- This separation allows piping matrix output to files or other tools.

### NFR-3: Offline Support

- With `-c` (cache mode), the command uses cached API responses without making live calls.
- `--scoring` requires no API calls at all.
- `--solution` mode requires no API calls (shows static mappings).

### NFR-4: Authentication

- Requires a valid Rapid7 API key for all modes except `--scoring` and `--solution`.
- Reality mode additionally requires permissions for IVM, IDR, Surface Command, and InsightConnect APIs.

---

## CLI Interface

```
r7-cli platform matrix [OPTIONS]

Options:
  -p, --percent                Show coverage percentages instead of checkmarks
  --solution                   Show Rapid7 solution names mapped to each cell
  --reality / --no-reality     Adjust percentages based on actual deployment state
  --deployment / --no-deployment  Alias for --reality
  --scoring                    Print the scoring rules and exit
  --json                       Output the matrix as JSON
  -h, --help                   Show help and exit
```

The `rapid7` subcommand is retained as a backward-compatible alias:

```
r7-cli platform matrix rapid7 [OPTIONS]
```

---

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `click` | CLI framework, option parsing, context passing |
| `httpx` | HTTP client (via R7Client) for API calls |
| `tabulate` | Grid-format table rendering |

---

## Future Considerations

- **Historical tracking**: Store matrix snapshots over time to show coverage trend.
- **Additional deployment checks**: Response Policies (RP), NGAV, Cloud Harvesters (APIs not yet available).
- **Custom weighting**: Allow organizations to override default percentage weights.
- **Export formats**: PDF or HTML report generation for executive reporting.
- **Integration with compliance**: Cross-reference matrix cells with specific CIS controls from `controls.csv`.
- **Vector Command and Active Patching**: Expand PROTECT SOFTWARE cell with additional products as APIs become available.
