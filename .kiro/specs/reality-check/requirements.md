# Requirements Document

## Introduction

The `--reality` / `--deployment` option extends the existing `matrix rapid7` command to adjust coverage percentages based on the actual deployment state of infrastructure components. When enabled, the Matrix_Command queries Rapid7 deployment APIs to determine which components (scan engines, collectors, network sensors, honeypots, orchestrators) are deployed, reduces cell percentages for missing deployments, and prints actionable remediation items after the matrix.

## Glossary

- **Matrix_Command**: The `matrix rapid7` Click subcommand in `security_checklist.py` that renders a NIST CSF × CIS v8 coverage matrix.
- **CELL_PERCENT_MAPPING**: The static dictionary in `security_checklist.py` mapping each (NIST stage, CIS asset type) cell to a list of (product, percentage) tuples.
- **R7Client**: The HTTP client class in `client.py` that handles authenticated requests to Rapid7 APIs.
- **Scan_Engine**: A Rapid7 InsightVM scan engine registered via the IVM v4 scan engine API, excluding collectors.
- **Collector**: An InsightIDR collector reported by the IDR v1 health-metrics API with resource type `collectors`.
- **Network_Sensor**: An InsightIDR network sensor reported by the IDR v1 health-metrics API with resource type `network_sensors`.
- **Honeypot**: An InsightIDR honeypot reported by the IDR v1 health-metrics API with resource type `honeypots`.
- **Orchestrator**: An InsightIDR orchestrator reported by the IDR v1 health-metrics API with resource type `orchestrator`.
- **Deployment_Check**: A query to a Rapid7 API to determine whether a specific infrastructure component type has at least one deployed instance.
- **Reduction**: A percentage decrease applied to a product's contribution within a cell when its associated infrastructure component is not deployed.
- **Action_Item**: A remediation line printed after the matrix indicating which component to deploy and the coverage improvement it would provide.
- **IVM_V4_BASE**: The URL template `https://{region}.api.insight.rapid7.com/vm/v4` defined in `models.py`.
- **IDR_V1_BASE**: The URL template `https://{region}.api.insight.rapid7.com/idr/v1` defined in `models.py`.

## Requirements

### Requirement 1: Reality Flag Registration

**User Story:** As a CLI user, I want to pass `--reality` or `--deployment` to the matrix rapid7 command, so that I can see coverage adjusted for actual deployment state.

#### Acceptance Criteria

1. WHEN the `--reality` flag is passed to the Matrix_Command, THE Matrix_Command SHALL enable deployment-adjusted percentage mode.
2. WHEN the `--deployment` flag is passed to the Matrix_Command, THE Matrix_Command SHALL enable deployment-adjusted percentage mode identically to `--reality`.
3. WHEN `--reality` is passed without `--percent`, THE Matrix_Command SHALL implicitly enable percentage display mode.
4. WHEN `--reality` is passed together with `--solution`, THE Matrix_Command SHALL report an error indicating the two flags are mutually exclusive.

### Requirement 2: Scan Engine Deployment Check

**User Story:** As a CLI user, I want the tool to check whether scan engines are deployed, so that insightVM coverage reflects actual scanning capability.

#### Acceptance Criteria

1. WHEN `--reality` is enabled, THE Matrix_Command SHALL query `GET {IVM_V4_BASE}/integration/scan/engine` to retrieve the list of registered scan engines.
2. WHEN the scan engine API returns zero scan engines (excluding collectors), THE Matrix_Command SHALL record that scan engines are missing.
3. IF the scan engine API request fails, THEN THE Matrix_Command SHALL log a warning to stderr and treat scan engines as missing.

### Requirement 3: Collector Deployment Check

**User Story:** As a CLI user, I want the tool to check whether collectors are deployed, so that insightIDR coverage reflects actual log collection capability.

#### Acceptance Criteria

1. WHEN `--reality` is enabled, THE Matrix_Command SHALL query `GET {IDR_V1_BASE}/health-metrics` with resource type `collectors` to retrieve the list of deployed collectors.
2. WHEN the health-metrics API returns zero collectors, THE Matrix_Command SHALL record that collectors are missing.
3. IF the collector health-metrics API request fails, THEN THE Matrix_Command SHALL log a warning to stderr and treat collectors as missing.

### Requirement 4: Network Sensor Deployment Check

**User Story:** As a CLI user, I want the tool to check whether network sensors are deployed, so that insightIDR coverage reflects actual network monitoring capability.

#### Acceptance Criteria

1. WHEN `--reality` is enabled, THE Matrix_Command SHALL query `GET {IDR_V1_BASE}/health-metrics` with resource type `network_sensors` to retrieve the list of deployed network sensors.
2. WHEN the health-metrics API returns zero network sensors, THE Matrix_Command SHALL record that network sensors are missing.
3. IF the network sensor health-metrics API request fails, THEN THE Matrix_Command SHALL log a warning to stderr and treat network sensors as missing.

### Requirement 5: Honeypot Deployment Check

**User Story:** As a CLI user, I want the tool to check whether honeypots are deployed, so that insightIDR coverage reflects actual deception capability.

#### Acceptance Criteria

1. WHEN `--reality` is enabled, THE Matrix_Command SHALL query `GET {IDR_V1_BASE}/health-metrics` with resource type `honeypots` to retrieve the list of deployed honeypots.
2. WHEN the health-metrics API returns zero honeypots, THE Matrix_Command SHALL record that honeypots are missing.
3. IF the honeypot health-metrics API request fails, THEN THE Matrix_Command SHALL log a warning to stderr and treat honeypots as missing.

### Requirement 6: Orchestrator Deployment Check

**User Story:** As a CLI user, I want the tool to check whether an orchestrator is deployed, so that insightIDR DETECT coverage reflects actual orchestration capability.

#### Acceptance Criteria

1. WHEN `--reality` is enabled, THE Matrix_Command SHALL query `GET {IDR_V1_BASE}/health-metrics` with resource type `orchestrator` to retrieve the list of deployed orchestrators.
2. WHEN the health-metrics API returns zero orchestrators, THE Matrix_Command SHALL record that orchestrators are missing.
3. IF the orchestrator health-metrics API request fails, THEN THE Matrix_Command SHALL log a warning to stderr and treat orchestrators as missing.

### Requirement 7: Percentage Reduction for Missing Scan Engines

**User Story:** As a CLI user, I want insightVM cell percentages reduced when no scan engines are deployed, so that the matrix reflects reduced scanning coverage.

#### Acceptance Criteria

1. WHEN scan engines are missing, THE Matrix_Command SHALL reduce the percentage contribution of "insightVM" by 25% in every cell where "insightVM" appears in CELL_PERCENT_MAPPING.
2. THE Matrix_Command SHALL apply the 25% reduction to the product-level percentage before summing across products in the cell.

### Requirement 8: Percentage Reduction for Missing Collectors

**User Story:** As a CLI user, I want insightIDR cell percentages reduced when no collectors are deployed, so that the matrix reflects reduced detection coverage.

#### Acceptance Criteria

1. WHEN collectors are missing, THE Matrix_Command SHALL reduce the percentage contribution of "insightIDR" by 50% in every cell where "insightIDR" appears in CELL_PERCENT_MAPPING.
2. THE Matrix_Command SHALL apply the 50% reduction to the product-level percentage before summing across products in the cell.

### Requirement 9: Percentage Reduction for Missing Network Sensors

**User Story:** As a CLI user, I want insightIDR cell percentages reduced when no network sensors are deployed, so that the matrix reflects reduced network visibility.

#### Acceptance Criteria

1. WHEN network sensors are missing, THE Matrix_Command SHALL reduce the percentage contribution of "insightIDR" by 25% in every cell where "insightIDR" appears in CELL_PERCENT_MAPPING.
2. THE Matrix_Command SHALL apply the 25% reduction to the product-level percentage before summing across products in the cell.

### Requirement 10: Percentage Reduction for Missing Honeypots

**User Story:** As a CLI user, I want insightIDR cell percentages reduced when no honeypots are deployed, so that the matrix reflects reduced deception coverage.

#### Acceptance Criteria

1. WHEN honeypots are missing, THE Matrix_Command SHALL reduce the percentage contribution of "insightIDR" by 10% in every cell where "insightIDR" appears in CELL_PERCENT_MAPPING.
2. THE Matrix_Command SHALL apply the 10% reduction to the product-level percentage before summing across products in the cell.

### Requirement 11: Percentage Reduction for Missing Orchestrator

**User Story:** As a CLI user, I want insightIDR DETECT cell percentages reduced when no orchestrator is deployed, so that the matrix reflects reduced orchestration in detection.

#### Acceptance Criteria

1. WHEN the orchestrator is missing, THE Matrix_Command SHALL reduce the percentage contribution of "insightIDR" by 10% in every cell where "insightIDR" appears in CELL_PERCENT_MAPPING and the NIST stage is DETECT.
2. THE Matrix_Command SHALL apply the orchestrator reduction only to DETECT-stage cells, leaving other stages unaffected.

### Requirement 12: Reduction Stacking and Floor

**User Story:** As a CLI user, I want multiple reductions to stack correctly and never produce negative percentages, so that the matrix remains accurate and readable.

#### Acceptance Criteria

1. WHEN multiple deployment checks fail for the same product in the same cell, THE Matrix_Command SHALL sum the reduction percentages and apply the combined reduction to that product's contribution.
2. THE Matrix_Command SHALL clamp each product's reduced contribution to a minimum of 0%.
3. THE Matrix_Command SHALL clamp each cell's total percentage to a minimum of 0% and a maximum of 100%.

### Requirement 13: Action Items Output

**User Story:** As a CLI user, I want to see a list of action items after the matrix, so that I know which components to deploy to improve my coverage scores.

#### Acceptance Criteria

1. WHEN at least one Deployment_Check finds a missing component, THE Matrix_Command SHALL print a section titled "Action Items to Improve Coverage:" after the matrix output.
2. WHEN scan engines are missing, THE Matrix_Command SHALL print "Deploy scan engines to increase insightVM coverage by 25%".
3. WHEN collectors are missing, THE Matrix_Command SHALL print "Deploy collectors to increase insightIDR coverage by 50%".
4. WHEN network sensors are missing, THE Matrix_Command SHALL print "Deploy network sensors to increase insightIDR coverage by 25%".
5. WHEN honeypots are missing, THE Matrix_Command SHALL print "Deploy honeypots to increase insightIDR coverage by 10%".
6. WHEN the orchestrator is missing, THE Matrix_Command SHALL print "Deploy orchestrator to increase insightIDR DETECT coverage by 10%".
7. WHEN all deployment checks pass, THE Matrix_Command SHALL omit the action items section entirely.

### Requirement 14: Adjusted Matrix Display

**User Story:** As a CLI user, I want the adjusted matrix rendered in the same grid format as the standard percent mode, so that the output is consistent and familiar.

#### Acceptance Criteria

1. WHEN `--reality` is enabled, THE Matrix_Command SHALL render the adjusted percentages using the same `render_matrix` grid format used by `--percent`.
2. WHEN `--reality` is enabled, THE Matrix_Command SHALL print a descriptive header to stderr indicating that percentages are adjusted for deployment state.


## Post-Implementation Changes

- Additional deployment checks added beyond the original 5: event sources (no event sources → -75%, fewer than 5 → -50%), stale/offline agents (dynamic: 10% reduction per 10% unhealthy), active InsightConnect workflows (no workflows → -10% DETECT), Surface Command connectors (fewer than 5 third-party → -50%)
- `--scoring` flag added to print all scoring rules
- `build_recommendations()` added for product recommendations
