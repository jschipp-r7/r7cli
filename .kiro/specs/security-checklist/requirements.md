# Requirements Document

## Introduction

Add a top-level `security-checklist` command to the r7-cli tool, invoked as `r7-cli security-checklist`. The command fetches the user's licensed Rapid7 products from the Insight Platform account API, maps them against a predefined matrix of NIST CSF stages (columns) and CIS v8 asset types (rows), and renders an ASCII matrix to stdout. Each cell displays a green checkmark (✅) when the user has at least one required product licensed, a red prohibited sign (🚫) when no required product is licensed, or N/A when no product mapping exists for that cell.

## Glossary

- **CLI**: The `r7-cli` Click-based command-line application whose entry point is the `SolutionGroup` multi-command in `main.py`.
- **Security_Checklist_Command**: The new top-level Click command registered as `security-checklist` on the root `SolutionGroup`.
- **Products_API**: The Insight Platform endpoint at `https://{region}.api.insight.rapid7.com/account/api/1/products` that returns the user's licensed products as a JSON array.
- **Product_Record**: A single JSON object returned by the Products_API, containing at minimum `product_code` (string) and `product_token` (string).
- **Product_Code_Map**: A static lookup table mapping product codes (e.g. `"SC"`, `"IVM"`, `"IDR"`) to canonical product names (e.g. `"Surface Command"`, `"insightVM"`, `"insightIDR"`).
- **Cell_Mapping**: A static lookup table mapping each (NIST_Stage, CIS_Asset_Type) pair to a set of product names required for coverage, or `None`/`N/A` when no product applies.
- **NIST_Stage**: One of the six NIST Cybersecurity Framework function stages used as matrix columns: GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER.
- **CIS_Asset_Type**: One of the six CIS Controls v8 asset categories used as matrix rows: DEVICES, SOFTWARE, NETWORK, USERS, DATA, DOCUMENTATION.
- **Coverage_Matrix**: The rendered ASCII table showing coverage status for each (NIST_Stage, CIS_Asset_Type) cell.
- **R7Client**: The HTTP client class in `client.py` used for all API communication.
- **Config**: The resolved runtime configuration dataclass from `config.py`.
- **SolutionGroup**: The Click `MultiCommand` in `main.py` that dispatches to per-solution command groups and top-level commands.

## Requirements

### Requirement 1: Register the Security Checklist Command

**User Story:** As a CLI user, I want to invoke `r7-cli security-checklist` as a top-level command, so that I can view my product coverage against NIST CSF and CIS v8 frameworks.

#### Acceptance Criteria

1. THE SolutionGroup SHALL list `security-checklist` among its available commands.
2. WHEN a user invokes `r7-cli security-checklist`, THE CLI SHALL execute the Security_Checklist_Command.
3. THE Security_Checklist_Command SHALL accept the same global flags (region, api-key, verbose, debug, cache, timeout) as other top-level commands.
4. WHEN a user invokes `r7-cli security-checklist --help`, THE CLI SHALL display usage information describing the command purpose and available options.

### Requirement 2: Fetch Licensed Products

**User Story:** As a CLI user, I want the command to automatically retrieve my licensed Rapid7 products, so that the matrix reflects my actual entitlements.

#### Acceptance Criteria

1. WHEN the Security_Checklist_Command is executed, THE Security_Checklist_Command SHALL send a GET request to the Products_API using the configured region and API key.
2. WHEN the Products_API returns a JSON array of Product_Records, THE Security_Checklist_Command SHALL extract the `product_code` field from each record.
3. THE Security_Checklist_Command SHALL resolve each extracted product code to a canonical product name using the Product_Code_Map.
4. WHEN a product code is not present in the Product_Code_Map, THE Security_Checklist_Command SHALL ignore that product code and continue processing the remaining codes.

### Requirement 3: Product Code to Name Mapping

**User Story:** As a developer, I want a well-defined static mapping from product codes to product names, so that the matrix logic can determine coverage accurately.

#### Acceptance Criteria

1. THE Product_Code_Map SHALL contain the following mappings: "SC" to "Surface Command", "ICS" to "insightCloudSec", "IVM" to "insightVM", "IDR" to "insightIDR", "OPS" to "insightIDR", "ICON" to "insightConnect", "TC" to "ThreatCommand", "AS" to "insightAppSec", "MDR" to "MDR", "DSPM" to "DSPM", "CGRC" to "Cyber GRC".
2. THE Product_Code_Map SHALL map both "IDR" and "OPS" product codes to the same canonical name "insightIDR".
3. THE Product_Code_Map SHALL be defined as a static constant, not fetched from an external source.

### Requirement 4: Cell Coverage Mapping

**User Story:** As a developer, I want a well-defined static mapping from (NIST_Stage, CIS_Asset_Type) pairs to required products, so that each cell in the matrix can be evaluated.

#### Acceptance Criteria

1. THE Cell_Mapping SHALL define required products for all 36 cells (6 NIST stages × 6 CIS asset types).
2. THE Cell_Mapping SHALL map the GOVERN column to "Cyber GRC" for DEVICES, SOFTWARE, NETWORK, USERS, DATA, and DOCUMENTATION rows.
3. THE Cell_Mapping SHALL map the IDENTIFY column as follows: DEVICES to "Surface Command"; SOFTWARE to "insightVM" and "Surface Command"; NETWORK to "insightVM" and "Surface Command"; USERS to "Surface Command"; DATA to "DSPM".
4. THE Cell_Mapping SHALL leave IDENTIFY-DOCUMENTATION as N/A (no product mapping).
5. THE Cell_Mapping SHALL map the PROTECT column as follows: DEVICES to "insightVM" and "insightCloudSec"; SOFTWARE to "insightVM", "insightAppSec", "insightCloudSec", and "Surface Command"; NETWORK to "insightVM" and "insightCloudSec"; USERS to "insightVM", "insightCloudSec", and "Surface Command"; DATA to "DSPM"; DOCUMENTATION to "Cyber GRC".
6. THE Cell_Mapping SHALL map the DETECT column to "insightIDR" and "MDR" for DEVICES, SOFTWARE, NETWORK, USERS, and DATA rows, and to N/A for DOCUMENTATION.
7. THE Cell_Mapping SHALL map the RESPOND column to "insightIDR" and "MDR" for DEVICES, SOFTWARE, NETWORK, USERS, and DATA rows, and to N/A for DOCUMENTATION.
8. THE Cell_Mapping SHALL map all six RECOVER column cells to None (no product exists).
9. THE Cell_Mapping SHALL be defined as a static constant, not fetched from an external source.

### Requirement 5: Evaluate Cell Coverage

**User Story:** As a CLI user, I want each cell evaluated against my licensed products, so that I can see where I have coverage and where I have gaps.

#### Acceptance Criteria

1. WHEN a cell's required product set contains at least one product that matches a product in the user's licensed product set, THE Security_Checklist_Command SHALL mark that cell as covered.
2. WHEN a cell's required product set contains products but none match the user's licensed product set, THE Security_Checklist_Command SHALL mark that cell as not covered.
3. WHEN a cell's mapping is N/A (no product mapping exists), THE Security_Checklist_Command SHALL mark that cell as not applicable.
4. WHEN a cell's mapping is None (no product exists for that cell), THE Security_Checklist_Command SHALL mark that cell as not applicable.

### Requirement 6: Render the ASCII Coverage Matrix

**User Story:** As a CLI user, I want the coverage results displayed as a readable ASCII matrix, so that I can quickly assess my security posture.

#### Acceptance Criteria

1. THE Security_Checklist_Command SHALL render the Coverage_Matrix with NIST_Stage values as column headers in the order: GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER.
2. THE Security_Checklist_Command SHALL render the Coverage_Matrix with CIS_Asset_Type values as row labels in the order: DEVICES, SOFTWARE, NETWORK, USERS, DATA, DOCUMENTATION.
3. WHEN a cell is marked as covered, THE Security_Checklist_Command SHALL display the ✅ character (U+2705) in that cell.
4. WHEN a cell is marked as not covered, THE Security_Checklist_Command SHALL display the 🚫 character (U+1F6AB) in that cell.
5. WHEN a cell is marked as not applicable, THE Security_Checklist_Command SHALL display "N/A" in bold white text in that cell.
6. THE Security_Checklist_Command SHALL render the matrix using the `tabulate` library with a grid format to produce aligned columns and row separators.
7. THE Security_Checklist_Command SHALL write the rendered matrix to stdout.

### Requirement 7: Cache Support

**User Story:** As a CLI user, I want to reuse a previously fetched product list when using the `--cache` flag, so that I can re-render the matrix without making an API call.

#### Acceptance Criteria

1. WHEN the global `--cache` flag is set AND a cached response exists for the Products_API request, THE Security_Checklist_Command SHALL use the cached product list instead of making a live API call.
2. WHEN the global `--cache` flag is not set, THE Security_Checklist_Command SHALL always make a live API call to the Products_API.
3. THE Security_Checklist_Command SHALL rely on the existing R7Client caching mechanism for cache storage and retrieval.

### Requirement 8: Error Handling

**User Story:** As a CLI user, I want clear error messages when something goes wrong, so that I can diagnose and fix issues.

#### Acceptance Criteria

1. IF the API key is missing or unauthorized, THEN THE Security_Checklist_Command SHALL display the same authentication error messages used by other CLI commands and exit with code 2.
2. IF a network error occurs during the Products_API call, THEN THE Security_Checklist_Command SHALL print the network error to stderr and exit with code 3.
3. IF the Products_API returns an unexpected response format (not a JSON array), THEN THE Security_Checklist_Command SHALL print a descriptive error to stderr and exit with code 2.

### Requirement 9: Coverage Evaluation Correctness

**User Story:** As a developer, I want confidence that the coverage evaluation logic is correct for all possible combinations of licensed products and cell mappings.

#### Acceptance Criteria

1. FOR ALL subsets of the Product_Code_Map values as the user's licensed products, evaluating coverage for every cell SHALL produce "covered" only when the intersection of the cell's required products and the licensed products is non-empty.
2. FOR ALL subsets of the Product_Code_Map values as the user's licensed products, evaluating coverage for every cell SHALL produce "not covered" only when the cell has required products and the intersection with the licensed products is empty.
3. FOR ALL cells where the Cell_Mapping value is None or N/A, evaluating coverage SHALL produce "not applicable" regardless of the user's licensed products.
4. FOR ALL valid product code lists returned by the Products_API, resolving codes through the Product_Code_Map and then evaluating coverage SHALL produce the same result as directly evaluating with the corresponding canonical product names (round-trip property through code resolution).


## Post-Implementation Changes

- Module renamed from `security_checklist.py` to `matrix.py`
- Command moved from top-level `r7-cli security-checklist` to `r7-cli platform matrix`
- Product code map updated: "IH" and "TC" both map to "DRP", "CAS" maps to Vector Command
- Cell mappings updated with DRP in DETECT/RESPOND, percentages added to cells
- `--scoring` flag added to print scoring rules
- `--solution` flag added to show product names per cell
- `build_recommendations()` function added for product recommendations
- Backward-compat alias `security_checklist = matrix` removed
- Per-solution `cis` subcommand added to every solution group (vm, siem, asm, drp, appsec, cnapp, soar) via `cis.make_cis_command()` — lists CIS/NIST CSF controls relevant to each product from `controls.csv`
