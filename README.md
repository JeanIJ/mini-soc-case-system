# SOC Case Builder

Assignment 8 for Code:You SecOps Python course.

## What It Does

This script pulls security artifact data from a Mockaroo API, models it using Python classes, groups artifacts into cases, recalculates severity based on the type of evidence, and writes a human-readable report.

## API Endpoint

- **URL:** https://my.api.mockaroo.com/ironclad-soc-case-artifacts
- **Method:** GET
- **Key:** cf7bbbd0

## JSON Field Mapping

| API Field | Python Attribute | Description |
|-----------|-----------------|-------------|
|  |  | Groups artifacts into the same case |
|  |  | Type of evidence (ip, domain, file_hash) |
|  /  /  |  | The actual IOC value, pulled dynamically based on  |
|  |  | Analyst notes or context |

## Severity Rules

| Severity | Condition |
|----------|-----------|
| **HIGH** | Any  artifact present |
| **MEDIUM** | External IP or suspicious domain (contains "login", "verify", "secure") |
| **LOW** | Everything else |

## Challenges Completed

- **A:**  Enum — converts raw strings into typed enum values
- **B:**  rule — HIGH severity cases must go to  before closing
- **C:**  — returns deduplicated list of IOCs per case
- **D:** Sort cases by severity (HIGH → MEDIUM → LOW)
- **E:**  — calculates age since oldest artifact timestamp

## How to Run



## Output Files

-  — generated report with all case details
