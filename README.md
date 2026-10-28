# Mini SOC Case System

Code:You SecOps Assignment 8 — build SOC cases from security artifacts pulled via API.

## Description
Fetches artifact records from a Mockaroo endpoint, models them with Python classes/enums, groups artifacts into cases, recalculates severity (hash → HIGH; external IP / suspicious domain → MEDIUM; else LOW), sorts by severity, and writes a human-readable report.

## Technologies
- Python 3, `requests`, standard library (`enum`, `datetime`)

## Setup
```bash
python3 -m pip install requests
export MOCKAROO_API_KEY="your_key_here"
```

## Usage
```bash
python3 soc_case_builder.py
```
Output: `case_report.txt`

## Status
Completed course assignment.
