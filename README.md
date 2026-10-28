# Mini SOC Case System

Assignment 8 for Code:You SecOps. `soc_case_builder.py` pulls security artifacts from a Mockaroo API, groups them into cases, and writes `case_report.txt`.

A case is HIGH when it contains a hash, MEDIUM when it has an external IP or a suspicious domain (the name includes "login", "verify", or "secure"), and LOW otherwise. Printed summaries are sorted HIGH, then MEDIUM, then LOW.

## Setup

```bash
python3 -m pip install requests
export MOCKAROO_API_KEY="your_key_here"
```

The script reads `MOCKAROO_API_KEY` from the environment and exits if it is missing.

## Usage

```bash
python3 soc_case_builder.py
```

The report is written to `case_report.txt`.
