# CN-AWS-FRR-Engine

Cloud Security Posture & Compliance Analyzer

Built for:
- Internal Penetration Testing
- AWS FRR Reviews
- PCI DSS Preparation
- CIS Benchmark Validation

# Author: Abhishek CN

## Installation

pip install -r requirements.txt

## Run Analysis

python engine.py input.xlsx output.xlsx

This generates:
- output.xlsx (Full FRR Report)
- dashboard.html (HTML Compliance Dashboard)

## Baseline Comparison

python baseline_compare.py old.xlsx new.xlsx diff.xlsx
