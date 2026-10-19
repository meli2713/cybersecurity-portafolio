# Python Authentication Log Analyzer

## Overview
A Python tool that analyzes authentication logs to identify repeated failed login attempts and summarize successful logins.

## Features
- Parses authentication log entries.
- Counts failed login attempts by source IP address.
- Identifies sources that meet a configurable threshold.
- Generates JSON and CSV reports.
- Uses sample data for safe practice.

## Technologies
- Python 3
- Regular expressions
- CSV and JSON
- Command-line arguments

## How to Run
```bash
python3 log_analyzer.py samples/auth.log --out reports
```

## Disclaimer
This project is for educational and defensive security purposes. Findings are indicators for investigation, not proof of malicious activity.
