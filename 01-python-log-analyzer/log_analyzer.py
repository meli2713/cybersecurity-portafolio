
#!/usr/bin/env python3
"""Analyze authentication logs and report failed login attempts."""

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?.*? "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for .*? "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze_log(logfile):
    failed = Counter()
    successful = Counter()
    total_lines = 0

    with logfile.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            total_lines += 1

            match = FAILED_PATTERN.search(line)
            if match:
                failed[match.group("ip")] += 1
                continue

            match = SUCCESS_PATTERN.search(line)
            if match:
                successful[match.group("ip")] += 1

    return total_lines, failed, successful


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs."
    )
    parser.add_argument("logfile", type=Path, help="Log file to analyze")
    parser.add_argument("--out", type=Path, default=Path("reports"))
    parser.add_argument("--threshold", type=int, default=3)
    args = parser.parse_args()

    if not args.logfile.is_file():
        parser.error(f"File not found: {args.logfile}")

    if args.threshold < 1:
        parser.error("Threshold must be at least 1")

    total, failed, successful = analyze_log(args.logfile)
    args.out.mkdir(parents=True, exist_ok=True)

    flagged = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in failed.most_common()
        if count >= args.threshold
    ]

    summary = {
        "total_lines": total,
        "failed_attempts": sum(failed.values()),
        "successful_logins": sum(successful.values()),
        "flagged_sources": flagged,
        "note": "Repeated failures require investigation; they do not prove an attack."
    }

    (args.out / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    with (args.out / "failures_by_ip.csv").open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)
        writer.writerow(["ip", "failed_attempts"])
        writer.writerows(failed.most_common())

    print("Analysis complete")
    print(f"Log lines: {total}")
    print(f"Failed attempts: {sum(failed.values())}")
    print(f"Successful logins: {sum(successful.values())}")
    print(f"Reports saved to: {args.out}")


if __name__ == "__main__":
    main()

