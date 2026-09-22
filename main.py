#!/usr/bin/env python3
"""
Runs the full pipeline: discover + pull versions (aws_version_audit.py),
then enrich with EOL/compatibility/CVE data (vuln_lookup.py).

Usage:
    python3 main.py                                  # all accounts in ACCOUNTS
    python3 main.py --profile X --region eu-west-3 --label foo   # one account
    WPSCAN_API_TOKEN=xxx python3 main.py              # also pull WordPress core CVEs
"""

import argparse
import runpy
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent


def run_audit(argv: list[str]) -> None:
    sys.argv = ["aws_version_audit.py", *argv]
    runpy.run_path(str(SCRIPT_DIR / "aws_version_audit.py"), run_name="__main__")


def run_vuln_lookup() -> None:
    sys.argv = ["vuln_lookup.py"]
    runpy.run_path(str(SCRIPT_DIR / "vuln_lookup.py"), run_name="__main__")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", help="Only audit this single AWS profile")
    parser.add_argument("--region", default="eu-west-3")
    parser.add_argument("--label", help="Override the account label, auto-detected from AWS if omitted")
    args = parser.parse_args()

    audit_argv = []
    if args.profile:
        audit_argv = ["--profile", args.profile, "--region", args.region]
        if args.label:
            audit_argv += ["--label", args.label]

    print("### step 1/2: version audit ###")
    run_audit(audit_argv)

    print("\n### step 2/2: vuln / EOL enrichment ###")
    run_vuln_lookup()


if __name__ == "__main__":
    main()
