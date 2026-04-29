#!/usr/bin/env python3
"""Pre-commit hook for Apex Debug.

Usage:
    Copy to .git/hooks/pre-commit and make executable:
        cp scripts/pre-commit.py .git/hooks/pre-commit
        chmod +x .git/hooks/pre-commit

    Or use with pre-commit framework:
        - repo: local
          hooks:
            - id: apex-debug
              name: Apex Debug Analysis
              entry: python scripts/pre-commit.py
              language: system
              pass_filenames: false
              always_run: true

Exits with non-zero code if CRITICAL or HIGH severity findings are found.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    """Run Apex Debug on staged Python files.

    Returns:
        0 if no critical/high findings, 1 otherwise
    """
    # Get staged Python files
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
    )

    staged = [f for f in result.stdout.strip().split("\n") if f.endswith(".py")]
    if not staged:
        print("Apex Debug: No staged Python files.")
        return 0

    print(f"Apex Debug: Analyzing {len(staged)} staged file(s)...")

    # Run apex-debug analyze on each staged file
    critical_count = 0
    high_count = 0

    for filepath in staged:
        if not Path(filepath).exists():
            continue

        output = subprocess.run(
            [sys.executable, "-m", "apex_debug.cli.app", "analyze", filepath, "--min-severity", "high"],
            capture_output=True,
            text=True,
        )

        # Count severities from output
        for line in output.stdout.splitlines():
            if "CRITICAL" in line:
                critical_count += 1
            elif "HIGH" in line:
                high_count += 1

    if critical_count > 0 or high_count > 0:
        print(f"\nApex Debug: Found {critical_count} CRITICAL and {high_count} HIGH issues.")
        print("Commit blocked. Fix security issues before committing.")
        print("Run 'apex-debug analyze <file>' for details.")
        return 1

    print("Apex Debug: No critical or high issues found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
