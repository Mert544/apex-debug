"""JSON reporter for machine-readable output."""

from __future__ import annotations

import json
from pathlib import Path

from apex_debug.core.finding import Finding


def generate_json(findings: list[Finding], pretty: bool = True) -> str:
    """Generate JSON from findings.

    Args:
        findings: List of findings
        pretty: If True, indent with 2 spaces

    Returns:
        JSON string
    """
    data = [f.model_dump(mode="json") for f in findings]
    if pretty:
        return json.dumps(data, indent=2, ensure_ascii=False)
    return json.dumps(data)


def save_json(findings: list[Finding], filepath: str) -> Path:
    """Save JSON report to disk.

    Args:
        findings: List of findings
        filepath: Output file path

    Returns:
        Path to the saved file
    """
    out = Path(filepath)
    report = generate_json(findings)
    out.write_text(report, encoding="utf-8")
    return out
