"""SARIF (Static Analysis Results Interchange Format) reporter.

Generates SARIF v2.1.0 output compatible with GitHub Code Scanning.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from apex_debug.core.finding import Finding


def generate_sarif(findings: list[Finding], tool_name: str = "ApexDebug") -> dict:
    """Generate a SARIF v2.1.0 document from findings.

    Args:
        findings: List of detected findings
        tool_name: Name of the tool in the SARIF output

    Returns:
        SARIF document as dict
    """
    results = []
    for f in findings:
        sev = f.severity.name.lower()
        sarif_level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

        results.append(
            {
                "ruleId": f.id,
                "level": sarif_level.get(sev, "warning"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column + 1,
                                "endLine": f.end_line or f.line,
                                "endColumn": (f.end_column or 0) + 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "category": f.category,
                    "title": f.title,
                    "confidence": f.confidence,
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://apex.debug",
                        "rules": [
                            {
                                "id": f.id,
                                "name": f.title,
                                "shortDescription": {"text": f.description if hasattr(f, "description") else f.title},
                                "defaultConfiguration": {
                                    "level": "error" if f.severity.value >= 3 else "warning"
                                },
                            }
                            for f in findings
                        ],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }


def save_sarif(findings: list[Finding], filepath: str) -> Path:
    """Save SARIF output to disk.

    Args:
        findings: List of findings
        filepath: Output file path (usually .sarif)

    Returns:
        Path to the saved file
    """
    out = Path(filepath)
    doc = generate_sarif(findings)
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return out
