"""Baseline management for filtering known issues.

Allows saving current findings as a baseline and only reporting new ones.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from apex_debug.core.finding import Finding


class BaselineManager:
    """Manage baseline files to suppress known findings.

    Usage:
        manager = BaselineManager("apex-baseline.json")
        manager.save(session.findings)

        new_findings = manager.filter_new(session.findings)
    """

    def __init__(self, baseline_path: str | Path) -> None:
        self.path = Path(baseline_path)
        self._entries: set[str] = set()
        if self.path.exists():
            self._load()

    def _fingerprint(self, finding: Finding) -> str:
        """Stable fingerprint for a finding."""
        return f"{finding.file}:{finding.line}:{finding.title}"

    def _load(self) -> None:
        """Load baseline from disk."""
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._entries = set(data.get("findings", []))
        except (json.JSONDecodeError, OSError):
            self._entries = set()

    def save(self, findings: list[Finding]) -> None:
        """Save findings as the new baseline."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._entries = {self._fingerprint(f) for f in findings}
        data = {
            "version": 1,
            "findings": sorted(self._entries),
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def filter_new(self, findings: list[Finding]) -> list[Finding]:
        """Return only findings not present in the baseline."""
        return [f for f in findings if self._fingerprint(f) not in self._entries]

    def get_suppressed_count(self, findings: list[Finding]) -> int:
        """Count how many findings would be suppressed."""
        return sum(1 for f in findings if self._fingerprint(f) in self._entries)
