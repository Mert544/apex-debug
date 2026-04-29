"""Tests for baseline management."""

from __future__ import annotations

from pathlib import Path

import pytest

from apex_debug.core.finding import Finding, Severity
from apex_debug.engine.baseline import BaselineManager


class TestBaselineManager:
    """Test baseline filtering and persistence."""

    def _make_finding(self, file: str, line: int, title: str) -> Finding:
        return Finding(
            id="T001",
            file=file,
            line=line,
            severity=Severity.CRITICAL,
            category="security",
            title=title,
            message="test",
            confidence=0.9,
        )

    def test_save_and_load_baseline(self, tmp_path: Path):
        """Baseline should persist to disk and reload."""
        baseline_file = tmp_path / "baseline.json"
        bm = BaselineManager(baseline_file)

        findings = [
            self._make_finding("app.py", 10, "eval() usage"),
            self._make_finding("app.py", 20, "os.system() usage"),
        ]
        bm.save(findings)

        assert baseline_file.exists()

        # Reload from disk
        bm2 = BaselineManager(baseline_file)
        assert bm2.get_suppressed_count(findings) == 2

    def test_filter_new_findings(self, tmp_path: Path):
        """Only new findings not in baseline should be returned."""
        baseline_file = tmp_path / "baseline.json"
        bm = BaselineManager(baseline_file)

        old = self._make_finding("app.py", 10, "eval() usage")
        bm.save([old])

        new = self._make_finding("app.py", 30, "sql injection")
        result = bm.filter_new([old, new])

        assert len(result) == 1
        assert result[0].title == "sql injection"

    def test_empty_baseline_allows_all(self, tmp_path: Path):
        """Empty baseline should not suppress anything."""
        baseline_file = tmp_path / "baseline.json"
        bm = BaselineManager(baseline_file)

        findings = [self._make_finding("app.py", 1, "x")]
        assert bm.filter_new(findings) == findings
        assert bm.get_suppressed_count(findings) == 0

    def test_corrupted_baseline_graceful(self, tmp_path: Path):
        """Corrupted baseline file should behave like empty baseline."""
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text("not json{{{")

        bm = BaselineManager(baseline_file)
        findings = [self._make_finding("app.py", 1, "x")]
        assert bm.filter_new(findings) == findings
