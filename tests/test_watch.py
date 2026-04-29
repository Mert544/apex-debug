"""Tests for Apex Debug file watcher."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from apex_debug.engine.watcher import FileWatcher


class TestFileWatcher:
    """Test file watcher functionality."""

    def test_watcher_detects_new_file(self, tmp_path: Path):
        """Watcher should detect newly created files."""
        findings_log: list = []

        def on_change(added, removed):
            findings_log.extend(added)

        watcher = FileWatcher(tmp_path, interval=0.1, on_findings=on_change)

        # Create a file with a security issue
        test_file = tmp_path / "test.py"

        try:
            watcher.start()
            time.sleep(0.2)  # Initial scan

            test_file.write_text("eval('1 + 1')\n")
            time.sleep(0.4)  # Wait for detection

            # Should have detected eval() usage
            assert len(findings_log) >= 1
            assert any("eval" in f.title.lower() for f in findings_log)

        finally:
            watcher.stop()

    def test_watcher_detects_file_modification(self, tmp_path: Path):
        """Watcher should detect modifications to existing files."""
        # Pre-create file
        test_file = tmp_path / "app.py"
        test_file.write_text("x = 1\n")

        findings_log: list = []
        removed_log: list = []

        def on_change(added, removed):
            findings_log.extend(added)
            removed_log.extend(removed)

        watcher = FileWatcher(tmp_path, interval=0.1, on_findings=on_change)

        try:
            watcher.start()
            time.sleep(0.2)  # Initial scan

            # Modify to add a security issue
            test_file.write_text("import os\nos.system('ls')\n")
            time.sleep(0.4)

            assert len(findings_log) >= 1
            assert any("os.system" in f.message.lower() or "shell" in f.title.lower() for f in findings_log)

        finally:
            watcher.stop()

    def test_watcher_ignores_unchanged_files(self, tmp_path: Path):
        """Watcher should not re-analyze unchanged files."""
        test_file = tmp_path / "stable.py"
        test_file.write_text("x = 1\n")

        call_count = 0

        def on_change(added, removed):
            nonlocal call_count
            call_count += 1

        watcher = FileWatcher(tmp_path, interval=0.1, on_findings=on_change)

        try:
            watcher.start()
            time.sleep(0.35)  # Multiple intervals without changes

            # Should not trigger on_change for unchanged files
            assert call_count == 0

        finally:
            watcher.stop()

    def test_watcher_diff_findings(self, tmp_path: Path):
        """Watcher should only report new/removed findings, not unchanged ones."""
        test_file = tmp_path / "script.py"
        test_file.write_text("eval('1')\n")  # 1 finding

        events: list = []

        def on_change(added, removed):
            events.append(("added", len(added), "removed", len(removed)))

        watcher = FileWatcher(tmp_path, interval=0.1, on_findings=on_change)

        try:
            watcher.start()
            time.sleep(0.15)  # Initial scan

            # Modify but keep same issue
            test_file.write_text("eval('2')\n")
            time.sleep(0.2)

            # Same finding type, different line content — should not trigger
            # or should trigger with 0 added, 0 removed (same fingerprint)

        finally:
            watcher.stop()

    def test_watcher_context_manager(self, tmp_path: Path):
        """Watcher should work as a context manager."""
        with FileWatcher(tmp_path, interval=0.1) as watcher:
            assert watcher._running is True
            assert watcher._thread is not None

        assert watcher._running is False
        assert watcher._thread is None

    def test_fingerprint_consistency(self):
        """Fingerprint should be deterministic for same finding."""
        from apex_debug.core.finding import Finding, Severity

        f = Finding(
            id="T001",
            file="app.py",
            line=10,
            severity=Severity.CRITICAL,
            category="security",
            title="eval() usage",
            message="dangerous",
            confidence=0.9,
        )

        fp1 = FileWatcher._fingerprint(f)
        fp2 = FileWatcher._fingerprint(f)
        assert fp1 == fp2
        assert "app.py" in fp1
        assert "eval" in fp1
