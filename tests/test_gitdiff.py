"""Tests for git diff integration."""

from __future__ import annotations

from apex_debug.core.finding import Finding, Severity
from apex_debug.engine.gitdiff import DiffHunk, _parse_diff, filter_findings_to_diff


class TestGitDiff:
    """Test git diff parsing and filtering."""

    def test_parse_simple_diff(self):
        """Parse a simple git diff with one added line."""
        diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10 +10 @@ def hello():
-    print("old")
+    print("new")
"""
        hunks = _parse_diff(diff)
        assert len(hunks) == 1
        assert hunks[0].filepath == "app.py"
        assert hunks[0].start_line == 10

    def test_parse_multiple_additions(self):
        """Parse diff with multiple added lines."""
        diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -5,0 +6,2 @@ def hello():
+    x = 1
+    y = 2
"""
        hunks = _parse_diff(diff)
        assert len(hunks) == 2
        assert hunks[0].start_line == 6
        assert hunks[1].start_line == 7

    def test_filter_findings_to_diff(self):
        """Only keep findings on changed lines."""
        hunks = [
            DiffHunk(filepath="app.py", start_line=10, lines=["eval('1')"]),
        ]
        findings = [
            Finding(id="T1", file="app.py", line=10, severity=Severity.CRITICAL, category="security", title="eval", message="x", confidence=0.9),
            Finding(id="T2", file="app.py", line=50, severity=Severity.CRITICAL, category="security", title="exec", message="x", confidence=0.9),
        ]
        filtered = filter_findings_to_diff(findings, hunks)
        assert len(filtered) == 1
        assert filtered[0].line == 10

    def test_empty_diff_returns_empty(self):
        """Empty diff should return no hunks."""
        hunks = _parse_diff("")
        assert hunks == []

    def test_diff_no_changes(self):
        """Diff with no additions should return empty."""
        diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10 +10 @@ def hello():
-    print("old")
     print("old")
"""
        hunks = _parse_diff(diff)
        # Only context line, no +
        assert len(hunks) == 0
