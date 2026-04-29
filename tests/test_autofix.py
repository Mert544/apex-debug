"""Tests for auto-fix engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from apex_debug.engine.autofix import AutoFixer


class TestAutoFixer:
    """Test safe auto-fix transformations."""

    def test_fix_none_comparison(self):
        """== None should become is None."""
        fixer = AutoFixer()
        source = "if x == None:\n    pass\n"
        suggestions = fixer.analyze(source)

        assert len(suggestions) == 1
        assert "is None" in suggestions[0].replacement
        assert suggestions[0].line == 1

    def test_fix_not_none_comparison(self):
        """!= None should become is not None."""
        fixer = AutoFixer()
        source = "if x != None:\n    pass\n"
        suggestions = fixer.analyze(source)

        assert len(suggestions) == 1
        assert "is not None" in suggestions[0].replacement

    def test_fix_bare_except(self):
        """bare except: should become except Exception:."""
        fixer = AutoFixer()
        source = "try:\n    pass\nexcept:\n    pass\n"
        suggestions = fixer.analyze(source)

        assert len(suggestions) == 1
        assert "except Exception:" in suggestions[0].replacement

    def test_no_fix_for_is_none(self):
        """Already correct 'is None' should not be flagged."""
        fixer = AutoFixer()
        source = "if x is None:\n    pass\n"
        suggestions = fixer.analyze(source)

        assert len(suggestions) == 0

    def test_apply_fixes(self):
        """Apply should transform source correctly."""
        fixer = AutoFixer()
        source = "if x == None:\n    pass\n"
        suggestions = fixer.analyze(source)
        new_source = fixer.apply(source, suggestions)

        assert "is None" in new_source
        assert "== None" not in new_source

    def test_apply_to_file(self, tmp_path: Path):
        """Apply fixes to a real file."""
        fixer = AutoFixer()
        test_file = tmp_path / "test.py"
        test_file.write_text("if x == None:\n    pass\n")

        suggestions, new_source = fixer.apply_to_file(test_file, dry_run=False)

        assert len(suggestions) == 1
        assert "is None" in test_file.read_text()

    def test_dry_run_does_not_modify(self, tmp_path: Path):
        """Dry run should not modify the file."""
        fixer = AutoFixer()
        test_file = tmp_path / "test.py"
        original = "if x == None:\n    pass\n"
        test_file.write_text(original)

        suggestions, new_source = fixer.apply_to_file(test_file, dry_run=True)

        assert len(suggestions) == 1
        assert test_file.read_text() == original

    def test_fix_type_comparison(self):
        """type(x) == list should become isinstance(x, list)."""
        fixer = AutoFixer()
        source = "if type(x) == list:\n    pass\n"
        suggestions = fixer.analyze(source)

        assert len(suggestions) == 1
        assert "isinstance" in suggestions[0].replacement
