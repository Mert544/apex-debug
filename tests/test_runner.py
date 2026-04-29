"""Tests for Apex Debug runner and config."""

from __future__ import annotations

from pathlib import Path

import pytest

from apex_debug.config import load_config, apply_config_to_session, find_project_root
from apex_debug.core.session import SessionConfig
from apex_debug.engine.runner import get_all_patterns, get_categories
from apex_debug.parsers.registry import ParserRegistry


class TestConfig:
    """Test configuration loading."""

    def test_load_default_config(self):
        config = load_config()
        assert "patterns" in config
        assert config["patterns"]["security"] is True

    def test_apply_config(self):
        cfg = {"patterns": {"security": False, "style": False}}
        session = SessionConfig(target=Path("."))
        apply_config_to_session(cfg, session)
        assert session.patterns_security is False
        assert session.patterns_style is False
        assert session.patterns_correctness is True  # unchanged

    def test_find_project_root_with_git(self, tmp_path: Path):
        (tmp_path / ".git").mkdir()
        found = find_project_root(tmp_path / "src")
        assert found == tmp_path

    def test_find_project_root_with_config(self, tmp_path: Path):
        (tmp_path / ".apex-debug.yaml").write_text("patterns:\n  security: true\n")
        found = find_project_root(tmp_path / "src" / "app.py")
        assert found == tmp_path


class TestRunner:
    """Test pattern engine runner."""

    def test_get_all_patterns(self):
        patterns = get_all_patterns()
        assert len(patterns) == 27
        categories = get_categories()
        assert len(categories) == 4
        assert len(categories["security"]) == 14
        assert len(categories["correctness"]) == 4
        assert len(categories["performance"]) == 4
        assert len(categories["style"]) == 5


class TestParser:
    """Test file parser registry."""

    def test_detect_python(self):
        reg = ParserRegistry()
        assert reg.detect_language(Path("app.py")) == "python"
        assert reg.detect_language(Path("script.pyi")) == "python"

    def test_detect_javascript(self):
        reg = ParserRegistry()
        assert reg.detect_language(Path("app.js")) == "javascript"
        assert reg.detect_language(Path("app.ts")) == "typescript"

    def test_is_supported(self):
        reg = ParserRegistry()
        assert reg.is_supported(Path("app.py")) is True
        assert reg.is_supported(Path("app.txt")) is False

    def test_discover_files(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("x = 1")
        (tmp_path / "b.js").write_text("var x = 1")
        (tmp_path / "readme.txt").write_text("hello")
        reg = ParserRegistry()
        files = reg.discover_files(tmp_path)
        assert len(files) == 2
        assert all(f.suffix in (".py", ".js") for f in files)

    def test_read_file(self, tmp_path: Path):
        (tmp_path / "test.py").write_text("# hello\n", encoding="utf-8")
        reg = ParserRegistry()
        content = reg.read_file(tmp_path / "test.py")
        assert content == "# hello\n"
