"""Plugin system for custom pattern loading.

Users can write their own patterns in Python files and Apex Debug
will discover and load them automatically.

Usage:
    Place custom pattern files in .apex-debug/plugins/
    or specify a custom plugin directory in config.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Optional

from apex_debug.engine.patterns.base import AbstractPattern


class PluginLoader:
    """Discover and load custom pattern plugins from directories.

    Usage:
        loader = PluginLoader()
        custom_patterns = loader.load_from_directory(".apex-debug/plugins/")
    """

    def __init__(self) -> None:
        self.loaded: list[AbstractPattern] = []

    def load_from_directory(self, plugin_dir: str | Path) -> list[AbstractPattern]:
        """Load all valid pattern plugins from a directory.

        Args:
            plugin_dir: Path to directory containing .py plugin files

        Returns:
            List of instantiated AbstractPattern subclasses
        """
        path = Path(plugin_dir)
        if not path.exists():
            return []

        patterns: list[AbstractPattern] = []
        for py_file in sorted(path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            result = self._load_file(py_file)
            patterns.extend(result)

        self.loaded.extend(patterns)
        return patterns

    def _load_file(self, filepath: Path) -> list[AbstractPattern]:
        """Load a single Python file and instantiate pattern classes."""
        patterns: list[AbstractPattern] = []

        try:
            spec = importlib.util.spec_from_file_location(
                filepath.stem, str(filepath)
            )
            if spec is None or spec.loader is None:
                return patterns

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            # Find all AbstractPattern subclasses in the module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, AbstractPattern)
                    and attr is not AbstractPattern
                    and not attr.__name__.startswith("_")
                ):
                    try:
                        instance = attr()
                        patterns.append(instance)
                    except Exception:
                        continue

        except Exception:
            pass

        return patterns

    @staticmethod
    def create_example_plugin(directory: str | Path) -> Path:
        """Create an example custom pattern plugin file.

        Returns:
            Path to the created example file
        """
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)

        example = path / "example_custom_pattern.py"
        example.write_text(
            '''"""Example custom pattern for Apex Debug.

Copy this file and modify it to add your own detection rules.
"""

import ast
from apex_debug.core.finding import Finding, Severity
from apex_debug.engine.patterns.base import AbstractPattern


class TodoFinderPattern(AbstractPattern):
    """Finds TODO comments in code."""

    name = "TODO comment found"
    description = "Detects TODO/FIXME comments that may indicate incomplete work"
    severity = Severity.INFO
    category = "style"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            return findings

        text = node.value.lower()
        if "todo" in text or "fixme" in text:
            findings.append(
                self._make_finding(
                    filepath=filepath,
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"TODO/FIXME comment found: {node.value[:60]}",
                    snippet=node.value[:80],
                    confidence=0.95,
                )
            )
        return findings
''',
            encoding="utf-8",
        )
        return example
