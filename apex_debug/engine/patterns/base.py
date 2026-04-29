"""Abstract pattern interface — each bug type is a plugin.

Patterns MUST work without any AI. They use:
1. Python's built-in `ast` module for .py files (always available)
2. tree-sitter for multi-language support (optional, graceful fallback)
3. Regex as universal last-resort fallback

A pattern is a self-contained detector for one category of bug.
"""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from typing import ClassVar, Optional

from apex_debug.core.finding import Finding, Severity


class AbstractPattern(ABC):
    """Base class for all bug detection patterns.

    Subclasses must define:
    - name, description, severity, category (class vars)
    - analyze_python_ast() — uses stdlib ast for .py files
    - get_treesitter_query() — returns query string for tree-sitter
    - get_regex() — returns (pattern, message_template) for regex fallback
    """

    name: ClassVar[str]
    description: ClassVar[str]
    severity: ClassVar[Severity]
    category: ClassVar[str]

    _counter: ClassVar[int] = 0

    def __init__(self) -> None:
        self._match_index = 0

    # -- AST-based detection (Python, always available) --

    @abstractmethod
    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        """Analyze a Python AST node. Called recursively by the pattern engine.

        Args:
            node: A Python AST node (Module, FunctionDef, Call, etc.)
            source: Full source code as string
            filepath: Relative file path

        Returns:
            List of Findings detected from this node.
        """
        ...

    # -- Tree-sitter query (multi-language, optional) --

    def get_treesitter_query(self) -> Optional[str]:
        """Return a tree-sitter query string, or None if not applicable.

        The query uses S-expression syntax:
            (call function: (identifier) @func (#match? @func "eval"))

        Returns:
            Tree-sitter query string or None.
        """
        return None

    def on_treesitter_match(
        self, captures: dict[str, list], source: bytes, filepath: str
    ) -> Optional[Finding]:
        """Handle a tree-sitter query match. Override for custom logic.

        Args:
            captures: Dict of capture_name -> list of captured nodes
            source: Source code as bytes
            filepath: File path

        Returns:
            A Finding or None.
        """
        return None

    # -- Regex fallback (all languages, always available) --

    def get_regex(self) -> Optional[tuple[str, str]]:
        """Return (regex_pattern, message_template) or None.

        message_template can use {line}, {file}, {match} placeholders.
        """
        return None

    # -- Helpers --

    def _next_id(self) -> str:
        AbstractPattern._counter += 1
        return f"{self.category[:3].upper()}-{AbstractPattern._counter:03d}"

    def _make_finding(
        self,
        filepath: str,
        line: int,
        message: str,
        snippet: str = "",
        column: int = 0,
        end_line: int = 0,
        end_column: int = 0,
        confidence: float = 1.0,
    ) -> Finding:
        return Finding(
            id=self._next_id(),
            file=filepath,
            line=line,
            column=column,
            end_line=end_line or line,
            end_column=end_column,
            severity=self.severity,
            category=self.category,
            title=self.name,
            message=message,
            snippet=snippet,
            confidence=confidence,
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} category={self.category} severity={self.severity.value}>"
