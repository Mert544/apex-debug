"""Code style and quality patterns."""

from __future__ import annotations

import ast
from typing import Optional

from apex_debug.core.finding import Finding, Severity
from apex_debug.engine.patterns.base import AbstractPattern


class MissingDocstringPattern(AbstractPattern):
    name = "Missing docstring"
    description = "Detects public functions, classes, and methods without docstrings"
    severity = Severity.INFO
    category = "style"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                return findings
            if not self._has_docstring(node):
                snippet = ast.get_source_segment(source, node) or ""
                line = node.lineno
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=line,
                        column=node.col_offset,
                        message=f"Function '{node.name}()' is missing a docstring.",
                        snippet=snippet.split("\n")[0] if snippet else "",
                        confidence=1.0,
                    )
                )

        elif isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                return findings
            if not self._has_docstring(node):
                snippet = ast.get_source_segment(source, node) or ""
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        message=f"Class '{node.name}' is missing a docstring.",
                        snippet=snippet.split("\n")[0] if snippet else "",
                        confidence=1.0,
                    )
                )

        return findings

    def _has_docstring(self, node: ast.AST) -> bool:
        if not node.body:
            return False
        first = node.body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            return isinstance(first.value.value, str)
        return False


class LongFunctionPattern(AbstractPattern):
    name = "Function is too long"
    description = "Detects functions exceeding a configurable line count threshold"
    severity = Severity.INFO
    category = "style"
    _threshold = 50

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return findings

        if node.end_lineno is None:
            return findings

        length = node.end_lineno - node.lineno + 1
        if length > self._threshold:
            snippet = ast.get_source_segment(source, node) or ""
            findings.append(
                self._make_finding(
                    filepath=filepath,
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"Function '{node.name}()' is {length} lines long (threshold: {self._threshold}). Consider splitting into smaller functions.",
                    snippet=snippet.split("\n")[0] if snippet else "",
                    confidence=0.8,
                )
            )

        return findings


class TooManyArgumentsPattern(AbstractPattern):
    name = "Too many function arguments"
    description = "Detects functions with too many parameters (> 5)"
    severity = Severity.INFO
    category = "style"
    _threshold = 5

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return findings

        args = [a for a in node.args.args if a.arg != "self" and a.arg != "cls"]
        if len(args) > self._threshold:
            snippet = f"def {node.name}({', '.join(a.arg for a in node.args.args)})"
            findings.append(
                self._make_finding(
                    filepath=filepath,
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"Function '{node.name}()' has {len(args)} parameters (threshold: {self._threshold}). Consider using a dataclass or typed dict.",
                    snippet=snippet,
                    confidence=0.8,
                )
            )

        return findings


class DeadCodePattern(AbstractPattern):
    name = "Potentially unreachable code"
    description = "Detects code after return/raise/break/continue in the same block"
    severity = Severity.LOW
    category = "style"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not hasattr(node, "body"):
            return findings

        body = node.body
        for i, stmt in enumerate(body[:-1]):
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                next_stmt = body[i + 1]
                snippet = ast.get_source_segment(source, next_stmt) or ""
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=next_stmt.lineno,
                        column=next_stmt.col_offset,
                        message=f"Code after {type(stmt).__name__.lower()} will never be executed.",
                        snippet=snippet,
                        confidence=0.95,
                    )
                )

        return findings


class UnusedFunctionPattern(AbstractPattern):
    name = "Potentially unused function"
    description = "Detects module-level functions that are never called within the file"
    severity = Severity.INFO
    category = "style"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Module):
            return findings

        # Collect all function definitions and calls at module level
        defined: dict[str, ast.FunctionDef] = {}
        called: set[str] = set()

        for child in ast.walk(node):
            if isinstance(child, ast.FunctionDef):
                defined[child.name] = child
            elif isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    called.add(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    called.add(child.func.attr)

        # Find functions defined but never called (excluding __main__ guards)
        for name, func in defined.items():
            if name.startswith("_") or name in called:
                continue
            snippet = ast.get_source_segment(source, func) or ""
            findings.append(
                self._make_finding(
                    filepath=filepath,
                    line=func.lineno,
                    column=func.col_offset,
                    message=f"Function '{name}()' is defined but never called in this file. Consider removing if it's dead code.",
                    snippet=snippet.split("\n")[0] if snippet else "",
                    confidence=0.6,
                )
            )

        return findings
