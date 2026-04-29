"""Logic error and correctness bug detection patterns."""

from __future__ import annotations

import ast
from typing import Optional

from apex_debug.core.finding import Finding, Severity
from apex_debug.engine.patterns.base import AbstractPattern


class BareExceptPattern(AbstractPattern):
    name = "Bare except clause"
    description = "Detects bare 'except:' clauses that catch all exceptions including SystemExit and KeyboardInterrupt"
    severity = Severity.MEDIUM
    category = "correctness"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.ExceptHandler):
            return findings

        if node.type is None:
            snippet = ast.get_source_segment(source, node) or ""
            findings.append(
                self._make_finding(
                    filepath=filepath,
                    line=node.lineno,
                    column=node.col_offset,
                    end_line=node.end_lineno or node.lineno,
                    message="Bare except catches all exceptions including SystemExit and KeyboardInterrupt. Use 'except Exception:' instead.",
                    snippet=snippet,
                    confidence=0.95,
                )
            )

        return findings

    def get_treesitter_query(self) -> str:
        return '(except_clause (_) @body (#not-has-type? @body))'

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (r"^\s*except\s*:", "bare except clause")


class NoneComparisonPattern(AbstractPattern):
    name = "Equality comparison with None"
    description = "Detects '== None' instead of 'is None'"
    severity = Severity.LOW
    category = "correctness"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Compare):
            return findings

        for op in node.ops:
            if isinstance(op, ast.Eq) or isinstance(op, ast.NotEq):
                for comparator in node.comparators:
                    if isinstance(comparator, ast.Constant) and comparator.value is None:
                        snippet = ast.get_source_segment(source, node) or ""
                        findings.append(
                            self._make_finding(
                                filepath=filepath,
                                line=node.lineno,
                                column=node.col_offset,
                                end_line=node.end_lineno or node.lineno,
                                message="Use 'is None' instead of '== None'. The 'is' operator checks identity, which is the correct way to compare with None.",
                                snippet=snippet,
                                confidence=1.0,
                            )
                        )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (r"(?:==|!=)\s*None", "use 'is None' instead of '== None'")


class TypeComparisonPattern(AbstractPattern):
    name = "Type comparison with =="
    description = "Detects 'type(x) == Y' instead of 'isinstance(x, Y)'"
    severity = Severity.LOW
    category = "correctness"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Compare):
            return findings

        # Check if left side is type() call
        if not isinstance(node.left, ast.Call):
            return findings
        if not (isinstance(node.left.func, ast.Name) and node.left.func.id == "type"):
            return findings

        # Check if any comparator is used with == or !=
        for op in node.ops:
            if isinstance(op, (ast.Eq, ast.NotEq)):
                snippet = ast.get_source_segment(source, node) or ""
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        end_line=node.end_lineno or node.lineno,
                        message="Use isinstance() instead of type() == . isinstance() respects inheritance and is the Pythonic way to check types.",
                        snippet=snippet,
                        confidence=0.9,
                    )
                )
                break

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (r"type\s*\([^)]+\)\s*(?:==|!=)\s*\w+", "use isinstance() instead of type() == ")


class UnusedVariablePattern(AbstractPattern):
    name = "Potentially unused variable"
    description = "Detects variables assigned but never used in local scope"
    severity = Severity.INFO
    category = "correctness"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.FunctionDef):
            return findings

        assigned: set[str] = set()
        used: set[str] = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if isinstance(child.ctx, ast.Store):
                    assigned.add(child.id)
                elif isinstance(child.ctx, ast.Load):
                    used.add(child.id)

        unused = assigned - used
        for var_name in sorted(unused):
            if var_name.startswith("_"):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id == var_name and isinstance(child.ctx, ast.Store):
                    findings.append(
                        self._make_finding(
                            filepath=filepath,
                            line=child.lineno,
                            column=child.col_offset,
                            message=f"Variable '{var_name}' is assigned but never used in '{node.name}()'.",
                            snippet=f"{var_name} = ...",
                            confidence=0.7,
                        )
                    )
                    break

        return findings
