"""Performance anti-pattern detection."""

from __future__ import annotations

import ast
from typing import Optional

from apex_debug.core.finding import Finding, Severity
from apex_debug.engine.patterns.base import AbstractPattern


class NestedLoopPattern(AbstractPattern):
    name = "Nested loop (potential O(n²))"
    description = "Detects loops nested inside other loops, which may cause O(n²) complexity"
    severity = Severity.MEDIUM
    category = "performance"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, (ast.For, ast.While)):
            return findings

        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.For, ast.While)):
                outer = type(node).__name__.lower()
                inner = type(child).__name__.lower()
                snippet = ast.get_source_segment(source, node) or ""
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=child.lineno,
                        column=child.col_offset,
                        end_line=child.end_lineno or child.lineno,
                        message=f"{inner} loop nested inside {outer} loop — potential O(n²) complexity. Consider restructuring with dictionaries or sets.",
                        snippet=snippet,
                        confidence=0.7,
                    )
                )
                break

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (r"(for|while).*\n.*(for|while)", "nested loop detected")


class RepeatedCallInLoopPattern(AbstractPattern):
    name = "Repeated function call in loop condition"
    description = "Detects calls like len() or range(len()) repeated in loop conditions"
    severity = Severity.MEDIUM
    category = "performance"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []

        if isinstance(node, ast.For) and isinstance(node.iter, ast.Call):
            if isinstance(node.iter.func, ast.Name) and node.iter.func.id in ("range", "enumerate"):
                for arg in node.iter.args:
                    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "len":
                        snippet = ast.get_source_segment(source, node) or ""
                        findings.append(
                            self._make_finding(
                                filepath=filepath,
                                line=node.lineno,
                                column=node.col_offset,
                                message="Using range(len(x)) in a for-loop is inefficient. Use 'for item in x' or 'for i, item in enumerate(x)' directly.",
                                snippet=snippet,
                                confidence=0.9,
                            )
                        )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (r"range\s*\(\s*len\s*\(", "range(len()) pattern — use enumerate() instead")


class GlobalInLoopPattern(AbstractPattern):
    name = "Global variable access in loop"
    description = "Detects repeated global variable reads inside loops"
    severity = Severity.LOW
    category = "performance"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, (ast.For, ast.While)):
            return findings

        global_reads: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                if not child.id.startswith("_"):
                    global_reads.add(child.id)

        if len(global_reads) >= 3:
            snippet = ast.get_source_segment(source, node) or ""
            findings.append(
                self._make_finding(
                    filepath=filepath,
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"Loop body accesses {len(global_reads)}+ global variables ({', '.join(sorted(global_reads)[:5])}). Cache in local variable for performance.",
                    snippet=snippet,
                    confidence=0.5,
                )
            )

        return findings


class StringConcatInLoopPattern(AbstractPattern):
    name = "String concatenation in loop"
    description = "Detects '+=' string building inside loops — use list + join()"
    severity = Severity.MEDIUM
    category = "performance"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, (ast.For, ast.While)):
            return findings

        for child in ast.walk(node):
            if isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                if isinstance(child.target, ast.Name):
                    snippet = ast.get_source_segment(source, child) or ""
                    findings.append(
                        self._make_finding(
                            filepath=filepath,
                            line=child.lineno,
                            column=child.col_offset,
                            message="String concatenation ('+=') inside loop creates a new string each iteration. Use 'parts.append()' and ''.join() instead.",
                            snippet=snippet,
                            confidence=0.85,
                        )
                    )

        return findings
