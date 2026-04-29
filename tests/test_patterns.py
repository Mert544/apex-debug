"""Tests for Apex Debug patterns."""

from __future__ import annotations

import ast

import pytest

from apex_debug.core.finding import Severity
from apex_debug.engine.patterns.correctness import (
    BareExceptPattern,
    NoneComparisonPattern,
    UnusedVariablePattern,
)
from apex_debug.engine.patterns.performance import (
    NestedLoopPattern,
    RepeatedCallInLoopPattern,
)
from apex_debug.engine.patterns.security import (
    DangerousSubprocessPattern,
    EvalExecPattern,
    PicklePattern,
    SQLInjectionPattern,
)
from apex_debug.engine.patterns.style import MissingDocstringPattern


def _parse(source: str):
    return ast.parse(source)


def _walk_findings(pattern, source: str, filepath: str = "test.py"):
    tree = _parse(source)
    findings = []
    for node in ast.walk(tree):
        findings.extend(pattern.analyze_python_ast(node, source, filepath))
    return findings


class TestSecurityPatterns:
    """Test security vulnerability detection."""

    def test_eval_detection(self):
        source = "result = eval(user_input)"
        findings = _walk_findings(EvalExecPattern(), source)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "eval()" in findings[0].message

    def test_exec_detection(self):
        source = "exec(malicious_code)"
        findings = _walk_findings(EvalExecPattern(), source)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_os_system_detection(self):
        source = "os.system(cmd)"
        findings = _walk_findings(DangerousSubprocessPattern(), source)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "os.system" in findings[0].message

    def test_subprocess_shell_true(self):
        source = "subprocess.run(cmd, shell=True)"
        findings = _walk_findings(DangerousSubprocessPattern(), source)
        assert len(findings) == 1
        assert "shell=True" in findings[0].message

    def test_pickle_loads(self):
        source = "pickle.loads(data)"
        findings = _walk_findings(PicklePattern(), source)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_sql_injection_fstring(self):
        source = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = _walk_findings(SQLInjectionPattern(), source)
        assert len(findings) == 1
        assert "f-string" in findings[0].message

    def test_safe_code_no_findings(self):
        source = "result = json.loads(data)"
        findings = _walk_findings(EvalExecPattern(), source)
        assert len(findings) == 0


class TestCorrectnessPatterns:
    """Test logic error detection."""

    def test_bare_except(self):
        source = """
try:
    pass
except:
    pass
"""
        findings = _walk_findings(BareExceptPattern(), source)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Bare except" in findings[0].message

    def test_none_comparison(self):
        source = "if x == None: pass"
        findings = _walk_findings(NoneComparisonPattern(), source)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "is None" in findings[0].message

    def test_is_none_ok(self):
        source = "if x is None: pass"
        findings = _walk_findings(NoneComparisonPattern(), source)
        assert len(findings) == 0


class TestPerformancePatterns:
    """Test performance anti-pattern detection."""

    def test_nested_loop(self):
        source = """
for i in range(10):
    for j in range(10):
        pass
"""
        findings = _walk_findings(NestedLoopPattern(), source)
        assert len(findings) == 1
        assert "O(n²)" in findings[0].message

    def test_range_len(self):
        source = """
for i in range(len(items)):
    pass
"""
        findings = _walk_findings(RepeatedCallInLoopPattern(), source)
        assert len(findings) == 1
        assert "enumerate" in findings[0].message


class TestStylePatterns:
    """Test code style detection."""

    def test_missing_docstring(self):
        source = """
def hello():
    pass
"""
        findings = _walk_findings(MissingDocstringPattern(), source)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "docstring" in findings[0].message

    def test_has_docstring(self):
        source = '''
def hello():
    """Say hello."""
    pass
'''
        findings = _walk_findings(MissingDocstringPattern(), source)
        assert len(findings) == 0

    def test_private_function_ignored(self):
        source = """
def _private():
    pass
"""
        findings = _walk_findings(MissingDocstringPattern(), source)
        assert len(findings) == 0
