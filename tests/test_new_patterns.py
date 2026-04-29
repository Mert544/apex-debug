"""Tests for new patterns added after experiment evaluation."""

from __future__ import annotations

import ast

import pytest

from apex_debug.core.finding import Severity
from apex_debug.engine.patterns.security import (
    AssertStatementPattern,
    CORSWildcardPattern,
    DebugTruePattern,
    HardcodedIPPattern,
    HardcodedSecretPattern,
    InsecureRandomPattern,
    PathTraversalPattern,
    SensitiveDataInLogPattern,
    SQLInjectionPattern,
    UnsafeYAMLLoadPattern,
    UrllibWithoutTimeoutPattern,
    WeakHashPattern,
)
from apex_debug.engine.patterns.correctness import TypeComparisonPattern
from apex_debug.engine.patterns.style import UnusedFunctionPattern


class TestSQLInjectionPattern:
    """Test SQL injection detection with f-string assignment."""

    def test_fstring_variable_assignment(self):
        """Detect f-string assigned to query variable."""
        pattern = SQLInjectionPattern()
        source = 'query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "query" in findings[0].message.lower()

    def test_safe_parametrized_query(self):
        """Safe query should not be flagged."""
        pattern = SQLInjectionPattern()
        source = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestWeakHashPattern:
    """Test weak hash detection."""

    def test_md5_detection(self):
        """Detect hashlib.md5() usage."""
        pattern = WeakHashPattern()
        source = "import hashlib\nh = hashlib.md5(password.encode()).hexdigest()\n"
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "md5" in findings[0].message.lower()
        assert findings[0].severity == Severity.MEDIUM

    def test_sha1_detection(self):
        """Detect hashlib.sha1() usage."""
        pattern = WeakHashPattern()
        source = "import hashlib\nh = hashlib.sha1(data).hexdigest()\n"
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "sha1" in findings[0].message.lower()

    def test_sha256_safe(self):
        """sha256 should not be flagged."""
        pattern = WeakHashPattern()
        source = "import hashlib\nh = hashlib.sha256(data).hexdigest()\n"
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestTypeComparisonPattern:
    """Test type() == detection."""

    def test_type_equality_detected(self):
        """Detect type(x) == list."""
        pattern = TypeComparisonPattern()
        source = "if type(x) == list:\n    pass\n"
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "isinstance" in findings[0].message

    def test_isinstance_safe(self):
        """isinstance should not be flagged."""
        pattern = TypeComparisonPattern()
        source = "if isinstance(x, list):\n    pass\n"
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestUnusedFunctionPattern:
    """Test unused function detection."""

    def test_unused_function_detected(self):
        """Detect function never called in file."""
        pattern = UnusedFunctionPattern()
        source = "def old_func():\n    pass\n\nx = 1\n"
        tree = ast.parse(source)
        findings = pattern.analyze_python_ast(tree, source, "test.py")
        assert len(findings) == 1
        assert "old_func" in findings[0].message

    def test_used_function_not_flagged(self):
        """Used function should not be flagged."""
        pattern = UnusedFunctionPattern()
        source = "def helper():\n    pass\n\nhelper()\n"
        tree = ast.parse(source)
        findings = pattern.analyze_python_ast(tree, source, "test.py")
        assert len(findings) == 0


class TestHardcodedSecretPattern:
    """Test hardcoded secret detection."""

    def test_hardcoded_password_detected(self):
        """Detect hardcoded password assignment."""
        pattern = HardcodedSecretPattern()
        source = 'DB_PASSWORD = "supersecret123"\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "password" in findings[0].message.lower()

    def test_hardcoded_api_key_detected(self):
        """Detect hardcoded API key."""
        pattern = HardcodedSecretPattern()
        source = 'API_KEY = "sk-abc123xyz"\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1

    def test_safe_env_var_not_flagged(self):
        """Environment variable usage should not be flagged."""
        pattern = HardcodedSecretPattern()
        source = 'PASSWORD = os.environ.get("DB_PASSWORD")\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestInsecureRandomPattern:
    """Test insecure random detection."""

    def test_random_choice_detected(self):
        """Detect random.choice for security."""
        pattern = InsecureRandomPattern()
        source = "import random\ntoken = random.choice('abc')\n"
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "secrets" in findings[0].message.lower()

    def test_secrets_safe(self):
        """secrets module should not be flagged."""
        pattern = InsecureRandomPattern()
        source = "import secrets\ntoken = secrets.token_hex(16)\n"
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestPathTraversalPattern:
    """Test path traversal detection."""

    def test_open_with_variable_detected(self):
        """Detect open() with non-literal path."""
        pattern = PathTraversalPattern()
        source = 'open(user_input, "r")\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "path traversal" in findings[0].message.lower()

    def test_open_with_literal_safe(self):
        """open() with literal string should be safe."""
        pattern = PathTraversalPattern()
        source = 'open("data.txt", "r")\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestHardcodedIPPattern:
    """Test hardcoded IP detection."""

    def test_hardcoded_ip_detected(self):
        """Detect hardcoded IP address."""
        pattern = HardcodedIPPattern()
        source = 'SERVER = "192.168.1.100"\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "192.168.1.100" in findings[0].message

    def test_localhost_ignored(self):
        """127.0.0.1 should be ignored."""
        pattern = HardcodedIPPattern()
        source = 'HOST = "127.0.0.1"\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestDebugTruePattern:
    """Test DEBUG=True detection."""

    def test_debug_true_detected(self):
        """Detect DEBUG = True."""
        pattern = DebugTruePattern()
        source = "DEBUG = True\n"
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "DEBUG" in findings[0].message

    def test_debug_false_safe(self):
        """DEBUG = False should not be flagged."""
        pattern = DebugTruePattern()
        source = "DEBUG = False\n"
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestCORSWildcardPattern:
    """Test CORS wildcard detection."""

    def test_cors_list_wildcard_detected(self):
        """Detect CORS_ORIGINS = [\"*\"]."""
        pattern = CORSWildcardPattern()
        source = 'CORS_ORIGINS = ["*"]\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "CORS" in findings[0].message

    def test_cors_kwarg_wildcard_detected(self):
        """Detect origins="*" in function call."""
        pattern = CORSWildcardPattern()
        source = 'CORS(app, origins="*")\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1

    def test_cors_specific_safe(self):
        """Specific origins should not be flagged."""
        pattern = CORSWildcardPattern()
        source = 'CORS_ORIGINS = ["https://example.com"]\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestUnsafeYAMLLoadPattern:
    """Test unsafe YAML load detection."""

    def test_yaml_load_without_loader(self):
        """Detect yaml.load() without Loader."""
        pattern = UnsafeYAMLLoadPattern()
        source = 'import yaml\ndata = yaml.load(stream)\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "safe_load" in findings[0].message.lower()
        assert findings[0].severity == Severity.HIGH

    def test_yaml_load_with_loader_safe(self):
        """yaml.load() with Loader should not be flagged."""
        pattern = UnsafeYAMLLoadPattern()
        source = 'import yaml\ndata = yaml.load(stream, Loader=yaml.SafeLoader)\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0

    def test_yaml_safe_load_not_flagged(self):
        """yaml.safe_load() should not be flagged."""
        pattern = UnsafeYAMLLoadPattern()
        source = 'import yaml\ndata = yaml.safe_load(stream)\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestAssertStatementPattern:
    """Test assert statement detection."""

    def test_assert_detected(self):
        """Detect assert statement."""
        pattern = AssertStatementPattern()
        source = 'assert x > 0, "must be positive"\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "-O" in findings[0].message
        assert findings[0].severity == Severity.LOW

    def test_no_assert_not_flagged(self):
        """Code without assert should not be flagged."""
        pattern = AssertStatementPattern()
        source = 'x = 1\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestUrllibWithoutTimeoutPattern:
    """Test urlopen without timeout detection."""

    def test_urlopen_without_timeout(self):
        """Detect urllib.request.urlopen() without timeout."""
        pattern = UrllibWithoutTimeoutPattern()
        source = 'import urllib.request\nresp = urllib.request.urlopen(url)\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "timeout" in findings[0].message.lower()
        assert findings[0].severity == Severity.MEDIUM

    def test_urlopen_with_timeout_safe(self):
        """urlopen with timeout should not be flagged."""
        pattern = UrllibWithoutTimeoutPattern()
        source = 'import urllib.request\nresp = urllib.request.urlopen(url, timeout=5)\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0


class TestSensitiveDataInLogPattern:
    """Test sensitive data in log detection."""

    def test_fstring_password_logged(self):
        """Detect f-string logging password."""
        pattern = SensitiveDataInLogPattern()
        source = 'import logging\nlogging.info(f"User password: {password}")\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "password" in findings[0].message.lower()
        assert findings[0].severity == Severity.MEDIUM

    def test_fstring_token_logged(self):
        """Detect f-string logging token."""
        pattern = SensitiveDataInLogPattern()
        source = 'logger.debug(f"Auth token: {auth_token}")\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 1
        assert "token" in findings[0].message.lower()

    def test_safe_literal_log_not_flagged(self):
        """Literal string without sensitive vars should not be flagged."""
        pattern = SensitiveDataInLogPattern()
        source = 'logging.info("User logged in successfully")\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0

    def test_non_logging_call_not_flagged(self):
        """Non-logging calls should not be flagged."""
        pattern = SensitiveDataInLogPattern()
        source = 'print(f"Password: {password}")\n'
        tree = ast.parse(source)
        findings = []
        for node in ast.walk(tree):
            findings.extend(pattern.analyze_python_ast(node, source, "test.py"))
        assert len(findings) == 0
