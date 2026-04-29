"""Security vulnerability detection patterns."""

from __future__ import annotations

import ast
import re
from typing import Optional

from apex_debug.core.finding import Finding, Severity
from apex_debug.engine.patterns.base import AbstractPattern

DANGEROUS_FUNCTIONS = {
    "eval": "eval() executes arbitrary code. Use ast.literal_eval() or json.loads() instead.",
    "exec": "exec() executes arbitrary code. Avoid entirely; there is almost always a safer alternative.",
    "compile": "compile() can be used to execute arbitrary code. Validate input source carefully.",
    "__import__": "Dynamic imports via __import__() can load arbitrary modules.",
}

DANGEROUS_MODULE_CALLS = {
    ("os", "system"): "os.system() spawns a shell. Use subprocess.run() with a command list instead.",
    ("os", "popen"): "os.popen() is deprecated and spawns a shell. Use subprocess.run().",
    ("subprocess", "call"): "subprocess.call() with shell=True is dangerous. Use shell=False with a list.",
    ("pickle", "loads"): "pickle.loads() can execute arbitrary code. Use json.loads() or validate input.",
    ("pickle", "load"): "pickle.load() can execute arbitrary code. Avoid untrusted pickle data.",
}

DANGEROUS_SHELL_TRUE = {
    ("subprocess", "Popen"): "shell=True in Popen is dangerous. Use a command list with shell=False.",
    ("subprocess", "run"): "shell=True in run() is dangerous. Use a command list with shell=False.",
    ("subprocess", "check_output"): "shell=True in check_output() is dangerous. Use a command list.",
    ("subprocess", "check_call"): "shell=True in check_call() is dangerous. Use a command list.",
}

SQL_INJECTION_PATTERNS = [
    r"(?:execute|cursor)\(.*%.*\)",
    r"(?:execute|cursor)\(.*f['\"].*\)",
    r"\.execute\(['\"].*\{.*\}.*['\"]",
]


class EvalExecPattern(AbstractPattern):
    name = "Dangerous eval/exec usage"
    description = "Detects eval(), exec(), and compile() calls with unvalidated input"
    severity = Severity.CRITICAL
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Call):
            return findings

        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in DANGEROUS_FUNCTIONS:
            # Skip safe compile() usages (re.compile, regex.compile)
            if func_name == "compile" and isinstance(node.func, ast.Attribute):
                module_name = ""
                if isinstance(node.func.value, ast.Name):
                    module_name = node.func.value.id
                if module_name in ("re", "regex"):
                    return findings
            
            snippet = ast.get_source_segment(source, node) or ""
            findings.append(
                self._make_finding(
                    filepath=filepath,
                    line=node.lineno,
                    column=node.col_offset,
                    end_line=node.end_lineno or node.lineno,
                    end_column=node.end_col_offset or 0,
                    message=f"{func_name}() is dangerous: {DANGEROUS_FUNCTIONS[func_name]}",
                    snippet=snippet,
                )
            )

        return findings

    def get_treesitter_query(self) -> str:
        return '(call function: (identifier) @func (#any-of? @func "eval" "exec" "compile"))'

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (r"\b(eval|exec|compile)\s*\(", "dangerous {match}() call detected")


class DangerousSubprocessPattern(AbstractPattern):
    name = "Dangerous subprocess/shell usage"
    description = "Detects os.system(), os.popen(), and subprocess calls with shell=True"
    severity = Severity.CRITICAL
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Call):
            return findings

        # Check for os.system(), os.popen(), etc.
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            func = node.func.attr
            pair = (module, func)

            if pair in DANGEROUS_MODULE_CALLS:
                snippet = ast.get_source_segment(source, node) or ""
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        end_line=node.end_lineno or node.lineno,
                        message=DANGEROUS_MODULE_CALLS[pair],
                        snippet=snippet,
                    )
                )

            # Check for shell=True in subprocess calls
            if pair in DANGEROUS_SHELL_TRUE:
                for kw in node.keywords:
                    if kw.arg == "shell" and (
                        (isinstance(kw.value, ast.Constant) and kw.value.value is True)
                    ):
                        snippet = ast.get_source_segment(source, node) or ""
                        findings.append(
                            self._make_finding(
                                filepath=filepath,
                                line=node.lineno,
                                column=node.col_offset,
                                end_line=node.end_lineno or node.lineno,
                                message=DANGEROUS_SHELL_TRUE[pair],
                                snippet=snippet,
                            )
                        )

        return findings

    def get_treesitter_query(self) -> str:
        return """(
  (call
    function: (attribute
      object: (identifier) @mod
      attribute: (identifier) @func)
    arguments: (argument_list) @args)
  (#any-of? @mod "os" "subprocess")
  (#any-of? @func "system" "popen" "call" "run" "Popen" "check_output" "check_call")
)"""

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (r"\b(os\.(?:system|popen)|shell\s*=\s*True)", "dangerous shell/subprocess usage")


class PicklePattern(AbstractPattern):
    name = "Insecure deserialization (pickle)"
    description = "Detects pickle.loads()/pickle.load() with potentially untrusted input"
    severity = Severity.HIGH
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Call):
            return findings

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "pickle" and node.func.attr in ("loads", "load"):
                snippet = ast.get_source_segment(source, node) or ""
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        end_line=node.end_lineno or node.lineno,
                        message=f"pickle.{node.func.attr}() can execute arbitrary code during deserialization. Use json or validate input.",
                        snippet=snippet,
                        confidence=0.9,
                    )
                )

        return findings

    def get_treesitter_query(self) -> str:
        return """(
  (call
    function: (attribute
      object: (identifier) @mod
      attribute: (identifier) @func)
    arguments: (argument_list) @args)
  (#eq? @mod "pickle")
  (#any-of? @func "loads" "load")
)"""

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (r"\bpickle\.(?:loads|load)\s*\(", "insecure pickle deserialization")


class SQLInjectionPattern(AbstractPattern):
    name = "SQL injection risk"
    description = "Detects potential SQL injection via string formatting in SQL queries"
    severity = Severity.HIGH
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []

        # Pattern 1: Direct .execute() with f-string or % formatting
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany"):
                if node.args:
                    first_arg = node.args[0]
                    snippet = ast.get_source_segment(source, node) or ""
                    if isinstance(first_arg, ast.JoinedStr):
                        findings.append(
                            self._make_finding(
                                filepath=filepath,
                                line=node.lineno,
                                column=node.col_offset,
                                message="SQL query uses f-string — this is vulnerable to SQL injection. Use parameterized queries.",
                                snippet=snippet,
                                confidence=0.85,
                            )
                        )
                    elif (
                        isinstance(first_arg, ast.BinOp)
                        and isinstance(first_arg.op, ast.Mod)
                        and isinstance(first_arg.left, ast.Constant)
                    ):
                        findings.append(
                            self._make_finding(
                                filepath=filepath,
                                line=node.lineno,
                                column=node.col_offset,
                                message="SQL query uses % formatting — this is vulnerable to SQL injection. Use parameterized queries.",
                                snippet=snippet,
                                confidence=0.8,
                            )
                        )

        # Pattern 2: f-string or .format() assigned to a variable then used in SQL
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, ast.JoinedStr):
                    var_name = target.id
                    # Check if variable name looks like a SQL query
                    if any(keyword in var_name.lower() for keyword in ("query", "sql", "select", "insert", "update", "delete")):
                        snippet = ast.get_source_segment(source, node) or ""
                        findings.append(
                            self._make_finding(
                                filepath=filepath,
                                line=node.lineno,
                                column=node.col_offset,
                                message=f"Variable '{var_name}' uses f-string — potential SQL injection. Use parameterized queries.",
                                snippet=snippet,
                                confidence=0.75,
                            )
                        )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"(?:query|sql|select|insert|update|delete)\s*=\s*f['\"]",
            "potential SQL injection via string formatting",
        )


class WeakHashPattern(AbstractPattern):
    name = "Weak cryptographic hash"
    description = "Detects usage of weak hash algorithms (MD5, SHA1) for security purposes"
    severity = Severity.MEDIUM
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Call):
            return findings

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            func = node.func.attr
            if module == "hashlib" and func in ("md5", "sha1"):
                snippet = ast.get_source_segment(source, node) or ""
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        end_line=node.end_lineno or node.lineno,
                        message=f"hashlib.{func}() is a weak hash algorithm. Use hashlib.sha256() or stronger for security-sensitive operations.",
                        snippet=snippet,
                        confidence=0.8,
                    )
                )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"hashlib\.(md5|sha1)\s*\(",
            "weak hash algorithm {match} detected — use sha256 or stronger",
        )


class HardcodedSecretPattern(AbstractPattern):
    name = "Hardcoded secret"
    description = "Detects hardcoded passwords, API keys, and secrets in source code"
    severity = Severity.HIGH
    category = "security"

    SECRET_KEYWORDS = (
        "password", "passwd", "pwd", "secret", "api_key", "apikey",
        "token", "auth_token", "access_token", "private_key",
        "secret_key", "aws_secret", "github_token", "db_password",
    )

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Assign):
            return findings

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_lower = target.id.lower()
                if any(keyword in var_lower for keyword in self.SECRET_KEYWORDS):
                    # Check if value is a non-empty string literal
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 3:  # Skip empty/placeholder strings
                            snippet = ast.get_source_segment(source, node) or ""
                            findings.append(
                                self._make_finding(
                                    filepath=filepath,
                                    line=node.lineno,
                                    column=node.col_offset,
                                    message=f"Hardcoded secret detected in variable '{target.id}'. Use environment variables or a secrets manager instead.",
                                    snippet=snippet,
                                    confidence=0.85,
                                )
                            )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"(?i)(password|secret|api_key|token)\s*=\s*['\"][^'\"]{4,}['\"]",
            "hardcoded secret detected — use environment variables",
        )


class InsecureRandomPattern(AbstractPattern):
    name = "Insecure random for security"
    description = "Detects usage of random module for security-sensitive operations"
    severity = Severity.MEDIUM
    category = "security"

    INSECURE_RANDOM_FUNCS = {
        "random": ("random", "randint", "randrange", "choice", "choices", "shuffle", "sample"),
    }

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Call):
            return findings

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            func = node.func.attr
            if module == "random" and func in self.INSECURE_RANDOM_FUNCS["random"]:
                snippet = ast.get_source_segment(source, node) or ""
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        end_line=node.end_lineno or node.lineno,
                        message=f"random.{func}() is not cryptographically secure. Use secrets module for security-sensitive operations like tokens, passwords, or IDs.",
                        snippet=snippet,
                        confidence=0.75,
                    )
                )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"\brandom\.(random|randint|choice|shuffle|sample)\s*\(",
            "insecure random for security — use secrets module",
        )


class PathTraversalPattern(AbstractPattern):
    name = "Potential path traversal"
    description = "Detects file open() with user-controlled paths"
    severity = Severity.MEDIUM
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Call):
            return findings

        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "open":
            func_name = "open"

        if func_name == "open" and node.args:
            first_arg = node.args[0]
            # Flag if the argument is not a literal string
            if not isinstance(first_arg, ast.Constant):
                snippet = ast.get_source_segment(source, node) or ""
                findings.append(
                    self._make_finding(
                        filepath=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        end_line=node.end_lineno or node.lineno,
                        message="open() called with a non-literal path — potential path traversal. Validate and sanitize user input before using as a file path.",
                        snippet=snippet,
                        confidence=0.7,
                    )
                )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"\bopen\s*\(\s*[^'\"]",
            "potential path traversal — validate file paths",
        )


class HardcodedIPPattern(AbstractPattern):
    name = "Hardcoded IP address"
    description = "Detects hardcoded IP addresses in source code"
    severity = Severity.LOW
    category = "security"

    # Regex for matching IPv4 addresses (excluding common localhost/private ranges as hints)
    IP_REGEX = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            return findings

        value = node.value
        if self.IP_REGEX.search(value):
            # Skip localhost/private as they might be intentional
            if value.startswith(("127.", "0.0.0.0", "::1")):
                return findings
            snippet = ast.get_source_segment(source, node) or value
            findings.append(
                self._make_finding(
                    filepath=filepath,
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"Hardcoded IP address detected: '{value}'. Consider using configuration files or environment variables for network addresses.",
                    snippet=snippet,
                    confidence=0.7,
                )
            )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"['\"]\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b['\"]",
            "hardcoded IP address — use configuration",
        )


class DebugTruePattern(AbstractPattern):
    name = "DEBUG set to True"
    description = "Detects DEBUG = True in web framework configurations"
    severity = Severity.MEDIUM
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(node, ast.Assign):
            return findings

        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.upper() == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    snippet = ast.get_source_segment(source, node) or ""
                    findings.append(
                        self._make_finding(
                            filepath=filepath,
                            line=node.lineno,
                            column=node.col_offset,
                            message="DEBUG is set to True. Never enable DEBUG in production as it exposes sensitive information.",
                            snippet=snippet,
                            confidence=0.9,
                        )
                    )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"(?i)^\s*DEBUG\s*=\s*True\b",
            "DEBUG=True detected — disable in production",
        )


class CORSWildcardPattern(AbstractPattern):
    name = "CORS wildcard allowed"
    description = "Detects overly permissive CORS configuration allowing all origins"
    severity = Severity.MEDIUM
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings = []

        # Pattern 1: CORS_ORIGINS = ["*"] or CORS_ALLOW_ALL = True
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name_upper = target.id.upper()
                    if "CORS" in name_upper and "ORIGIN" in name_upper:
                        # Check for "*" in a list
                        if isinstance(node.value, ast.List):
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant) and elt.value == "*":
                                    snippet = ast.get_source_segment(source, node) or ""
                                    findings.append(
                                        self._make_finding(
                                            filepath=filepath,
                                            line=node.lineno,
                                            column=node.col_offset,
                                            message="CORS allows all origins ('*'). This is a security risk in production. Specify explicit allowed origins.",
                                            snippet=snippet,
                                            confidence=0.85,
                                        )
                                    )

        # Pattern 2: CORS(app, origins="*") or similar function call
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg and "origin" in kw.arg.lower():
                    if isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                        snippet = ast.get_source_segment(source, node) or ""
                        findings.append(
                            self._make_finding(
                                filepath=filepath,
                                line=node.lineno,
                                column=node.col_offset,
                                message="CORS allows all origins ('*'). This is a security risk in production. Specify explicit allowed origins.",
                                snippet=snippet,
                                confidence=0.85,
                            )
                        )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"(?i)(?:origins|allow_origin|allowed_origin)\s*=\s*['\"]\*['\"]",
            "CORS wildcard — specify explicit origins",
        )


class UnsafeYAMLLoadPattern(AbstractPattern):
    name = "Unsafe YAML load"
    description = "Detects yaml.load() without Loader specification which can execute arbitrary code"
    severity = Severity.HIGH
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "yaml" and node.func.attr == "load":
                # Check if Loader kwarg is provided
                has_loader = any(
                    kw.arg == "Loader" for kw in node.keywords
                )
                if not has_loader:
                    snippet = ast.get_source_segment(source, node) or ""
                    findings.append(
                        self._make_finding(
                            filepath=filepath,
                            line=node.lineno,
                            column=node.col_offset,
                            message="yaml.load() without Loader is unsafe and can execute arbitrary code. Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
                            snippet=snippet,
                            confidence=0.9,
                        )
                    )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"yaml\.load\s*\([^)]*\)(?!.*Loader)",
            "unsafe yaml.load() — use yaml.safe_load() or specify Loader",
        )


class AssertStatementPattern(AbstractPattern):
    name = "Assert statement in production"
    description = "Detects assert statements that are removed when Python runs with -O (optimized)"
    severity = Severity.LOW
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings = []
        if isinstance(node, ast.Assert):
            snippet = ast.get_source_segment(source, node) or ""
            findings.append(
                self._make_finding(
                    filepath=filepath,
                    line=node.lineno,
                    column=node.col_offset,
                    message="assert statements are removed when Python runs with -O. Use explicit checks and raise proper exceptions for production-critical validation.",
                    snippet=snippet,
                    confidence=0.8,
                )
            )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"^\s*assert\s+",
            "assert statement — removed under python -O; use explicit checks",
        )


class UrllibWithoutTimeoutPattern(AbstractPattern):
    name = "Network call without timeout"
    description = "Detects urllib.request.urlopen() calls without a timeout parameter"
    severity = Severity.MEDIUM
    category = "security"

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        if isinstance(node.func, ast.Attribute) and node.func.attr == "urlopen":
            # Walk up attribute chain to find root module (e.g. urllib.request -> urllib)
            root = node.func.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id == "urllib":
                has_timeout = any(
                    kw.arg == "timeout" for kw in node.keywords
                )
                if not has_timeout:
                    snippet = ast.get_source_segment(source, node) or ""
                    findings.append(
                        self._make_finding(
                            filepath=filepath,
                            line=node.lineno,
                            column=node.col_offset,
                            message="urllib.request.urlopen() without timeout can hang indefinitely. Always specify a timeout (e.g., timeout=5).",
                            snippet=snippet,
                            confidence=0.85,
                        )
                    )

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"urllib\.request\.urlopen\s*\([^)]*\)(?!.*timeout)",
            "urlopen without timeout — specify timeout to prevent hangs",
        )


class SensitiveDataInLogPattern(AbstractPattern):
    name = "Sensitive data in log"
    description = "Detects logging of passwords, tokens, secrets, or other sensitive data"
    severity = Severity.MEDIUM
    category = "security"

    SENSITIVE_KEYWORDS = (
        "password", "passwd", "pwd", "secret", "api_key", "apikey",
        "token", "auth_token", "access_token", "private_key",
        "secret_key", "credit_card", "ssn", "social_security",
    )

    LOGGING_FUNCS = {
        "logging", "logger", "log",
    }

    def analyze_python_ast(self, node: ast.AST, source: str, filepath: str) -> list[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # Check if it's a logging call (logger.info, logging.debug, etc.)
        is_logging = False
        if isinstance(node.func, ast.Attribute):
            root = node.func.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in self.LOGGING_FUNCS:
                is_logging = True
            if node.func.attr in ("info", "debug", "warning", "warn", "error", "critical", "log"):
                is_logging = True

        if not is_logging:
            return findings

        # Check all arguments for sensitive keywords in f-strings or .format()
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                # f-string: check the values (not the constants)
                for value in arg.values:
                    if isinstance(value, ast.FormattedValue):
                        # Check the expression inside {}
                        expr = value.value
                        if isinstance(expr, ast.Name):
                            if any(kw in expr.id.lower() for kw in self.SENSITIVE_KEYWORDS):
                                snippet = ast.get_source_segment(source, node) or ""
                                findings.append(
                                    self._make_finding(
                                        filepath=filepath,
                                        line=node.lineno,
                                        column=node.col_offset,
                                        message=f"Logging f-string may expose sensitive variable '{expr.id}'. Avoid logging secrets, passwords, or tokens.",
                                        snippet=snippet,
                                        confidence=0.75,
                                    )
                                )
                                return findings

        return findings

    def get_regex(self) -> Optional[tuple[str, str]]:
        return (
            r"(?i)(?:logging|logger)\.(?:info|debug|warning|error)\s*\(.*(?:password|secret|token|api_key)",
            "potential sensitive data in log — avoid logging secrets",
        )
