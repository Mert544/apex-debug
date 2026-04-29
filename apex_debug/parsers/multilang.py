"""Multi-language support via tree-sitter.

Future enhancement: When tree-sitter is installed, this module provides
universal AST parsing for 25+ languages. Falls back to regex for all.

For now, regex fallback in runner.py handles all non-Python files.
"""

from __future__ import annotations

import importlib
from typing import Optional


class MultiLanguageParser:
    """Universal parser wrapper — tree-sitter when available, regex fallback otherwise.

    Languages supported (via regex fallback until tree-sitter installed):
    - Python (.py, .pyi, .pyx)
    - JavaScript (.js, .mjs, .cjs)
    - TypeScript (.ts, .tsx)
    - Go (.go)
    - Rust (.rs)
    - Java (.java)
    - C/C++ (.c, .cpp, .cc, .cxx, .h, .hpp)
    - C# (.cs)
    - Ruby (.rb)
    - PHP (.php)
    - Swift (.swift)
    - Kotlin (.kt)
    - Scala (.scala)
    - Lua (.lua)
    """

    _instance: Optional["MultiLanguageParser"] = None

    def __new__(cls) -> "MultiLanguageParser":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        self._has_treesitter = False
        self._parsers: dict[str, any] = {}

        try:
            from tree_sitter import Language, Parser
            self._has_treesitter = True
            self._parser_cls = Parser
            self._language_cls = Language
        except ImportError:
            pass

    def is_available(self) -> bool:
        return self._has_treesitter

    def get_parser(self, language: str) -> Optional[any]:
        """Get or create a tree-sitter parser for a language.

        Args:
            language: Language name (e.g. 'python', 'javascript')

        Returns:
            Parser instance or None if not available
        """
        if not self._has_treesitter:
            return None

        if language in self._parsers:
            return self._parsers[language]

        # Try to load language grammar dynamically
        lang_module = self._load_language_module(language)
        if lang_module is None:
            return None

        parser = self._parser_cls(self._language_cls(lang_module.language()))
        self._parsers[language] = parser
        return parser

    def _load_language_module(self, language: str):
        """Try to import a tree-sitter language grammar package.

        Args:
            language: Language name

        Returns:
            Module or None
        """
        module_map = {
            "python": "tree_sitter_python",
            "javascript": "tree_sitter_javascript",
            "typescript": "tree_sitter_typescript",
            "tsx": "tree_sitter_typescript",  # tsx uses same module
            "go": "tree_sitter_go",
            "rust": "tree_sitter_rust",
            "java": "tree_sitter_java",
            "c": "tree_sitter_c",
            "cpp": "tree_sitter_cpp",
            "csharp": "tree_sitter_c_sharp",
            "ruby": "tree_sitter_ruby",
            "php": "tree_sitter_php",
            "swift": "tree_sitter_swift",
            "kotlin": "tree_sitter_kotlin",
            "scala": "tree_sitter_scala",
            "lua": "tree_sitter_lua",
        }

        module_name = module_map.get(language)
        if not module_name:
            return None

        try:
            return importlib.import_module(module_name)
        except ImportError:
            return None

    def parse(self, source: str, language: str) -> Optional[any]:
        """Parse source code with tree-sitter.

        Args:
            source: Source code string
            language: Language name

        Returns:
            AST tree or None
        """
        parser = self.get_parser(language)
        if parser is None:
            return None

        try:
            return parser.parse(bytes(source, "utf8"))
        except Exception:
            return None

    def query(self, tree: any, query_str: str, language: str) -> list:
        """Run a tree-sitter query on an AST.

        Args:
            tree: Parsed tree
            query_str: Tree-sitter query (S-expression)
            language: Language name

        Returns:
            List of captures
        """
        if not self._has_treesitter:
            return []

        try:
            from tree_sitter import Query, QueryCursor
            lang_module = self._load_language_module(language)
            if not lang_module:
                return []

            lang = self._language_cls(lang_module.language())
            query = Query(lang, query_str)
            cursor = QueryCursor(query)
            captures = cursor.captures(tree.root_node)
            return captures
        except Exception:
            return []


# Convenience functions for non-Python language regex fallbacks

def _js_ts_security_patterns(source: str, filepath: str) -> list:
    """Regex-based security patterns for JS/TS files."""
    import re
    from apex_debug.core.finding import Finding, Severity

    findings = []
    lines = source.splitlines()

    # Pre-compile regex patterns for performance
    dangerous = [
        (re.compile(r"\beval\s*\("), "Dangerous eval() usage", Severity.CRITICAL, "eval() executes arbitrary code. Avoid entirely."),
        (re.compile(r"\bnew\s+Function\s*\("), "Dangerous Function constructor", Severity.HIGH, "new Function() is equivalent to eval(). Avoid."),
        (re.compile(r"\bsetTimeout\s*\(\s*['\"`]`"), "setTimeout with string", Severity.MEDIUM, "setTimeout(string) uses eval internally. Use function reference."),
        (re.compile(r"\bsetInterval\s*\(\s*['\"`]`"), "setInterval with string", Severity.MEDIUM, "setInterval(string) uses eval internally. Use function reference."),
        (re.compile(r"\bdocument\.write\s*\("), "document.write()", Severity.MEDIUM, "document.write() can lead to XSS. Use safer DOM manipulation."),
        (re.compile(r"\binnerHTML\s*="), "innerHTML assignment", Severity.MEDIUM, "innerHTML without sanitization can cause XSS. Use textContent or sanitize input."),
    ]

    for line_no, line in enumerate(lines, start=1):
        for compiled_re, title, sev, msg in dangerous:
            if compiled_re.search(line):
                findings.append(Finding(
                    id=f"JS-{line_no:03d}",
                    file=filepath,
                    line=line_no,
                    severity=sev,
                    category="security",
                    title=title,
                    message=msg,
                    snippet=line.strip(),
                    confidence=0.85,
                ))

    return findings


def _go_security_patterns(source: str, filepath: str) -> list:
    """Regex-based security patterns for Go files."""
    import re
    from apex_debug.core.finding import Finding, Severity

    findings = []
    lines = source.splitlines()

    # Pre-compile regex patterns for performance
    dangerous = [
        (re.compile(r"\bexec\.Command\s*\(\s*['\"`]sh['\"`]`"), "Shell injection via exec.Command", Severity.CRITICAL, "Passing 'sh' to exec.Command with user input is dangerous. Use command arrays."),
        (re.compile(r"\bos\.Open\s*\(.*\+"), "Path traversal risk", Severity.HIGH, "Concatenating paths with user input can lead to path traversal. Use filepath.Join()."),
        (re.compile(r"\bioutil\.ReadFile\s*\(.*\+"), "Path traversal risk", Severity.HIGH, "Concatenating paths with user input can lead to path traversal."),
        (re.compile(r"\bunsafe\."), "unsafe package usage", Severity.MEDIUM, "unsafe package bypasses Go's type safety. Use only when absolutely necessary."),
        (re.compile(r"\brand\.Intn\s*\("), "Weak randomness", Severity.LOW, "math/rand is not cryptographically secure. Use crypto/rand for security-sensitive code."),
    ]

    for line_no, line in enumerate(lines, start=1):
        for compiled_re, title, sev, msg in dangerous:
            if compiled_re.search(line):
                findings.append(Finding(
                    id=f"GO-{line_no:03d}",
                    file=filepath,
                    line=line_no,
                    severity=sev,
                    category="security",
                    title=title,
                    message=msg,
                    snippet=line.strip(),
                    confidence=0.8,
                ))

    return findings


def _rust_security_patterns(source: str, filepath: str) -> list:
    """Regex-based security patterns for Rust files."""
    import re
    from apex_debug.core.finding import Finding, Severity

    findings = []
    lines = source.splitlines()

    # Pre-compile regex patterns for performance
    dangerous = [
        (re.compile(r"\bunsafe\s*\{"), "Unsafe block", Severity.MEDIUM, "unsafe blocks bypass Rust's memory safety. Minimize and audit carefully."),
        (re.compile(r"\bstd::mem::transmute"), "Dangerous transmute", Severity.HIGH, "transmute can cause undefined behavior. Use safe alternatives."),
        (re.compile(r"\bstd::process::Command::new\s*\(\s*['\"`]sh['\"`]`"), "Shell injection", Severity.CRITICAL, "Using 'sh' in Command can lead to shell injection. Pass command as array."),
        (re.compile(r"\b\.unwrap\s*\(\)"), "unwrap() on Result/Option", Severity.LOW, "unwrap() can panic. Use match, if let, or expect() with a message."),
        (re.compile(r"\b\.expect\s*\(\s*['\"`]`\s*['\"`]`\)"), "empty expect() message", Severity.INFO, "expect() with empty message provides no context on failure."),
    ]

    for line_no, line in enumerate(lines, start=1):
        for compiled_re, title, sev, msg in dangerous:
            if compiled_re.search(line):
                findings.append(Finding(
                    id=f"RS-{line_no:03d}",
                    file=filepath,
                    line=line_no,
                    severity=sev,
                    category="security",
                    title=title,
                    message=msg,
                    snippet=line.strip(),
                    confidence=0.8,
                ))

    return findings


def analyze_non_python(language: str, source: str, filepath: str) -> list:
    """Analyze non-Python source files using language-specific regex patterns.

    Args:
        language: Detected language name
        source: Source code string
        filepath: File path

    Returns:
        List of Finding objects
    """
    if language in ("javascript", "typescript", "tsx"):
        return _js_ts_security_patterns(source, filepath)
    elif language == "go":
        return _go_security_patterns(source, filepath)
    elif language == "rust":
        return _rust_security_patterns(source, filepath)

    return []
