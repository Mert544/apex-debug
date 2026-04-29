"""Parser registry — file discovery and language detection.

Works WITHOUT any external dependencies.
Detects language by file extension and maps to appropriate parser.
Tree-sitter integration is added as optional enhancement.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".pyx": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".lua": "lua",
}


class ParserRegistry:
    """Detects file language and provides access to source files.

    Future: will integrate tree-sitter for full AST parsing of all languages.
    For Phase 1, it handles file discovery and language detection.
    """

    def __init__(self, auto_detect: bool = True, default_language: str = "python"):
        self.auto_detect = auto_detect
        self.default_language = default_language

    def detect_language(self, filepath: Path) -> str:
        """Detect programming language from file extension.

        Args:
            filepath: Path to source file

        Returns:
            Language name (e.g. 'python', 'javascript')
        """
        if not self.auto_detect:
            return self.default_language

        suffix = filepath.suffix.lower()
        if suffix in LANGUAGE_EXTENSIONS:
            return LANGUAGE_EXTENSIONS[suffix]
        # Check dual extensions (e.g. .d.ts)
        if len(filepath.suffixes) >= 2:
            dual = "".join(filepath.suffixes[-2:]).lower()
            if dual in LANGUAGE_EXTENSIONS:
                return LANGUAGE_EXTENSIONS[dual]

        return self.default_language

    def is_supported(self, filepath: Path) -> bool:
        """Check if the file extension is recognized."""
        return filepath.suffix.lower() in LANGUAGE_EXTENSIONS

    def discover_files(self, target: Path, exclude: Optional[set[str]] = None) -> list[Path]:
        """Recursively discover source files in a directory.

        Skips hidden directories (starting with .) and common non-source dirs.

        Args:
            target: File or directory to scan
            exclude: Additional directory/file name fragments to skip

        Returns:
            List of source file paths
        """
        if target.is_file():
            return [target]

        source_files: list[Path] = []
        skip_dirs = {
            ".git", ".svn", ".hg", "__pycache__", "node_modules",
            "venv", ".venv", "env", ".env", "dist", "build",
            ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
            "target", ".next", ".turbo",
        }
        if exclude:
            skip_dirs.update(exclude)

        for path in target.rglob("*"):
            if path.is_file() and self.is_supported(path):
                # Skip hidden dirs and user-specified excludes
                parts = set(path.parts)
                if skip_dirs.isdisjoint(parts):
                    source_files.append(path)

        return sorted(source_files)

    def read_file(self, filepath: Path) -> Optional[str]:
        """Read source file content with encoding detection.

        Args:
            filepath: Path to source file

        Returns:
            File content as string, or None if unreadable
        """
        try:
            return filepath.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                return filepath.read_text(encoding="latin-1")
            except Exception:
                return None
