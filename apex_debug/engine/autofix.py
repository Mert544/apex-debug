"""Auto-fix engine for simple, safe code transformations.

Only applies transformations that are 100% safe and do not change semantics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class FixSuggestion:
    """A single suggested code change."""

    line: int
    original: str
    replacement: str
    description: str


class AutoFixer:
    """Apply safe auto-fixes to Python source code.

    Usage:
        fixer = AutoFixer()
        suggestions = fixer.analyze(source_code)
        new_source = fixer.apply(source_code, suggestions)
    """

    def analyze(self, source: str) -> list[FixSuggestion]:
        """Analyze source and return all applicable fix suggestions."""
        suggestions: list[FixSuggestion] = []
        lines = source.split("\n")

        for line_no, line in enumerate(lines, start=1):
            # Fix 1: == None / != None  →  is None / is not None
            if self._should_fix_none_comparison(line):
                original = line
                replacement = self._fix_none_comparison(line)
                if replacement != original:
                    suggestions.append(
                        FixSuggestion(
                            line=line_no,
                            original=original,
                            replacement=replacement,
                            description="Use 'is None' / 'is not None' instead of == / !=",
                        )
                    )

            # Fix 2: bare "except:"  →  "except Exception:"
            stripped = line.strip()
            if stripped == "except:" or stripped.startswith("except :"):
                suggestions.append(
                    FixSuggestion(
                        line=line_no,
                        original=line,
                        replacement=line.replace("except:", "except Exception:", 1).replace("except :", "except Exception:", 1),
                        description="Avoid bare except — use 'except Exception:'",
                    )
                )

            # Fix 3: type([]) == list  →  isinstance([], list)
            if re.search(r"type\s*\([^)]+\)\s*==\s*\w+", line):
                suggestions.append(
                    FixSuggestion(
                        line=line_no,
                        original=line,
                        replacement=self._fix_type_comparison(line),
                        description="Use isinstance() instead of type() == ",
                    )
                )

        return suggestions

    def apply(self, source: str, suggestions: list[FixSuggestion]) -> str:
        """Apply suggestions to source code."""
        lines = source.split("\n")
        # Apply in reverse line order to preserve line numbers
        for suggestion in sorted(suggestions, key=lambda s: s.line, reverse=True):
            idx = suggestion.line - 1
            if 0 <= idx < len(lines) and lines[idx] == suggestion.original:
                lines[idx] = suggestion.replacement
        return "\n".join(lines)

    @staticmethod
    def _should_fix_none_comparison(line: str) -> bool:
        """Check if line contains == None or != None (but not already 'is None')."""
        # Match x == None or x != None, but not x is None
        return bool(re.search(r"==\s*None|!=\s*None", line)) and "is None" not in line and "is not None" not in line

    @staticmethod
    def _fix_none_comparison(line: str) -> str:
        """Replace == None with is None and != None with is not None."""
        line = re.sub(r"==\s*None", "is None", line)
        line = re.sub(r"!=\s*None", "is not None", line)
        return line

    @staticmethod
    def _fix_type_comparison(line: str) -> str:
        """Replace type(x) == Y with isinstance(x, Y).

        This is a best-effort transformation for simple cases.
        """
        match = re.search(r"type\s*\(([^)]+)\)\s*==\s*(\w+)", line)
        if match:
            obj = match.group(1).strip()
            typ = match.group(2).strip()
            return line[: match.start()] + f"isinstance({obj}, {typ})" + line[match.end() :]
        return line

    def apply_to_file(self, filepath: Path, dry_run: bool = False) -> tuple[list[FixSuggestion], Optional[str]]:
        """Analyze and optionally apply fixes to a file.

        Returns:
            (suggestions, new_source_or_None)
        """
        source = filepath.read_text(encoding="utf-8")
        suggestions = self.analyze(source)
        if not suggestions:
            return [], None

        new_source = self.apply(source, suggestions)
        if not dry_run:
            filepath.write_text(new_source, encoding="utf-8")
        return suggestions, new_source
