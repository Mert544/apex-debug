"""Git diff integration — analyze only changed lines.

Useful for pre-commit hooks and CI: only lint what you changed.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DiffHunk:
    """A single changed hunk in a diff."""

    filepath: str
    start_line: int
    lines: list[str] = field(default_factory=list)


def get_git_diff(staged: bool = False) -> list[DiffHunk]:
    """Parse git diff and return changed hunks.

    Args:
        staged: If True, only check staged changes.

    Returns:
        List of DiffHunk with line numbers of added/modified lines.
    """
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    cmd.extend(["--unified=0"])  # Minimal context for easier parsing

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    return _parse_diff(result.stdout)


def _parse_diff(diff_text: str) -> list[DiffHunk]:
    """Parse git diff --unified=0 output."""
    hunks: list[DiffHunk] = []
    current_file: Optional[str] = None
    current_start: int = 0

    for line in diff_text.split("\n"):
        if line.startswith("+++"):
            # +++ b/path/to/file.py
            parts = line.split("\t")
            current_file = parts[0][6:]  # Strip "+++ b/"
        elif line.startswith("@@"):
            # @@ -old_start,old_count +new_start,new_count @@
            # We care about the new file side (+)
            match = __import__("re").search(r"\+\d+(?:,\d+)?", line)
            if match:
                start_str = match.group(0)[1:]  # Strip leading +
                if "," in start_str:
                    current_start = int(start_str.split(",")[0])
                else:
                    current_start = int(start_str)
        elif line.startswith("+") and not line.startswith("+++"):
            # Added line
            if current_file is not None:
                hunks.append(
                    DiffHunk(
                        filepath=current_file,
                        start_line=current_start,
                        lines=[line[1:]],
                    )
                )
                current_start += 1
        elif line.startswith(" "):
            # Context line — skip for our purposes
            current_start += 1

    return hunks


def filter_findings_to_diff(
    findings: list, hunks: list[DiffHunk]
) -> list:
    """Keep only findings that fall within changed hunks.

    Args:
        findings: List of Finding objects
        hunks: List of DiffHunk from git diff

    Returns:
        Findings whose line numbers overlap with changed lines.
    """
    # Build a set of (filepath, line) tuples for quick lookup
    changed_lines: set[tuple[str, int]] = set()
    for hunk in hunks:
        # Normalize path separators for cross-platform matching
        filepath = hunk.filepath.replace("/", __import__("os").sep).replace("\\", __import__("os").sep)
        for offset in range(len(hunk.lines)):
            changed_lines.add((filepath, hunk.start_line + offset))

    filtered = []
    for f in findings:
        fpath = str(f.file).replace("/", __import__("os").sep).replace("\\", __import__("os").sep)
        if (fpath, f.line) in changed_lines:
            filtered.append(f)

    return filtered
