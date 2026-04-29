"""File watcher for continuous analysis.

Watches a directory for file changes and re-runs analysis automatically.
Zero external dependencies — uses stdlib only.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from apex_debug.core.finding import Finding
from apex_debug.core.session import DebugSession, SessionConfig
from apex_debug.engine.runner import run_pattern_engine
from apex_debug.parsers.registry import ParserRegistry


class FileWatcher:
    """Watch a directory for source file changes and trigger analysis.

    Usage:
        watcher = FileWatcher("src/", on_findings=lambda findings: print(findings))
        watcher.start()
        # ... later ...
        watcher.stop()
    """

    def __init__(
        self,
        target: str | Path,
        interval: float = 2.0,
        on_findings: Optional[Callable[[list[Finding], list[Finding]], None]] = None,
        session_config: Optional[SessionConfig] = None,
    ) -> None:
        self.target = Path(target).resolve()
        self.interval = max(0.5, interval)
        self.on_findings = on_findings or (lambda x: None)
        self.config = session_config or SessionConfig(target=self.target)

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._snapshots: dict[Path, float] = {}
        self._previous_findings: dict[Path, list[Finding]] = {}
        self._parser = ParserRegistry()

    def _take_snapshot(self) -> dict[Path, float]:
        """Return mtime snapshot for all supported files under target."""
        snap: dict[Path, float] = {}
        for f in self._parser.discover_files(self.target):
            try:
                snap[f] = f.stat().st_mtime
            except (OSError, ValueError):
                pass
        return snap

    def _get_changed_files(self, new_snap: dict[Path, float]) -> list[Path]:
        """Compare new snapshot to previous and return changed file paths."""
        changed: list[Path] = []
        # New or modified files
        for f, mtime in new_snap.items():
            if f not in self._snapshots or self._snapshots[f] != mtime:
                changed.append(f)
        # Deleted files (cleanup previous findings)
        for f in list(self._previous_findings):
            if f not in new_snap:
                del self._previous_findings[f]
        return changed

    def _analyze_file(self, filepath: Path) -> list[Finding]:
        """Run analysis on a single file and return findings."""
        source = self._parser.read_file(filepath)
        if source is None:
            return []

        session = DebugSession(config=self.config)
        run_pattern_engine(session, filepath, source)
        return session.findings

    def _diff_findings(
        self, filepath: Path, new_findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding]]:
        """Compare new findings to previous ones.

        Returns:
            (added, removed) tuple of findings.
        """
        old = self._previous_findings.get(filepath, [])
        old_fps = {self._fingerprint(f) for f in old}
        new_fps = {self._fingerprint(f) for f in new_findings}

        added = [f for f in new_findings if self._fingerprint(f) not in old_fps]
        removed = [f for f in old if self._fingerprint(f) not in new_fps]
        return added, removed

    @staticmethod
    def _fingerprint(f: Finding) -> str:
        """Simple fingerprint for deduplication."""
        return f"{f.file}:{f.line}:{f.title}"

    def _loop(self) -> None:
        """Main watch loop — runs in a background thread."""
        # Initial scan
        self._snapshots = self._take_snapshot()
        for f in self._snapshots:
            findings = self._analyze_file(f)
            self._previous_findings[f] = findings

        while self._running:
            time.sleep(self.interval)
            if not self._running:
                break

            new_snap = self._take_snapshot()
            changed = self._get_changed_files(new_snap)
            self._snapshots = new_snap

            if changed:
                all_added: list[Finding] = []
                all_removed: list[Finding] = []

                for filepath in changed:
                    new_findings = self._analyze_file(filepath)
                    added, removed = self._diff_findings(filepath, new_findings)
                    self._previous_findings[filepath] = new_findings
                    all_added.extend(added)
                    all_removed.extend(removed)

                if all_added or all_removed:
                    self.on_findings(all_added, all_removed)

    def start(self) -> None:
        """Start watching in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop watching and wait for thread to finish."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=self.interval + 1)
            self._thread = None

    def __enter__(self) -> FileWatcher:
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.stop()
