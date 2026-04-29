"""Knowledge base — persistent store for resolved bugs and deduplication.

Uses SQLite for zero-dependency storage.
Enables: "We've seen this bug before — here's the fix."
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path
from typing import Optional

from apex_debug.core.finding import Finding


class KnowledgeBase:
    """Persistent knowledge base for resolved and historical findings.

    Fingerprint-based deduplication — same bug pattern gives same fingerprint.
    """

    def __init__(self, db_path: str = ".apex-debug/knowledge.db") -> None:
        self._db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._migrate()
        return self._conn

    def _migrate(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                fingerprint TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity INTEGER NOT NULL,
                message TEXT NOT NULL,
                snippet TEXT,
                ai_explanation TEXT,
                ai_fix TEXT,
                file TEXT,
                line INTEGER,
                resolved INTEGER DEFAULT 0,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                seen_count INTEGER DEFAULT 1,
                resolved_at REAL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_resolved ON findings(resolved);
        """)
        self.conn.commit()

    @staticmethod
    def fingerprint(finding: Finding) -> str:
        """Generate a content-based fingerprint for deduplication.

        Uses SHA256 of (category + title + normalized message) to identify
        semantically identical findings across different locations.
        """
        content = f"{finding.category}:{finding.title}:{finding.message[:200]}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def add(self, finding: Finding) -> bool:
        """Record a finding in the knowledge base.

        Returns True if this is a NEW finding, False if already known.
        """
        fp = finding.fingerprint or self.fingerprint(finding)
        finding.fingerprint = fp
        now = time.time()

        existing = self.get(fp)
        if existing:
            self.conn.execute(
                "UPDATE findings SET last_seen = ?, seen_count = seen_count + 1, "
                "line = ?, file = ?, snippet = ? WHERE fingerprint = ?",
                (now, finding.line, finding.file, finding.snippet, fp),
            )
            self.conn.commit()
            return False

        self.conn.execute(
            "INSERT INTO findings (fingerprint, title, category, severity, message, "
            "snippet, ai_explanation, ai_fix, file, line, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fp,
                finding.title,
                finding.category,
                finding.severity.value,
                finding.message,
                finding.snippet,
                finding.ai_explanation,
                finding.ai_fix,
                finding.file,
                finding.line,
                now,
                now,
            ),
        )
        self.conn.commit()
        return True

    def get(self, fingerprint: str) -> Optional[dict]:
        """Look up a finding by fingerprint."""
        row = self.conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return dict(row) if row else None

    def resolve(self, fingerprint: str) -> None:
        """Mark a finding as resolved."""
        now = time.time()
        self.conn.execute(
            "UPDATE findings SET resolved = 1, resolved_at = ? WHERE fingerprint = ?",
            (now, fingerprint),
        )
        self.conn.commit()

    def get_unresolved(self) -> list[dict]:
        """Get all unresolved findings."""
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE resolved = 0 ORDER BY severity DESC, last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        """Get knowledge base statistics."""
        total = self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        resolved = self.conn.execute("SELECT COUNT(*) FROM findings WHERE resolved = 1").fetchone()[0]
        by_cat = self.conn.execute(
            "SELECT category, COUNT(*) as cnt FROM findings GROUP BY category"
        ).fetchall()
        return {
            "total": total,
            "resolved": resolved,
            "unresolved": total - resolved,
            "by_category": {r["category"]: r["cnt"] for r in by_cat},
        }

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
