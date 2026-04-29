"""Debug session — the main state container for a debugging run."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, PrivateAttr

from apex_debug.core.events import EventBus
from apex_debug.core.finding import Finding
from apex_debug.core.history import Step


class SessionConfig(BaseModel):
    """Configuration for a single debug session."""

    target: Path = Field(description="Target file or directory to analyze")
    ai_enabled: bool = False
    ai_model: str = "deepseek-v4-pro"
    ai_base_url: str = "https://api.deepseek.com"
    ai_api_key: str = ""
    ai_max_tokens: int = 4096
    ai_temperature: float = 0.1

    patterns_security: bool = True
    patterns_correctness: bool = True
    patterns_performance: bool = True
    patterns_style: bool = True

    min_severity: str = "low"
    knowledge_base_path: str = ".apex-debug/knowledge.db"

    auto_detect_language: bool = True
    default_language: str = "python"


class DebugSession(BaseModel):
    """Root state container for an Apex Debug session.

    One session = one analyze/debug/fix/trace run.
    """

    id: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    config: SessionConfig
    findings: list[Finding] = Field(default_factory=list)
    history: list[Step] = Field(default_factory=list)

    start_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None

    _bus: EventBus = PrivateAttr(default_factory=EventBus)

    model_config = {"arbitrary_types_allowed": True}

    @property
    def bus(self) -> EventBus:
        return self._bus

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self._bus.emit("finding.found", finding=finding.model_dump(mode="json"))

    def add_step(self, step: Step) -> None:
        self.history.append(step)

    def finish(self) -> None:
        self.end_time = datetime.now(timezone.utc).isoformat()

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def findings_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity.name.lower() == severity]

    def findings_by_category(self, category: str) -> list[Finding]:
        return [f for f in self.findings if f.category == category]
