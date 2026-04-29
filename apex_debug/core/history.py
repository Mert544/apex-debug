"""History model — linear step log for debug sessions."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class StepKind(str, Enum):
    PARSE = "parse"
    ANALYZE = "analyze"
    EXPLAIN = "explain"
    FIX = "fix"
    EXECUTE = "execute"
    INSPECT = "inspect"
    BREAKPOINT = "breakpoint"
    ERROR = "error"
    INFO = "info"


class Step(BaseModel):
    """A single step in the debug session history."""

    kind: StepKind
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    message: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    duration_ms: Optional[float] = None
