"""Finding model — a detected bug, vulnerability, or code quality issue."""

from __future__ import annotations

from enum import IntEnum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name


class Finding(BaseModel):
    """A single detected issue in source code."""

    id: str = Field(description="Unique finding identifier (e.g. SEC-001)")
    file: str = Field(description="Relative file path")
    line: int = Field(description="Line number (1-indexed)")
    column: int = Field(default=0, description="Column number (0-indexed)")
    end_line: int = Field(default=0, description="End line of the issue span")
    end_column: int = Field(default=0, description="End column of the issue span")

    severity: Severity = Field(description="Issue severity level")
    category: str = Field(description="Pattern category: security, correctness, performance, style")
    title: str = Field(description="Short human-readable title")
    message: str = Field(description="Detailed description of the issue")

    snippet: str = Field(default="", description="The offending code snippet")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence 0..1")

    ai_explanation: Optional[str] = Field(default=None, description="AI-generated NL explanation")
    ai_fix: Optional[str] = Field(default=None, description="AI-generated fix suggestion (unified diff)")

    resolved: bool = Field(default=False)
    fingerprint: str = Field(default="", description="Content-based hash for knowledge base dedup")

    def to_dict(self) -> dict:
        return self.model_dump(exclude_none=True)

    def location_str(self) -> str:
        return f"{self.file}:{self.line}"
