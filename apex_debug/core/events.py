"""Event bus — lightweight pub/sub for decoupled communication."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

from pydantic import BaseModel, Field


class Event(BaseModel):
    """An event emitted during a debug session."""

    name: str
    payload: dict[str, Any] = Field(default_factory=dict)


Handler = Callable[[Event], None]


class EventBus:
    """Simple in-process pub/sub event bus.

    Usage:
        bus = EventBus()
        bus.on("finding.found", lambda e: print(e.payload))
        bus.emit("finding.found", finding=some_finding)
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._all_handlers: list[Handler] = []

    def on(self, event_name: str, handler: Handler) -> None:
        self._handlers[event_name].append(handler)

    def on_any(self, handler: Handler) -> None:
        self._all_handlers.append(handler)

    def off(self, event_name: str, handler: Handler) -> None:
        try:
            self._handlers[event_name].remove(handler)
        except ValueError:
            pass

    def emit(self, name: str, **payload: Any) -> None:
        event = Event(name=name, payload=payload)
        for handler in self._handlers[name]:
            handler(event)
        for handler in self._all_handlers:
            handler(event)

    def clear(self) -> None:
        self._handlers.clear()
        self._all_handlers.clear()
