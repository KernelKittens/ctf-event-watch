"""Event source adapters."""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel

from flagwatch.domain import Event, EventFacts


class SourceHealth(BaseModel):
    name: str
    events: int = 0
    failures: int = 0
    status: str = "ok"
    route: str = "primary"


@dataclass(frozen=True)
class EventBatch:
    events: list[tuple[Event, EventFacts]] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    cancelled_keys: list[str] = field(default_factory=list)
    source_health: list[SourceHealth] = field(default_factory=list)
