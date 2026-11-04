"""Live provider, independent transport mirror, then explicitly stale local state."""

from __future__ import annotations

from datetime import datetime

from flagwatch.domain import EventStatus
from flagwatch.sources import EventBatch
from flagwatch.sources.composite import RankedEventSource
from flagwatch.storage import Database


class FallbackSource:
    def __init__(
        self, primary: RankedEventSource, secondary: RankedEventSource, database: Database
    ) -> None:
        self.primary, self.secondary, self.database = primary, secondary, database
        self.source_name = primary.source_name
        self.precedence = primary.precedence
        self.last_route = "untried"

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        failures: list[str] = []
        for route, source in (("primary", self.primary), ("secondary", self.secondary)):
            try:
                batch = source.fetch_events(start, finish)
            except Exception as error:
                failures.append(f"{source.source_name}: {type(error).__name__}")
                continue
            failures.extend(batch.failures)
            if batch.events or (not batch.failures and route == "primary"):
                self.last_route = route
                return EventBatch(
                    events=batch.events, failures=failures, cancelled_keys=batch.cancelled_keys
                )
            if not batch.failures:
                failures.append(f"{source.source_name}: no replacement events available")
        self.last_route = "saved"
        names = {self.primary.source_name, self.secondary.source_name}
        events = []
        for view in self.database.list_events():
            event = view.event
            if not (event.starts_at < finish and event.finishes_at > start):
                continue
            if event.source not in names and not any(
                ref.source in names for ref in event.source_refs
            ):
                continue
            status = (
                EventStatus.CANCELLED
                if event.status is EventStatus.CANCELLED
                else EventStatus.TENTATIVE
            )
            event = event.model_copy(
                update={"status": status, "raw": {**event.raw, "cached_schedule": True}}
            )
            events.append((event, view.facts.model_copy(update={"analysis_stale": True})))
        return EventBatch(events=events, failures=failures)
