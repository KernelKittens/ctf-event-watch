from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from pydantic import HttpUrl

from flagwatch.domain import Event, EventFacts, SourceConflict, SourceRef
from flagwatch.sources import EventBatch


class RankedEventSource(Protocol):
    source_name: str
    precedence: int

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch: ...


@dataclass(frozen=True)
class _Candidate:
    event: Event
    facts: EventFacts
    precedence: int


SAFETY_EVENT_FIELDS = ("starts_at", "finishes_at", "registration_url")
DISPLAY_EVENT_FIELDS = (
    "format",
    "platform",
    "participants",
    "registration_url",
    "weight",
)
FACT_FIELDS = (
    "team_max",
    "divisions",
    "schedule_mode",
    "prize_summary",
    "registration_status",
    "categories",
)
SAFETY_FACT_FIELDS = {"team_max", "registration_status"}
CONFLICT_VALUE_MAX_LENGTH = 500
CONFLICT_VALUE_ELLIPSIS = "..."


def _canonical_url(value: object) -> str:
    if value is None:
        return ""
    parsed = urlsplit(str(value))
    host = (parsed.hostname or "").casefold()
    port = parsed.port
    if port is not None and not (
        (parsed.scheme.casefold() == "https" and port == 443)
        or (parsed.scheme.casefold() == "http" and port == 80)
    ):
        host = f"{host}:{port}"
    path = re.sub(r"/+", "/", parsed.path).rstrip("/") or "/"
    return urlunsplit((parsed.scheme.casefold(), host, path, "", ""))


def _normalized_text(value: str) -> str:
    return " ".join(value.casefold().split())


def _event_urls(event: Event) -> set[str]:
    values = {
        _canonical_url(event.official_url),
        _canonical_url(event.primary_source_url),
        _canonical_url(event.registration_url),
    }
    return {value for value in values if value}


def _time_ranges_overlap(left: Event, right: Event) -> bool:
    return left.starts_at < right.finishes_at and right.starts_at < left.finishes_at


def _same_identity(left: Event, right: Event) -> bool:
    if _event_urls(left) & _event_urls(right):
        return True
    if _normalized_text(left.title) != _normalized_text(right.title):
        return False
    left_organizers = {_normalized_text(value) for value in left.organizers if value.strip()}
    right_organizers = {_normalized_text(value) for value in right.organizers if value.strip()}
    return bool(left_organizers & right_organizers) and _time_ranges_overlap(left, right)


def _source_url(event: Event) -> str:
    if event.source_refs:
        return str(event.source_refs[0].url)
    return str(event.primary_source_url or event.official_url)


def _printable(value: object) -> str:
    if isinstance(value, datetime):
        rendered = value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    elif isinstance(value, list):
        rendered = ", ".join(str(item) for item in value)
    else:
        rendered = "" if value is None else str(value)
    if len(rendered) <= CONFLICT_VALUE_MAX_LENGTH:
        return rendered
    keep = CONFLICT_VALUE_MAX_LENGTH - len(CONFLICT_VALUE_ELLIPSIS)
    return f"{rendered[:keep]}{CONFLICT_VALUE_ELLIPSIS}"


def _is_empty(value: object) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _merge_refs(chosen: Event, other: Event) -> list[SourceRef]:
    refs: list[SourceRef] = []
    seen: set[tuple[str, str, str, str | None]] = set()
    for ref in [*chosen.source_refs, *other.source_refs]:
        key = (ref.source.casefold(), ref.kind.value, _canonical_url(ref.url), ref.record_id)
        if key in seen:
            continue
        seen.add(key)
        refs.append(ref)
    return refs


def _conflict(
    field: str,
    chosen_value: object,
    other_value: object,
    chosen: Event,
    other: Event,
    detected_at: datetime,
    *,
    suppresses_alert: bool,
) -> SourceConflict | None:
    chosen_url = _source_url(chosen)
    other_url = _source_url(other)
    if _canonical_url(chosen_url) == _canonical_url(other_url):
        return None
    return SourceConflict(
        field=field,
        chosen_value=_printable(chosen_value),
        other_value=_printable(other_value),
        chosen_source_url=HttpUrl(chosen_url),
        other_source_url=HttpUrl(other_url),
        detected_at=detected_at,
        suppresses_alert=suppresses_alert,
    )


def _merge_candidates(left: _Candidate, right: _Candidate, detected_at: datetime) -> _Candidate:
    chosen, other = (right, left) if right.precedence < left.precedence else (left, right)
    event = chosen.event.model_copy(deep=True)
    facts = chosen.facts.model_copy(deep=True)
    event_updates: dict[str, object] = {}
    fact_updates: dict[str, object] = {}
    conflicts = [*event.conflicts, *other.event.conflicts]

    for field in DISPLAY_EVENT_FIELDS:
        chosen_value = getattr(event, field)
        other_value = getattr(other.event, field)
        if _is_empty(chosen_value) and not _is_empty(other_value):
            event_updates[field] = other_value

    for field in SAFETY_EVENT_FIELDS:
        chosen_value = getattr(event, field)
        other_value = getattr(other.event, field)
        if _is_empty(chosen_value) or _is_empty(other_value) or chosen_value == other_value:
            continue
        conflict = _conflict(
            field,
            chosen_value,
            other_value,
            event,
            other.event,
            detected_at,
            suppresses_alert=True,
        )
        if conflict is not None:
            conflicts.append(conflict)

    for field in FACT_FIELDS:
        chosen_value = getattr(facts, field)
        other_value = getattr(other.facts, field)
        if _is_empty(chosen_value) and not _is_empty(other_value):
            fact_updates[field] = other_value
            continue
        if _is_empty(chosen_value) or _is_empty(other_value) or chosen_value == other_value:
            continue
        conflict = _conflict(
            field,
            chosen_value,
            other_value,
            event,
            other.event,
            detected_at,
            suppresses_alert=field in SAFETY_FACT_FIELDS,
        )
        if conflict is not None:
            conflicts.append(conflict)

    organizers = list(dict.fromkeys([*event.organizers, *other.event.organizers]))
    event_updates.update(
        source_refs=_merge_refs(event, other.event),
        conflicts=conflicts,
        organizers=organizers,
    )
    return _Candidate(
        event=event.model_copy(update=event_updates),
        facts=facts.model_copy(update=fact_updates),
        precedence=chosen.precedence,
    )


class CompositeSource:
    source_name = "composite"
    precedence = 0

    def __init__(
        self,
        sources: Sequence[RankedEventSource],
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.sources = list(sources)
        self.now = now

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        candidates: list[_Candidate] = []
        failures: list[str] = []
        for source in self.sources:
            try:
                batch = source.fetch_events(start, finish)
            except Exception as error:
                failures.append(f"{source.source_name}: {type(error).__name__}")
                continue
            failures.extend(batch.failures)
            for event, facts in batch.events:
                incoming = _Candidate(
                    event=event.model_copy(deep=True),
                    facts=facts.model_copy(deep=True),
                    precedence=source.precedence,
                )
                matching_index = next(
                    (
                        index
                        for index, candidate in enumerate(candidates)
                        if _same_identity(candidate.event, incoming.event)
                    ),
                    None,
                )
                if matching_index is None:
                    candidates.append(incoming)
                    continue
                candidates[matching_index] = _merge_candidates(
                    candidates[matching_index], incoming, self.now()
                )
        events = sorted(
            ((candidate.event, candidate.facts) for candidate in candidates),
            key=lambda item: (item[0].starts_at, item[0].key),
        )
        return EventBatch(events=events, failures=failures)
