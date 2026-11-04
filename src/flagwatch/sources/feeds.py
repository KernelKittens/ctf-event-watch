from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, date, datetime, time
from typing import Any

import httpx
from icalendar import Calendar
from pydantic import HttpUrl

from flagwatch.domain import Event, EventFacts, EventStatus, ScheduleMode, SourceKind, SourceRef
from flagwatch.fetching import FetchError, GuardedFetcher
from flagwatch.rule_pages import extract_readable_text
from flagwatch.sources import EventBatch


def _aware_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event time must include a timezone")
        return value
    if isinstance(value, date):
        return datetime.combine(value, time.min, tzinfo=UTC)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("event time must include a timezone")
        return parsed
    raise ValueError("event time is missing or invalid")


def _overlaps(event: Event, start: datetime, finish: datetime) -> bool:
    return event.starts_at < finish and event.finishes_at > start


def _record_id(payload: Mapping[str, object]) -> str:
    explicit = payload.get("id") or payload.get("uid") or payload.get("source_id")
    if explicit is not None and str(explicit).strip():
        return str(explicit).strip()[:200]
    identity = "\0".join(
        str(payload.get(key) or "") for key in ("title", "name", "start", "starts_at", "url")
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def _organizers(value: object) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()][:32]
    return []


def _ical_organizers(component: Any) -> list[str]:
    raw = component.get("ORGANIZER")
    values: Iterable[object] = raw if isinstance(raw, list) else [raw]
    names: list[str] = []
    for value in values:
        if value is None:
            continue
        params = getattr(value, "params", {})
        name = str(params.get("CN") or "").strip()
        if name and name not in names:
            names.append(name)
    return names[:32]


class IcsFeedSource:
    precedence = 40

    def __init__(
        self,
        url: str,
        fetcher: GuardedFetcher,
        name: str = "ics",
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.url = url
        self.fetcher = fetcher
        self.source_name = name
        self.now = now

    def _normalize(self, component: Any) -> tuple[Event, EventFacts]:
        source_id = str(component.get("UID") or "").strip()
        if not source_id:
            raise ValueError("event UID is required")
        starts_at = _aware_datetime(component.decoded("DTSTART"))
        finishes_at = _aware_datetime(component.decoded("DTEND"))
        title = str(component.get("SUMMARY") or "").strip()
        if not title:
            raise ValueError("event summary is required")
        description = extract_readable_text(str(component.get("DESCRIPTION") or ""))
        location = str(component.get("LOCATION") or "").strip()
        location_key = location.casefold()
        online = not location or any(
            word in location_key for word in ("online", "virtual", "remote")
        )
        official_url = str(component.get("URL") or self.url).strip()
        event = Event(
            source=self.source_name,
            source_id=source_id[:200],
            status=EventStatus.CANCELLED
            if str(component.get("STATUS", "")).upper() == "CANCELLED"
            else EventStatus.SCHEDULED,
            title=title,
            official_url=HttpUrl(official_url),
            starts_at=starts_at,
            finishes_at=finishes_at,
            online=online,
            onsite=bool(location) and not online,
            description=description,
            raw={"location": location},
            organizers=_ical_organizers(component),
            primary_source_url=HttpUrl(self.url),
            source_refs=[
                SourceRef(
                    source=self.source_name,
                    kind=SourceKind.ICS,
                    url=HttpUrl(self.url),
                    record_id=source_id[:200],
                    collected_at=self.now(),
                )
            ],
        )
        return event, EventFacts(schedule_mode=ScheduleMode.FIXED)

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        if finish <= start:
            return EventBatch()
        try:
            page = self.fetcher.get_page(self.url)
            calendar = Calendar.from_ical(page.text)
        except (FetchError, httpx.HTTPError, ValueError, TypeError, KeyError) as error:
            return EventBatch(
                failures=[f"{self.source_name}: {type(error).__name__}: feed unavailable"]
            )
        events: list[tuple[Event, EventFacts]] = []
        failures: list[str] = []
        cancelled_keys: list[str] = []
        for index, component in enumerate(calendar.walk("VEVENT"), start=1):
            try:
                if str(component.get("STATUS", "")).upper() == "CANCELLED":
                    uid = str(component.get("UID") or "").strip()
                    if not uid:
                        raise ValueError("Cancellation requires a UID")
                    cancelled_keys.append(f"{self.source_name}:{uid[:200]}")
                    if "DTSTART" not in component or "DTEND" not in component:
                        continue
                if component.get("RRULE") or component.get("RECURRENCE-ID"):
                    raise ValueError("Recurring event needs explicit occurrence expansion")
                normalized = self._normalize(component)
                if _overlaps(normalized[0], start, finish):
                    events.append(normalized)
            except (ValueError, TypeError, KeyError) as error:
                failures.append(
                    f"{self.source_name} record {index}: {type(error).__name__}: invalid event data"
                )
        events.sort(key=lambda item: (item[0].starts_at, item[0].key))
        return EventBatch(events=events, failures=failures, cancelled_keys=cancelled_keys)


class JsonFeedSource:
    precedence = 45

    def __init__(
        self,
        url: str,
        fetcher: GuardedFetcher,
        name: str = "json",
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.url = url
        self.fetcher = fetcher
        self.source_name = name
        self.now = now

    def _normalize(self, payload: Mapping[str, object]) -> tuple[Event, EventFacts]:
        starts_at = _aware_datetime(payload.get("starts_at") or payload.get("start"))
        finishes_at = _aware_datetime(payload.get("finishes_at") or payload.get("finish"))
        title = str(payload.get("title") or payload.get("name") or "").strip()
        if not title:
            raise ValueError("event title is required")
        source_id = _record_id(payload)
        official_url = str(payload.get("official_url") or payload.get("url") or self.url)
        location = str(payload.get("location") or "").strip()
        default_online = not bool(location)
        online = bool(payload.get("online", default_online))
        onsite = bool(payload.get("onsite", bool(location) and not online))
        description = extract_readable_text(str(payload.get("description") or ""))
        prizes = extract_readable_text(str(payload.get("prizes") or ""))
        registration_url = payload.get("registration_url")
        event = Event(
            source=self.source_name,
            source_id=source_id,
            status=EventStatus.CANCELLED
            if payload.get("cancelled") is True
            or str(payload.get("status", "")).lower() == "cancelled"
            else EventStatus.SCHEDULED,
            title=title,
            official_url=HttpUrl(official_url),
            starts_at=starts_at,
            finishes_at=finishes_at,
            online=online,
            onsite=onsite,
            format=str(payload.get("format")) if payload.get("format") else None,
            description=description,
            prizes=prizes,
            organizers=_organizers(payload.get("organizers")),
            participants=(
                int(str(payload["participants"]))
                if payload.get("participants") is not None
                else None
            ),
            primary_source_url=HttpUrl(self.url),
            registration_url=HttpUrl(str(registration_url)) if registration_url else None,
            platform=str(payload.get("platform")) if payload.get("platform") else None,
            source_refs=[
                SourceRef(
                    source=self.source_name,
                    kind=SourceKind.JSON_FEED,
                    url=HttpUrl(self.url),
                    record_id=source_id,
                    collected_at=self.now(),
                )
            ],
            raw=dict(payload),
        )
        facts = EventFacts(
            schedule_mode=ScheduleMode.FIXED,
            prize_summary=prizes or None,
        )
        return event, facts

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        if finish <= start:
            return EventBatch()
        try:
            page = self.fetcher.get_page(self.url)
            payload = json.loads(page.text)
            records = payload.get("events") if isinstance(payload, dict) else payload
            if not isinstance(records, list):
                raise ValueError("JSON feed must provide an events array")
        except (
            FetchError,
            httpx.HTTPError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
        ) as error:
            return EventBatch(
                failures=[f"{self.source_name}: {type(error).__name__}: feed unavailable"]
            )
        events: list[tuple[Event, EventFacts]] = []
        failures: list[str] = []
        for index, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                failures.append(f"{self.source_name} record {index}: expected an object")
                continue
            try:
                normalized = self._normalize(record)
                if _overlaps(normalized[0], start, finish):
                    events.append(normalized)
            except (ValueError, TypeError, KeyError) as error:
                failures.append(
                    f"{self.source_name} record {index}: {type(error).__name__}: invalid event data"
                )
        events.sort(key=lambda item: (item[0].starts_at, item[0].key))
        return EventBatch(events=events, failures=failures)
