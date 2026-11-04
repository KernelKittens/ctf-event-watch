from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx
from pydantic import HttpUrl

from flagwatch.domain import Event, EventFacts, EventStatus, ScheduleMode, SourceKind, SourceRef
from flagwatch.rule_pages import extract_readable_text
from flagwatch.sources import EventBatch

USER_AGENT = "Flagwatch/0.1 personal CTF research"
QUERY_WINDOW_DAYS = 30
MAX_EVENTS_PER_REQUEST = 100
MIN_QUERY_WINDOW = timedelta(hours=1)
NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
}


def _parse_team_max(description: str) -> int | None:
    match = re.search(
        r"teams?(?:\s+may|\s+can)?(?:\s+include|\s+consist\s+of|\s+of)?\s+up\s+to\s+"
        r"(?P<count>\d+|one|two|three|four|five|six|seven|eight|nine|ten)",
        description,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    raw = match.group("count").lower()
    return int(raw) if raw.isdigit() else NUMBER_WORDS[raw]


def _parse_divisions(description: str) -> list[str]:
    match = re.search(
        r"(?:following\s+)?divisions?\s*:\s*(?P<divisions>[^.\r\n]+)",
        description,
        flags=re.IGNORECASE,
    )
    if not match:
        return []
    normalized = re.sub(r"\s+and\s+", ", ", match.group("divisions"), flags=re.IGNORECASE)
    return [value.strip(" ,") for value in normalized.split(",") if value.strip(" ,")]


def _decimal_or_none(value: object) -> Decimal | None:
    if value in (None, ""):
        return None
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return None


def normalize_ctftime_event(
    payload: dict[str, Any],
    collected_at: datetime | None = None,
) -> tuple[Event, EventFacts]:
    description = extract_readable_text(str(payload.get("description") or ""))
    prizes = extract_readable_text(str(payload.get("prizes") or ""))
    onsite = bool(payload.get("onsite", False))
    organizers = [
        str(organizer.get("name"))
        for organizer in payload.get("organizers", [])
        if isinstance(organizer, dict) and organizer.get("name")
    ]
    event = Event(
        source="ctftime",
        source_id=str(payload["id"]),
        status=EventStatus.CANCELLED if payload.get("cancelled") is True else EventStatus.SCHEDULED,
        title=str(payload["title"]).strip(),
        official_url=HttpUrl(str(payload["url"])),
        ctftime_url=HttpUrl(str(payload["ctftime_url"])),
        starts_at=datetime.fromisoformat(str(payload["start"])),
        finishes_at=datetime.fromisoformat(str(payload["finish"])),
        online=not onsite,
        onsite=onsite,
        format=str(payload.get("format")) if payload.get("format") else None,
        description=description,
        prizes=prizes,
        weight=_decimal_or_none(payload.get("weight")),
        organizers=organizers,
        participants=(
            int(payload["participants"]) if payload.get("participants") is not None else None
        ),
        primary_source_url=HttpUrl(str(payload["url"])),
        source_refs=[
            SourceRef(
                source="ctftime",
                kind=SourceKind.CTFTIME,
                url=HttpUrl(str(payload["ctftime_url"])),
                record_id=str(payload["id"]),
                collected_at=collected_at or datetime.now(UTC),
            )
        ],
        raw=dict(payload),
    )
    facts = EventFacts(
        team_max=_parse_team_max(description),
        divisions=_parse_divisions(description),
        schedule_mode=ScheduleMode.FIXED,
        prize_summary=prizes.strip() or None,
    )
    return event, facts


class CtftimeSource:
    source_name = "ctftime"
    precedence = 100

    def __init__(
        self,
        client: httpx.Client | None = None,
        base_url: str = "https://ctftime.org/api/v1",
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.client = client or httpx.Client(timeout=10.0)
        self.base_url = base_url.rstrip("/")
        self.now = now

    def _fetch_window(self, start: datetime, finish: datetime) -> list[object]:
        response = self.client.get(
            f"{self.base_url}/events/",
            params={
                "limit": MAX_EVENTS_PER_REQUEST,
                "start": int(start.timestamp()),
                "finish": int(finish.timestamp()),
            },
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            raise ValueError("CTFtime returned an unexpected event response")
        return payload

    def _fetch_complete_window(self, start: datetime, finish: datetime) -> list[object]:
        payload = self._fetch_window(start, finish)
        if len(payload) < MAX_EVENTS_PER_REQUEST:
            return payload
        if finish - start <= MIN_QUERY_WINDOW:
            raise ValueError(
                "CTFtime returned a saturated event response for the minimum query window"
            )
        midpoint = start + ((finish - start) / 2)
        return self._fetch_complete_window(start, midpoint) + self._fetch_complete_window(
            midpoint, finish
        )

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        if finish <= start:
            return EventBatch(events=[], failures=[])
        by_key: dict[str, tuple[Event, EventFacts]] = {}
        failures: list[str] = []
        seen_records: set[str] = set()
        cursor = start
        record_number = 0
        while cursor < finish:
            window_finish = min(cursor + timedelta(days=QUERY_WINDOW_DAYS), finish)
            try:
                payload = self._fetch_complete_window(cursor, window_finish)
            except (httpx.HTTPError, ValueError) as error:
                failures.append(
                    f"CTFtime {cursor.date()} to {window_finish.date()}: "
                    f"{type(error).__name__}: {error}"
                )
                cursor = window_finish
                continue
            for item in payload:
                record_key = json.dumps(item, sort_keys=True, default=str)
                if record_key in seen_records:
                    continue
                seen_records.add(record_key)
                record_number += 1
                if not isinstance(item, dict):
                    failures.append(f"CTFtime record {record_number}: expected an object")
                    continue
                try:
                    event, facts = normalize_ctftime_event(item, self.now())
                    by_key[event.key] = (event, facts)
                except Exception as error:
                    failures.append(
                        f"CTFtime record {record_number}: {type(error).__name__}: {error}"
                    )
            cursor = window_finish
        events = sorted(by_key.values(), key=lambda item: (item[0].starts_at, item[0].key))
        return EventBatch(events=events, failures=failures)
