from __future__ import annotations

import json
from collections.abc import Callable, Mapping, MutableMapping
from datetime import UTC, datetime

import httpx
from pydantic import HttpUrl

from flagwatch.domain import Event, EventFacts, ScheduleMode, SourceKind, SourceRef
from flagwatch.fetching import (
    FetchError,
    Resolver,
    ResponseTooLargeError,
    resolve_public_addresses,
    validate_public_url,
)
from flagwatch.rule_pages import extract_readable_text
from flagwatch.sources import EventBatch

API_PREFIX = "https://api.ctfhub.com/User_API/Event"
PAGE_SIZE = 100
MAX_PAGES = 40
MAX_RECORDS = 2_000


def _epoch(value: object) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("CTFHub event time must be a Unix timestamp in seconds")
    return datetime.fromtimestamp(value, UTC)


def _text(value: object, required: bool = False) -> str:
    result = value.strip() if isinstance(value, str) else ""
    if required and not result:
        raise ValueError("CTFHub required event field is missing")
    return result


def _optional_int(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = int(str(value))
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


class CtfHubSource:
    """Read the fixed, unauthenticated CTFHub API with bounded pagination."""

    source_name = "ctfhub"
    precedence = 70

    def __init__(
        self,
        client: httpx.Client,
        *,
        name: str = "ctfhub",
        resolver: Resolver = resolve_public_addresses,
        max_bytes: int = 2 * 1024 * 1024,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        detail_cache: MutableMapping[str, Mapping[str, object]] | None = None,
    ) -> None:
        self.client = client
        self.source_name = name
        self.resolver = resolver
        self.max_bytes = max_bytes
        self.now = now
        self.detail_cache = detail_cache if detail_cache is not None else {}

    def _post(self, endpoint: str, payload: Mapping[str, object]) -> Mapping[str, object]:
        url = f"{API_PREFIX}/{endpoint}"
        validate_public_url(url, self.resolver)
        with self.client.stream(
            "POST",
            url,
            json=payload,
            follow_redirects=False,
            headers={"Accept": "application/json", "User-Agent": "Flagwatch/0.2 public schedule"},
        ) as response:
            if 300 <= response.status_code < 400:
                raise FetchError("CTFHub API redirects are not allowed")
            response.raise_for_status()
            media_type = response.headers.get("content-type", "").split(";", 1)[0].casefold()
            if media_type != "application/json" and not media_type.endswith("+json"):
                raise FetchError("CTFHub API did not return JSON")
            content = bytearray()
            for chunk in response.iter_bytes():
                if len(content) + len(chunk) > self.max_bytes:
                    raise ResponseTooLargeError("CTFHub API response exceeds the size limit")
                content.extend(chunk)
        try:
            decoded = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FetchError("CTFHub API returned invalid JSON") from error
        if not isinstance(decoded, dict) or decoded.get("status") is not True:
            raise FetchError("CTFHub API returned an unsuccessful response")
        data = decoded.get("data")
        if not isinstance(data, dict):
            raise FetchError("CTFHub API response data was invalid")
        return data

    def _records(self, endpoint: str) -> list[Mapping[str, object]]:
        records: list[Mapping[str, object]] = []
        offset = 0
        total: int | None = None
        for _ in range(MAX_PAGES):
            data = self._post(endpoint, {"offset": offset, "limit": PAGE_SIZE})
            items, raw_total = data.get("items"), data.get("total")
            if not isinstance(items, list) or isinstance(raw_total, bool):
                raise FetchError(f"CTFHub {endpoint} response was invalid")
            try:
                page_total = int(str(raw_total))
            except (TypeError, ValueError) as error:
                raise FetchError(f"CTFHub {endpoint} total was invalid") from error
            if page_total < 0 or page_total > MAX_RECORDS:
                raise FetchError(f"CTFHub {endpoint} exceeds the bounded pagination limit")
            if total is None:
                total = page_total
            elif total != page_total:
                raise FetchError(f"CTFHub {endpoint} total changed during pagination")
            if any(not isinstance(item, dict) for item in items):
                raise FetchError(f"CTFHub {endpoint} contained malformed records")
            records.extend(items)
            offset += len(items)
            if offset >= total:
                return records
            if not items:
                raise FetchError(f"CTFHub {endpoint} ended before its reported total")
        raise FetchError(f"CTFHub {endpoint} reached the pagination limit")

    def _details(self, event_id: object) -> Mapping[str, object]:
        cache_key = str(event_id)
        if cache_key not in self.detail_cache:
            self.detail_cache[cache_key] = self._post("getInfo", {"event_id": event_id})
        return self.detail_cache[cache_key]

    def _normalize(
        self, summary: Mapping[str, object], details: Mapping[str, object]
    ) -> tuple[Event, EventFacts]:
        event_id = str(summary.get("id") or details.get("id") or "").strip()
        title = _text(details.get("title") or summary.get("title"), required=True)
        starts_at = _epoch(details.get("start_time", summary.get("start_time")))
        finishes_at = _epoch(details.get("end_time", summary.get("end_time")))
        official_url = _text(details.get("official_url"), required=True)
        if not event_id:
            raise ValueError("CTFHub event id is required")
        try:
            validate_public_url(official_url, self.resolver)
        except (FetchError, ValueError):
            official_url = f"https://www.ctfhub.com/#/event/{event_id}"
        form = _text(details.get("form") or summary.get("form"))
        event_class = _text(details.get("class") or summary.get("class"))
        description = extract_readable_text(_text(details.get("details")))
        prizes = _text(details.get("prizes") or details.get("prize"))
        participants = _optional_int(details.get("participants"))
        raw: dict[str, object] = {}
        if description:
            raw["description"] = description
        location = _text(details.get("location"))
        if location:
            raw["location"] = location
        if participants is not None:
            raw["participants"] = participants
        event = Event(
            source=self.source_name,
            source_id=event_id[:200],
            title=title[:240],
            official_url=HttpUrl(official_url),
            starts_at=starts_at,
            finishes_at=finishes_at,
            online=form != "线下",
            onsite=form == "线下",
            format=event_class or None,
            description=description,
            prizes=prizes,
            participants=participants,
            primary_source_url=HttpUrl(f"{API_PREFIX}/getInfo"),
            platform="CTFHub",
            source_refs=[
                SourceRef(
                    source=self.source_name,
                    kind=SourceKind.JSON_FEED,
                    url=HttpUrl(f"{API_PREFIX}/getInfo"),
                    record_id=event_id[:200],
                    collected_at=self.now(),
                )
            ],
            raw=raw,
        )
        return event, EventFacts(
            schedule_mode=ScheduleMode.FIXED,
            prize_summary=prizes or None,
            categories=[event_class] if event_class else [],
        )

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        if finish <= start:
            return EventBatch()
        candidates: dict[str, Mapping[str, object]] = {}
        failures: list[str] = []
        for endpoint in ("getUpcoming", "getAll"):
            try:
                records = self._records(endpoint)
                for item in records:
                    if item.get("id") is not None:
                        candidates[str(item["id"])] = item
            except (FetchError, httpx.HTTPError, ValueError, TypeError):
                failures.append(f"{self.source_name}: {endpoint}: feed unavailable")
        events: list[tuple[Event, EventFacts]] = []
        for index, summary in enumerate(candidates.values(), start=1):
            try:
                starts_at, finishes_at = (
                    _epoch(summary.get("start_time")),
                    _epoch(summary.get("end_time")),
                )
                if max(starts_at, finishes_at) <= start or min(starts_at, finishes_at) >= finish:
                    continue
                if finishes_at <= starts_at:
                    raise ValueError("CTFHub event finish must follow start")
                event, facts = self._normalize(summary, self._details(summary["id"]))
                events.append((event, facts))
            except (FetchError, httpx.HTTPError, ValueError, TypeError, KeyError) as error:
                failures.append(
                    f"{self.source_name} record {index}: {type(error).__name__}: invalid event data"
                )
        events.sort(key=lambda item: (item[0].starts_at, item[0].key))
        return EventBatch(events=events, failures=failures)
