from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Protocol
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup
from pydantic import HttpUrl

from flagwatch.analysis.discovery import DiscoveredWatchEvent
from flagwatch.analysis.evidence import EvidenceDocument
from flagwatch.domain import Event, EventFacts, ScheduleMode, SourceKind, SourceRef
from flagwatch.fetching import FetchedPage, FetchError, GuardedFetcher
from flagwatch.sources import EventBatch


class DiscoveryExtractor(Protocol):
    def try_extract(
        self,
        document: EvidenceDocument,
        allowed_urls: Sequence[str],
        evidence_by_url: Mapping[str, str] | None = None,
    ) -> list[DiscoveredWatchEvent]: ...


EVENT_LINK_TERMS = ("ctf", "event", "competition", "challenge", "hack")
DISCOVERY_PAGE_TEXT_LIMIT = 3_000
DISCOVERY_DOCUMENT_TEXT_LIMIT = 36_000


def _event_type(value: object) -> bool:
    values = value if isinstance(value, list) else [value]
    return any(str(item).rsplit("/", 1)[-1].casefold() == "event" for item in values)


def _json_objects(value: object) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from _json_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _json_objects(child)


def _parse_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value
    if isinstance(value, date):
        return datetime.combine(value, time.min, tzinfo=UTC)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("event time is missing")
    raw = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return datetime.combine(date.fromisoformat(raw), time.min, tzinfo=UTC)
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _names(value: object) -> list[str]:
    records = value if isinstance(value, list) else [value]
    names: list[str] = []
    for record in records:
        if isinstance(record, dict):
            name = str(record.get("name") or "").strip()
        else:
            name = str(record or "").strip()
        if name and name not in names:
            names.append(name[:120])
    return names[:32]


def _location_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(_location_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(str(value.get(key) or "") for key in ("name", "url", "address", "location"))
    return ""


def _same_origin(left: str, right: str) -> bool:
    first = urlsplit(left)
    second = urlsplit(right)
    return (
        first.scheme.casefold(),
        (first.hostname or "").casefold(),
        first.port,
    ) == (
        second.scheme.casefold(),
        (second.hostname or "").casefold(),
        second.port,
    )


def discover_event_links(base_url: str, html: str, limit: int = 12) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    for anchor in soup.find_all("a", href=True):
        absolute, _fragment = urldefrag(urljoin(base_url, str(anchor["href"]).strip()))
        parsed = urlsplit(absolute)
        searchable = f"{anchor.get_text(' ', strip=True)} {parsed.path}".casefold()
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.username
            or parsed.password
            or not _same_origin(base_url, absolute)
            or not any(term in searchable for term in EVENT_LINK_TERMS)
        ):
            continue
        if absolute.rstrip("/") == base_url.rstrip("/") or absolute in links:
            continue
        links.append(absolute)
        if len(links) == limit:
            break
    return links


def _source_id(payload: dict[str, Any], official_url: str, starts_at: datetime) -> str:
    identifier = payload.get("identifier") or payload.get("@id")
    if isinstance(identifier, dict):
        identifier = identifier.get("value")
    if identifier and str(identifier).strip():
        return str(identifier).strip()[:200]
    raw = f"{official_url}\0{starts_at.isoformat()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _registration_url(payload: dict[str, Any], base_url: str) -> HttpUrl | None:
    offers = payload.get("offers")
    records = offers if isinstance(offers, list) else [offers]
    for record in records:
        if isinstance(record, dict) and record.get("url"):
            return HttpUrl(urljoin(base_url, str(record["url"])))
    return None


class WatchPageSource:
    precedence = 10

    def __init__(
        self,
        url: str,
        fetcher: GuardedFetcher,
        name: str = "official-watch-page",
        organizers: Sequence[str] = (),
        max_event_pages: int = 12,
        discovery_extractor: DiscoveryExtractor | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.url = url
        self.fetcher = fetcher
        self.source_name = name
        self.organizers = list(organizers)[:32]
        self.max_event_pages = max_event_pages
        self.discovery_extractor = discovery_extractor
        self.now = now

    def _normalize_json_ld(
        self,
        payload: dict[str, Any],
        page_url: str,
    ) -> tuple[Event, EventFacts]:
        title = str(payload.get("name") or "").strip()
        if not title:
            raise ValueError("event name is missing")
        starts_at = _parse_datetime(payload.get("startDate"))
        raw_finish = payload.get("endDate")
        finishes_at = (
            _parse_datetime(raw_finish)
            if raw_finish
            else starts_at + timedelta(days=1)
            if isinstance(payload.get("startDate"), str)
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(payload["startDate"]).strip())
            else None
        )
        if finishes_at is None:
            raise ValueError("event finish is missing")
        official_url = urljoin(page_url, str(payload.get("url") or page_url))
        if not _same_origin(self.url, official_url):
            raise ValueError("event URL is outside the configured organizer origin")
        attendance = str(payload.get("eventAttendanceMode") or "").casefold()
        location = _location_text(payload.get("location")).casefold()
        online = "online" in attendance or any(
            term in location for term in ("online", "virtual", "remote")
        )
        onsite = "offline" in attendance or "mixed" in attendance or bool(location and not online)
        organizers = list(dict.fromkeys([*_names(payload.get("organizer")), *self.organizers]))
        source_id = _source_id(payload, official_url, starts_at)
        description = BeautifulSoup(str(payload.get("description") or ""), "html.parser").get_text(
            " ", strip=True
        )
        event = Event(
            source=self.source_name,
            source_id=source_id,
            title=title,
            official_url=HttpUrl(official_url),
            starts_at=starts_at,
            finishes_at=finishes_at,
            online=online,
            onsite=onsite,
            description=description[:4000],
            organizers=organizers,
            primary_source_url=HttpUrl(page_url),
            registration_url=_registration_url(payload, page_url),
            source_refs=[
                SourceRef(
                    source=self.source_name,
                    kind=SourceKind.ORGANIZER_PAGE,
                    url=HttpUrl(page_url),
                    record_id=source_id,
                    collected_at=self.now(),
                )
            ],
        )
        return event, EventFacts(schedule_mode=ScheduleMode.FIXED)

    def _json_ld_events(
        self,
        page: FetchedPage,
    ) -> tuple[list[tuple[Event, EventFacts]], list[str]]:
        if page.html is None:
            return [], []
        soup = BeautifulSoup(page.html, "html.parser")
        events: list[tuple[Event, EventFacts]] = []
        failures: list[str] = []
        record_number = 0
        for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
            try:
                document = json.loads(script.string or script.get_text() or "")
            except (json.JSONDecodeError, TypeError):
                failures.append(f"{self.source_name}: invalid JSON-LD document")
                continue
            for record in _json_objects(document):
                if not _event_type(record.get("@type")):
                    continue
                record_number += 1
                try:
                    events.append(self._normalize_json_ld(record, page.url))
                except (TypeError, ValueError) as error:
                    failures.append(
                        f"{self.source_name} JSON-LD event {record_number}: "
                        f"{type(error).__name__}: invalid event data"
                    )
        return events, failures

    def _model_events(
        self,
        homepage: FetchedPage,
        pages: Sequence[FetchedPage],
    ) -> list[tuple[Event, EventFacts]]:
        if self.discovery_extractor is None or len(pages) < 2:
            return []
        unique_pages: dict[str, FetchedPage] = {}
        for page in pages[1:]:
            key = page.url.rstrip("/").casefold()
            unique_pages.setdefault(key, page)
        approved_pages = list(unique_pages.values())
        if not approved_pages:
            return []
        all_pages = [homepage, *approved_pages]
        allowed_urls = [page.url for page in approved_pages]
        linked_text = "\n".join(f"APPROVED EVENT URL: {url}" for url in allowed_urls)
        headers = [f"OFFICIAL PAGE URL: {page.url}\n" for page in all_pages]
        fixed_length = (
            sum(len(header) for header in headers) + len("\n\n") * len(all_pages) + len(linked_text)
        )
        per_page_limit = min(
            DISCOVERY_PAGE_TEXT_LIMIT,
            max(0, DISCOVERY_DOCUMENT_TEXT_LIMIT - fixed_length) // len(all_pages),
        )
        if per_page_limit == 0:
            return []
        snippets = [page.text[:per_page_limit] for page in all_pages]
        page_text = "\n\n".join(
            f"{header}{snippet}" for header, snippet in zip(headers, snippets, strict=True)
        )
        document = EvidenceDocument(homepage.url, f"{page_text}\n\n{linked_text}".strip())
        evidence_by_url = {
            page.url: snippet for page, snippet in zip(approved_pages, snippets[1:], strict=True)
        }
        records = self.discovery_extractor.try_extract(
            document,
            allowed_urls,
            evidence_by_url,
        )
        events: list[tuple[Event, EventFacts]] = []
        for record in records:
            payload: dict[str, Any] = {
                "@type": "Event",
                "name": record.title,
                "startDate": record.starts_at,
                "endDate": record.finishes_at,
                "url": str(record.url),
                "organizer": [{"name": name} for name in self.organizers],
                "description": record.evidence,
                "eventAttendanceMode": "OnlineEventAttendanceMode",
            }
            events.append(self._normalize_json_ld(payload, homepage.url))
        return events

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        if finish <= start:
            return EventBatch()
        try:
            homepage = self.fetcher.get_page(self.url)
        except (FetchError, httpx.HTTPError, OSError) as error:
            return EventBatch(
                failures=[f"{self.source_name}: {type(error).__name__}: watch page unavailable"]
            )
        if not _same_origin(self.url, homepage.url):
            return EventBatch(
                failures=[f"{self.source_name}: watch page redirected outside configured origin"]
            )
        links = discover_event_links(homepage.url, homepage.html or "", self.max_event_pages)
        pages = [homepage]
        failures: list[str] = []
        for link in links:
            try:
                page = self.fetcher.get_page(link)
            except (FetchError, httpx.HTTPError, OSError) as error:
                failures.append(
                    f"{self.source_name}: {link}: {type(error).__name__}: event page unavailable"
                )
                continue
            if not _same_origin(homepage.url, page.url):
                failures.append(f"{self.source_name}: {link}: redirected outside configured origin")
                continue
            pages.append(page)
        events: list[tuple[Event, EventFacts]] = []
        for page in pages:
            parsed, parse_failures = self._json_ld_events(page)
            events.extend(parsed)
            failures.extend(parse_failures)
        if not events:
            events.extend(self._model_events(homepage, pages))
        unique: dict[str, tuple[Event, EventFacts]] = {}
        for event, facts in events:
            if event.starts_at < finish and event.finishes_at > start:
                unique[str(event.official_url).rstrip("/").casefold()] = (event, facts)
        return EventBatch(
            events=sorted(unique.values(), key=lambda item: (item[0].starts_at, item[0].key)),
            failures=failures,
        )
