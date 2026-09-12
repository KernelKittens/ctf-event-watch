from __future__ import annotations

import json
from datetime import UTC, datetime

from flagwatch.analysis.discovery import DiscoveredWatchEvent
from flagwatch.analysis.evidence import EvidenceDocument
from flagwatch.fetching import FetchedPage, FetchError
from flagwatch.sources.watch_page import (
    DISCOVERY_DOCUMENT_TEXT_LIMIT,
    WatchPageSource,
    discover_event_links,
)


class MappingFetcher:
    def __init__(self, pages: dict[str, FetchedPage]) -> None:
        self.pages = pages
        self.requested: list[str] = []

    def get_page(self, url: str) -> FetchedPage:
        self.requested.append(url)
        if url not in self.pages:
            raise FetchError("missing fixture")
        return self.pages[url]


class StaticDiscovery:
    def __init__(self, events: list[DiscoveredWatchEvent]) -> None:
        self.events = events
        self.documents: list[EvidenceDocument] = []
        self.evidence_by_url: dict[str, str] = {}

    def try_extract(
        self,
        document: EvidenceDocument,
        allowed_urls: list[str],
        evidence_by_url: dict[str, str] | None = None,
    ) -> list[DiscoveredWatchEvent]:
        self.documents.append(document)
        self.evidence_by_url = evidence_by_url or {}
        return [event for event in self.events if str(event.url) in allowed_urls]


def page(url: str, html: str) -> FetchedPage:
    return FetchedPage(url=url, text=" ".join(html.split()), html=html)


def test_watch_page_parses_schema_org_event_and_source_provenance() -> None:
    url = "https://organizer.example/events"
    payload = {
        "@context": "https://schema.org",
        "@type": "Event",
        "identifier": "kitten-2026",
        "name": "Kitten CTF 2026",
        "startDate": "2026-08-29T12:00:00Z",
        "endDate": "2026-08-30T12:00:00Z",
        "url": "https://organizer.example/events/kitten-2026",
        "eventAttendanceMode": "https://schema.org/OnlineEventAttendanceMode",
        "organizer": {"@type": "Organization", "name": "Kernel Kittens"},
        "offers": {"url": "https://organizer.example/register/kitten-2026"},
    }
    html = (
        '<main><h1>Events</h1></main><script type="application/ld+json">'
        + json.dumps(payload)
        + "</script>"
    )
    source = WatchPageSource(
        url,
        MappingFetcher({url: page(url, html)}),  # type: ignore[arg-type]
        now=lambda: datetime(2026, 8, 23, 12, tzinfo=UTC),
    )

    batch = source.fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 9, 1, tzinfo=UTC),
    )

    assert batch.failures == []
    event, facts = batch.events[0]
    assert event.source_id == "kitten-2026"
    assert event.online is True
    assert event.organizers == ["Kernel Kittens"]
    assert str(event.registration_url) == "https://organizer.example/register/kitten-2026"
    assert str(event.source_refs[0].url) == url
    assert facts.schedule_mode.value == "fixed"


def test_watch_page_reads_bounded_same_origin_event_links() -> None:
    home = "https://organizer.example/events"
    linked = "https://organizer.example/events/linked-ctf"
    linked_payload = {
        "@type": "Event",
        "name": "Linked CTF",
        "startDate": "2026-08-27T18:00:00Z",
        "endDate": "2026-08-28T18:00:00Z",
        "url": linked,
        "eventAttendanceMode": "OnlineEventAttendanceMode",
    }
    home_html = (
        '<main><a href="/events/linked-ctf">Linked CTF</a>'
        '<a href="https://outside.example/event/ignore">Outside event</a></main>'
    )
    linked_html = (
        '<script type="application/ld+json">'
        + json.dumps(linked_payload)
        + "</script><main>Linked CTF details</main>"
    )
    fetcher = MappingFetcher(
        {
            home: page(home, home_html),
            linked: page(linked, linked_html),
        }
    )
    source = WatchPageSource(home, fetcher, max_event_pages=1)  # type: ignore[arg-type]

    batch = source.fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 9, 1, tzinfo=UTC),
    )

    assert fetcher.requested == [home, linked]
    assert [event.title for event, _facts in batch.events] == ["Linked CTF"]
    assert discover_event_links(home, home_html, limit=1) == [linked]


def test_watch_page_uses_model_discovery_only_with_approved_event_url() -> None:
    home = "https://organizer.example/events"
    linked = "https://organizer.example/events/no-json-ctf"
    linked_evidence = (
        "Official event page evidence: August 29, 2026 12:00 UTC to August 30, 2026 12:00 UTC."
    )
    html = (
        "<main><p>See the official event page.</p>"
        '<a href="/events/no-json-ctf">CTF details</a></main>'
    )
    discovered = DiscoveredWatchEvent(
        title="No JSON CTF",
        starts_at=datetime(2026, 8, 29, 12, tzinfo=UTC),
        finishes_at=datetime(2026, 8, 30, 12, tzinfo=UTC),
        url=linked,
        source_url=home,
        evidence=linked_evidence,
    )
    extractor = StaticDiscovery([discovered])
    fetcher = MappingFetcher(
        {
            home: page(home, html),
            linked: page(linked, f"<main>{linked_evidence}</main>"),
        }
    )
    source = WatchPageSource(
        home,
        fetcher,  # type: ignore[arg-type]
        organizers=["Official Org"],
        discovery_extractor=extractor,
    )

    batch = source.fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 9, 1, tzinfo=UTC),
    )

    assert [event.title for event, _facts in batch.events] == ["No JSON CTF"]
    assert extractor.documents
    assert "APPROVED EVENT URL" in extractor.documents[0].text
    assert linked_evidence in extractor.documents[0].text
    assert linked_evidence in extractor.evidence_by_url[linked]


def test_watch_page_rejects_cross_origin_redirect_evidence() -> None:
    home = "https://organizer.example/events"
    linked = "https://organizer.example/events/redirected-ctf"
    foreign = "https://outside.example/redirected-ctf"
    foreign_evidence = "Foreign page claims a CTF happens August 29 through August 30."
    home_html = '<main><a href="/events/redirected-ctf">Redirected CTF</a></main>'
    discovered = DiscoveredWatchEvent(
        title="Redirected CTF",
        starts_at=datetime(2026, 8, 29, 12, tzinfo=UTC),
        finishes_at=datetime(2026, 8, 30, 12, tzinfo=UTC),
        url=linked,
        source_url=home,
        evidence=foreign_evidence,
    )
    extractor = StaticDiscovery([discovered])
    fetcher = MappingFetcher(
        {
            home: page(home, home_html),
            linked: page(foreign, f"<main>{foreign_evidence}</main>"),
        }
    )
    source = WatchPageSource(home, fetcher, discovery_extractor=extractor)  # type: ignore[arg-type]

    batch = source.fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 9, 1, tzinfo=UTC),
    )

    assert batch.events == []
    assert any("redirected outside" in failure for failure in batch.failures)
    assert all(foreign_evidence not in document.text for document in extractor.documents)


def test_watch_page_budgets_all_approved_pages_and_keeps_final_evidence() -> None:
    home = "https://organizer.example/events"
    links = [f"https://organizer.example/events/ctf-{index:02d}" for index in range(24)]
    final_evidence = "Final page dates are September 20, 2026 through September 21, 2026."
    home_html = (
        "<main>"
        + "".join(f'<a href="/events/ctf-{index:02d}">CTF {index:02d}</a>' for index in range(24))
        + "</main>"
    )
    pages = {home: page(home, home_html)}
    for index, link in enumerate(links):
        prefix = final_evidence if index == 23 else f"Official CTF page {index:02d}."
        pages[link] = page(link, f"<main>{prefix} {'X' * 4_000}</main>")
    discovered = DiscoveredWatchEvent(
        title="Final CTF",
        starts_at=datetime(2026, 9, 20, 12, tzinfo=UTC),
        finishes_at=datetime(2026, 9, 21, 12, tzinfo=UTC),
        url=links[-1],
        source_url=home,
        evidence=final_evidence,
    )
    extractor = StaticDiscovery([discovered])
    source = WatchPageSource(
        home,
        MappingFetcher(pages),  # type: ignore[arg-type]
        max_event_pages=24,
        discovery_extractor=extractor,
    )

    batch = source.fetch_events(
        datetime(2026, 9, 1, tzinfo=UTC),
        datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert [event.title for event, _facts in batch.events] == ["Final CTF"]
    assert len(extractor.documents[0].text) <= DISCOVERY_DOCUMENT_TEXT_LIMIT
    assert final_evidence in extractor.evidence_by_url[links[-1]]
    assert set(extractor.evidence_by_url) == set(links)


def test_watch_page_does_not_leak_bad_json_ld_body_in_failure() -> None:
    home = "https://organizer.example/events"
    html = (
        '<script type="application/ld+json">'
        '{"@type":"Event","secret":"do-not-leak"}'
        "</script><main>Events</main>"
    )
    source = WatchPageSource(
        home,
        MappingFetcher({home: page(home, html)}),  # type: ignore[arg-type]
    )

    batch = source.fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 9, 1, tzinfo=UTC),
    )

    assert batch.events == []
    assert len(batch.failures) == 1
    assert "do-not-leak" not in batch.failures[0]
