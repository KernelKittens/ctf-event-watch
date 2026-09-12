from datetime import UTC, datetime, timedelta

from flagwatch.domain import Event, EventFacts, SourceKind, SourceRef
from flagwatch.sources import EventBatch
from flagwatch.sources.composite import CompositeSource


class StubSource:
    def __init__(
        self,
        source_name: str,
        precedence: int,
        events: list[tuple[Event, EventFacts]],
        failures: list[str] | None = None,
    ) -> None:
        self.source_name = source_name
        self.precedence = precedence
        self.events = events
        self.failures = failures or []

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        return EventBatch(events=self.events, failures=self.failures)


class CrashingSource:
    source_name = "broken"
    precedence = 10

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        raise RuntimeError("token=must-not-leak")


def make_event(
    source: str,
    source_id: str,
    *,
    title: str = "Example CTF",
    official_url: str = "https://example.test/event",
    starts_at: datetime | None = None,
    organizers: list[str] | None = None,
    team_max: int | None = None,
    ref_url: str | None = None,
    kind: SourceKind = SourceKind.JSON_FEED,
) -> tuple[Event, EventFacts]:
    start = starts_at or datetime(2026, 9, 1, 12, tzinfo=UTC)
    event = Event(
        source=source,
        source_id=source_id,
        title=title,
        official_url=official_url,
        starts_at=start,
        finishes_at=start + timedelta(days=1),
        online=True,
        organizers=organizers or [],
        source_refs=[
            SourceRef(
                source=source,
                kind=kind,
                url=ref_url or official_url,
                record_id=source_id,
                collected_at=datetime(2026, 8, 23, 15, tzinfo=UTC),
            )
        ],
    )
    return event, EventFacts(team_max=team_max)


def test_merges_exact_official_url_and_keeps_all_sources() -> None:
    official = make_event(
        "official",
        "event",
        team_max=4,
        ref_url="https://example.test/rules",
        kind=SourceKind.OFFICIAL_PAGE,
    )
    feed = make_event(
        "feed",
        "42",
        ref_url="https://example.test/events.json",
        kind=SourceKind.JSON_FEED,
    )
    source = CompositeSource(
        [StubSource("official", 10, [official]), StubSource("feed", 30, [feed])],
        now=lambda: datetime(2026, 8, 23, 16, tzinfo=UTC),
    )

    batch = source.fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert len(batch.events) == 1
    event, facts = batch.events[0]
    assert event.key == "official:event"
    assert [ref.source for ref in event.source_refs] == ["official", "feed"]
    assert facts.team_max == 4


def test_title_only_similarity_never_merges() -> None:
    first = make_event("one", "1", official_url="https://one.test/event")
    second = make_event("two", "2", official_url="https://two.test/event")

    batch = CompositeSource(
        [StubSource("one", 20, [first]), StubSource("two", 20, [second])]
    ).fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert len(batch.events) == 2


def test_title_organizer_and_overlapping_time_can_merge() -> None:
    first = make_event(
        "one",
        "1",
        official_url="https://one.test/event",
        organizers=["Kernel Kittens"],
    )
    second = make_event(
        "two",
        "2",
        title="  EXAMPLE   ctf ",
        official_url="https://two.test/event",
        organizers=["kernel kittens"],
        starts_at=datetime(2026, 9, 1, 14, tzinfo=UTC),
    )

    batch = CompositeSource(
        [StubSource("one", 20, [first]), StubSource("two", 30, [second])]
    ).fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert len(batch.events) == 1


def test_higher_precedence_wins_and_safety_conflict_suppresses_alert() -> None:
    official = make_event(
        "official",
        "event",
        starts_at=datetime(2026, 9, 1, 12, tzinfo=UTC),
        team_max=4,
        ref_url="https://example.test/rules",
        kind=SourceKind.OFFICIAL_PAGE,
    )
    feed = make_event(
        "feed",
        "42",
        starts_at=datetime(2026, 9, 1, 13, tzinfo=UTC),
        team_max=5,
        ref_url="https://example.test/events.json",
        kind=SourceKind.JSON_FEED,
    )
    source = CompositeSource(
        [StubSource("feed", 30, [feed]), StubSource("official", 10, [official])],
        now=lambda: datetime(2026, 8, 23, 16, tzinfo=UTC),
    )

    batch = source.fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 10, 1, tzinfo=UTC),
    )

    event, facts = batch.events[0]
    assert event.key == "official:event"
    assert event.starts_at == datetime(2026, 9, 1, 12, tzinfo=UTC)
    assert facts.team_max == 4
    assert {conflict.field for conflict in event.conflicts} == {
        "finishes_at",
        "starts_at",
        "team_max",
    }
    assert all(conflict.suppresses_alert for conflict in event.conflicts)


def test_merge_bounds_long_conflicts_without_dropping_healthy_events() -> None:
    official_event, official_facts = make_event(
        "official",
        "event",
        ref_url="https://example.test/rules",
        kind=SourceKind.OFFICIAL_PAGE,
    )
    feed_event, feed_facts = make_event(
        "feed",
        "42",
        ref_url="https://example.test/events.json",
        kind=SourceKind.JSON_FEED,
    )
    healthy = make_event(
        "healthy",
        "1",
        official_url="https://healthy.test/event",
    )
    official = (
        official_event,
        official_facts.model_copy(update={"prize_summary": "A" * 501}),
    )
    feed = (
        feed_event,
        feed_facts.model_copy(update={"prize_summary": "B" * 501}),
    )

    batch = CompositeSource(
        [
            StubSource("official", 10, [official]),
            StubSource("feed", 30, [feed]),
            StubSource("healthy", 20, [healthy]),
        ],
        now=lambda: datetime(2026, 8, 23, 16, tzinfo=UTC),
    ).fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert {event.key for event, _facts in batch.events} == {"official:event", "healthy:1"}
    merged = next(event for event, _facts in batch.events if event.key == "official:event")
    conflict = next(item for item in merged.conflicts if item.field == "prize_summary")
    assert len(conflict.chosen_value) == 500
    assert len(conflict.other_value) == 500
    assert conflict.chosen_value.endswith("...")
    assert conflict.other_value.endswith("...")


def test_source_failures_do_not_remove_healthy_events() -> None:
    healthy = make_event("healthy", "1")
    batch = CompositeSource(
        [
            StubSource("broken", 10, [], ["broken: timeout"]),
            StubSource("healthy", 20, [healthy]),
        ]
    ).fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert [event.key for event, _ in batch.events] == ["healthy:1"]
    assert batch.failures == ["broken: timeout"]


def test_unexpected_source_failure_does_not_expose_exception_text() -> None:
    batch = CompositeSource([CrashingSource()]).fetch_events(
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert batch.events == []
    assert batch.failures == ["broken: RuntimeError"]
    assert "must-not-leak" not in batch.failures[0]
