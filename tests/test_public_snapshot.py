from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from flagwatch.domain import AiPolicy, Event, EventFacts, ScheduleMode, SourceScanStatus
from flagwatch.public_snapshot import build_public_snapshot
from flagwatch.storage import Database


def test_build_public_snapshot_exposes_display_facts_without_internal_data(tmp_path):
    database = Database(tmp_path / "flagwatch.sqlite3")
    database.initialize()
    starts_at = datetime(2026, 8, 15, 18, tzinfo=UTC)
    event = Event(
        source="ctftime",
        source_id="123",
        title="Example CTF",
        official_url="https://example.test/official",
        ctftime_url="https://ctftime.org/event/123",
        starts_at=starts_at,
        finishes_at=starts_at + timedelta(days=2),
        online=True,
        onsite=True,
        format="Jeopardy",
        weight=Decimal("42.50"),
        organizers=["Example Team"],
        participants=300,
        raw={"api_token": "do-not-publish", "source_payload": "private"},
    )
    database.upsert_event(event)
    database.save_facts(
        event.key,
        EventFacts(
            ai_policy=AiPolicy.AI_ASSISTED,
            ai_policy_reason="AI help is allowed for documentation.",
            ai_policy_source="https://example.test/rules",
            ai_policy_evidence="Teams may use AI for documentation.",
            ai_policy_confidence=0.9,
            ai_policy_conflicting=False,
            analysis_stale=True,
            analysis_error="model response included an internal failure",
            source_scan_status=SourceScanStatus.LIMITED,
            source_scan_reason="Some official source pages could not be read",
            source_pages_checked=2,
            source_rule_pages_found=1,
            source_checked_at=datetime(2026, 8, 14, 11, 30, tzinfo=UTC),
            team_max=4,
            divisions=["Open"],
            schedule_mode=ScheduleMode.FIXED,
            prize_summary="$1,000",
            registration_status="Open",
            categories=["web", "crypto"],
        ),
    )

    snapshot = build_public_snapshot(database, generated_at=datetime(2026, 8, 14, 12, tzinfo=UTC))
    payload = snapshot.model_dump_json()

    assert snapshot.generated_at == datetime(2026, 8, 14, 12, tzinfo=UTC)
    assert payload.count('"event_key"') == 1
    assert '"generated_at":"2026-08-14T12:00:00Z"' in payload
    assert '"starts_at":"2026-08-15T18:00:00Z"' in payload
    assert '"ai_policy":"ai_assisted"' in payload
    assert '"ai_policy_evidence":"Teams may use AI for documentation."' in payload
    assert '"schedule_mode":"fixed"' in payload
    assert '"categories":["web","crypto"]' in payload
    assert '"source_scan_status":"limited"' in payload
    assert '"source_pages_checked":2' in payload
    assert '"source_rule_pages_found":1' in payload
    assert '"source_checked_at":"2026-08-14T11:30:00Z"' in payload
    assert snapshot.scan_summary.sources_read == 0
    assert snapshot.scan_summary.sources_need_recheck == 1
    assert snapshot.scan_summary.policies_confirmed == 0
    assert "do-not-publish" not in payload
    assert "source_payload" not in payload
    assert "analysis_error" not in payload
    assert "internal failure" not in payload


def test_public_snapshot_counts_current_confirmed_policy_and_read_source(tmp_path):
    database = Database(tmp_path / "flagwatch.sqlite3")
    database.initialize()
    starts_at = datetime(2026, 8, 15, 18, tzinfo=UTC)
    event = Event(
        source="ctftime",
        source_id="confirmed",
        title="Confirmed CTF",
        official_url="https://example.test/official",
        ctftime_url="https://ctftime.org/event/confirmed",
        starts_at=starts_at,
        finishes_at=starts_at + timedelta(days=2),
        online=True,
    )
    database.upsert_event(event)
    database.save_facts(
        event.key,
        EventFacts(
            ai_policy=AiPolicy.AI_ASSISTED,
            source_scan_status=SourceScanStatus.READ,
            source_scan_reason="Official site and 1 rule page read",
            source_pages_checked=2,
            source_rule_pages_found=1,
            source_checked_at=starts_at,
        ),
    )

    snapshot = build_public_snapshot(database, generated_at=starts_at, filter_human_only=True)

    assert snapshot.scan_summary.sources_read == 1
    assert snapshot.scan_summary.sources_need_recheck == 0
    assert snapshot.scan_summary.policies_confirmed == 1


def test_build_public_snapshot_rejects_non_http_policy_evidence_url(tmp_path):
    database = Database(tmp_path / "flagwatch.sqlite3")
    database.initialize()
    starts_at = datetime(2026, 8, 15, 18, tzinfo=UTC)
    event = Event(
        source="ctftime",
        source_id="123",
        title="Example CTF",
        official_url="https://example.test/official",
        ctftime_url="https://ctftime.org/event/123",
        starts_at=starts_at,
        finishes_at=starts_at + timedelta(days=2),
        online=True,
    )
    database.upsert_event(event)
    database.save_facts(event.key, EventFacts(ai_policy_source="javascript:alert(1)"))

    with pytest.raises(ValidationError, match="URL scheme should be 'http' or 'https'"):
        build_public_snapshot(database, generated_at=starts_at)


def test_public_snapshot_omits_confirmed_full_ai_bans(tmp_path):
    database = Database(tmp_path / "flagwatch.sqlite3")
    database.initialize()
    starts_at = datetime(2026, 8, 15, 18, tzinfo=UTC)

    for source_id, policy in (
        ("assisted", AiPolicy.AI_ASSISTED),
        ("human-only", AiPolicy.HUMAN_ONLY),
        ("unverified", AiPolicy.UNKNOWN),
    ):
        event = Event(
            source="ctftime",
            source_id=source_id,
            title=f"{source_id} CTF",
            official_url=f"https://example.test/{source_id}",
            ctftime_url=f"https://ctftime.org/event/{source_id}",
            starts_at=starts_at,
            finishes_at=starts_at + timedelta(days=1),
            online=True,
        )
        database.upsert_event(event)
        database.save_facts(event.key, EventFacts(ai_policy=policy))

    for source_id, facts in (
        (
            "stale-human-only",
            EventFacts(ai_policy=AiPolicy.HUMAN_ONLY, analysis_stale=True),
        ),
        (
            "conflicting-human-only",
            EventFacts(ai_policy=AiPolicy.HUMAN_ONLY, ai_policy_conflicting=True),
        ),
    ):
        event = Event(
            source="ctftime",
            source_id=source_id,
            title=f"{source_id} CTF",
            official_url=f"https://example.test/{source_id}",
            ctftime_url=f"https://ctftime.org/event/{source_id}",
            starts_at=starts_at,
            finishes_at=starts_at + timedelta(days=1),
            online=True,
        )
        database.upsert_event(event)
        database.save_facts(event.key, facts)

    snapshot = build_public_snapshot(database, generated_at=starts_at, filter_human_only=True)

    assert {event.event_key for event in snapshot.events} == {
        "ctftime:assisted",
        "ctftime:conflicting-human-only",
        "ctftime:stale-human-only",
        "ctftime:unverified",
    }
