from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import azure.functions as func
import httpx

from flagwatch.analysis.llm import LlmPolicyResponse
from flagwatch.config import Settings
from flagwatch.domain import AiPolicy, Event, EventFacts, IntelClaim, IntelTopic
from flagwatch.fetching import FetchedPage
from flagwatch.public_snapshot import build_public_snapshot
from flagwatch.sources import EventBatch
from flagwatch.sources.ctftime import CtftimeSource
from flagwatch.storage import Database
from flagwatch.sync import SyncService

ROOT = Path(__file__).parents[1]


def _function_module():
    path = ROOT / "azure-functions" / "function_app.py"
    spec = importlib.util.spec_from_file_location("flagwatch_permanent_function_app", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _event(source_id: str, starts_at: datetime) -> Event:
    return Event(
        source="ctftime",
        source_id=source_id,
        title=f"History {source_id}",
        official_url="https://ctf.example/",
        ctftime_url=f"https://ctftime.org/event/{source_id}/",
        starts_at=starts_at,
        finishes_at=starts_at + timedelta(hours=12),
        online=True,
    )


def test_permanent_defaults_include_history_and_optional_model(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    settings = Settings()

    assert settings.ctftime_lookback_days == 31
    assert settings.ctftime_lookahead_days == 90
    assert settings.ai_enabled is False
    assert settings.ai_provider == "openai"
    assert settings.ai_model == "gpt-5-mini"


def test_ctftime_source_chunks_long_range_and_deduplicates(gaslight_payload) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=[gaslight_payload])

    source = CtftimeSource(client=httpx.Client(transport=httpx.MockTransport(handler)))
    start = datetime(2026, 7, 1, tzinfo=UTC)

    batch = source.fetch_events(start, start + timedelta(days=121))

    assert len(requests) == 5
    assert len(batch.events) == 1
    assert batch.failures == []
    for request in requests:
        window_start = int(request.url.params["start"])
        window_finish = int(request.url.params["finish"])
        assert 0 < window_finish - window_start <= int(timedelta(days=31).total_seconds())


def test_ctftime_source_bisects_saturated_windows(gaslight_payload) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        window_start = int(request.url.params["start"])
        window_finish = int(request.url.params["finish"])
        if window_finish - window_start > int(timedelta(days=1).total_seconds()):
            return httpx.Response(200, json=[gaslight_payload] * 100)
        return httpx.Response(200, json=[gaslight_payload])

    source = CtftimeSource(client=httpx.Client(transport=httpx.MockTransport(handler)))
    start = datetime(2026, 8, 1, tzinfo=UTC)

    batch = source.fetch_events(start, start + timedelta(days=2))

    assert len(requests) == 3
    assert len(batch.events) == 1
    assert batch.failures == []


class _CaptureSource:
    def __init__(self, event: Event) -> None:
        self.event = event
        self.ranges: list[tuple[datetime, datetime]] = []

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        self.ranges.append((start, finish))
        return EventBatch(events=[(self.event, EventFacts())])


class _IntelFetcher:
    def get_page(self, url: str) -> FetchedPage:
        if url.endswith("sitemap.xml"):
            return FetchedPage(url=url, text="not xml", html=None)
        return FetchedPage(
            url=url,
            text=(
                "Registration closes September 1. Teams may have up to four players. "
                "Sharing flags with another team is prohibited."
            ),
            html=(
                "<html><body><main>Competition rules and registration details.</main></body></html>"
            ),
        )


class _IntelExtractor:
    model = "DeepSeek-V4-Pro"

    def __init__(self, evidence: str = "Registration closes September 1.") -> None:
        self.calls = 0
        self.evidence = evidence

    def try_extract(self, _documents) -> LlmPolicyResponse:
        self.calls += 1
        return LlmPolicyResponse(
            policy=AiPolicy.UNKNOWN,
            reason="No explicit AI rule found.",
            evidence="No explicit AI rule found.",
            confidence=0.0,
            claims=[
                IntelClaim(
                    topic=IntelTopic.REGISTRATION,
                    label="Registration deadline",
                    value="September 1",
                    source_url="https://ctf.example/",
                    evidence=self.evidence,
                )
            ],
        )


def test_sync_queries_lookback_and_reuses_unchanged_intelligence(tmp_path) -> None:
    now = datetime(2026, 8, 23, 15, tzinfo=UTC)
    database = Database(tmp_path / "flagwatch.db")
    database.initialize()
    source = _CaptureSource(_event("cached-intel", now + timedelta(days=3)))
    extractor = _IntelExtractor()
    service = SyncService(
        database=database,
        source=source,
        fetcher=_IntelFetcher(),
        now=lambda: now,
        lookback_days=31,
        lookahead_days=90,
        policy_extractor=extractor,
        queue_notifications=False,
    )

    service.run()
    service.run()

    assert source.ranges[0] == (now - timedelta(days=31), now + timedelta(days=90))
    assert extractor.calls == 1
    facts = database.get_event("ctftime:cached-intel").facts
    assert facts.intel_model == "DeepSeek-V4-Pro"
    assert facts.intel_source_fingerprint
    assert facts.intel_stale is False
    assert facts.intel_claims[0].value == "September 1"


def test_sync_discards_intelligence_without_exact_source_evidence(tmp_path) -> None:
    now = datetime(2026, 8, 23, 15, tzinfo=UTC)
    database = Database(tmp_path / "flagwatch.db")
    database.initialize()
    source = _CaptureSource(_event("bad-intel", now + timedelta(days=3)))
    service = SyncService(
        database=database,
        source=source,
        fetcher=_IntelFetcher(),
        policy_extractor=_IntelExtractor("Registration is open forever."),
        queue_notifications=False,
    )

    service.run()

    facts = database.get_event("ctftime:bad-intel").facts
    assert facts.intel_claims == []


def test_model_intelligence_cannot_change_the_alert_policy_gate(tmp_path) -> None:
    now = datetime(2026, 8, 23, 15, tzinfo=UTC)
    database = Database(tmp_path / "flagwatch.db")
    database.initialize()
    source = _CaptureSource(_event("model-policy", now + timedelta(days=3)))
    extractor = _IntelExtractor()
    original_extract = extractor.try_extract

    def unsafe_extract(_documents) -> LlmPolicyResponse:
        result = original_extract(_documents)
        return result.model_copy(
            update={
                "policy": AiPolicy.AI_ASSISTED,
                "reason": "Registration text was mistaken for an AI rule.",
                "evidence": "Registration closes September 1.",
                "confidence": 0.99,
            }
        )

    extractor.try_extract = unsafe_extract
    service = SyncService(
        database=database,
        source=source,
        fetcher=_IntelFetcher(),
        now=lambda: now,
        policy_extractor=extractor,
        queue_notifications=False,
    )

    service.run()

    facts = database.get_event("ctftime:model-policy").facts
    assert facts.ai_policy is AiPolicy.UNKNOWN
    assert facts.intel_claims[0].value == "September 1"


def test_cached_model_intelligence_cannot_restore_an_alert_policy(tmp_path) -> None:
    service = SyncService(
        database=Database(tmp_path / "flagwatch.db"),
        source=_CaptureSource(_event("unused", datetime(2026, 8, 23, tzinfo=UTC))),
        fetcher=_IntelFetcher(),
        queue_notifications=False,
    )
    previous = EventFacts(
        ai_policy=AiPolicy.AI_ASSISTED,
        ai_policy_reason="Old model result",
        intel_claims=[
            IntelClaim(
                topic=IntelTopic.REGISTRATION,
                label="Registration deadline",
                value="September 1",
                source_url="https://ctf.example/",
                evidence="Registration closes September 1.",
            )
        ],
        intel_source_fingerprint="a" * 64,
        intel_model="DeepSeek-V4-Pro",
        intel_analyzed_at=datetime(2026, 8, 23, tzinfo=UTC),
    )

    facts = service._reuse_cached_analysis(EventFacts(), previous)

    assert facts.ai_policy is AiPolicy.UNKNOWN
    assert facts.intel_claims == previous.intel_claims


def test_public_snapshot_keeps_31_days_and_omits_older_events(tmp_path) -> None:
    generated_at = datetime(2026, 8, 23, 15, tzinfo=UTC)
    database = Database(tmp_path / "flagwatch.db")
    database.initialize()
    recent = _event("recent", generated_at - timedelta(days=30))
    old = _event("old", generated_at - timedelta(days=33))
    for event in (recent, old):
        database.upsert_event(event)
        database.save_facts(event.key, EventFacts())

    snapshot = build_public_snapshot(database, generated_at)

    assert [event.event_key for event in snapshot.events] == ["ctftime:recent"]


def test_public_snapshot_exposes_sourced_intelligence(tmp_path) -> None:
    generated_at = datetime(2026, 8, 23, 15, tzinfo=UTC)
    database = Database(tmp_path / "flagwatch.db")
    database.initialize()
    event = _event("intel", generated_at + timedelta(days=2))
    database.upsert_event(event)
    database.save_facts(
        event.key,
        EventFacts(
            intel_claims=[
                IntelClaim(
                    topic=IntelTopic.FLAG_SHARING,
                    label="Flag sharing",
                    value="Prohibited between teams",
                    source_url="https://ctf.example/",
                    evidence="Sharing flags with another team is prohibited.",
                )
            ],
            intel_model="DeepSeek-V4-Pro",
            intel_source_fingerprint="a" * 64,
            intel_analyzed_at=generated_at,
        ),
    )

    payload = build_public_snapshot(database, generated_at).model_dump_json()

    assert '"topic":"flag_sharing"' in payload
    assert '"evidence":"Sharing flags with another team is prohibited."' in payload
    assert '"intel_model":"DeepSeek-V4-Pro"' in payload


def test_function_events_serves_in_process_last_good_data_on_blob_failure(monkeypatch) -> None:
    module = _function_module()

    class FlakyBlobs:
        calls = 0

        def download(self, _name: str) -> bytes:
            self.calls += 1
            if self.calls == 1:
                return b'{"events":[{"event_key":"last-good"}]}'
            raise RuntimeError("temporary blob failure")

    blobs = FlakyBlobs()
    monkeypatch.setattr(module, "blob_store", lambda: blobs)
    request = func.HttpRequest(method="GET", url="https://example.test/api/events", body=b"")

    first = module.events(request)
    second = module.events(request)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.get_body() == first.get_body()
    assert second.headers["X-Flagwatch-Data-Source"] == "memory-cache"


def test_deployment_contract_keeps_http_always_ready_and_enables_intelligence() -> None:
    script = (ROOT / "scripts" / "deploy-azure.ps1").read_text(encoding="utf-8")

    assert "functionapp scale config always-ready set" in script
    assert "http=1" in script
    assert "FLAGWATCH_CTFTIME_LOOKBACK_DAYS = '31'" in script
    assert "FLAGWATCH_AI_ENABLED = 'true'" in script
    assert "FLAGWATCH_AI_MODEL = 'DeepSeek-V4-Flash-0731'" in script
    assert '"FLAGWATCH_AI_API_KEY=$aiApiKey"' not in script
    assert '--settings "@$aiSettingsPath"' in script
    assert "SetUnixFileMode" in script
