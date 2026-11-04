from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_serializer, field_validator

from flagwatch.domain import (
    AiPolicy,
    EventAnalytics,
    EventAssessment,
    EventStatus,
    EventView,
    IntelClaim,
    RecommendationStatus,
    ScheduleMode,
    SourceConflict,
    SourceRef,
    SourceScanStatus,
)
from flagwatch.sources import SourceHealth
from flagwatch.storage import Database
from flagwatch.sync import SyncService


class PublicEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    event_key: str
    status: EventStatus = EventStatus.SCHEDULED
    title: str
    official_url: HttpUrl
    ctftime_url: HttpUrl | None
    primary_source_url: HttpUrl
    registration_url: HttpUrl | None
    platform: str | None
    source_refs: list[SourceRef]
    conflicts: list[SourceConflict]
    analytics: EventAnalytics
    starts_at: datetime
    finishes_at: datetime
    online: bool
    onsite: bool
    format: str | None
    weight: Decimal | None
    organizers: list[str]
    participants: int | None
    assessment: EventAssessment | None = None
    ai_policy: AiPolicy
    ai_policy_reason: str
    ai_policy_source: HttpUrl | None
    ai_policy_evidence: str | None
    ai_policy_confidence: float
    ai_policy_conflicting: bool
    analysis_stale: bool
    team_max: int | None
    divisions: list[str]
    schedule_mode: ScheduleMode
    prize_summary: str | None
    registration_status: str | None
    categories: list[str]
    intel_claims: list[IntelClaim]
    intel_model: str | None
    intel_analyzed_at: datetime | None
    intel_stale: bool
    source_scan_status: SourceScanStatus
    source_scan_reason: str
    source_pages_checked: int
    source_rule_pages_found: int
    source_checked_at: datetime | None
    recheck_due_at: datetime | None = None

    @field_validator("starts_at", "finishes_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Public timestamps must include a timezone")
        return value.astimezone(UTC)

    @field_serializer("starts_at", "finishes_at", when_used="json")
    def serialize_timestamp(self, value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    @field_serializer("source_checked_at", "intel_analyzed_at", "recheck_due_at", when_used="json")
    def serialize_optional_timestamp(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class PublicScanSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sources_read: int
    sources_need_recheck: int
    policies_confirmed: int


class PublicSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    generated_at: datetime
    coverage: list[SourceHealth] = Field(default_factory=list)
    scan_summary: PublicScanSummary
    events: list[PublicEvent]

    @field_validator("generated_at")
    @classmethod
    def normalize_generated_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Public timestamps must include a timezone")
        return value.astimezone(UTC)

    @field_serializer("generated_at", when_used="json")
    def serialize_generated_at(self, value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")


def _recheck_due(view: EventView, now: datetime) -> datetime | None:
    checked = view.facts.source_checked_at
    return (
        checked + SyncService._recheck_priority_and_interval(view.event, now)[1]
        if checked
        else None
    )


def _stale(view: EventView, now: datetime) -> bool:
    due = _recheck_due(view, now)
    return (
        view.facts.analysis_stale
        or due is None
        or now > due
        or (
            view.facts.source_checked_at is not None
            and view.facts.source_checked_at - now > timedelta(minutes=5)
        )
    )


def _public_assessment(view: EventView, now: datetime) -> EventAssessment | None:
    assessment = view.facts.assessment
    if assessment is not None and _stale(view, now):
        return assessment.model_copy(update={"recommendation": RecommendationStatus.NEEDS_RULES})
    return assessment


def build_public_snapshot(
    database: Database,
    generated_at: datetime,
    history_days: int = 31,
) -> PublicSnapshot:
    history_cutoff = generated_at - timedelta(days=history_days)
    events = [
        PublicEvent(
            event_key=view.event.key,
            status=view.event.status,
            title=view.event.title,
            official_url=view.event.official_url,
            ctftime_url=view.event.ctftime_url,
            primary_source_url=view.event.primary_source_url or view.event.official_url,
            registration_url=view.event.registration_url,
            platform=view.event.platform,
            source_refs=view.event.source_refs,
            conflicts=view.event.conflicts,
            analytics=view.event.analytics,
            starts_at=view.event.starts_at,
            finishes_at=view.event.finishes_at,
            online=view.event.online,
            onsite=view.event.onsite,
            format=view.event.format,
            weight=view.event.weight,
            organizers=view.event.organizers,
            participants=view.event.participants,
            assessment=_public_assessment(view, generated_at),
            ai_policy=view.facts.ai_policy,
            ai_policy_reason=view.facts.ai_policy_reason,
            ai_policy_source=(
                HttpUrl(view.facts.ai_policy_source) if view.facts.ai_policy_source else None
            ),
            ai_policy_evidence=view.facts.ai_policy_evidence,
            ai_policy_confidence=view.facts.ai_policy_confidence,
            ai_policy_conflicting=view.facts.ai_policy_conflicting,
            analysis_stale=_stale(view, generated_at),
            team_max=view.facts.team_max,
            divisions=view.facts.divisions,
            schedule_mode=view.facts.schedule_mode,
            prize_summary=view.facts.prize_summary,
            registration_status=view.facts.registration_status,
            categories=view.facts.categories,
            intel_claims=view.facts.intel_claims,
            intel_model=None,
            intel_analyzed_at=view.facts.intel_analyzed_at,
            intel_stale=view.facts.intel_stale,
            source_scan_status=view.facts.source_scan_status,
            source_scan_reason=view.facts.source_scan_reason,
            source_pages_checked=view.facts.source_pages_checked,
            source_rule_pages_found=view.facts.source_rule_pages_found,
            source_checked_at=view.facts.source_checked_at,
            recheck_due_at=_recheck_due(view, generated_at),
        )
        for view in database.list_events()
        if view.event.finishes_at >= history_cutoff
    ]
    summary = PublicScanSummary(
        sources_read=sum(
            event.source_scan_status is SourceScanStatus.READ and not event.analysis_stale
            for event in events
        ),
        sources_need_recheck=sum(
            event.source_scan_status is not SourceScanStatus.READ or event.analysis_stale
            for event in events
        ),
        policies_confirmed=sum(
            event.ai_policy in {AiPolicy.AI_NATIVE, AiPolicy.AI_ASSISTED}
            and not event.analysis_stale
            and not event.ai_policy_conflicting
            for event in events
        ),
    )
    return PublicSnapshot(generated_at=generated_at, scan_summary=summary, events=events)
