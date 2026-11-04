from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator


class AiPolicy(StrEnum):
    AI_NATIVE = "ai_native"
    AI_ASSISTED = "ai_assisted"
    HUMAN_ONLY = "human_only"
    UNKNOWN = "unknown"


class ScheduleMode(StrEnum):
    FIXED = "fixed"
    ROLLING = "rolling"
    STAGGERED = "staggered"
    MULTI_STAGE = "multi_stage"
    UNKNOWN = "unknown"


class SourceScanStatus(StrEnum):
    READ = "read"
    LIMITED = "limited"
    FAILED = "failed"
    NOT_CHECKED = "not_checked"


class AssessmentState(StrEnum):
    SINGLE_SOURCE = "single_source"
    CORROBORATED = "corroborated"
    CONFLICTING = "conflicting"
    UNKNOWN = "unknown"


class RecommendationStatus(StrEnum):
    RECOMMENDED = "recommended"
    EXCLUDED_AI_BANNED = "excluded_ai_banned"
    NEEDS_RULES = "needs_rules"


class RewardState(StrEnum):
    AVAILABLE = "available"
    NONE = "none"
    UNKNOWN = "unknown"


class ParticipationKind(StrEnum):
    INTERESTED = "interested"
    REGISTERED = "registered"
    MEMBERS = "members"
    TEAMS = "teams"
    UNKNOWN = "unknown"


class GeographyScope(StrEnum):
    ST_LOUIS = "st_louis"
    MISSOURI = "missouri"
    USA = "usa"
    OTHER = "other"
    UNKNOWN = "unknown"


class AssessmentEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["quote", "record"] = "quote"
    source_url: HttpUrl
    quote: str = Field(min_length=1, max_length=500)
    checked_at: datetime


class AssessmentField(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: AssessmentState = AssessmentState.UNKNOWN
    source_count: int = Field(default=0, ge=0)
    distinct_source_count: int = Field(default=0, ge=0)
    evidence: list[AssessmentEvidence] = Field(default_factory=list, max_length=24)


class AiPolicyAssessment(AssessmentField):
    policy: AiPolicy = AiPolicy.UNKNOWN


class PrizeAssessment(AssessmentField):
    reward_state: RewardState = RewardState.UNKNOWN
    amount: Decimal | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    summary: str | None = Field(default=None, max_length=320)


class ParticipationAssessment(AssessmentField):
    kind: ParticipationKind = ParticipationKind.UNKNOWN
    count: int | None = Field(default=None, ge=0)


class LocationAssessment(AssessmentField):
    place: str | None = Field(default=None, max_length=160)
    geography: GeographyScope = GeographyScope.UNKNOWN


class DateAssessment(AssessmentField):
    starts_at: datetime | None = None
    finishes_at: datetime | None = None


class EventAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recommendation: RecommendationStatus = RecommendationStatus.NEEDS_RULES
    assessed_at: datetime
    ai_policy: AiPolicyAssessment = Field(default_factory=AiPolicyAssessment)
    prizes: PrizeAssessment = Field(default_factory=PrizeAssessment)
    participation: ParticipationAssessment = Field(default_factory=ParticipationAssessment)
    location: LocationAssessment = Field(default_factory=LocationAssessment)
    dates: DateAssessment = Field(default_factory=DateAssessment)


class IntelTopic(StrEnum):
    OVERVIEW = "overview"
    ELIGIBILITY = "eligibility"
    REGISTRATION = "registration"
    FORMAT = "format"
    SCHEDULE = "schedule"
    PRIZES = "prizes"
    CONDUCT = "conduct"
    FLAG_SHARING = "flag_sharing"
    PLATFORM = "platform"
    AI_POLICY = "ai_policy"
    OTHER = "other"


class SourceKind(StrEnum):
    OFFICIAL_PAGE = "official_page"
    ORGANIZER_PAGE = "organizer_page"
    ICS = "ics"
    JSON_FEED = "json_feed"
    CTFD = "ctfd"
    RCTF = "rctf"
    CTFTIME = "ctftime"


class SourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=120)
    kind: SourceKind
    url: HttpUrl
    record_id: str | None = Field(default=None, min_length=1, max_length=200)
    collected_at: datetime

    @field_validator("collected_at")
    @classmethod
    def collection_time_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Source collection time must include a timezone")
        return value


class SourceConflict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1, max_length=80)
    chosen_value: str = Field(max_length=500)
    other_value: str = Field(max_length=500)
    chosen_source_url: HttpUrl
    other_source_url: HttpUrl
    detected_at: datetime
    suppresses_alert: bool = False

    @field_validator("detected_at")
    @classmethod
    def detection_time_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Conflict detection time must include a timezone")
        return value

    @model_validator(mode="after")
    def sources_must_be_distinct(self) -> SourceConflict:
        if str(self.chosen_source_url).rstrip("/") == str(self.other_source_url).rstrip("/"):
            raise ValueError("Conflict source URLs must be distinct")
        return self


class EventAnalytics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenges_total: int | None = Field(default=None, ge=0)
    visible_solves: int | None = Field(default=None, ge=0)
    scoreboard_entries: int | None = Field(default=None, ge=0)
    participants_total: int | None = Field(default=None, ge=0)
    categories: dict[str, int] = Field(default_factory=dict)

    @field_validator("categories")
    @classmethod
    def categories_must_be_bounded(cls, value: dict[str, int]) -> dict[str, int]:
        if len(value) > 64:
            raise ValueError("Event analytics supports at most 64 categories")
        for name, count in value.items():
            if not name.strip() or len(name) > 80 or count < 0:
                raise ValueError(
                    "Analytics categories require bounded names and non-negative counts"
                )
        return value


class IntelClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    topic: IntelTopic
    label: str = Field(min_length=1, max_length=80)
    value: str = Field(min_length=1, max_length=320)
    source_url: HttpUrl
    evidence: str = Field(min_length=1, max_length=500)


class EventStatus(StrEnum):
    SCHEDULED = "scheduled"
    CANCELLED = "cancelled"
    TENTATIVE = "tentative"


class Event(BaseModel):
    source: str
    source_id: str
    status: EventStatus = EventStatus.SCHEDULED
    title: str
    official_url: HttpUrl
    ctftime_url: HttpUrl | None = None
    starts_at: datetime
    finishes_at: datetime
    online: bool
    onsite: bool = False
    format: str | None = None
    description: str = ""
    prizes: str = ""
    weight: Decimal | None = None
    organizers: list[str] = Field(default_factory=list)
    participants: int | None = None
    primary_source_url: HttpUrl | None = None
    registration_url: HttpUrl | None = None
    platform: str | None = Field(default=None, max_length=80)
    source_refs: list[SourceRef] = Field(default_factory=list, max_length=32)
    conflicts: list[SourceConflict] = Field(default_factory=list, max_length=32)
    analytics: EventAnalytics = Field(default_factory=EventAnalytics)
    raw: dict[str, object] = Field(default_factory=dict)

    @field_validator("starts_at", "finishes_at")
    @classmethod
    def event_time_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Event time must include a timezone")
        return value

    @model_validator(mode="after")
    def finish_must_follow_start(self) -> Event:
        if self.finishes_at <= self.starts_at:
            raise ValueError("Event finish must follow its start")
        if self.primary_source_url is None:
            self.primary_source_url = self.official_url
        return self

    @property
    def key(self) -> str:
        return f"{self.source}:{self.source_id}"


class EventFacts(BaseModel):
    assessment: EventAssessment | None = None
    ai_policy: AiPolicy = AiPolicy.UNKNOWN
    ai_policy_reason: str = "No clear AI policy found"
    ai_policy_source: str | None = None
    ai_policy_evidence: str | None = None
    ai_policy_confidence: float = 0.0
    ai_policy_conflicting: bool = False
    team_max: int | None = None
    divisions: list[str] = Field(default_factory=list)
    schedule_mode: ScheduleMode = ScheduleMode.UNKNOWN
    prize_summary: str | None = None
    registration_status: str | None = None
    categories: list[str] = Field(default_factory=list)
    intel_claims: list[IntelClaim] = Field(default_factory=list, max_length=24)
    intel_source_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    intel_model: str | None = None
    intel_analyzed_at: datetime | None = None
    intel_stale: bool = False
    analyzed_at: datetime | None = None
    analysis_stale: bool = False
    analysis_error: str | None = None
    source_scan_status: SourceScanStatus = SourceScanStatus.NOT_CHECKED
    source_scan_reason: str = "Official source has not been checked yet"
    source_pages_checked: int = Field(default=0, ge=0)
    source_rule_pages_found: int = Field(default=0, ge=0)
    source_checked_at: datetime | None = None


class Criteria(BaseModel):
    require_online: bool = True
    allow_hybrid: bool = True
    max_team_size: int | None = None
    min_duration_hours: int | None = None
    max_duration_hours: int | None = None
    require_prize: bool = False
    minimum_cash_prize: Decimal | None = None
    allowed_schedule_modes: set[ScheduleMode] = Field(default_factory=set)
    minimum_ctftime_weight: Decimal | None = None
    version: int = 1


class MatchResult(BaseModel):
    alert_eligible: bool
    match_reasons: list[str] = Field(default_factory=list)
    rejection_reasons: list[str] = Field(default_factory=list)


class EventView(BaseModel):
    event: Event
    facts: EventFacts
