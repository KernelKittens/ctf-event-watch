from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal
from urllib.parse import urlsplit

from pydantic import HttpUrl

from flagwatch.analysis.evidence import EvidenceDocument
from flagwatch.analysis.facts import extract_event_facts
from flagwatch.domain import (
    AiPolicy,
    AiPolicyAssessment,
    AssessmentEvidence,
    AssessmentState,
    DateAssessment,
    Event,
    EventAssessment,
    EventFacts,
    GeographyScope,
    IntelTopic,
    LocationAssessment,
    ParticipationAssessment,
    ParticipationKind,
    PrizeAssessment,
    RecommendationStatus,
    RewardState,
)


def _identity(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower().removeprefix("www.")
    return "ctftime-mirror" if host == "ctftime.org" or host.endswith("hello-ctf.com") else host


def _state(
    items: list[AssessmentEvidence], conflicting: bool = False
) -> tuple[AssessmentState, int, int]:
    domains = {_identity(str(item.source_url)) for item in items}
    state = (
        AssessmentState.CONFLICTING
        if conflicting
        else (
            AssessmentState.CORROBORATED
            if len(domains) > 1
            else AssessmentState.SINGLE_SOURCE
            if domains
            else AssessmentState.UNKNOWN
        )
    )
    return state, len(items), len(domains)


def _quote(text: str, phrase: str) -> str | None:
    index = text.casefold().find(phrase.casefold())
    if index >= 0:
        return text[index : index + len(phrase)]
    pattern = r"\s+".join(re.escape(part) for part in phrase.split())
    match = re.search(pattern, text, re.I) if pattern else None
    return match.group(0) if match else None


def _policy(documents: Sequence[EvidenceDocument], checked_at: datetime) -> AiPolicyAssessment:
    observations = []
    document_conflict = False
    for document in documents:
        result = extract_event_facts([document], EventFacts())
        document_conflict = document_conflict or result.ai_policy_conflicting
        if (
            result.ai_policy is not AiPolicy.UNKNOWN or result.ai_policy_conflicting
        ) and result.ai_policy_evidence:
            quote = _quote(document.text, result.ai_policy_evidence.removesuffix("..."))
            if quote:
                observations.append(
                    (
                        result.ai_policy,
                        AssessmentEvidence(
                            source_url=HttpUrl(document.source_url),
                            quote=quote[:500],
                            checked_at=checked_at,
                        ),
                    )
                )
    policies = {item[0] for item in observations}
    conflict = document_conflict or len(policies) > 1
    evidence = [item[1] for item in observations][:24]
    state, count, distinct = _state(evidence, conflict)
    policy = next(iter(policies)) if len(policies) == 1 else AiPolicy.UNKNOWN
    return AiPolicyAssessment(
        policy=policy,
        state=state,
        source_count=count,
        distinct_source_count=distinct,
        evidence=evidence,
    )


def _prizes(
    event: Event, facts: EventFacts, documents: Sequence[EvidenceDocument], checked_at: datetime
) -> PrizeAssessment:
    # Keep different prize tiers separate; only matching claims corroborate one another.
    groups: dict[str, tuple[str, list[AssessmentEvidence]]] = {}

    def add(value: str, document: EvidenceDocument, phrase: str) -> None:
        quote = _quote(document.text, phrase)
        if not quote:
            return
        key = " ".join(value.casefold().split())
        if key not in groups:
            groups[key] = (value, [])
        proof = AssessmentEvidence(
            source_url=HttpUrl(document.source_url), quote=quote[:500], checked_at=checked_at
        )
        if proof not in groups[key][1]:
            groups[key][1].append(proof)

    for value in (event.prizes, facts.prize_summary):
        if value:
            for document in documents:
                add(value, document, value)
    for claim in facts.intel_claims:
        if claim.topic is IntelTopic.PRIZES:
            for document in documents:
                if str(claim.source_url).rstrip("/") == document.source_url.rstrip("/"):
                    add(claim.value, document, claim.evidence)
    if not groups:
        return PrizeAssessment()
    summary, evidence = next(iter(groups.values()))
    evidence = evidence[:24]
    state, count, distinct = _state(
        evidence, any(c.field in {"prizes", "prize_summary"} for c in event.conflicts)
    )
    money = re.search(
        r"(?P<currency>USD|EUR|GBP)\s*(?P<amount>[0-9][0-9,]*(?:\.[0-9]{1,2})?)", summary, re.I
    )
    reward = RewardState.AVAILABLE
    if re.search(r"\b(?:may|might|possible|pending|tba|tbd)\b", summary, re.I):
        reward = RewardState.UNKNOWN
    elif re.search(r"\b(?:no|without)\s+prizes?\b", summary, re.I):
        reward = RewardState.NONE
    return PrizeAssessment(
        reward_state=reward,
        summary=summary[:320],
        amount=Decimal(money.group("amount").replace(",", "")) if money else None,
        currency=money.group("currency").upper() if money else None,
        state=state,
        source_count=count,
        distinct_source_count=distinct,
        evidence=evidence,
    )


def _location(
    event: Event, documents: Sequence[EvidenceDocument], checked_at: datetime
) -> LocationAssessment:
    sources: list[tuple[str, str]] = []
    raw = event.raw.get("location")
    if isinstance(raw, str) and raw.strip():
        sources.append((raw, str(event.primary_source_url or event.official_url)))
    for document in documents:
        match = re.search(
            r"\b(?:venue|location|held in|takes place in)\s*[:,-]?\s*([^\n]{1,120})",
            document.text,
            re.I,
        )
        if match:
            sources.append((match.group(1).strip(), document.source_url))
    evidence: list[AssessmentEvidence] = []
    geos: list[GeographyScope] = []
    for place, url in sources:
        if re.search(r"\b(?:online|virtual)\b", place, re.I):
            continue
        value = place.casefold()
        geo = (
            GeographyScope.ST_LOUIS
            if re.search(r"(?:st\.?|saint)\s+louis\s*,\s*(?:mo|missouri)\b", value)
            else GeographyScope.MISSOURI
            if re.search(r"\bmissouri\b|,\s*mo\b", value)
            else GeographyScope.USA
            if re.search(r"\b(?:usa|united states)\b|\bbrooklyn,\s*new york\b", value)
            else GeographyScope.OTHER
        )
        geos.append(geo)
        evidence.append(
            AssessmentEvidence(source_url=HttpUrl(url), quote=place[:500], checked_at=checked_at)
        )
    if not evidence:
        return LocationAssessment()
    state, count, distinct = _state(evidence, len(set(geos)) > 1)
    return LocationAssessment(
        geography=geos[0] if len(set(geos)) == 1 else GeographyScope.UNKNOWN,
        place=evidence[0].quote[:160],
        state=state,
        source_count=count,
        distinct_source_count=distinct,
        evidence=evidence,
    )


def assess_event(
    event: Event, facts: EventFacts, documents: Sequence[EvidenceDocument], checked_at: datetime
) -> EventAssessment:
    ai = _policy(documents, checked_at)
    recommendation = (
        RecommendationStatus.EXCLUDED_AI_BANNED
        if ai.policy is AiPolicy.HUMAN_ONLY and ai.state is not AssessmentState.CONFLICTING
        else RecommendationStatus.RECOMMENDED
        if ai.policy in {AiPolicy.AI_NATIVE, AiPolicy.AI_ASSISTED}
        and ai.state is not AssessmentState.CONFLICTING
        and not facts.analysis_stale
        else RecommendationStatus.NEEDS_RULES
    )
    participation = ParticipationAssessment()
    for document in documents:
        match = re.search(
            r"\b(?:(?P<count>[0-9][0-9,]*)\s+(?P<kind>teams?|participants?|players?)\s+(?:registered|competing|participating)"
            r"|(?P<kind2>(?:registered|competing|participating) teams?|"
            r"total participants?|total players?)"
            r"\s*:\s*(?P<count2>[0-9][0-9,]*))\b",
            document.text,
            re.I,
        )
        if match and not re.search(
            r"\b(?:last year|previous year|past)\b", document.text[: match.start()], re.I
        ):
            count = int((match.group("count") or match.group("count2")).replace(",", ""))
            word = (match.group("kind") or match.group("kind2")).casefold()
            kind = ParticipationKind.TEAMS if "team" in word else ParticipationKind.REGISTERED
            participation = ParticipationAssessment(
                kind=kind,
                count=count,
                state=AssessmentState.SINGLE_SOURCE,
                source_count=1,
                distinct_source_count=1,
                evidence=[
                    AssessmentEvidence(
                        source_url=HttpUrl(document.source_url),
                        quote=match.group(0),
                        checked_at=checked_at,
                    )
                ],
            )
            break
    if (
        participation.kind is ParticipationKind.UNKNOWN
        and event.source == "ctftime"
        and event.participants is not None
    ):
        ref = next((ref for ref in event.source_refs if ref.source == "ctftime"), None)
        if ref:
            participation = ParticipationAssessment(
                kind=ParticipationKind.INTERESTED,
                count=event.participants,
                state=AssessmentState.SINGLE_SOURCE,
                source_count=1,
                distinct_source_count=1,
                evidence=[
                    AssessmentEvidence(
                        source_url=ref.url,
                        kind="record",
                        quote=json.dumps({"participants": event.participants}),
                        checked_at=ref.collected_at,
                    )
                ],
            )
    players = event.raw.get("players")
    if (
        participation.kind is ParticipationKind.UNKNOWN
        and any(ref.source == "hack-the-box-public" for ref in event.source_refs)
        and isinstance(players, int)
        and not isinstance(players, bool)
        and players >= 0
    ):
        ref = next(ref for ref in event.source_refs if ref.source == "hack-the-box-public")
        participation = ParticipationAssessment(
            kind=ParticipationKind.MEMBERS,
            count=players,
            state=AssessmentState.SINGLE_SOURCE,
            source_count=1,
            distinct_source_count=1,
            evidence=[
                AssessmentEvidence(
                    source_url=ref.url,
                    kind="record",
                    quote=json.dumps({"players": players}),
                    checked_at=ref.collected_at,
                )
            ],
        )
    start, finish = event.starts_at.isoformat(), event.finishes_at.isoformat()
    de = []
    for d in documents:
        if start in d.text and finish in d.text:
            de.append(
                AssessmentEvidence(
                    source_url=HttpUrl(d.source_url),
                    kind="record",
                    quote=f"start: {start}; finish: {finish}",
                    checked_at=checked_at,
                )
            )
    if not de and event.source_refs:
        ref = event.source_refs[0]
        de = [
            AssessmentEvidence(
                source_url=ref.url,
                kind="record",
                checked_at=ref.collected_at,
                quote=f"record {ref.record_id or event.source_id}: start {start}; finish {finish}",
            )
        ]
    ds, dc, dd = _state(
        de,
        bool(event.raw.get("schedule_warning"))
        or any(c.field in {"starts_at", "finishes_at"} for c in event.conflicts),
    )
    return EventAssessment(
        recommendation=recommendation,
        assessed_at=checked_at,
        ai_policy=ai,
        prizes=_prizes(event, facts, documents, checked_at),
        participation=participation,
        location=_location(event, documents, checked_at),
        dates=DateAssessment(
            starts_at=event.starts_at,
            finishes_at=event.finishes_at,
            state=ds,
            source_count=dc,
            distinct_source_count=dd,
            evidence=de,
        ),
    )
