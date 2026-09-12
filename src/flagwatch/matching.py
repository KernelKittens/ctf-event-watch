from __future__ import annotations

from flagwatch.domain import AiPolicy, Criteria, Event, EventFacts, MatchResult

ALERT_ELIGIBLE_POLICIES = {AiPolicy.AI_NATIVE, AiPolicy.AI_ASSISTED}


def match_event(event: Event, facts: EventFacts, criteria: Criteria) -> MatchResult:
    rejected: list[str] = []
    matched: list[str] = []

    if any(conflict.suppresses_alert for conflict in event.conflicts):
        rejected.append("Authoritative source facts conflict")

    if facts.analysis_stale:
        rejected.append("Rule analysis is stale")

    if facts.ai_policy not in ALERT_ELIGIBLE_POLICIES:
        rejected.append("AI-assisted solving is prohibited or not confirmed")
    else:
        matched.append("AI-assisted solving is allowed")

    if criteria.require_online and not event.online:
        rejected.append("Not an online event")
    elif event.online:
        matched.append("Online event")

    if criteria.max_team_size is not None:
        if facts.team_max is None:
            rejected.append("Team limit is unknown")
        elif facts.team_max > criteria.max_team_size:
            rejected.append(f"Team limit of {facts.team_max} exceeds the saved maximum")
        else:
            matched.append(f"Team limit of {facts.team_max} fits")

    duration_hours = (event.finishes_at - event.starts_at).total_seconds() / 3600
    if criteria.min_duration_hours is not None and duration_hours < criteria.min_duration_hours:
        rejected.append("Event is shorter than the saved minimum")
    if criteria.max_duration_hours is not None and duration_hours > criteria.max_duration_hours:
        rejected.append("Event is longer than the saved maximum")

    if criteria.require_prize:
        if not facts.prize_summary and not event.prizes.strip():
            rejected.append("No prize is stated")
        else:
            matched.append("Prize is stated")

    if (
        criteria.allowed_schedule_modes
        and facts.schedule_mode not in criteria.allowed_schedule_modes
    ):
        rejected.append("Schedule mode is outside the saved choices")

    if criteria.minimum_ctftime_weight is not None and (
        event.weight is None or event.weight < criteria.minimum_ctftime_weight
    ):
        rejected.append("CTFtime weight is below the saved minimum")

    return MatchResult(
        alert_eligible=not rejected,
        match_reasons=matched,
        rejection_reasons=rejected,
    )
