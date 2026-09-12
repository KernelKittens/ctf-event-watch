from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from flagwatch.domain import (
    AiPolicy,
    Criteria,
    Event,
    EventFacts,
    ScheduleMode,
    SourceConflict,
)
from flagwatch.matching import match_event


def event_with_duration(hours: int = 24) -> Event:
    start = datetime(2026, 9, 5, 14, tzinfo=UTC)
    return Event(
        source="test",
        source_id="1",
        title="Compatible CTF",
        official_url="https://ctf.example/",
        ctftime_url="https://ctftime.org/event/1/",
        starts_at=start,
        finishes_at=start + timedelta(hours=hours),
        online=True,
        prizes="$500",
        weight=25,
    )


@pytest.mark.parametrize("policy", [AiPolicy.HUMAN_ONLY, AiPolicy.UNKNOWN])
def test_incompatible_policy_never_matches(policy):
    result = match_event(
        event_with_duration(),
        EventFacts(ai_policy=policy, team_max=4),
        Criteria(max_team_size=6),
    )

    assert result.alert_eligible is False
    assert any("AI" in reason for reason in result.rejection_reasons)


def test_automation_only_ban_can_match_saved_criteria():
    result = match_event(
        event_with_duration(),
        EventFacts(
            ai_policy=AiPolicy.AI_ASSISTED,
            team_max=4,
            schedule_mode=ScheduleMode.FIXED,
            prize_summary="$500",
        ),
        Criteria(
            max_team_size=6,
            max_duration_hours=48,
            require_prize=True,
            allowed_schedule_modes={ScheduleMode.FIXED},
        ),
    )

    assert result.alert_eligible is True
    assert "AI-assisted solving is allowed" in result.match_reasons


def test_unknown_team_limit_fails_a_saved_maximum():
    result = match_event(
        event_with_duration(),
        EventFacts(ai_policy=AiPolicy.AI_NATIVE),
        Criteria(max_team_size=6),
    )

    assert result.alert_eligible is False
    assert "Team limit is unknown" in result.rejection_reasons


def test_source_conflict_suppresses_otherwise_eligible_alert() -> None:
    event = event_with_duration().model_copy(
        update={
            "conflicts": [
                SourceConflict(
                    field="team_max",
                    chosen_value="4",
                    other_value="5",
                    chosen_source_url="https://ctf.example/rules",
                    other_source_url="https://ctf.example/feed.json",
                    detected_at=datetime(2026, 9, 1, 12, tzinfo=UTC),
                    suppresses_alert=True,
                )
            ]
        }
    )

    result = match_event(
        event,
        EventFacts(
            ai_policy=AiPolicy.AI_ASSISTED,
            team_max=4,
            schedule_mode=ScheduleMode.FIXED,
        ),
        Criteria(max_team_size=6),
    )

    assert result.alert_eligible is False
    assert "Authoritative source facts conflict" in result.rejection_reasons
