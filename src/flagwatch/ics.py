from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from icalendar import Calendar
from icalendar import Event as CalendarEvent

from flagwatch.domain import Event


def render_calendar(events: Iterable[Event], generated_at: datetime | None = None) -> str:
    calendar = Calendar()
    calendar.add("version", "2.0")
    calendar.add("prodid", "-//Flagwatch//CTF Calendar//EN")
    calendar.add("calscale", "GREGORIAN")
    stamp = generated_at or datetime.now(UTC)
    for event in events:
        item = CalendarEvent()
        item.add("uid", f"{event.key}@flagwatch.local")
        item.add("dtstamp", stamp)
        item.add("dtstart", event.starts_at.astimezone(UTC))
        item.add("dtend", event.finishes_at.astimezone(UTC))
        item.add("summary", event.title)
        item.add("description", str(event.official_url))
        item.add("url", str(event.official_url))
        item.add(
            "status",
            {"cancelled": "CANCELLED", "tentative": "TENTATIVE"}.get(
                event.status.value, "CONFIRMED"
            ),
        )
        item.add("transp", "TRANSPARENT")
        calendar.add_component(item)
    return str(calendar.to_ical().decode("utf-8"))


def render_ics(event: Event) -> str:
    return render_calendar([event])
