"""Bounded public schedule reader for the current US Cyber Quests edition."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone

import httpx
from bs4 import BeautifulSoup
from pydantic import HttpUrl

from flagwatch.domain import Event, EventFacts, EventStatus, ScheduleMode, SourceKind, SourceRef
from flagwatch.fetching import FetchError, GuardedFetcher
from flagwatch.sources import EventBatch

URL = "https://uscc.cyberquests.org/"


def _date(value: str) -> tuple[datetime, bool]:
    match = re.fullmatch(
        r"([A-Za-z]{3})\.\s+([A-Za-z]{3})\.\s+(\d{1,2}),\s+(\d{4})\s+"
        r"(\d{1,2}:\d{2}[ap]m)\s+(EDT|EST|PDT|PST)",
        value,
        re.I,
    )
    if not match:
        raise ValueError("Unrecognized timezone-aware schedule")
    weekday, month, day, year, clock, zone = match.groups()
    offset = {"EDT": -4, "EST": -5, "PDT": -7, "PST": -8}[zone.upper()]
    parsed = datetime.strptime(f"{month} {day} {year} {clock}", "%b %d %Y %I:%M%p")
    parsed = parsed.replace(tzinfo=timezone(timedelta(hours=offset)))
    return parsed.astimezone(UTC), parsed.strftime("%a").lower() != weekday.lower()


class UsccSource:
    precedence = 70
    source_name = "uscc-cyberquests"

    def __init__(self, fetcher: GuardedFetcher, name: str = "uscc-cyberquests") -> None:
        self.fetcher = fetcher
        self.source_name = name

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        try:
            page = self.fetcher.get_page(URL)
            soup = BeautifulSoup(page.html or page.text, "html.parser")
            title = soup.title.get_text(" ", strip=True) if soup.title else ""
            edition = re.search(r"(Spring|Summer|Fall|Winter)\s+(20\d{2})", title)
            if not edition:
                raise ValueError("Current edition missing")
            dates: dict[str, tuple[datetime, bool]] = {}
            for row in soup.select("tr"):
                cells = row.find_all("td")
                if len(cells) != 2:
                    continue
                label = cells[1].get_text(" ", strip=True).casefold()
                if label in {"quiz opens", "registration & quiz close"}:
                    dates[label] = _date(cells[0].get_text(" ", strip=True))
            begins, start_warning = dates["quiz opens"]
            ends, end_warning = dates["registration & quiz close"]
            if ends <= begins:
                raise ValueError("Invalid date order")
            if begins >= finish or ends <= start:
                return EventBatch()
            collected = datetime.now(UTC)
            text = soup.get_text(" ", strip=True)
            reward = re.search(
                r"Additional awards, prizes and scholarships may become available\.", text
            )
            warning = start_warning or end_warning
            event = Event(
                source=self.source_name,
                source_id=edition.group(0).lower().replace(" ", "-"),
                title=f"US Cyber Quests {edition.group(0)}"
                + (" (schedule needs confirmation)" if warning else ""),
                official_url=HttpUrl(URL),
                primary_source_url=HttpUrl(URL),
                starts_at=begins,
                finishes_at=ends,
                online=True,
                status=EventStatus.TENTATIVE if warning else EventStatus.SCHEDULED,
                format="Individual quiz",
                organizers=["US Cyber Challenge"],
                description=text[:18000],
                prizes=reward.group(0) if reward else "",
                raw={
                    "schedule_warning": "Published weekday disagrees with calendar date"
                    if warning
                    else ""
                },
                source_refs=[
                    SourceRef(
                        source=self.source_name,
                        kind=SourceKind.ORGANIZER_PAGE,
                        url=HttpUrl(URL),
                        record_id=edition.group(0),
                        collected_at=collected,
                    )
                ],
            )
            return EventBatch(events=[(event, EventFacts(schedule_mode=ScheduleMode.ROLLING))])
        except (FetchError, httpx.HTTPError, ValueError, KeyError, TypeError):
            return EventBatch(
                failures=[f"{self.source_name}: current official schedule unavailable or changed"]
            )
