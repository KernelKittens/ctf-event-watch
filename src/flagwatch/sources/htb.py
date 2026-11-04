"""The public event listing used by the HTB events page."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from pydantic import HttpUrl

from flagwatch.domain import Event, EventFacts, ScheduleMode, SourceKind, SourceRef
from flagwatch.sources import EventBatch
from flagwatch.sources.feeds import _aware_datetime

LISTING = "https://ctf.hackthebox.com/events/upcoming"
API = "https://ctf.hackthebox.com/api/public/ctfs"
MAX_BYTES = 2 * 1024 * 1024


def browser_listing() -> list[dict[str, Any]]:
    # The ordinary public page performs this request. No login or saved browser state.
    from playwright.sync_api import sync_playwright

    with sync_playwright() as driver:
        browser = driver.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.route(
                "**/*",
                lambda route: (
                    route.continue_()
                    if urlsplit(route.request.url).hostname
                    in {"ctf.hackthebox.com", "js.recurly.com"}
                    else route.abort()
                ),
            )
            with page.expect_response(
                lambda response: response.url == API, timeout=30_000
            ) as pending:
                navigation = page.goto(LISTING, wait_until="domcontentloaded", timeout=30_000)
                if navigation is None or navigation.status != 200:
                    raise ValueError("Public listing navigation unavailable")
            response = pending.value
            if response.status != 200:
                raise ValueError("Public listing unavailable")
            declared = response.headers.get("content-length")
            if declared and int(declared) > MAX_BYTES:
                raise ValueError("Public listing exceeds size limit")
            body = response.body()
            if len(body) > MAX_BYTES:
                raise ValueError("Public listing exceeds size limit")
            records = json.loads(body)
            if not isinstance(records, list) or len(records) > 2000:
                raise ValueError("Unexpected public listing shape")
            return records
        finally:
            browser.close()


class HtbSource:
    source_name = "hack-the-box-public"
    precedence = 20

    def fetch_events(self, start: datetime, finish: datetime) -> EventBatch:
        events: list[tuple[Event, EventFacts]] = []
        failures: list[str] = []
        try:
            records = browser_listing()
        except Exception as error:
            return EventBatch(
                failures=[f"{self.source_name}: {type(error).__name__}: listing unavailable"]
            )
        for index, record in enumerate(records):
            try:
                if record.get("private") or record.get("isOrganizationScoped"):
                    continue
                slug = str(record["slug"])
                if not re.fullmatch(r"[A-Za-z0-9-]{1,240}", slug):
                    raise ValueError("Invalid event slug")
                begins = _aware_datetime(record["starts_at"])
                ends = _aware_datetime(record["ends_at"])
                if begins >= finish or ends <= start:
                    continue
                url = HttpUrl("https://ctf.hackthebox.com/event/details/" + slug)
                identifier = str(record["id"])
                event = Event(
                    source=self.source_name,
                    source_id=identifier,
                    title=str(record["name"]),
                    official_url=url,
                    primary_source_url=HttpUrl(API),
                    registration_url=url,
                    starts_at=begins,
                    finishes_at=ends,
                    online=True,
                    platform="Hack The Box",
                    format=str(record.get("format") or "Jeopardy"),
                    participants=record.get("players"),
                    raw={"players": record.get("players")},
                    organizers=[record["org_name"]] if record.get("org_name") else [],
                    source_refs=[
                        SourceRef(
                            source=self.source_name,
                            record_id=identifier,
                            kind=SourceKind.ORGANIZER_PAGE,
                            url=HttpUrl(API),
                            collected_at=datetime.now(UTC),
                        )
                    ],
                )
                facts = EventFacts(
                    schedule_mode=ScheduleMode.FIXED,
                    team_max=record.get("team_size"),
                    registration_status="Access code required" if record.get("hasCode") else None,
                )
                # mcp_access_mode describes platform access, not permission to use AI.
                events.append((event, facts))
            except (KeyError, TypeError, ValueError, AttributeError) as error:
                failures.append(f"{self.source_name} record {index}: {type(error).__name__}")
        return EventBatch(events=events, failures=failures)
