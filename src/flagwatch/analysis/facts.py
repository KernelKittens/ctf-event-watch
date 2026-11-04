from __future__ import annotations

import re
from collections.abc import Sequence

from pydantic import HttpUrl

from flagwatch.analysis.evidence import EvidenceDocument
from flagwatch.analysis.policy import classify_ai_policy
from flagwatch.domain import EventFacts, IntelClaim, IntelTopic, ScheduleMode

NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
}
COUNT_PATTERN = (
    r"(?P<count>\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|"
    r"thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty)"
)


def _parse_count(raw: str) -> int:
    return int(raw) if raw.isdigit() else NUMBER_WORDS.get(raw.lower(), 1)


def _team_max(text: str) -> int | None:
    if re.search(
        r"\b(?:solo|individual)\s+(?:only|format|competition|contest|event|players?)\b",
        text,
        re.IGNORECASE,
    ):
        return 1
    if re.search(
        r"\bthis\s+is\s+a\s+(?:solo|individual)\s+(?:ctf|competition|contest)\b",
        text,
        re.IGNORECASE,
    ):
        return 1

    explicit = re.search(
        rf"\b(?:team\s*(?:size|limit)|max(?:imum)?\s*(?:team\s*size|team\s*members?|players?|members?|participants?))\s*[:=]\s*{COUNT_PATTERN}\b",
        text,
        re.IGNORECASE,
    )
    if explicit:
        return _parse_count(explicit.group("count"))

    per_team = re.search(
        rf"\b(?:up\s*to|at\s*most|maximum\s*of)\s+{COUNT_PATTERN}\s*(?:players?|members?|people|participants?)?\s*(?:per|in\s*a)\s*team\b",
        text,
        re.IGNORECASE,
    )
    if per_team:
        return _parse_count(per_team.group("count"))

    per_team_direct = re.search(
        rf"\b{COUNT_PATTERN}\s*(?:players?|members?|people|participants?)\s*per\s*team\b",
        text,
        re.IGNORECASE,
    )
    if per_team_direct:
        return _parse_count(per_team_direct.group("count"))

    limited = re.search(
        rf"\bteams?\s*(?:are\s*)?limited\s*to\s+{COUNT_PATTERN}\b",
        text,
        re.IGNORECASE,
    )
    if limited:
        return _parse_count(limited.group("count"))

    match = re.search(
        rf"teams?(?:\s+may|\s+can)?(?:\s+include|\s+consist\s+of|\s+of)?\s+up\s+to\s+{COUNT_PATTERN}",
        text,
        flags=re.IGNORECASE,
    )
    if match:
        return _parse_count(match.group("count"))

    teams_of = re.search(
        rf"\bteams?\s*of\s+{COUNT_PATTERN}\s*(?:members?|players?|people|participants?)\b",
        text,
        re.IGNORECASE,
    )
    if teams_of:
        return _parse_count(teams_of.group("count"))

    range_match = re.search(r"teams?\s+of\s+\d+\s*[-to]+\s*(?P<count>\d+)", text, re.I)
    if range_match:
        return int(range_match.group("count"))

    range_players = re.search(
        r"\b[1-9]\s*[-to]\s*(?P<count>\d+)\s*(?:players?|members?)\b", text, re.I
    )
    if range_players:
        return int(range_players.group("count"))

    return None


def _divisions(text: str) -> list[str]:
    match = re.search(r"divisions?\s*:\s*(?P<values>[^.\r\n]+)", text, re.IGNORECASE)
    if not match:
        return []
    normalized = re.sub(r"\s+and\s+", ", ", match.group("values"), flags=re.IGNORECASE)
    return [value.strip(" ,") for value in normalized.split(",") if value.strip(" ,")]


def _schedule_mode(text: str, current: ScheduleMode) -> ScheduleMode:
    if re.search(r"\bstaggered\s+start", text, re.IGNORECASE):
        return ScheduleMode.STAGGERED
    if re.search(r"\b(rolling\s+start|start\s+anytime|choose your start)\b", text, re.I):
        return ScheduleMode.ROLLING
    if re.search(r"\b(qualifier|qualification)\b", text, re.I) and re.search(
        r"\bfinal(?:s| stage)?\b", text, re.I
    ):
        return ScheduleMode.MULTI_STAGE
    return current


CATEGORY_MAP: list[tuple[str, re.Pattern[str]]] = [
    ("Web", re.compile(r"\b(?:web(?:\s+exploitation|\s+security)?)\b", re.I)),
    ("Crypto", re.compile(r"\b(?:crypto|cryptography)\b", re.I)),
    ("Reverse Engineering", re.compile(r"\b(?:rev|reversing|reverse\s+engineering)\b", re.I)),
    ("Pwn", re.compile(r"\b(?:pwn|pwnable|binary\s+exploitation|binary\s+exploit)\b", re.I)),
    ("Forensics", re.compile(r"\b(?:forensics?|dfir)\b", re.I)),
    ("Misc", re.compile(r"\b(?:misc|miscellaneous)\b", re.I)),
    ("OSINT", re.compile(r"\b(?:osint|open\s+source\s+intelligence)\b", re.I)),
    ("Blockchain", re.compile(r"\b(?:blockchain|smart\s+contracts?|web3)\b", re.I)),
    ("Hardware", re.compile(r"\b(?:hardware|iot|firmware)\b", re.I)),
    ("Mobile", re.compile(r"\b(?:mobile|android|ios)\b", re.I)),
    ("Cloud", re.compile(r"\b(?:cloud|aws|azure|gcp)\b", re.I)),
]


def _categories(text: str) -> list[str]:
    has_challenge_context = bool(
        re.search(
            r"\b(?:categories|challenges|category|tracks|topics|problems?|jeopardy)\b",
            text,
            re.I,
        )
    )
    found = [label for label, pattern in CATEGORY_MAP if pattern.search(text)]
    if len(found) >= 2 or (found and has_challenge_context):
        return found
    return []


def _prize_summary(text: str, current: str | None) -> str | None:
    if current and current.strip():
        return current.strip()
    match = re.search(
        r"\bprizes?\s*:\s*(?P<summary>[^\r\n]+(?:\r?\n(?:\s*[-*•]|\s*\d+\.)[^\r\n]+){0,5})",
        text,
        re.I,
    )
    if match:
        cleaned = re.sub(r"\s+", " ", match.group("summary")).strip()
        if len(cleaned) >= 3:
            return cleaned[:300]
    cash_match = re.search(
        r"(?:(?:first|1st)\s*place(?:\s*prize)?\s*[:=-]?\s*|top\s*teams?\s*receive\s*)"
        r"(?P<amount>(?:\$|€|£|¥)\s*[0-9,]+|[0-9,]+\s*(?:USD|EUR|GBP|USDT))",
        text,
        re.I,
    )
    if cash_match:
        return cash_match.group(0).strip()[:200]
    return None


def _registration_url(text: str) -> str | None:
    match = re.search(
        r"\b(?:register|registration|sign[ -]?up|ctfd)\s*(?:at|here|link|portal|page)?\s*[:=-]?\s*"
        r"(?P<url>https?://[^\s)\]\"'>]+)",
        text,
        re.I,
    )
    if match:
        url = match.group("url").rstrip(".,;")
        if "ctftime.org" not in url:
            return url
    platform_match = re.search(
        r"(?P<url>https?://(?:[a-zA-Z0-9-]+\.)?(?:ctfd\.io|challs\.io|hackerone\.com|tryhackme\.com|metactf\.com)/[^\s)\]\"'>]*)",
        text,
        re.I,
    )
    if platform_match:
        return platform_match.group("url").rstrip(".,;")
    form_match = re.search(
        r"(?P<url>https?://(?:forms\.gle|docs\.google\.com/forms/[^\s)\]\"'>]+))",
        text,
        re.I,
    )
    if form_match:
        return form_match.group("url").rstrip(".,;")
    return None


def _community_url(text: str) -> str | None:
    match = re.search(
        r"(?P<url>https?://(?:discord\.gg/[a-zA-Z0-9_-]+|discord\.com/invite/[a-zA-Z0-9_-]+))",
        text,
        re.I,
    )
    if match:
        return match.group("url").rstrip(".,;")
    return None


def extract_event_facts(documents: Sequence[EvidenceDocument], seed: EventFacts) -> EventFacts:
    combined = "\n".join(document.text for document in documents)
    policy = classify_ai_policy(documents)
    team_max = _team_max(combined)
    divisions = _divisions(combined)
    categories = _categories(combined)
    prize_summary = _prize_summary(combined, seed.prize_summary)
    registration_link = _registration_url(combined)
    community_link = _community_url(combined)

    intel_claims = list(seed.intel_claims)
    seen_urls = {str(claim.source_url) for claim in intel_claims}

    if registration_link and registration_link not in seen_urls:
        try:
            intel_claims.append(
                IntelClaim(
                    topic=IntelTopic.REGISTRATION,
                    label="Registration Link",
                    value=f"Direct sign-up at {registration_link}",
                    source_url=HttpUrl(registration_link),
                    evidence=f"Registration URL: {registration_link}",
                )
            )
            seen_urls.add(registration_link)
        except Exception:
            pass

    if community_link and community_link not in seen_urls:
        try:
            intel_claims.append(
                IntelClaim(
                    topic=IntelTopic.OVERVIEW,
                    label="Community Discord",
                    value=f"Discord community: {community_link}",
                    source_url=HttpUrl(community_link),
                    evidence=f"Discord URL: {community_link}",
                )
            )
            seen_urls.add(community_link)
        except Exception:
            pass

    return seed.model_copy(
        update={
            "ai_policy": policy.policy,
            "ai_policy_reason": policy.reason,
            "ai_policy_source": policy.source_url,
            "ai_policy_evidence": policy.evidence,
            "ai_policy_confidence": policy.confidence,
            "ai_policy_conflicting": policy.conflicting,
            "team_max": team_max if team_max is not None else seed.team_max,
            "divisions": divisions or seed.divisions,
            "categories": categories or seed.categories,
            "prize_summary": prize_summary or seed.prize_summary,
            "schedule_mode": _schedule_mode(combined, seed.schedule_mode),
            "intel_claims": intel_claims,
        }
    )
