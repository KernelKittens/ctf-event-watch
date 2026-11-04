#!/usr/bin/env python3
"""Weekly CTF Calendar Digest for Kernel Kittens Discord.

Dispatches a rich weekly briefing of upcoming CTFs for the team.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta

try:
    from datetime import UTC
except ImportError:
    from datetime import timezone
    UTC = timezone.utc
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    normalized = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except Exception:
        return None


def _format_ai_policy(policy: str | None, reason: str | None) -> str:
    policy_str = (policy or "unknown").lower()
    if policy_str == "ai_native":
        badge = "🟢 **AI Native** (Unrestricted AI solving permitted)"
    elif policy_str == "ai_assisted":
        badge = "🟡 **AI Assisted** (Interactive AI allowed; auto-solvers banned)"
    elif policy_str == "human_only":
        badge = "🔴 **Human Only** (No AI allowed on challenge problems)"
    else:
        badge = "⚪ **Unverified** (Official rules unverified / pending recheck)"
    if reason and reason not in {"No clear AI policy found", "unknown"}:
        return f"{badge}\n> *{reason[:120]}*"
    return badge


def _format_team_max(team_max: int | None) -> str:
    if team_max is None:
        return "Not specified"
    if team_max == 0:
        return "Unlimited"
    if team_max == 1:
        return "Solo (1 player)"
    return f"Max {team_max} members"


def _format_links(event: dict[str, Any]) -> str:
    parts: list[str] = []
    reg_url = event.get("registration_url")
    official_url = event.get("official_url")
    ctftime_url = event.get("ctftime_url")

    if reg_url:
        parts.append(f"[**Sign Up / Register**]({reg_url})")
    if official_url and str(official_url) != str(reg_url):
        parts.append(f"[Official Website]({official_url})")
    if ctftime_url:
        parts.append(f"[CTFtime]({ctftime_url})")
    return " • ".join(parts) if parts else "No public links available"


def fetch_events(api_url: str) -> list[dict[str, Any]]:
    # Try fetching from API URL or local JSON path
    if api_url.startswith(("http://", "https://")):
        req = Request(
            api_url,
            headers={
                "User-Agent": "KernelKittens-CTFDigest/1.0",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=15) as res:
                payload = json.loads(res.read().decode("utf-8"))
                return payload.get("events", [])
        except Exception as error:
            # Fallback to local files if URL fails
            local_fallback = "/var/lib/flagwatch/public/events.json"
            if os.path.exists(local_fallback):
                with open(local_fallback, "r", encoding="utf-8") as f:
                    return json.load(f).get("events", [])
            raise RuntimeError(f"Failed to fetch CTF events: {error}") from error
    else:
        with open(api_url, "r", encoding="utf-8") as f:
            return json.load(f).get("events", [])


def build_weekly_embeds(
    events: list[dict[str, Any]],
    now: datetime,
    days: int = 7,
) -> list[dict[str, Any]]:
    window_end = now + timedelta(days=days)

    upcoming: list[tuple[datetime, dict[str, Any]]] = []
    for ev in events:
        starts_at = _parse_iso(ev.get("starts_at"))
        finishes_at = _parse_iso(ev.get("finishes_at"))
        if not starts_at or not finishes_at:
            continue
        # Include events that start within the window or are currently running
        if (now <= starts_at <= window_end) or (starts_at <= now < finishes_at):
            upcoming.append((starts_at, ev))

    upcoming.sort(key=lambda item: item[0])

    if not upcoming:
        return [
            {
                "title": "🚩 Kernel Kittens // Weekly CTF Match Briefing",
                "description": f"No online CTF competitions scheduled in the next {days} days.",
                "color": 3447003,
                "footer": {"text": "KernelKittens CTF Intelligence • Flagwatch"},
                "timestamp": now.isoformat(),
            }
        ]

    embeds: list[dict[str, Any]] = []

    # Main Header Embed
    embeds.append(
        {
            "title": "🚩 Kernel Kittens // Weekly CTF Match Briefing",
            "url": "https://kernelkittens.team/resources/",
            "description": (
                f"**{len(upcoming)} competitions** detected for the upcoming {days} days.\n"
                f"Review format, team member limits, AI eligibility, and registration portals below."
            ),
            "color": 15690286,  # Kernel Kittens Red/Orange
            "fields": [
                {
                    "name": "Live Public Calendar",
                    "value": "[calendar.kernelkittens.team](https://calendar.kernelkittens.team)",
                    "inline": True,
                },
                {
                    "name": "Team Resources",
                    "value": "[kernelkittens.team/resources](https://kernelkittens.team/resources/)",
                    "inline": True,
                },
            ],
            "footer": {"text": "KernelKittens CTF Intelligence • Flagwatch"},
            "timestamp": now.isoformat(),
        }
    )

    # Individual Event Embeds (limit max 9 embeds per Discord message to stay under 10 total)
    for starts_at, ev in upcoming[:9]:
        finishes_at = _parse_iso(ev.get("finishes_at"))
        start_ts = int(starts_at.timestamp())
        finish_ts = int(finishes_at.timestamp()) if finishes_at else start_ts

        # Determine status badge
        if starts_at <= now < (finishes_at or starts_at):
            status_text = "🔴 **LIVE NOW**"
            color = 15158332  # Red
        else:
            status_text = f"<t:{start_ts}:R>"
            color = 3447003  # Blue

        fmt = ev.get("format") or "Jeopardy"
        categories = ev.get("categories") or []
        cat_str = f" • Categories: {', '.join(categories)}" if categories else ""
        fmt_line = f"{fmt}{cat_str}"

        prizes = ev.get("prize_summary")
        prize_str = f"🏆 **Prizes**: {prizes[:160]}\n" if prizes else ""

        fields = [
            {
                "name": "Timing",
                "value": (
                    f"**Starts**: <t:{start_ts}:F> (<t:{start_ts}:R>)\n"
                    f"**Finishes**: <t:{finish_ts}:F>"
                ),
                "inline": False,
            },
            {
                "name": "Structure & Team",
                "value": (
                    f"**Format**: {fmt_line}\n"
                    f"**Team Limit**: {_format_team_max(ev.get('team_max'))}"
                ),
                "inline": True,
            },
            {
                "name": "AI Policy",
                "value": _format_ai_policy(ev.get("ai_policy"), ev.get("ai_policy_reason")),
                "inline": True,
            },
        ]

        if prize_str:
            fields.append({
                "name": "Prizes",
                "value": prize_str.strip(),
                "inline": False,
            })

        fields.append({
            "name": "Portals & Links",
            "value": _format_links(ev),
            "inline": False,
        })

        embeds.append(
            {
                "title": f"{ev.get('title', 'Unknown CTF')}",
                "url": ev.get("official_url") or ev.get("ctftime_url"),
                "color": color,
                "fields": fields,
            }
        )

    return embeds


def send_to_discord(
    embeds: list[dict[str, Any]],
    webhook_url: str | None = None,
    bot_token: str | None = None,
    channel_id: str | None = None,
) -> bool:
    payload = {"embeds": embeds}

    if webhook_url:
        req = Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "KernelKittens-CTFDigest/1.0",
            },
            method="POST",
        )
    elif bot_token and channel_id:
        req = Request(
            f"https://discord.com/api/v10/channels/{channel_id}/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bot {bot_token}",
                "Content-Type": "application/json",
                "User-Agent": "KernelKittens-CTFDigest/1.0",
            },
            method="POST",
        )
    else:
        raise ValueError("Must provide either webhook_url or bot_token and channel_id")

    try:
        with urlopen(req, timeout=15) as res:
            return 200 <= res.status < 300
    except HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        print(f"Discord API error {err.code}: {body}", file=sys.stderr)
        return False
    except URLError as err:
        print(f"Network error sending to Discord: {err}", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Send weekly CTF match briefing to Discord")
    parser.add_argument(
        "--api-url",
        default=os.environ.get(
            "FLAGWATCH_PUBLIC_URL", "https://calendar.kernelkittens.team/api/events"
        ),
        help="URL or local path to flagwatch events JSON",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Lookahead days for upcoming matches (default: 7)",
    )
    parser.add_argument(
        "--webhook-url",
        default=os.environ.get("DISCORD_CTF_WEBHOOK"),
        help="Discord webhook URL",
    )
    parser.add_argument(
        "--bot-token",
        default=os.environ.get("DISCORD_TOKEN"),
        help="Discord bot token",
    )
    parser.add_argument(
        "--channel-id",
        default=os.environ.get("DISCORD_CTF_CHANNEL", "1567275364718215168"),
        help="Discord channel ID (default Kum Kabal admin-log: 1567275364718215168)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print embeds payload to stdout without dispatching to Discord",
    )
    args = parser.parse_args()

    now = datetime.now(UTC)
    events = fetch_events(args.api_url)
    embeds = build_weekly_embeds(events, now, days=args.days)

    if args.dry_run:
        print(json.dumps(embeds, indent=2))
        return 0

    success = send_to_discord(
        embeds,
        webhook_url=args.webhook_url,
        bot_token=args.bot_token,
        channel_id=args.channel_id,
    )

    if success:
        print(f"Successfully posted weekly CTF digest ({len(embeds) - 1} matches) to Discord.")
        return 0
    else:
        print("Failed to dispatch CTF digest to Discord.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
