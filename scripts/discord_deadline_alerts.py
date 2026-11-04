#!/usr/bin/env python3
"""24-Hour CTF Registration & Match Starting Alerts for Kernel Kittens Discord.

Monitors upcoming CTF competitions and dispatches 24-hour deadline reminders
with match details, team limits, and direct registration links.
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


def _format_ai_policy(policy: str | None) -> str:
    policy_str = (policy or "unknown").lower()
    if policy_str == "ai_native":
        return "🟢 **AI Native** (Unrestricted AI permitted)"
    if policy_str == "ai_assisted":
        return "🟡 **AI Assisted** (Interactive AI allowed; auto-solvers banned)"
    if policy_str == "human_only":
        return "🔴 **Human Only** (No AI permitted)"
    return "⚪ **Unverified** (Official rules pending confirmation)"


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
        parts.append(f"[**Register / Sign Up Portal**]({reg_url})")
    if official_url and str(official_url) != str(reg_url):
        parts.append(f"[Official Website]({official_url})")
    if ctftime_url:
        parts.append(f"[CTFtime]({ctftime_url})")
    return " • ".join(parts) if parts else "No public links available"


def fetch_events(api_url: str) -> list[dict[str, Any]]:
    if api_url.startswith(("http://", "https://")):
        req = Request(
            api_url,
            headers={
                "User-Agent": "KernelKittens-CTFAlerts/1.0",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=15) as res:
                data = json.loads(res.read().decode("utf-8"))
        except Exception as err:
            print(f"Failed to fetch events from {api_url}: {err}", file=sys.stderr)
            return []
    else:
        try:
            with open(api_url, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as err:
            print(f"Failed to read local file {api_url}: {err}", file=sys.stderr)
            return []

    return data.get("events", []) if isinstance(data, dict) else []


def load_sent_alerts(state_path: str) -> dict[str, Any]:
    if not os.path.exists(state_path):
        return {}
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_sent_alerts(state_path: str, sent_data: dict[str, Any]) -> None:
    now = datetime.now(UTC)
    pruned: dict[str, Any] = {}
    for key, val in sent_data.items():
        if isinstance(val, dict) and "starts_at" in val:
            st = _parse_iso(val["starts_at"])
            if st and (now - st).days < 7:
                pruned[key] = val
        else:
            pruned[key] = val

    os.makedirs(os.path.dirname(os.path.abspath(state_path)), exist_ok=True)
    tmp_path = f"{state_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(pruned, f, indent=2)
    os.replace(tmp_path, state_path)


def build_deadline_embed(event: dict[str, Any]) -> dict[str, Any]:
    title = event.get("title", "CTF Competition")
    starts_dt = _parse_iso(event.get("starts_at"))
    finishes_dt = _parse_iso(event.get("finishes_at"))

    if starts_dt:
        start_ts = int(starts_dt.timestamp())
        start_relative = f"<t:{start_ts}:R>"
        start_full = f"<t:{start_ts}:F>"
    else:
        start_relative = "soon"
        start_full = "TBD"

    duration_str = ""
    if starts_dt and finishes_dt:
        hours = int((finishes_dt - starts_dt).total_seconds() // 3600)
        duration_str = f"{hours}h duration"

    embed: dict[str, Any] = {
        "title": f"🚨 CTF Starting Soon: {title}",
        "description": (
            f"**Countdown:** Starts {start_relative} ({start_full})\n"
            f"Registration deadline is approaching. Ensure team rosters and accounts are ready!"
        ),
        "color": 0xFF5722,  # Urgent Deep Orange
        "fields": [],
        "footer": {
            "text": "Kernel Kittens CTF Deadline Watch • calendar.kernelkittens.team",
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }

    official_url = event.get("official_url") or event.get("registration_url")
    if official_url:
        embed["url"] = str(official_url)

    # Format & Team
    fmt = event.get("format") or "Jeopardy"
    team_str = _format_team_max(event.get("team_max"))
    format_val = f"**Format:** {fmt}\n**Team Limit:** {team_str}"
    if duration_str:
        format_val += f"\n**Length:** {duration_str}"
    embed["fields"].append({"name": "🎯 Competition Structure", "value": format_val, "inline": True})

    # AI Policy
    policy_str = _format_ai_policy(event.get("ai_policy"))
    embed["fields"].append({"name": "🤖 AI Policy", "value": policy_str, "inline": True})

    # Categories
    categories = event.get("categories") or []
    if categories:
        embed["fields"].append({"name": "🏷️ Categories", "value": ", ".join(categories[:8]), "inline": True})

    # Prizes
    prizes = event.get("prize_summary")
    if prizes and prizes.lower() not in {"none", "null", "tbd", "tba"}:
        prize_snippet = prizes.split("\n")[0].strip()[:100]
        embed["fields"].append({"name": "🏆 Prizes", "value": prize_snippet, "inline": False})

    # Action / Sign up
    links = _format_links(event)
    embed["fields"].append({
        "name": "🔗 Registration & Links",
        "value": f"{links}\n\n*Use `/ctf join {title[:30]}` to sign up on the team roster.*",
        "inline": False,
    })

    return embed


def send_to_discord(
    embeds: list[dict[str, Any]],
    webhook_url: str | None = None,
    bot_token: str | None = None,
    channel_id: str | None = None,
) -> bool:
    if not embeds:
        return True

    payload = {"embeds": embeds}

    if webhook_url:
        req = Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "KernelKittens-CTFAlerts/1.0",
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
                "User-Agent": "KernelKittens-CTFAlerts/1.0",
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
    parser = argparse.ArgumentParser(description="Dispatch 24-hour CTF starting & deadline alerts")
    parser.add_argument(
        "--api-url",
        default=os.environ.get(
            "FLAGWATCH_PUBLIC_URL", "https://calendar.kernelkittens.team/api/events"
        ),
        help="URL or local path to flagwatch events JSON",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Alert lookahead window in hours (default: 24)",
    )
    parser.add_argument(
        "--state-file",
        default=os.environ.get(
            "FLAGWATCH_ALERTS_STATE", "/var/lib/flagwatch/deadline_alerts_sent.json"
        ),
        help="Path to state file tracking sent alerts",
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
        help="Discord channel ID for CTF alerts",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print alerts without sending to Discord or modifying state",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Ignore state file and send alerts even if already sent",
    )
    args = parser.parse_args()

    events = fetch_events(args.api_url)
    if not events:
        print("No events retrieved from source.", file=sys.stderr)
        return 0

    now = datetime.now(UTC)
    window_end = now + timedelta(hours=args.hours)

    sent_alerts = {} if args.force else load_sent_alerts(args.state_file)
    qualifying_events = []

    for event in events:
        if event.get("status") == "cancelled":
            continue
        starts_at = _parse_iso(event.get("starts_at"))
        if not starts_at:
            continue

        # Event must start between now and now + hours
        if now <= starts_at <= window_end:
            key = str(event.get("event_key") or event.get("title"))
            if key not in sent_alerts:
                qualifying_events.append(event)

    print(
        f"Found {len(qualifying_events)} events starting within {args.hours}h that need alerts."
    )

    if not qualifying_events:
        return 0

    for event in qualifying_events:
        embed = build_deadline_embed(event)
        key = str(event.get("event_key") or event.get("title"))
        if args.dry_run:
            print(f"[DRY RUN] Would send alert for: {event.get('title')}")
            print(json.dumps(embed, indent=2))
        else:
            success = send_to_discord(
                [embed],
                webhook_url=args.webhook_url,
                bot_token=args.bot_token,
                channel_id=args.channel_id,
            )
            if success:
                print(f"Sent deadline alert for: {event.get('title')}")
                sent_alerts[key] = {
                    "sent_at": now.isoformat(),
                    "starts_at": event.get("starts_at"),
                    "title": event.get("title"),
                }
            else:
                print(f"Failed to send alert for: {event.get('title')}", file=sys.stderr)

    if not args.dry_run:
        save_sent_alerts(args.state_file, sent_alerts)

    return 0


if __name__ == "__main__":
    sys.exit(main())
