from __future__ import annotations

import hashlib
import json
import smtplib
import ssl
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Protocol

import httpx
from pydantic import BaseModel

from flagwatch.domain import Event, EventFacts, MatchResult
from flagwatch.matching import match_event
from flagwatch.storage import Database
from flagwatch.time_display import duration_label, format_central_range


class AlertMessage(BaseModel):
    title: str
    body: str
    url: str


class NotificationSender(Protocol):
    def send(self, message: AlertMessage) -> str | None: ...


def discord_payload(message: AlertMessage) -> dict[str, object]:
    title = message.title.replace("\r", " ").replace("\n", " ")[:200]
    # Keep the source link intact even when a source supplies a long description.
    suffix = "\n" + message.url[:500]
    prefix = f"**{title}**\n"
    body = message.body[: max(0, 2000 - len(prefix) - len(suffix))]
    return {"content": prefix + body + suffix, "allowed_mentions": {"parse": []}}


class DiscordWebhookSender:
    def __init__(self, webhook_url: str, client: httpx.Client | None = None) -> None:
        self.webhook_url = webhook_url
        self.client = client or httpx.Client(timeout=10.0)

    def send(self, message: AlertMessage) -> str:
        response = self.client.post(
            self.webhook_url,
            headers={"User-Agent": "Flagwatch/0.1 personal CTF alerts"},
            params={"wait": "true"},
            json=discord_payload(message),
        )
        response.raise_for_status()
        if response.status_code == 204 or not response.content:
            return "delivered"
        try:
            receipt = response.json()
            if isinstance(receipt, dict) and str(receipt.get("id", "")).isdigit():
                return str(receipt["id"])
        except (ValueError, TypeError):
            pass
        return "delivered"


class NtfySender:
    """Push alerts to an ntfy topic. Receipt is the ntfy message id."""

    def __init__(
        self,
        server: str,
        topic: str,
        priority: int = 4,
        client: httpx.Client | None = None,
    ) -> None:
        self.url = server.rstrip("/") + "/" + topic
        self.priority = str(max(1, min(5, int(priority))))
        self.client = client or httpx.Client(timeout=10.0)

    def send(self, message: AlertMessage) -> str:
        title = message.title.replace("\r", " ").replace("\n", " ")[:200]
        body = (message.body[:3500] + "\n" + message.url[:500]).encode("utf-8")
        response = self.client.post(
            self.url,
            headers={
                "User-Agent": "Flagwatch/0.1 personal CTF alerts",
                "Title": "Flagwatch: " + title,
                "Priority": self.priority,
                "Tags": "triangular_flag_on_post",
                "Click": message.url[:500],
            },
            content=body,
        )
        response.raise_for_status()
        receipt = response.json()
        if not isinstance(receipt, dict) or not receipt.get("id"):
            raise ValueError("ntfy did not return a message receipt")
        return str(receipt["id"])


def build_sender(settings) -> "NotificationSender | None":
    """Pick the first configured destination: ntfy, then Discord, then SMTP."""
    if getattr(settings, "ntfy_topic", None):
        return NtfySender(str(settings.ntfy_server), settings.ntfy_topic, settings.ntfy_priority)
    if settings.discord_webhook_url is not None:
        return DiscordWebhookSender(settings.discord_webhook_url.get_secret_value())
    if settings.smtp_host and settings.smtp_username and settings.smtp_password and settings.smtp_from and settings.smtp_to:
        return SmtpSender(
            host=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password.get_secret_value(),
            sender=settings.smtp_from,
            recipient=settings.smtp_to,
        )
    return None


class SmtpSender:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        sender: str,
        recipient: str,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sender = sender
        self.recipient = recipient

    def send(self, message: AlertMessage) -> None:
        email = EmailMessage()
        email["Subject"] = f"Flagwatch match: {message.title}"
        email["From"] = self.sender
        email["To"] = self.recipient
        email.set_content(f"{message.body}\n\n{message.url}")
        with smtplib.SMTP(self.host, self.port, timeout=10.0) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            smtp.login(self.username, self.password)
            smtp.send_message(email)


def render_alert(event: Event, facts: EventFacts, match: MatchResult) -> AlertMessage:
    details = [
        format_central_range(event),
        duration_label(event),
        f"AI policy: {facts.ai_policy.value.replace('_', ' ')}",
    ]
    if facts.team_max is not None:
        details.append(f"Team maximum: {facts.team_max}")
    if facts.divisions:
        details.append(f"Divisions: {', '.join(facts.divisions)}")
    if facts.prize_summary:
        details.append(f"Prizes: {facts.prize_summary}")
    details.append(f"Matched because: {', '.join(match.match_reasons)}")
    return AlertMessage(title=event.title, body="\n".join(details), url=str(event.official_url))


def _dedupe_key(event: Event, facts: EventFacts, criteria_version: int, channel: str) -> str:
    material = {
        "event": {
            "key": event.key,
            "title": event.title,
            "official_url": str(event.official_url),
            "starts_at": event.starts_at.isoformat(),
            "finishes_at": event.finishes_at.isoformat(),
            "online": event.online,
            "onsite": event.onsite,
            "format": event.format,
            "weight": str(event.weight) if event.weight is not None else None,
            "prizes": event.prizes,
        },
        "facts": {
            "ai_policy": facts.ai_policy.value,
            "team_max": facts.team_max,
            "divisions": facts.divisions,
            "schedule_mode": facts.schedule_mode.value,
            "prize_summary": facts.prize_summary,
            "registration_status": facts.registration_status,
            "categories": facts.categories,
        },
        "criteria_version": criteria_version,
        "channel": channel,
    }
    serialized = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


def queue_alert(
    database: Database,
    event: Event,
    facts: EventFacts,
    match: MatchResult,
    criteria_version: int,
    channel: str = "preview",
) -> bool:
    if not match.alert_eligible:
        return False
    message = render_alert(event, facts, match)
    return database.queue_outbox(
        dedupe_key=_dedupe_key(event, facts, criteria_version, channel),
        event_key=event.key,
        channel=channel,
        payload_json=message.model_dump_json(),
    )


def deliver_pending(
    database: Database,
    sender: NotificationSender,
    sending_enabled: bool,
    *,
    now: datetime | None = None,
) -> int:
    if not sending_enabled:
        return 0
    current_time = now or datetime.now(UTC)
    delivered = 0
    criteria = database.get_criteria()
    for record in database.list_pending_outbox():
        if not database.claim_outbox(record.record_id):
            continue
        current = database.get_event(record.event_key)
        if current is None:
            database.mark_outbox_suppressed(record.record_id, "Event is no longer available")
            continue
        checked = current.facts.source_checked_at or current.facts.analyzed_at
        if current.event.finishes_at <= current_time:
            database.mark_outbox_suppressed(record.record_id, "Event has finished")
            continue
        if checked is not None and (
            checked.tzinfo is None
            or current_time - checked > timedelta(hours=48)
            or checked > current_time + timedelta(minutes=5)
        ):
            database.mark_outbox_suppressed(
                record.record_id, "Source evidence is stale or unchecked"
            )
            continue
        current_match = match_event(current.event, current.facts, criteria)
        if not current_match.alert_eligible:
            reason = "; ".join(current_match.rejection_reasons) or "Event no longer matches"
            database.mark_outbox_suppressed(record.record_id, reason)
            continue
        try:
            receipt = sender.send(render_alert(current.event, current.facts, current_match))
        except httpx.HTTPStatusError as error:
            if error.response.status_code == 429:
                database.mark_outbox_failed(record.record_id, "Discord rate limited the request")
                break
            if 400 <= error.response.status_code < 500:
                database.mark_outbox_suppressed(
                    record.record_id, f"Destination rejected HTTP {error.response.status_code}"
                )
            else:
                database.mark_outbox_uncertain(record.record_id)
            continue
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout):
            database.mark_outbox_failed(record.record_id, "Destination connection unavailable")
            continue
        except Exception as error:
            database.mark_outbox_failed(record.record_id, str(error))
            continue
        database.mark_outbox_sent(record.record_id, receipt_id=receipt)
        delivered += 1
    return delivered
