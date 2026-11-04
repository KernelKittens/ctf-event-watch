from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated

import httpx
import typer
import uvicorn

from flagwatch.analysis.discovery import WatchPageDiscoveryExtractor
from flagwatch.analysis.llm import LlmPolicyExtractor
from flagwatch.analysis.providers import (
    CallBudget,
    FallbackConnector,
    TrackedConnector,
    build_model_connector,
)
from flagwatch.config import Settings
from flagwatch.fetching import GuardedFetcher
from flagwatch.matching import match_event
from flagwatch.notifications import (
    DiscordWebhookSender,
    NotificationSender,
    SmtpSender,
    deliver_pending,
    discord_payload,
    render_alert,
)
from flagwatch.public_snapshot import build_public_snapshot
from flagwatch.sources.factory import build_event_source
from flagwatch.storage import Database
from flagwatch.sync import SyncService
from flagwatch.web import create_app

app = typer.Typer(no_args_is_help=True, help="Private CTF discovery and rule monitoring.")


def _settings(database: Path | None) -> Settings:
    return Settings(database_path=database) if database is not None else Settings()


def _database(settings: Settings) -> Database:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    database = Database(settings.database_path)
    database.initialize()
    return database


def _require_loopback(host: str) -> None:
    if host.casefold() == "localhost":
        return
    try:
        address = ip_address(host)
    except ValueError as error:
        raise typer.BadParameter("Flagwatch only binds to a loopback address") from error
    if not address.is_loopback:
        raise typer.BadParameter("Flagwatch only binds to a loopback address")


def build_sync_service(settings: Settings, *, queue_notifications: bool = True) -> SyncService:
    database = _database(settings)
    source_client = httpx.Client(timeout=settings.request_timeout_seconds)
    page_client = httpx.Client(timeout=settings.request_timeout_seconds)
    policy_extractor = None
    discovery_extractor = None
    if settings.ai_enabled:
        model_client = httpx.Client(timeout=settings.ai_timeout_seconds)
        connector = build_model_connector(
            provider=settings.ai_provider,
            client=model_client,
            endpoint=str(settings.ai_endpoint),
            api_key=(
                settings.ai_api_key.get_secret_value() if settings.ai_api_key is not None else None
            ),
            model=settings.ai_model,
        )
        budget = CallBudget(settings.ai_max_calls_per_run)
        connector = TrackedConnector(
            connector,
            provider=settings.ai_provider,
            max_calls=settings.ai_max_calls_per_run,
            telemetry_path=settings.model_telemetry_path,
            budget=budget,
        )
        if settings.ai_fallback_model and settings.ai_fallback_api_key is not None:
            backup = build_model_connector(
                provider=settings.ai_fallback_provider,
                client=model_client,
                endpoint=str(settings.ai_fallback_endpoint),
                api_key=settings.ai_fallback_api_key.get_secret_value(),
                model=settings.ai_fallback_model,
            )
            connector = FallbackConnector(
                [
                    connector,
                    TrackedConnector(
                        backup,
                        provider=settings.ai_fallback_provider,
                        max_calls=settings.ai_max_calls_per_run,
                        budget=budget,
                        telemetry_path=settings.model_telemetry_path,
                    ),
                ]
            )
        policy_extractor = LlmPolicyExtractor(connector=connector)
        discovery_extractor = WatchPageDiscoveryExtractor(connector)
    fetcher = GuardedFetcher(page_client, max_bytes=settings.max_response_bytes)
    return SyncService(
        database=database,
        source=build_event_source(
            settings,
            source_client,
            fetcher,
            discovery_extractor=discovery_extractor,
        ),
        fetcher=fetcher,
        lookahead_days=settings.ctftime_lookahead_days,
        lookback_days=settings.ctftime_lookback_days,
        policy_extractor=policy_extractor,
        queue_notifications=queue_notifications,
        adaptive_rechecks_enabled=settings.adaptive_rechecks_enabled,
        max_event_scans_per_run=settings.max_event_scans_per_run,
    )


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Interface to bind.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to bind.")] = 4814,
    database: Annotated[
        Path | None, typer.Option("--database", help="SQLite database path.")
    ] = None,
) -> None:
    """Run the private dashboard."""
    _require_loopback(host)
    settings = _settings(database)
    store = _database(settings)
    sync_service = build_sync_service(settings)
    uvicorn.run(
        create_app(settings, store, sync_runner=sync_service.run),
        host=host,
        port=port,
    )


@app.command("sync")
def sync_command(
    database: Annotated[
        Path | None, typer.Option("--database", help="SQLite database path.")
    ] = None,
) -> None:
    """Import recent and upcoming events and inspect reachable rules."""
    settings = _settings(database)
    report = build_sync_service(settings).run()
    typer.echo(
        f"Imported {report.imported} events. "
        f"Analyzed {report.analyzed} rule sets. "
        f"Queued {report.queued} alert preview{'s' if report.queued != 1 else ''}. "
        f"Deferred {report.deferred} scans "
        f"({report.skipped} not due)."
    )
    if report.failures:
        typer.echo(f"Kept going after {len(report.failures)} source fetch failures.")


@app.command()
def refresh(
    output: Annotated[
        Path,
        typer.Option("--output", help="Public snapshot destination."),
    ] = Path("data/public/events.json"),
    database: Annotated[
        Path | None, typer.Option("--database", help="SQLite database path.")
    ] = None,
) -> None:
    """Sync sources and atomically publish a last-good public snapshot."""
    settings = _settings(database)
    report = build_sync_service(settings, queue_notifications=False).run()
    if report.failures and report.imported == 0:
        typer.echo(
            "No source produced an event. The previous public snapshot was kept.",
            err=True,
        )
        raise typer.Exit(code=2)

    snapshot = build_public_snapshot(_database(settings), datetime.now(UTC))
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, candidate_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    candidate = Path(candidate_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(snapshot.model_dump_json())
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(candidate, output)
    finally:
        candidate.unlink(missing_ok=True)
    typer.echo(f"Published {len(snapshot.events)} events to {output}.")


@app.command("discord-preview")
def discord_preview(
    database: Annotated[
        Path | None, typer.Option("--database", help="SQLite database path.")
    ] = None,
) -> None:
    """Print current Discord payloads without contacting Discord."""
    store = _database(_settings(database))
    criteria = store.get_criteria()
    current = datetime.now(UTC)
    messages: list[dict[str, object]] = []
    for view in store.list_events():
        match = match_event(view.event, view.facts, criteria)
        checked = view.facts.source_checked_at
        if (
            not match.alert_eligible
            or view.event.finishes_at <= current
            or checked is None
            or checked.tzinfo is None
            or not 0 <= (current - checked).total_seconds() <= 172800
        ):
            continue
        messages.append(
            {
                "event_key": view.event.key,
                "source_checked_at": checked.isoformat(),
                "payload": discord_payload(render_alert(view.event, view.facts, match)),
            }
        )
    typer.echo(json.dumps({"sending_enabled": False, "messages": messages}, indent=2))


@app.command()
def deliver(
    database: Annotated[
        Path | None, typer.Option("--database", help="SQLite database path.")
    ] = None,
) -> None:
    """Send pending alerts only when explicitly enabled and configured."""
    settings = _settings(database)
    store = _database(settings)
    if not settings.send_enabled:
        typer.echo("Sending is disabled. Alert previews remain in the local outbox.")
        return

    if settings.discord_webhook_url is not None:
        sender: NotificationSender = DiscordWebhookSender(
            settings.discord_webhook_url.get_secret_value()
        )
    elif all(
        [
            settings.smtp_host,
            settings.smtp_username,
            settings.smtp_password,
            settings.smtp_from,
            settings.smtp_to,
        ]
    ):
        sender = SmtpSender(
            host=settings.smtp_host or "",
            port=settings.smtp_port,
            username=settings.smtp_username or "",
            password=(settings.smtp_password.get_secret_value() if settings.smtp_password else ""),
            sender=settings.smtp_from or "",
            recipient=settings.smtp_to or "",
        )
    else:
        typer.echo("Sending is enabled, but no complete Discord or SMTP destination is configured.")
        raise typer.Exit(code=2)

    delivered = deliver_pending(store, sender, sending_enabled=True)
    typer.echo(f"Delivered {delivered} alert{'s' if delivered != 1 else ''}.")


if __name__ == "__main__":
    app()
