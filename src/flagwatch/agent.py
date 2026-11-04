"""Scheduled collection and publication of public CTF evidence."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from flagwatch.cli import _database, build_sync_service
from flagwatch.config import Settings
from flagwatch.domain import AiPolicy, EventStatus
from flagwatch.ics import render_calendar
from flagwatch.notifications import build_sender, deliver_pending
from flagwatch.public_snapshot import build_public_snapshot
from flagwatch.publication import publish_bundle, recover_bundle
from flagwatch.state_recovery import backup_database, recover_database


def atomic_write(target: Path, content: str, mode: int = 0o644) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".candidate-", dir=target.parent)
    candidate = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        candidate.chmod(mode)
        os.replace(candidate, target)
    finally:
        candidate.unlink(missing_ok=True)


def run(settings: Settings, output: Path) -> int:
    started = datetime.now(UTC)
    published = [output / "calendar.ics", output / "candidates.ics", output / "events.json"]
    previous = {
        path: path.read_text(encoding="utf-8") if path.exists() else None
        for path in published
        if not settings.resilience_enabled
    }
    publication_started = False
    recovery_tier = 1
    database_recovery_tier = 0
    try:
        if settings.resilience_enabled and (output / ".generations").exists():
            recovery_tier = recover_bundle(output)
        if settings.resilience_enabled:
            database_recovery_tier = recover_database(settings.database_path)
        service = build_sync_service(settings, queue_notifications=settings.send_enabled)
        report = service.run()
        connector = getattr(getattr(service, "policy_extractor", None), "connector", None)
        analysis_route = getattr(connector, "last_route", "primary")
        attempts = getattr(connector, "attempts", [])
        if settings.resilience_enabled:
            atomic_write(
                settings.database_path.parent / "analysis-health.json",
                json.dumps(
                    {
                        "checked_at": datetime.now(UTC).isoformat(),
                        "route": analysis_route,
                        "attempts": attempts,
                    }
                ),
                0o600,
            )
        atomic_write(
            settings.database_path.parent / "last-run.json", report.model_dump_json(), 0o600
        )
        if report.imported == 0 and report.failures:
            raise RuntimeError("AllSourcesUnavailable")
        now = datetime.now(UTC)
        database = _database(settings)
        snapshot = build_public_snapshot(database, now)
        snapshot.coverage = report.source_health
        events = [
            view.event
            for view in database.list_events()
            if view.event.finishes_at >= now - timedelta(days=31)
        ]
        calendar = render_calendar(events, now)
        candidates = [
            view.event.model_copy(update={"status": EventStatus.CANCELLED})
            if view.facts.ai_policy is AiPolicy.HUMAN_ONLY
            else view.event
            for view in database.list_events()
            if view.event.finishes_at >= now - timedelta(days=31)
        ]
        candidate_calendar = render_calendar(candidates, now)
        if settings.resilience_enabled:
            backup_database(settings.database_path)
        publication_started = True
        if settings.resilience_enabled:
            publish_bundle(
                output,
                {
                    "calendar.ics": calendar,
                    "candidates.ics": candidate_calendar,
                    "events.json": snapshot.model_dump_json() + "\n",
                },
                atomic_write,
            )
        else:
            atomic_write(output / "calendar.ics", calendar)
            atomic_write(output / "candidates.ics", candidate_calendar)
            atomic_write(output / "events.json", snapshot.model_dump_json() + "\n")
        status = {
            "ok": True,
            "publication_recovery_tier": recovery_tier,
            "database_recovery_tier": database_recovery_tier,
            "analysis_route": analysis_route,
            "started_at": started.isoformat(),
            "generated_at": now.isoformat(),
            "events": len(snapshot.events),
            "analyzed": report.analyzed,
            "issues": len(report.failures),
            "sources": [source.model_dump() for source in report.source_health],
        }
        delivered = 0
        delivery_error = None
        if settings.send_enabled:
            try:
                sender = build_sender(settings)
                if sender is None:
                    delivery_error = "send_enabled but no destination configured"
                else:
                    delivered = deliver_pending(database, sender, sending_enabled=True)
            except Exception as error:  # delivery must never break publication
                delivery_error = type(error).__name__
        status["delivered"] = delivered
        status["pending_alerts"] = len(database.list_pending_outbox())
        if delivery_error:
            status["delivery_error"] = delivery_error
        atomic_write(output / "status.json", json.dumps(status) + "\n")
        print(json.dumps(status), flush=True)
        return 0
    except Exception as error:
        preserved = True
        if settings.resilience_enabled and (output / ".generations").exists():
            try:
                recovery_tier = recover_bundle(output)
            except (OSError, ValueError):
                preserved = False
        elif publication_started:
            for path, content in previous.items():
                try:
                    if content is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path, content)
                except OSError:
                    preserved = False
        status = {
            "ok": False,
            "attempted_at": started.isoformat(),
            "error": type(error).__name__,
            "last_good_preserved": preserved,
            "publication_recovery_tier": recovery_tier,
            "database_recovery_tier": database_recovery_tier,
        }
        atomic_write(output / "status.json", json.dumps(status) + "\n")
        print(json.dumps(status), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(run(Settings(), Path(os.environ.get("FLAGWATCH_PUBLIC_PATH", "data/public"))))
