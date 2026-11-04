"""Online SQLite snapshots with validation before any automatic restore."""

from __future__ import annotations

import os
import shutil
import sqlite3
import uuid
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path


def _healthy(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        with closing(
            sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
        ) as connection:
            tables = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            return {"events", "event_facts"}.issubset(tables) and connection.execute(
                "PRAGMA quick_check"
            ).fetchall() == [("ok",)]
    except sqlite3.Error as error:
        code = getattr(error, "sqlite_errorcode", 0) & 255
        if code in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}:
            return False
        raise


def snapshots(path: Path) -> list[Path]:
    return sorted((path.parent / "state-backups").glob("state-*.sqlite"), reverse=True)


def backup_database(path: Path) -> Path:
    if not _healthy(path):
        raise ValueError("Database failed integrity validation")
    root = path.parent / "state-backups"
    root.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    candidate = root / (".candidate-" + uuid.uuid4().hex)
    target = root / ("state-" + stamp + ".sqlite")
    try:
        with (
            closing(sqlite3.connect(path)) as source,
            closing(sqlite3.connect(candidate)) as destination,
        ):
            source.backup(destination)
        candidate.chmod(0o600)
        if not _healthy(candidate):
            raise ValueError("Database snapshot failed integrity validation")
        with candidate.open("rb") as handle:
            os.fsync(handle.fileno())
        candidate.rename(target)
        for obsolete in snapshots(path)[3:]:
            obsolete.unlink()
        return target
    finally:
        candidate.unlink(missing_ok=True)


def recover_database(path: Path) -> int:
    if _healthy(path):
        return 0
    backups = snapshots(path)
    if not path.exists() and not backups:
        return 0
    for tier, source in enumerate(backups, 1):
        if not _healthy(source):
            continue
        candidate = path.with_name(".restore-" + uuid.uuid4().hex)
        try:
            shutil.copyfile(source, candidate)
            candidate.chmod(0o600)
            if not _healthy(candidate):
                continue
            archive = path.parent / "damaged-state" / uuid.uuid4().hex
            archive.mkdir(parents=True, mode=0o700)
            for suffix in ("", "-wal", "-shm"):
                damaged = path.with_name(path.name + suffix)
                if damaged.exists():
                    damaged.rename(archive / damaged.name)
            os.replace(candidate, path)
            return tier
        finally:
            candidate.unlink(missing_ok=True)
    raise ValueError("No valid database snapshot available")
