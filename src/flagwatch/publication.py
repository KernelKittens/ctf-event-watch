"""Validated calendar generations with a single atomic publication pointer."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from icalendar import Calendar

from flagwatch.public_snapshot import PublicSnapshot

NAMES = ("events.json", "calendar.ics", "candidates.ics")
GENERATION = re.compile(r"^generation-[0-9]{20}-[a-f0-9]{8}$")
Writer = Callable[[Path, str, int], None]


def validate_bundle(files: Mapping[str, str]) -> None:
    if set(files) != set(NAMES):
        raise ValueError("Incomplete calendar generation")
    snapshot = PublicSnapshot.model_validate_json(files["events.json"])
    expected = {event.event_key + "@flagwatch.local" for event in snapshot.events}
    if len(expected) != len(snapshot.events):
        raise ValueError("Duplicate calendar event identity")
    for name in NAMES[1:]:
        entries = Calendar.from_ical(files[name]).walk("VEVENT")
        if len(entries) != len(expected) or {str(item["UID"]) for item in entries} != expected:
            raise ValueError("Calendar and snapshot identities disagree")


def _generations(output: Path) -> list[Path]:
    root = output / ".generations"
    if not root.exists():
        return []
    return sorted(
        (
            p
            for p in root.iterdir()
            if GENERATION.fullmatch(p.name) and p.is_dir() and not p.is_symlink()
        ),
        reverse=True,
    )


def _valid(path: Path) -> bool:
    try:
        manifest = json.loads((path / "manifest.json").read_text())
        files = {}
        for name in NAMES:
            file = path / name
            if file.is_symlink() or file.stat().st_size > 32 * 1024 * 1024:
                return False
            payload = file.read_bytes()
            if hashlib.sha256(payload).hexdigest() != manifest.get(name):
                return False
            files[name] = payload.decode("utf-8")
        validate_bundle(files)
        return True
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        return False


def _link(target: Path, destination: str) -> None:
    candidate = target.with_name(".link-" + uuid.uuid4().hex)
    try:
        candidate.symlink_to(destination)
        os.replace(candidate, target)
    finally:
        candidate.unlink(missing_ok=True)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def recover_bundle(output: Path) -> int:
    generations = _generations(output)
    valid = [(index, path) for index, path in enumerate(generations, 1) if _valid(path)]
    if not valid:
        raise ValueError("No valid calendar generation available")
    tier, chosen = valid[0]
    _link(output / ".current", str(chosen.relative_to(output)))
    for name in NAMES:
        alias = output / name
        if not alias.is_symlink() or os.readlink(alias) != ".current/" + name:
            _link(alias, ".current/" + name)
    backup = valid[1][1] if len(valid) > 1 else chosen
    _link(output / "recovery", str(backup.relative_to(output)))
    _sync_directory(output)
    return tier


def publish_bundle(output: Path, files: Mapping[str, str], write: Writer) -> None:
    validate_bundle(files)
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o755)
    root = output / ".generations"
    root.mkdir(exist_ok=True, mode=0o755)
    root.chmod(0o755)
    name = "generation-" + datetime.now(UTC).strftime("%Y%m%d%H%M%S%f") + "-" + uuid.uuid4().hex[:8]
    candidate = root / (".candidate-" + uuid.uuid4().hex)
    candidate.mkdir(mode=0o755)
    candidate.chmod(0o755)
    try:
        manifest = {}
        for filename in NAMES:
            write(candidate / filename, files[filename], 0o644)
            manifest[filename] = hashlib.sha256(files[filename].encode()).hexdigest()
        write(candidate / "manifest.json", json.dumps(manifest), 0o644)
        if not _valid(candidate):
            raise ValueError("Staged calendar generation failed validation")
        _sync_directory(candidate)
        candidate.rename(root / name)
        _sync_directory(root)
        recover_bundle(output)
        for obsolete in _generations(output)[3:]:
            shutil.rmtree(obsolete)
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)
