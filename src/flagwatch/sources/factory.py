from __future__ import annotations

import json
import os
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, TypeAdapter, field_validator

from flagwatch.analysis.discovery import WatchPageDiscoveryExtractor
from flagwatch.config import Settings
from flagwatch.domain import Event
from flagwatch.fetching import GuardedFetcher, Resolver, resolve_public_addresses
from flagwatch.sources.composite import CompositeSource, RankedEventSource
from flagwatch.sources.ctfd import CtfdSource
from flagwatch.sources.ctfhub import CtfHubSource
from flagwatch.sources.ctftime import CtftimeSource
from flagwatch.sources.fallback import FallbackSource
from flagwatch.sources.feeds import IcsFeedSource, JsonFeedSource
from flagwatch.sources.htb import HtbSource
from flagwatch.sources.rctf import RctfSource
from flagwatch.sources.uscc import UsccSource
from flagwatch.sources.watch_page import WatchPageSource
from flagwatch.storage import Database


class SourceDefinitionBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True


class HtbSourceDefinition(SourceDefinitionBase):
    kind: Literal["htb_public"]


class CtfHubSourceDefinition(SourceDefinitionBase):
    kind: Literal["ctfhub"]


class UsccSourceDefinition(SourceDefinitionBase):
    kind: Literal["uscc"]


class IcsSourceDefinition(SourceDefinitionBase):
    kind: Literal["ics"]
    url: HttpUrl


class JsonSourceDefinition(SourceDefinitionBase):
    kind: Literal["json"]
    url: HttpUrl


class WatchSourceDefinition(SourceDefinitionBase):
    kind: Literal["watch"]
    url: HttpUrl
    organizers: list[str] = Field(default_factory=list, max_length=32)
    max_event_pages: int = Field(default=12, ge=0, le=24)
    ai_discovery: bool = True


class PlatformEventDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=240)
    official_url: HttpUrl
    starts_at: datetime
    finishes_at: datetime
    online: bool
    onsite: bool = False
    organizers: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("starts_at", "finishes_at")
    @classmethod
    def event_times_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Configured event times must include a timezone")
        return value

    def to_event(self, source: str) -> Event:
        return Event(
            source=source,
            source_id=self.id,
            title=self.title,
            official_url=self.official_url,
            starts_at=self.starts_at,
            finishes_at=self.finishes_at,
            online=self.online,
            onsite=self.onsite,
            organizers=self.organizers,
        )


class CtfdSourceDefinition(SourceDefinitionBase):
    kind: Literal["ctfd"]
    base_url: HttpUrl
    token_env: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]*$")
    event: PlatformEventDefinition


class RctfSourceDefinition(SourceDefinitionBase):
    kind: Literal["rctf"]
    base_url: HttpUrl
    token_env: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]*$")
    event: PlatformEventDefinition


SourceDefinition = Annotated[
    HtbSourceDefinition
    | CtfHubSourceDefinition
    | UsccSourceDefinition
    | IcsSourceDefinition
    | JsonSourceDefinition
    | WatchSourceDefinition
    | CtfdSourceDefinition
    | RctfSourceDefinition,
    Field(discriminator="kind"),
]
SOURCE_DEFINITIONS = TypeAdapter(list[SourceDefinition])


def load_source_definitions(
    inline_json: str | None,
    path: Path | None,
) -> list[SourceDefinition]:
    if inline_json and path is not None:
        raise ValueError("Configure source JSON inline or by path, not both")
    if path is not None:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as error:
            raise ValueError(f"Could not read source configuration: {path}") from error
    elif inline_json:
        raw = inline_json
    else:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("Source configuration is not valid JSON") from error
    records = payload.get("sources") if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        raise ValueError("Source configuration must contain a sources array")
    return SOURCE_DEFINITIONS.validate_python(records)


def _token(
    definition: CtfdSourceDefinition | RctfSourceDefinition,
    environ: Mapping[str, str],
) -> str | None:
    if definition.token_env is None:
        return None
    value = environ.get(definition.token_env)
    if not value:
        raise ValueError(
            f"Source {definition.name} requires environment variable {definition.token_env}"
        )
    return value


def build_event_source(
    settings: Settings,
    source_client: httpx.Client,
    fetcher: GuardedFetcher,
    *,
    environ: Mapping[str, str] = os.environ,
    resolver: Resolver = resolve_public_addresses,
    discovery_extractor: WatchPageDiscoveryExtractor | None = None,
) -> CompositeSource:
    sources: list[RankedEventSource] = []
    if settings.ctftime_enabled:
        primary = CtftimeSource(source_client, str(settings.ctftime_base_url))
        if settings.resilience_enabled:
            mirror = IcsFeedSource(
                "https://raw.githubusercontent.com/ProbiusOfficial/Hello-CTFtime/main/calendar/Global.ics",
                fetcher,
                "hello-ctftime-mirror",
            )
            sources.append(FallbackSource(primary, mirror, Database(settings.database_path)))
        else:
            sources.append(primary)
    definitions = load_source_definitions(settings.sources_json, settings.sources_path)
    for definition in definitions:
        if not definition.enabled:
            continue
        if isinstance(definition, HtbSourceDefinition):
            sources.append(HtbSource())
        elif isinstance(definition, CtfHubSourceDefinition):
            sources.append(
                CtfHubSource(
                    source_client,
                    name=definition.name,
                    resolver=resolver,
                    max_bytes=fetcher.max_bytes,
                )
            )
        elif isinstance(definition, UsccSourceDefinition):
            sources.append(UsccSource(fetcher=fetcher, name=definition.name))
        elif isinstance(definition, IcsSourceDefinition):
            sources.append(IcsFeedSource(str(definition.url), fetcher, definition.name))
        elif isinstance(definition, JsonSourceDefinition):
            sources.append(JsonFeedSource(str(definition.url), fetcher, definition.name))
        elif isinstance(definition, WatchSourceDefinition):
            sources.append(
                WatchPageSource(
                    str(definition.url),
                    fetcher,
                    definition.name,
                    definition.organizers,
                    definition.max_event_pages,
                    discovery_extractor if definition.ai_discovery else None,
                )
            )
        elif isinstance(definition, CtfdSourceDefinition):
            sources.append(
                CtfdSource(
                    str(definition.base_url),
                    definition.event.to_event(definition.name),
                    source_client,
                    _token(definition, environ),
                    resolver,
                    name=definition.name,
                )
            )
        else:
            sources.append(
                RctfSource(
                    str(definition.base_url),
                    definition.event.to_event(definition.name),
                    source_client,
                    _token(definition, environ),
                    resolver,
                    name=definition.name,
                )
            )
    return CompositeSource(sources)
