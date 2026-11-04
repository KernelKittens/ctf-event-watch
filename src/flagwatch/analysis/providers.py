from __future__ import annotations

import json
import os
import time
import uuid
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, TypeVar

import httpx


class StructuredOutputMode(StrEnum):
    JSON_SCHEMA = "json_schema"
    JSON_OBJECT = "json_object"
    PROMPT_ONLY = "prompt_only"


class ModelConnector(Protocol):
    model: str

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
    ) -> str | None: ...


def _openai_completion_endpoint(endpoint: str) -> str:
    normalized = endpoint.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    if normalized.endswith("/v1"):
        return normalized + "/chat/completions"
    return normalized + "/v1/chat/completions"


def _anthropic_messages_endpoint(endpoint: str) -> str:
    normalized = endpoint.rstrip("/")
    if normalized.endswith("/messages"):
        return normalized
    if normalized.endswith("/v1"):
        return normalized + "/messages"
    return normalized + "/v1/messages"


class OpenAICompatibleConnector:
    def __init__(
        self,
        client: httpx.Client,
        endpoint: str,
        api_key: str | None,
        model: str,
        *,
        auth_header: str = "Authorization",
        structured_output: StructuredOutputMode = StructuredOutputMode.JSON_SCHEMA,
    ) -> None:
        self.client = client
        self.endpoint = _openai_completion_endpoint(endpoint)
        self.api_key = api_key
        self.model = model
        self.auth_header = auth_header
        self.structured_output = structured_output
        self.last_call: dict[str, Any] = {}

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
    ) -> str | None:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers[self.auth_header] = (
                f"Bearer {self.api_key}"
                if self.auth_header.casefold() == "authorization"
                else self.api_key
            )
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 2400,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if self.structured_output is StructuredOutputMode.JSON_SCHEMA:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "ctf_event_intelligence",
                    "strict": True,
                    "schema": schema,
                },
            }
        elif self.structured_output is StructuredOutputMode.JSON_OBJECT:
            payload["response_format"] = {"type": "json_object"}
        self.last_call = {}
        try:
            response = self.client.post(self.endpoint, headers=headers, json=payload)
            self.last_call["status"] = response.status_code
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict):
                raise ValueError("Unexpected model response shape")
            self.last_call["usage"] = body.get("usage", {})
            content = body["choices"][0]["message"]["content"]
            return content if isinstance(content, str) else None
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as error:
            self.last_call["errorType"] = type(error).__name__
            return None


class AnthropicMessagesConnector:
    def __init__(
        self,
        client: httpx.Client,
        endpoint: str,
        api_key: str | None,
        model: str,
        *,
        anthropic_version: str = "2023-06-01",
    ) -> None:
        self.client = client
        self.endpoint = _anthropic_messages_endpoint(endpoint)
        self.api_key = api_key
        self.model = model
        self.anthropic_version = anthropic_version
        self.last_call: dict[str, Any] = {}

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
    ) -> str | None:
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": self.anthropic_version,
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        schema_text = json.dumps(schema, separators=(",", ":"), sort_keys=True)
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "tools": [
                {
                    "name": "record_extraction",
                    "description": (
                        "Return extracted public facts matching the requested schema. "
                        "This records data only and performs no external action."
                    ),
                    "input_schema": schema,
                }
            ],
            "tool_choice": {"type": "tool", "name": "record_extraction"},
            "system": f"{system_prompt}\n\nOutput JSON Schema:\n{schema_text}",
            "messages": [{"role": "user", "content": user_prompt}],
        }
        self.last_call = {}
        try:
            response = self.client.post(self.endpoint, headers=headers, json=payload)
            self.last_call["status"] = response.status_code
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict):
                raise ValueError("Unexpected model response shape")
            self.last_call["usage"] = body.get("usage", {})
            self.last_call["stopReason"] = body.get("stop_reason")
            if body.get("stop_reason") == "max_tokens":
                self.last_call["errorType"] = "TruncatedResponse"
                return None
            blocks = body["content"]
            if not isinstance(blocks, list):
                return None
            for block in blocks:
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_use"
                    and block.get("name") == "record_extraction"
                    and isinstance(block.get("input"), dict)
                ):
                    return json.dumps(block["input"])
            for block in blocks:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text")
                    if isinstance(text, str):
                        return text
            return None
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as error:
            self.last_call["errorType"] = type(error).__name__
            return None


def build_model_connector(
    *,
    provider: str,
    client: httpx.Client,
    endpoint: str,
    api_key: str | None,
    model: str,
) -> ModelConnector:
    normalized = provider.strip().casefold().replace("-", "_")
    if normalized == "anthropic":
        return AnthropicMessagesConnector(client, endpoint, api_key, model)
    if normalized in {"openai", "litellm"}:
        return OpenAICompatibleConnector(client, endpoint, api_key, model)
    if normalized in {"deepseek", "local"}:
        return OpenAICompatibleConnector(
            client,
            endpoint,
            api_key,
            model,
            structured_output=StructuredOutputMode.JSON_OBJECT,
        )
    raise ValueError(f"Unsupported model provider: {provider}")


def _token_count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


@dataclass
class CallBudget:
    limit: int
    used: int = 0


T = TypeVar("T")


class FallbackConnector:
    """Try independent providers, then leave deterministic extraction in control."""

    def __init__(self, connectors: Sequence[ModelConnector]) -> None:
        if not connectors:
            raise ValueError("At least one model route is required")
        self.connectors = list(connectors)
        self.model = connectors[0].model
        self.last_route = "untried"
        self.disabled: set[int] = set()
        self.attempts: list[dict[str, object]] = []

    def complete_validated(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
        validate: Callable[[str], T],
    ) -> T | None:
        for index, connector in enumerate(self.connectors):
            if index in self.disabled:
                continue
            raw = connector.complete(system_prompt, user_prompt, schema)
            if not raw:
                self.disabled.add(index)
                self.attempts.append({"tier": index + 1, "outcome": "unavailable"})
                continue
            try:
                result = validate(raw)
            except (ValueError, TypeError):
                self.attempts.append({"tier": index + 1, "outcome": "invalid_response"})
                continue
            self.model = connector.model
            self.last_route = "primary" if index == 0 else "secondary"
            self.attempts.append({"tier": index + 1, "outcome": "selected"})
            return result
        self.last_route = "offline"
        return None

    def complete(self, system_prompt: str, user_prompt: str, schema: dict[str, Any]) -> str | None:
        return self.complete_validated(system_prompt, user_prompt, schema, lambda raw: raw)


def complete_validated[T](
    connector: ModelConnector,
    system_prompt: str,
    user_prompt: str,
    schema: dict[str, Any],
    validate: Callable[[str], T],
) -> T | None:
    if isinstance(connector, FallbackConnector):
        return connector.complete_validated(system_prompt, user_prompt, schema, validate)
    raw = connector.complete(system_prompt, user_prompt, schema)
    return validate(raw) if isinstance(raw, str) else None


class TrackedConnector:
    """Bound real calls and record private usage without storing source text."""

    def __init__(
        self,
        connector: ModelConnector,
        *,
        provider: str,
        max_calls: int,
        telemetry_path: Path | None = None,
        budget: CallBudget | None = None,
    ) -> None:
        self.connector = connector
        self.model = connector.model
        self.provider = provider
        self.max_calls = max_calls
        self.telemetry_path = telemetry_path
        self.calls = 0
        self.budget_skips = 0
        self.budget = budget or CallBudget(max_calls)

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
    ) -> str | None:
        if self.calls >= self.max_calls or self.budget.used >= self.budget.limit:
            self.budget_skips += 1
            return None
        self.calls += 1
        self.budget.used += 1
        started = datetime.now(UTC).isoformat()
        clock = time.monotonic()
        result = self.connector.complete(system_prompt, user_prompt, schema)
        elapsed = (time.monotonic() - clock) * 1000
        details = getattr(self.connector, "last_call", {})
        usage = details.get("usage", {})
        if not isinstance(usage, dict):
            usage = {}
        tokens_in = _token_count(usage.get("prompt_tokens", usage.get("input_tokens")))
        tokens_out = _token_count(usage.get("completion_tokens", usage.get("output_tokens")))
        error_type = details.get("errorType") or (None if result else "EmptyModelResponse")
        row = {
            "event": "call_finish",
            "id": str(uuid.uuid4()),
            "ts": datetime.now(UTC).isoformat(),
            "startedAt": started,
            "model": self.model,
            "provider": self.provider,
            "ok": bool(result),
            "ms": elapsed,
            "tokensIn": tokens_in,
            "tokensOut": tokens_out,
            "status": details.get("status"),
            "stopReason": details.get("stopReason"),
            "errorType": error_type,
            "generationMs": None,
            "timingSource": None,
            "generationTokensPerSecond": None,
            "requestTokensPerSecond": tokens_out * 1000 / elapsed
            if tokens_out is not None and elapsed > 0
            else None,
        }
        try:
            if self.telemetry_path is not None:
                target = self.telemetry_path
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if target.exists() and target.stat().st_size >= 2 * 1024 * 1024:
                    target.replace(target.with_name(target.name + ".1"))
                descriptor = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    if os.name == "posix":
                        os.fchmod(descriptor, 0o640)
                    os.write(descriptor, (json.dumps(row) + "\n").encode())
                finally:
                    os.close(descriptor)
        except OSError as error:
            warnings.warn(
                "Model usage telemetry write failed: " + type(error).__name__,
                RuntimeWarning,
                stacklevel=2,
            )
        return result
