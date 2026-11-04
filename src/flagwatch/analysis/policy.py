from __future__ import annotations

import re
from collections.abc import Sequence
from itertools import pairwise

from flagwatch.analysis.evidence import EvidenceDocument, PolicyResult
from flagwatch.domain import AiPolicy

AI_TERMS = re.compile(
    r"\b(ai|llms?|large language models?|artificial intelligence|generative ai|chatgpt|"
    r"claude|copilot|gemini)\b",
    re.IGNORECASE,
)
NATIVE_ALLOW = re.compile(
    r"(?:\b(all forms of ai usage|all ai tools|unrestricted ai|ai[- ]native)\b.{0,32}"
    r"\b(allowed|permitted|welcome)\b|"
    r"\bunrestricted\s+(?:use\s+of\s+)?ai\b|"
    r"\bany\s+and\s+all\s+(?:ai\s+)?tools?\s+(?:are\s+)?allowed\b|"
    r"\bautonomous\s+(?:ai|agents?)\s+(?:allowed|permitted|welcome)\b|"
    r"\b(?:any|all)\s+tools?\b.{0,24}\b(?:allowed|permitted|fine)\b.{0,40}"
    r"\b(?:including|includes?)\s+(?:ai|llms?|large language models?)\b|"
    r"\btools?\s+of\s+any\s+kind\b.{0,24}\b(?:allowed|permitted)\b.{0,64}"
    r"\b(?:this\s+)?includes?\s+(?:ai|llms?|large language models?)\b|"
    r"\bdo not forbid\b.{0,48}\b(?:using|use of)\s+ai\b|"
    r"\b(?:using|use of)\s+ai\b.{0,64}\b(?:not disallowed|not forbidden)\b|"
    r"\bseparate\s+ai\s*/\s*human\s+leaderboards?\b)",
    re.IGNORECASE,
)
ASSISTED_ALLOW = re.compile(
    r"(?:\b(interactive ai assistance|ai assistance|ai-assisted code generation|use of ai)\b"
    r".{0,48}\b(allowed|permitted|encouraged|fine)\b|"
    r"\b(?:chatgpt|copilot|claude|gemini|llms?)\b.{0,32}\b(?:allowed|permitted|welcome|fine)\b|"
    r"\b(?:you\s+may|can|feel\s+free\s+to)\s+use\s+(?:ai|chatgpt|copilot|claude|llms?)\b|"
    r"\bai\s+(?:tools?\s+)?(?:is|are)\s+(?:allowed|permitted|welcome|fine)\b|"
    r"\busing\s+ai\s+to\b.{0,72}\b(?:explain|research|learn)\b.{0,72}"
    r"\b(?:allowed|permitted|fine)\b)",
    re.IGNORECASE,
)
DOCUMENTED_AI_SOLVING = re.compile(
    r"\bif\s+ai\s+is\s+used\s+to\s+solve\s+(?:the\s+)?challenges?\b"
    r".{0,180}\bwrite[- ]up\b",
    re.IGNORECASE,
)
SOLVING_PROHIBITION = re.compile(
    r"(?:\bif\s+ai\s+is\s+used\s+to\s+solve\b.{0,120}\bdisqualif|"
    r"\bno\s+(?:llms?|ai assistants?)\b.{0,72}\bsolv|"
    r"\b(?:strictly\s+)?no\s+ai\b(?!\s+(?:hacking|category|challenges?))|"
    r"\bai\s+(?:is\s+)?(?:strictly\s+)?(?:prohibited|forbidden|banned|disallowed|not\s+allowed)\b|"
    r"\b(?:using|use\s+of)\s+ai\s+(?:is\s+)?(?:strictly\s+)?(?:prohibited|forbidden|banned|disallowed|not\s+allowed)\b|"
    r"\b(?:chatgpt|copilot|claude|gemini)\b.{0,32}\b(?:prohibited|forbidden|banned|disallowed|not\s+allowed)\b|"
    r"\b(?:all\s+)?(?:ai usage|ai use|use of ai|artificial intelligence)\b"
    r".{0,40}\b(?:prohibited|forbidden|not allowed)\b|"
    r"\b(?:llms?|ai assistants?|ai tools?)\b.{0,72}\b(?:prohibited|forbidden|not allowed)\b|"
    r"\bchallenge (?:details|material)\b.{0,72}\bmust not\b.{0,40}\bai\b|"
    r"\bmust not\b.{0,72}\bchallenge (?:details|material)\b.{0,40}\bai\b|"
    r"\b(?:all\s+)?a\s*/\s*d\b.{0,24}\bno[- ]ai\b|"
    r"\b(?:has|have|uses?|follows?|enforces?|requires?)\b.{0,48}"
    r"\b(?:a\s+)?(?:strict\s+)?no[- ]ai\s+(?:policy|rules?)\b|"
    r"\b(?:comply|complies|compliant)\s+with\b.{0,48}"
    r"\b(?:a\s+)?(?:strict\s+)?no[- ]ai\s+(?:policy|rules?)\b)",
    re.IGNORECASE,
)
AUTOMATION_LIMIT = re.compile(
    r"(?:\b(fully automated|autonomous)\b.{0,32}\b(solv|agent).{0,32}"
    r"\b(prohibited|forbidden|not allowed|banned)\b|"
    r"\bdo not use\s+ai tools?\b.{0,72}\bautomatically solve\b)",
    re.IGNORECASE,
)


def _sentences(document: EvidenceDocument) -> list[tuple[str, str]]:
    values = re.split(r"(?<=[.!?])\s+|[\r\n]+", document.text)
    sentences = [value.strip() for value in values if value.strip()]
    adjacent = [f"{first} {second}" for first, second in pairwise(sentences)]
    return [(document.source_url, value) for value in [*sentences, *adjacent]]


def _excerpt(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value).strip()
    return normalized if len(normalized) <= 240 else f"{normalized[:237].rstrip()}..."


def classify_ai_policy(documents: Sequence[EvidenceDocument]) -> PolicyResult:
    sentences = [item for document in documents for item in _sentences(document)]
    relevant = [(source, text) for source, text in sentences if AI_TERMS.search(text)]
    native = [(source, text) for source, text in relevant if NATIVE_ALLOW.search(text)]
    assisted = [
        (source, text) for source, text in relevant
        if ASSISTED_ALLOW.search(text) or DOCUMENTED_AI_SOLVING.search(text)
    ]
    prohibited = [(source, text) for source, text in relevant if SOLVING_PROHIBITION.search(text)]
    automation_limited = [
        (source, text) for source, text in sentences if AUTOMATION_LIMIT.search(text)
    ]

    if prohibited and (native or assisted):
        source, text = prohibited[0]
        return PolicyResult(
            policy=AiPolicy.UNKNOWN,
            reason="Official AI-policy statements conflict",
            source_url=source,
            evidence=_excerpt(text),
            confidence=1.0,
            conflicting=True,
        )
    if prohibited:
        source, text = prohibited[0]
        return PolicyResult(
            policy=AiPolicy.HUMAN_ONLY,
            reason="AI-assisted challenge solving is prohibited",
            source_url=source,
            evidence=_excerpt(text),
            confidence=1.0,
        )
    if assisted:
        source, text = assisted[0]
        reason = (
            "Interactive AI is allowed, but automated solving is restricted"
            if automation_limited
            else "AI use has write-up requirements"
            if DOCUMENTED_AI_SOLVING.search(text)
            else "Interactive AI assistance is allowed"
        )
        return PolicyResult(
            policy=AiPolicy.AI_ASSISTED,
            reason=reason,
            source_url=source,
            evidence=_excerpt(text),
            confidence=0.95,
        )
    if native:
        source, text = native[0]
        return PolicyResult(
            policy=AiPolicy.AI_NATIVE,
            reason="The rules explicitly allow unrestricted AI use",
            source_url=source,
            evidence=_excerpt(text),
            confidence=0.95,
        )
    return PolicyResult(
        policy=AiPolicy.UNKNOWN,
        reason="No clear AI policy found",
        confidence=0.0,
    )
