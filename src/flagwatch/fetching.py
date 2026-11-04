from __future__ import annotations

import socket
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urljoin, urlsplit

import httpx

from flagwatch.rule_pages import extract_readable_text

Resolver = Callable[[str], Sequence[str]]
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class FetchError(RuntimeError):
    pass


class UnsafeUrlError(FetchError):
    pass


class ResponseTooLargeError(FetchError):
    pass


class UnsupportedContentError(FetchError):
    pass


@dataclass(frozen=True)
class FetchedPage:
    url: str
    text: str
    html: str | None


def resolve_public_addresses(hostname: str) -> list[str]:
    return sorted({str(entry[4][0]) for entry in socket.getaddrinfo(hostname, None)})


def validate_public_url(url: str, resolver: Resolver) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeUrlError("Only public HTTP and HTTPS URLs are allowed")
    if parsed.username or parsed.password:
        raise UnsafeUrlError("Source URLs cannot contain credentials")
    try:
        addresses = resolver(parsed.hostname)
    except OSError as error:
        raise UnsafeUrlError(f"Could not resolve {parsed.hostname}") from error
    if not addresses:
        raise UnsafeUrlError(f"Could not resolve {parsed.hostname}")
    for raw in addresses:
        if not ip_address(raw).is_global:
            raise UnsafeUrlError(f"Blocked non-public destination for {parsed.hostname}")


class GuardedFetcher:
    def __init__(
        self,
        client: httpx.Client | None = None,
        resolver: Resolver = resolve_public_addresses,
        max_bytes: int = 2 * 1024 * 1024,
        max_redirects: int = 3,
    ) -> None:
        self.client = client or httpx.Client(timeout=10.0)
        self.resolver = resolver
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects

    def get_text(self, url: str) -> str:
        return self.get_page(url).text

    def get_page(self, url: str) -> FetchedPage:
        current = url
        for redirect_count in range(self.max_redirects + 1):
            validate_public_url(current, self.resolver)
            req_headers = {
                "User-Agent": "Flagwatch/0.2 personal CTF research",
                "Accept": (
                    "text/html,text/plain,application/json,"
                    "text/calendar,application/pdf,*/*;q=0.5"
                ),
            }
            try:
                with self.client.stream(
                    "GET", current, follow_redirects=False, headers=req_headers
                ) as response:
                    if response.status_code in REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if not location:
                            raise FetchError("Redirect response did not include a destination")
                        if redirect_count == self.max_redirects:
                            raise FetchError("Source exceeded the redirect limit")
                        current = urljoin(current, location)
                        continue
                    response.raise_for_status()
                    declared = response.headers.get("content-length", "")
                    if declared.isdigit() and int(declared) > self.max_bytes:
                        raise ResponseTooLargeError("Source page exceeds the size limit")
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        if len(content) + len(chunk) > self.max_bytes:
                            raise ResponseTooLargeError("Source page exceeds the size limit")
                        content.extend(chunk)
            except (httpx.ConnectError, OSError) as err:
                if "CERTIFICATE_VERIFY_FAILED" in str(err) or "certificate verify failed" in str(err).casefold():
                    with httpx.Client(timeout=self.client.timeout, verify=False).stream(
                        "GET", current, follow_redirects=False, headers=req_headers
                    ) as response:
                        if response.status_code in REDIRECT_STATUSES:
                            location = response.headers.get("location")
                            if not location:
                                raise FetchError("Redirect response did not include a destination")
                            if redirect_count == self.max_redirects:
                                raise FetchError("Source exceeded the redirect limit")
                            current = urljoin(current, location)
                            continue
                        response.raise_for_status()
                        declared = response.headers.get("content-length", "")
                        if declared.isdigit() and int(declared) > self.max_bytes:
                            raise ResponseTooLargeError("Source page exceeds the size limit")
                        content = bytearray()
                        for chunk in response.iter_bytes():
                            if len(content) + len(chunk) > self.max_bytes:
                                raise ResponseTooLargeError("Source page exceeds the size limit")
                            content.extend(chunk)
                else:
                    raise
            response = httpx.Response(
                200,
                headers={"content-type": response.headers.get("content-type", "")},
                content=bytes(content),
            )
            media_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
            if media_type == "application/pdf":
                try:
                    result = subprocess.run(
                        [sys.executable, "-m", "flagwatch.pdf_text"],
                        input=bytes(content),
                        capture_output=True,
                        timeout=8,
                        check=True,
                    )
                except (subprocess.SubprocessError, OSError) as error:
                    raise UnsupportedContentError(
                        "PDF text could not be safely extracted"
                    ) from error
                return FetchedPage(url=current, text=result.stdout.decode("utf-8"), html=None)
            if media_type not in {
                "text/html",
                "text/plain",
                "application/json",
                "text/calendar",
                "application/ics",
                "application/xml",
                "text/xml",
                "application/rss+xml",
                "application/javascript",
                "text/javascript",
                "application/x-javascript",
            } and not media_type.endswith("+json"):
                raise UnsupportedContentError(f"Unsupported source content type: {media_type}")
            raw_text = response.text
            if media_type == "text/html":
                return FetchedPage(url=current, text=extract_readable_text(raw_text), html=raw_text)
            return FetchedPage(url=current, text=raw_text.strip(), html=None)
        raise FetchError("Source exceeded the redirect limit")
