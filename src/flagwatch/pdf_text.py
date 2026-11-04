"""Inert PDF extraction in a process with CPU, memory and output bounds."""

from __future__ import annotations

import io
import os
import sys


def main() -> None:
    if os.name == "posix":
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    from pypdf import PdfReader

    payload = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
    if len(payload) > 2 * 1024 * 1024:
        raise ValueError("PDF too large")
    reader = PdfReader(io.BytesIO(payload), strict=True)
    if reader.is_encrypted or len(reader.pages) > 30:
        raise ValueError("PDF encrypted or too many pages")
    parts: list[str] = []
    for page in reader.pages:
        text = page.extract_text() or ""
        parts.append(text)
        if sum(map(len, parts)) > 80000:
            raise ValueError("PDF text too large")
    result = "\n".join(parts).strip()
    if not result:
        raise ValueError("PDF has no extractable text")
    sys.stdout.write(result)


if __name__ == "__main__":
    main()
