from __future__ import annotations

import mimetypes


def guess_mime_type(filename: str) -> str | None:
    """Extension-based best guess (stdlib, no file content read) — good
    enough for forensic metadata triage, not a content-sniffing claim."""
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type
