from __future__ import annotations

from sentinel.infrastructure.mime import guess_mime_type


def test_guess_mime_type_recognizes_common_extension() -> None:
    assert guess_mime_type("report.html") == "text/html"


def test_guess_mime_type_returns_none_for_unregistered_extension() -> None:
    # .php has no entry in Python's stdlib mimetypes table.
    assert guess_mime_type("shell.php") is None
