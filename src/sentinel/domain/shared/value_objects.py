from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from sentinel.domain.shared.entity import ValueObject
from sentinel.domain.shared.exceptions import ValidationError

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, kw_only=True)
class Sha256Hash(ValueObject):
    value: str

    def __post_init__(self) -> None:
        normalized = self.value.lower()
        if not _SHA256_PATTERN.match(normalized):
            raise ValidationError(f"Invalid SHA-256 hash: {self.value!r}")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, kw_only=True)
class DomainName(ValueObject):
    """A fully-qualified domain name, as it appears in cPanel account records,
    vhost configuration, or wp-config.php. Normalized to lowercase so two
    differently-cased references to the same domain compare equal."""

    value: str

    def __post_init__(self) -> None:
        normalized = self.value.lower().rstrip(".")
        if not _DOMAIN_PATTERN.match(normalized):
            raise ValidationError(f"Invalid domain name: {self.value!r}")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, kw_only=True)
class AbsoluteFilePath(ValueObject):
    """An absolute filesystem path, typically sourced from parsing system
    files (``/etc/trueuserdomains``, cPanel userdata) or filesystem walks.

    Rejects relative paths and ``..`` traversal segments for the same reason
    as ``RelativeFilePath``: once validated, the value can be used directly
    in filesystem operations without a second check at the call site — which
    matters here because this data originates outside the application.
    """

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValidationError("File path cannot be empty")
        if not self.value.startswith("/"):
            raise ValidationError(f"Expected absolute path, got relative: {self.value!r}")
        if ".." in self.value.split("/"):
            raise ValidationError(f"Path traversal segment not allowed: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, kw_only=True)
class RelativeFilePath(ValueObject):
    """A path relative to a WordPress installation root or cPanel home directory.

    Rejects absolute paths and ``..`` traversal segments so that a value of this
    type can always be safely joined onto a trusted filesystem root without a
    second validation pass at the call site.
    """

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValidationError("File path cannot be empty")
        if self.value.startswith("/"):
            raise ValidationError(f"Expected relative path, got absolute: {self.value!r}")
        if ".." in self.value.split("/"):
            raise ValidationError(f"Path traversal segment not allowed: {self.value!r}")

    def __str__(self) -> str:
        return self.value
