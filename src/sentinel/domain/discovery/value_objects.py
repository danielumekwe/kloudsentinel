from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.domain.shared.entity import ValueObject
from sentinel.domain.shared.exceptions import ValidationError
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName

_USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9]{0,15}$")


@dataclass(frozen=True, kw_only=True)
class LinuxUsername(ValueObject):
    """A cPanel/Linux system account username.

    cPanel enforces lowercase-alphanumeric, leading-letter, max-16-character
    usernames since they double as Linux system usernames. Validating this
    shape at construction means the discovery reader can't hand a malformed
    value (e.g. one containing a path separator) downstream to code that
    builds filesystem paths from it.
    """

    value: str

    def __post_init__(self) -> None:
        if not _USERNAME_PATTERN.match(self.value):
            raise ValidationError(f"Invalid cPanel username: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, kw_only=True)
class DiscoveredCpanelAccount(ValueObject):
    """Raw finding produced by a ``CpanelAccountReader`` adapter, before
    reconciliation against persisted state assigns it an identity."""

    username: LinuxUsername
    primary_domain: DomainName
    home_directory: AbsoluteFilePath
    is_suspended: bool


@dataclass(frozen=True, kw_only=True)
class DiscoveredWordPressInstallation(ValueObject):
    """Raw finding produced by a ``WordPressDetector`` adapter, before
    reconciliation against persisted state assigns it an identity."""

    absolute_path: AbsoluteFilePath
    domain: DomainName | None
    wp_version: str | None
    is_multisite: bool
