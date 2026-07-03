from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from sentinel.domain.discovery.entities import CpanelAccount, Server, WordPressInstallation
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import ValidationError
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName


@pytest.mark.parametrize("bad_value", ["", "Bob", "1bob", "bob-smith", "a" * 17])
def test_linux_username_rejects_invalid_values(bad_value: str) -> None:
    with pytest.raises(ValidationError):
        LinuxUsername(value=bad_value)


def test_linux_username_accepts_valid_value() -> None:
    assert str(LinuxUsername(value="examplebob1")) == "examplebob1"


def _account(*, is_active: bool = True) -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value="examplebob1"),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value="/home/examplebob1"),
        is_suspended=False,
        is_active=is_active,
        last_seen_at=utcnow(),
    )


def test_server_mark_seen_updates_last_seen_and_touches() -> None:
    server = Server(
        hostname="host.example.com",
        os_info="Linux 6.1",
        agent_version="0.1.0",
        last_seen_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    original_updated_at = server.updated_at

    new_seen_at = utcnow()
    server.mark_seen(at=new_seen_at)

    assert server.last_seen_at == new_seen_at
    assert server.updated_at >= original_updated_at


def test_cpanel_account_mark_seen_reactivates_and_updates_fields() -> None:
    account = _account(is_active=False)
    new_domain = DomainName(value="newdomain.com")

    account.mark_seen(primary_domain=new_domain, is_suspended=True, at=utcnow())

    assert account.is_active is True
    assert account.is_suspended is True
    assert account.primary_domain == new_domain


def test_cpanel_account_mark_inactive_deactivates() -> None:
    account = _account(is_active=True)
    account.mark_inactive()
    assert account.is_active is False


def test_wordpress_installation_mark_seen_and_mark_inactive() -> None:
    installation = WordPressInstallation(
        cpanel_account_id=uuid4(),
        absolute_path=AbsoluteFilePath(value="/home/examplebob1/public_html"),
        domain=DomainName(value="example.com"),
        wp_version="6.4",
        is_multisite=False,
        last_seen_at=utcnow(),
        is_active=False,
    )

    installation.mark_seen(domain=None, wp_version="6.5", is_multisite=True, at=utcnow())
    assert installation.is_active is True
    assert installation.wp_version == "6.5"
    assert installation.is_multisite is True
    assert installation.domain is None

    installation.mark_inactive()
    assert installation.is_active is False
