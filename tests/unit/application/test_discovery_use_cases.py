from __future__ import annotations

from uuid import UUID

import pytest

from sentinel.application.discovery.use_cases import RunDiscoveryUseCase
from sentinel.domain.discovery.entities import CpanelAccount, Server, WordPressInstallation
from sentinel.domain.discovery.value_objects import (
    DiscoveredCpanelAccount,
    DiscoveredWordPressInstallation,
    LinuxUsername,
)
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName


class FakeServerRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, Server] = {}

    async def add(self, entity: Server) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: Server) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> Server | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[Server]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_hostname(self, hostname: str) -> Server | None:
        return next((s for s in self.by_id.values() if s.hostname == hostname), None)


class FakeCpanelAccountRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, CpanelAccount] = {}

    async def add(self, entity: CpanelAccount) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: CpanelAccount) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> CpanelAccount | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[CpanelAccount]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_username(self, username: LinuxUsername) -> CpanelAccount | None:
        return next((a for a in self.by_id.values() if a.username == username), None)

    async def list_by_server(self, server_id: UUID) -> list[CpanelAccount]:
        return [a for a in self.by_id.values() if a.server_id == server_id]


class FakeWordPressInstallationRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, WordPressInstallation] = {}

    async def add(self, entity: WordPressInstallation) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: WordPressInstallation) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> WordPressInstallation | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[WordPressInstallation]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_path(self, absolute_path: str) -> WordPressInstallation | None:
        return next((i for i in self.by_id.values() if str(i.absolute_path) == absolute_path), None)

    async def list_by_account(self, cpanel_account_id: UUID) -> list[WordPressInstallation]:
        return [i for i in self.by_id.values() if i.cpanel_account_id == cpanel_account_id]


class FakeCpanelAccountReader:
    def __init__(self, accounts: list[DiscoveredCpanelAccount]) -> None:
        self._accounts = accounts

    async def discover(self) -> list[DiscoveredCpanelAccount]:
        return self._accounts


class FakeWordPressDetector:
    def __init__(self, by_username: dict[str, list[DiscoveredWordPressInstallation]]) -> None:
        self._by_username = by_username

    async def detect(self, account: CpanelAccount) -> list[DiscoveredWordPressInstallation]:
        return self._by_username.get(str(account.username), [])


class FakeHostInfoProvider:
    def get_hostname(self) -> str:
        return "host.example.com"

    def get_os_info(self) -> str:
        return "Linux 6.1"

    def get_agent_version(self) -> str:
        return "0.1.0"


def _account_finding(username: str, domain: str) -> DiscoveredCpanelAccount:
    return DiscoveredCpanelAccount(
        username=LinuxUsername(value=username),
        primary_domain=DomainName(value=domain),
        home_directory=AbsoluteFilePath(value=f"/home/{username}"),
        is_suspended=False,
    )


def _wp_finding(path: str, domain: str | None = None) -> DiscoveredWordPressInstallation:
    return DiscoveredWordPressInstallation(
        absolute_path=AbsoluteFilePath(value=path),
        domain=DomainName(value=domain) if domain else None,
        wp_version="6.5",
        is_multisite=False,
    )


@pytest.fixture
def repos() -> tuple[
    FakeServerRepository, FakeCpanelAccountRepository, FakeWordPressInstallationRepository
]:
    return (
        FakeServerRepository(),
        FakeCpanelAccountRepository(),
        FakeWordPressInstallationRepository(),
    )


async def test_first_run_creates_server_accounts_and_installations(
    repos: tuple[
        FakeServerRepository, FakeCpanelAccountRepository, FakeWordPressInstallationRepository
    ],
) -> None:
    server_repo, account_repo, installation_repo = repos
    use_case = RunDiscoveryUseCase(
        server_repository=server_repo,
        account_repository=account_repo,
        installation_repository=installation_repo,
        account_reader=FakeCpanelAccountReader([_account_finding("examplebob1", "example.com")]),
        wp_detector=FakeWordPressDetector(
            {"examplebob1": [_wp_finding("/home/examplebob1/public_html", "example.com")]}
        ),
        host_info=FakeHostInfoProvider(),
    )

    result = await use_case.execute()

    assert len(server_repo.by_id) == 1
    assert result.accounts_found == 1
    assert result.installations_found == 1
    assert result.accounts_deactivated == 0
    assert result.installations_deactivated == 0


async def test_second_run_reuses_existing_server_and_deactivates_missing_account(
    repos: tuple[
        FakeServerRepository, FakeCpanelAccountRepository, FakeWordPressInstallationRepository
    ],
) -> None:
    server_repo, account_repo, installation_repo = repos
    host_info = FakeHostInfoProvider()

    first_use_case = RunDiscoveryUseCase(
        server_repository=server_repo,
        account_repository=account_repo,
        installation_repository=installation_repo,
        account_reader=FakeCpanelAccountReader([_account_finding("examplebob1", "example.com")]),
        wp_detector=FakeWordPressDetector(
            {"examplebob1": [_wp_finding("/home/examplebob1/public_html", "example.com")]}
        ),
        host_info=host_info,
    )
    await first_use_case.execute()
    assert len(server_repo.by_id) == 1

    second_use_case = RunDiscoveryUseCase(
        server_repository=server_repo,
        account_repository=account_repo,
        installation_repository=installation_repo,
        account_reader=FakeCpanelAccountReader([]),
        wp_detector=FakeWordPressDetector({}),
        host_info=host_info,
    )
    result = await second_use_case.execute()

    assert len(server_repo.by_id) == 1
    assert result.accounts_found == 0
    assert result.accounts_deactivated == 1
    assert result.installations_deactivated == 1

    (account,) = account_repo.by_id.values()
    assert account.is_active is False
    (installation,) = installation_repo.by_id.values()
    assert installation.is_active is False
