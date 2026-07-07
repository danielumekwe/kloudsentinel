from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import structlog

from sentinel.domain.discovery.entities import CpanelAccount, Server, WordPressInstallation
from sentinel.domain.discovery.ports import (
    CpanelAccountReader,
    CpanelAccountRepository,
    HostInfoProvider,
    ServerRepository,
    WordPressDetector,
    WordPressInstallationRepository,
)
from sentinel.domain.discovery.value_objects import (
    DiscoveredCpanelAccount,
    DiscoveredWordPressInstallation,
)
from sentinel.domain.shared.entity import utcnow

logger = structlog.get_logger()


@dataclass(frozen=True)
class DiscoveryResult:
    server_id: UUID
    accounts_found: int
    accounts_deactivated: int
    installations_found: int
    installations_deactivated: int


class RunDiscoveryUseCase:
    """Orchestrates one full discovery pass: identify the host, read its
    cPanel accounts, detect WordPress installations under each, and
    reconcile all three against persisted state.

    Reconciliation marks anything previously known but no longer found as
    inactive rather than deleting it — an account or installation
    disappearing between scans is itself a fact worth keeping, not noise.
    """

    def __init__(
        self,
        *,
        server_repository: ServerRepository,
        account_repository: CpanelAccountRepository,
        installation_repository: WordPressInstallationRepository,
        account_reader: CpanelAccountReader,
        wp_detector: WordPressDetector,
        host_info: HostInfoProvider,
    ) -> None:
        self._servers = server_repository
        self._accounts = account_repository
        self._installations = installation_repository
        self._account_reader = account_reader
        self._wp_detector = wp_detector
        self._host_info = host_info

    async def execute(self) -> DiscoveryResult:
        now = utcnow()
        server = await self._reconcile_server(now=now)

        discovered_accounts = await self._account_reader.discover()
        seen_account_ids: set[UUID] = set()
        seen_installation_ids: set[UUID] = set()
        installations_found = 0

        for finding in discovered_accounts:
            account = await self._reconcile_account(server.id, finding, now=now)
            seen_account_ids.add(account.id)

            installations = await self._wp_detector.detect(account)
            for wp_finding in installations:
                installation = await self._reconcile_installation(account.id, wp_finding, now=now)
                seen_installation_ids.add(installation.id)
            installations_found += len(installations)

        accounts_deactivated = await self._deactivate_stale_accounts(seen_account_ids)
        installations_deactivated = await self._deactivate_stale_installations(
            seen_installation_ids
        )

        logger.info(
            "discovery_completed",
            server_hostname=server.hostname,
            accounts_found=len(discovered_accounts),
            accounts_deactivated=accounts_deactivated,
            installations_found=installations_found,
            installations_deactivated=installations_deactivated,
        )

        return DiscoveryResult(
            server_id=server.id,
            accounts_found=len(discovered_accounts),
            accounts_deactivated=accounts_deactivated,
            installations_found=installations_found,
            installations_deactivated=installations_deactivated,
        )

    async def _reconcile_server(self, *, now: datetime) -> Server:
        hostname = self._host_info.get_hostname()
        server = await self._servers.get_by_hostname(hostname)
        if server is None:
            server = Server(
                hostname=hostname,
                os_info=self._host_info.get_os_info(),
                agent_version=self._host_info.get_agent_version(),
                last_seen_at=now,
            )
            await self._servers.add(server)
        else:
            server.mark_seen(at=now)
            await self._servers.save(server)
        return server

    async def _reconcile_account(
        self, server_id: UUID, finding: DiscoveredCpanelAccount, *, now: datetime
    ) -> CpanelAccount:
        existing = await self._accounts.get_by_username(finding.username)
        if existing is None:
            account = CpanelAccount(
                server_id=server_id,
                username=finding.username,
                primary_domain=finding.primary_domain,
                home_directory=finding.home_directory,
                is_suspended=finding.is_suspended,
                last_seen_at=now,
            )
            await self._accounts.add(account)
            return account

        existing.mark_seen(
            primary_domain=finding.primary_domain,
            is_suspended=finding.is_suspended,
            at=now,
        )
        await self._accounts.save(existing)
        return existing

    async def _reconcile_installation(
        self,
        cpanel_account_id: UUID,
        finding: DiscoveredWordPressInstallation,
        *,
        now: datetime,
    ) -> WordPressInstallation:
        existing = await self._installations.get_by_path(str(finding.absolute_path))
        if existing is None:
            installation = WordPressInstallation(
                cpanel_account_id=cpanel_account_id,
                absolute_path=finding.absolute_path,
                domain=finding.domain,
                wp_version=finding.wp_version,
                is_multisite=finding.is_multisite,
                last_seen_at=now,
                php_version=finding.php_version,
            )
            await self._installations.add(installation)
            return installation

        existing.mark_seen(
            domain=finding.domain,
            wp_version=finding.wp_version,
            is_multisite=finding.is_multisite,
            at=now,
            php_version=finding.php_version,
        )
        await self._installations.save(existing)
        return existing

    async def _deactivate_stale_accounts(self, seen_account_ids: set[UUID]) -> int:
        deactivated = 0
        for account in await self._accounts.list(limit=10_000):
            if account.is_active and account.id not in seen_account_ids:
                account.mark_inactive()
                await self._accounts.save(account)
                deactivated += 1
        return deactivated

    async def _deactivate_stale_installations(self, seen_installation_ids: set[UUID]) -> int:
        deactivated = 0
        for installation in await self._installations.list(limit=10_000):
            if installation.is_active and installation.id not in seen_installation_ids:
                installation.mark_inactive()
                await self._installations.save(installation)
                deactivated += 1
        return deactivated
