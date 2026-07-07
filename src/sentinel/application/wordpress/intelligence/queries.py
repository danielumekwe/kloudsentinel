from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from uuid import UUID

from sentinel.domain.discovery.ports import WordPressInstallationRepository
from sentinel.domain.events.ports import SecurityEventRepository
from sentinel.domain.intelligence.ports import IncidentAccountLinkRepository, IncidentRepository
from sentinel.domain.inventory.ports import InstalledPluginRepository, InstalledThemeRepository
from sentinel.domain.shared.exceptions import EntityNotFoundError


@dataclass(frozen=True)
class SharedArtifact:
    identifier: str
    account_count: int


@dataclass(frozen=True)
class WordPressIncidentReport:
    incident_id: UUID
    title: str
    severity: str
    confidence: float
    root_cause: str | None
    recommended_actions: str | None
    affected_account_ids: list[UUID]
    shared_plugins: list[SharedArtifact]
    shared_themes: list[SharedArtifact]
    shared_hashes: list[SharedArtifact]


class GetWordPressIncidentReportQuery:
    """Assembles the WordPress-specific incident report entirely at read
    time from existing repositories — no schema change, and no
    reimplementation of ``AnalyzeRootCauseUseCase``'s shared-plugin logic
    (mirrored here for themes and shared file hashes too, not duplicated
    from scratch). ``Incident.root_cause``/``recommended_actions`` stay the
    free-text summary they already are; this is the structured breakdown
    behind them.
    """

    def __init__(
        self,
        *,
        incident_repository: IncidentRepository,
        link_repository: IncidentAccountLinkRepository,
        installation_repository: WordPressInstallationRepository,
        plugin_repository: InstalledPluginRepository,
        theme_repository: InstalledThemeRepository,
        event_repository: SecurityEventRepository,
    ) -> None:
        self._incidents = incident_repository
        self._links = link_repository
        self._installations = installation_repository
        self._plugins = plugin_repository
        self._themes = theme_repository
        self._events = event_repository

    async def execute(self, incident_id: UUID) -> WordPressIncidentReport:
        incident = await self._incidents.get(incident_id)
        if incident is None:
            raise EntityNotFoundError("Incident", incident_id)

        links = await self._links.list_by_incident(incident_id)
        account_ids = [link.account_id for link in links]

        return WordPressIncidentReport(
            incident_id=incident.id,
            title=incident.title,
            severity=incident.severity.value,
            confidence=incident.confidence,
            root_cause=incident.root_cause,
            recommended_actions=incident.recommended_actions,
            affected_account_ids=account_ids,
            shared_plugins=await self._shared_plugins(account_ids),
            shared_themes=await self._shared_themes(account_ids),
            shared_hashes=await self._shared_hashes(account_ids),
        )

    async def _shared_plugins(self, account_ids: list[UUID]) -> list[SharedArtifact]:
        if len(account_ids) < 2:
            return []
        per_account_sets: list[set[str]] = []
        for account_id in account_ids:
            identifiers: set[str] = set()
            for installation in await self._installations.list_by_account(account_id):
                plugins = await self._plugins.list_by_installation(installation.id)
                identifiers.update(
                    f"{plugin.slug} {plugin.version or 'unknown'}"
                    for plugin in plugins
                    if plugin.is_present
                )
            per_account_sets.append(identifiers)
        common = set.intersection(*per_account_sets) if per_account_sets else set()
        return [
            SharedArtifact(identifier=identifier, account_count=len(account_ids))
            for identifier in sorted(common)
        ]

    async def _shared_themes(self, account_ids: list[UUID]) -> list[SharedArtifact]:
        if len(account_ids) < 2:
            return []
        per_account_sets: list[set[str]] = []
        for account_id in account_ids:
            identifiers: set[str] = set()
            for installation in await self._installations.list_by_account(account_id):
                themes = await self._themes.list_by_installation(installation.id)
                identifiers.update(
                    f"{theme.slug} {theme.version or 'unknown'}"
                    for theme in themes
                    if theme.is_present
                )
            per_account_sets.append(identifiers)
        common = set.intersection(*per_account_sets) if per_account_sets else set()
        return [
            SharedArtifact(identifier=identifier, account_count=len(account_ids))
            for identifier in sorted(common)
        ]

    async def _shared_hashes(self, account_ids: list[UUID]) -> list[SharedArtifact]:
        if len(account_ids) < 2:
            return []
        hash_to_accounts: dict[str, set[UUID]] = defaultdict(set)
        for account_id in account_ids:
            for event in await self._events.list_by_account(account_id, limit=200):
                if event.sha256:
                    hash_to_accounts[event.sha256].add(account_id)

        shared = [
            SharedArtifact(identifier=sha256, account_count=len(accounts))
            for sha256, accounts in hash_to_accounts.items()
            if len(accounts) >= 2
        ]
        return sorted(shared, key=lambda artifact: -artifact.account_count)
