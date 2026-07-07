from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from sentinel.application.wordpress.intelligence.queries import GetWordPressIncidentReportQuery
from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.intelligence.entities import Incident, IncidentAccountLink
from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import EntityNotFoundError
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName, Severity

_HASH = "a" * 64


class FakeIncidentRepository:
    def __init__(self, incidents: list[Incident] | None = None) -> None:
        self.by_id: dict[UUID, Incident] = {i.id: i for i in incidents or []}

    async def add(self, entity: Incident) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: Incident) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> Incident | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[Incident]:
        return list(self.by_id.values())[offset : offset + limit]

    async def find_open_matching(self, signature: str, *, since):  # type: ignore[no-untyped-def]
        return None

    async def list_open(self) -> list[Incident]:
        return [i for i in self.by_id.values()]


class FakeIncidentAccountLinkRepository:
    def __init__(self, links: list[IncidentAccountLink] | None = None) -> None:
        self.by_id: dict[UUID, IncidentAccountLink] = {link.id: link for link in links or []}

    async def add(self, entity: IncidentAccountLink) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: IncidentAccountLink) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> IncidentAccountLink | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[IncidentAccountLink]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_incident_and_account(
        self, incident_id: UUID, account_id: UUID
    ) -> IncidentAccountLink | None:
        return next(
            (
                link
                for link in self.by_id.values()
                if link.incident_id == incident_id and link.account_id == account_id
            ),
            None,
        )

    async def list_by_incident(self, incident_id: UUID) -> list[IncidentAccountLink]:
        return [link for link in self.by_id.values() if link.incident_id == incident_id]


class FakeWordPressInstallationRepository:
    def __init__(self, installations: list[WordPressInstallation] | None = None) -> None:
        self.by_id: dict[UUID, WordPressInstallation] = {i.id: i for i in installations or []}

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


class FakeInstalledPluginRepository:
    def __init__(self, plugins: list[InstalledPlugin] | None = None) -> None:
        self.by_id: dict[UUID, InstalledPlugin] = {p.id: p for p in plugins or []}

    async def add(self, entity: InstalledPlugin) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: InstalledPlugin) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> InstalledPlugin | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[InstalledPlugin]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledPlugin | None:
        return next(
            (
                p
                for p in self.by_id.values()
                if p.installation_id == installation_id and p.slug == slug
            ),
            None,
        )

    async def list_by_installation(self, installation_id: UUID) -> list[InstalledPlugin]:
        return [p for p in self.by_id.values() if p.installation_id == installation_id]


class FakeInstalledThemeRepository:
    def __init__(self, themes: list[InstalledTheme] | None = None) -> None:
        self.by_id: dict[UUID, InstalledTheme] = {t.id: t for t in themes or []}

    async def add(self, entity: InstalledTheme) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: InstalledTheme) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> InstalledTheme | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[InstalledTheme]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledTheme | None:
        return next(
            (
                t
                for t in self.by_id.values()
                if t.installation_id == installation_id and t.slug == slug
            ),
            None,
        )

    async def list_by_installation(self, installation_id: UUID) -> list[InstalledTheme]:
        return [t for t in self.by_id.values() if t.installation_id == installation_id]


class FakeSecurityEventRepository:
    def __init__(self, events: list[SecurityEvent] | None = None) -> None:
        self.by_id: dict[UUID, SecurityEvent] = {e.id: e for e in events or []}

    async def add(self, entity: SecurityEvent) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: SecurityEvent) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> SecurityEvent | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[SecurityEvent]:
        return list(self.by_id.values())[offset : offset + limit]

    async def list_unprocessed(self, *, limit: int = 200) -> list[SecurityEvent]:
        return [e for e in self.by_id.values() if e.processed_at is None][:limit]

    async def count_total(self) -> int:
        return len(self.by_id)

    async def count_unprocessed(self) -> int:
        return len([e for e in self.by_id.values() if e.processed_at is None])

    async def list_by_account(self, account_id: UUID, *, limit: int = 200) -> list[SecurityEvent]:
        return [e for e in self.by_id.values() if e.account_id == account_id][:limit]


def _incident() -> Incident:
    now = utcnow()
    return Incident(
        title="Correlated activity",
        correlation_signature="temp_file_malicious:webshell-signature",
        severity=Severity.CRITICAL,
        confidence=0.9,
        first_seen_at=now,
        last_seen_at=now,
        root_cause="Shared plugin akismet (5.1)",
        recommended_actions="Update or remove plugin 'akismet'",
    )


def _installation(account_id: UUID) -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=account_id,
        absolute_path=AbsoluteFilePath(value="/home/x/public_html"),
        domain=DomainName(value="example.com"),
        wp_version="6.5",
        is_multisite=False,
        last_seen_at=utcnow(),
    )


def _event(*, account_id: UUID, sha256: str | None) -> SecurityEvent:
    return SecurityEvent(
        event_type="wordpress_dropin_present",
        source_context="wordpress",
        account_id=account_id,
        severity=Severity.CRITICAL,
        payload={},
        occurred_at=utcnow(),
        sha256=sha256,
    )


async def test_incident_report_finds_shared_plugins_themes_and_hashes() -> None:
    incident = _incident()
    account_a, account_b = uuid4(), uuid4()
    links = [
        IncidentAccountLink(incident_id=incident.id, account_id=account_a),
        IncidentAccountLink(incident_id=incident.id, account_id=account_b),
    ]
    installation_a = _installation(account_a)
    installation_b = _installation(account_b)

    plugins = [
        InstalledPlugin(
            installation_id=installation_a.id,
            slug="akismet",
            name="Akismet",
            version="5.1",
            last_seen_at=utcnow(),
        ),
        InstalledPlugin(
            installation_id=installation_b.id,
            slug="akismet",
            name="Akismet",
            version="5.1",
            last_seen_at=utcnow(),
        ),
    ]
    themes = [
        InstalledTheme(
            installation_id=installation_a.id,
            slug="twentytwenty",
            name="Twenty Twenty",
            version="1.0",
            last_seen_at=utcnow(),
        ),
        InstalledTheme(
            installation_id=installation_b.id,
            slug="twentytwenty",
            name="Twenty Twenty",
            version="1.0",
            last_seen_at=utcnow(),
        ),
    ]
    events = [
        _event(account_id=account_a, sha256=_HASH),
        _event(account_id=account_b, sha256=_HASH),
    ]

    query = GetWordPressIncidentReportQuery(
        incident_repository=FakeIncidentRepository([incident]),
        link_repository=FakeIncidentAccountLinkRepository(links),
        installation_repository=FakeWordPressInstallationRepository(
            [installation_a, installation_b]
        ),
        plugin_repository=FakeInstalledPluginRepository(plugins),
        theme_repository=FakeInstalledThemeRepository(themes),
        event_repository=FakeSecurityEventRepository(events),
    )

    report = await query.execute(incident.id)

    assert report.title == "Correlated activity"
    assert report.root_cause == "Shared plugin akismet (5.1)"
    assert set(report.affected_account_ids) == {account_a, account_b}
    assert [a.identifier for a in report.shared_plugins] == ["akismet 5.1"]
    assert [a.identifier for a in report.shared_themes] == ["twentytwenty 1.0"]
    assert [a.identifier for a in report.shared_hashes] == [_HASH]
    assert report.shared_hashes[0].account_count == 2


async def test_incident_report_returns_empty_shared_lists_for_single_account() -> None:
    incident = _incident()
    account_a = uuid4()
    links = [IncidentAccountLink(incident_id=incident.id, account_id=account_a)]

    query = GetWordPressIncidentReportQuery(
        incident_repository=FakeIncidentRepository([incident]),
        link_repository=FakeIncidentAccountLinkRepository(links),
        installation_repository=FakeWordPressInstallationRepository(),
        plugin_repository=FakeInstalledPluginRepository(),
        theme_repository=FakeInstalledThemeRepository(),
        event_repository=FakeSecurityEventRepository(),
    )

    report = await query.execute(incident.id)

    assert report.shared_plugins == []
    assert report.shared_themes == []
    assert report.shared_hashes == []


async def test_incident_report_raises_for_unknown_incident() -> None:
    query = GetWordPressIncidentReportQuery(
        incident_repository=FakeIncidentRepository(),
        link_repository=FakeIncidentAccountLinkRepository(),
        installation_repository=FakeWordPressInstallationRepository(),
        plugin_repository=FakeInstalledPluginRepository(),
        theme_repository=FakeInstalledThemeRepository(),
        event_repository=FakeSecurityEventRepository(),
    )

    with pytest.raises(EntityNotFoundError):
        await query.execute(uuid4())
