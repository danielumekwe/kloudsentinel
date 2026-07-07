from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sentinel.application.intelligence.use_cases import (
    AnalyzeRootCauseUseCase,
    RunCorrelationUseCase,
)
from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.intelligence.entities import Incident, IncidentAccountLink, ThreatTimelineEntry
from sentinel.domain.intelligence.value_objects import IncidentStatus
from sentinel.domain.inventory.entities import InstalledPlugin
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName, Severity

_RULE_IDS = ["webshell-signature"]


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


class FakeIncidentRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, Incident] = {}

    async def add(self, entity: Incident) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: Incident) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> Incident | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[Incident]:
        return list(self.by_id.values())[offset : offset + limit]

    async def find_open_matching(self, signature: str, *, since: datetime) -> Incident | None:
        return next(
            (
                i
                for i in self.by_id.values()
                if i.correlation_signature == signature
                and i.status is IncidentStatus.OPEN
                and i.last_seen_at >= since
            ),
            None,
        )

    async def list_open(self) -> list[Incident]:
        return [i for i in self.by_id.values() if i.status is IncidentStatus.OPEN]


class FakeIncidentAccountLinkRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, IncidentAccountLink] = {}

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


class FakeThreatTimelineEntryRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, ThreatTimelineEntry] = {}

    async def add(self, entity: ThreatTimelineEntry) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: ThreatTimelineEntry) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> ThreatTimelineEntry | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[ThreatTimelineEntry]:
        return list(self.by_id.values())[offset : offset + limit]

    async def list_by_incident(self, incident_id: UUID) -> list[ThreatTimelineEntry]:
        return [e for e in self.by_id.values() if e.incident_id == incident_id]


class FakeWordPressInstallationRepository:
    def __init__(self, installations: list[WordPressInstallation]) -> None:
        self._installations = installations

    async def add(self, entity: WordPressInstallation) -> None:
        raise NotImplementedError

    async def save(self, entity: WordPressInstallation) -> None:
        raise NotImplementedError

    async def get(self, entity_id: UUID) -> WordPressInstallation | None:
        return next((i for i in self._installations if i.id == entity_id), None)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[WordPressInstallation]:
        return self._installations[offset : offset + limit]

    async def get_by_path(self, absolute_path: str) -> WordPressInstallation | None:
        return next((i for i in self._installations if str(i.absolute_path) == absolute_path), None)

    async def list_by_account(self, cpanel_account_id: UUID) -> list[WordPressInstallation]:
        return [i for i in self._installations if i.cpanel_account_id == cpanel_account_id]


class FakeInstalledPluginRepository:
    def __init__(self, plugins: list[InstalledPlugin]) -> None:
        self._plugins = plugins

    async def add(self, entity: InstalledPlugin) -> None:
        raise NotImplementedError

    async def save(self, entity: InstalledPlugin) -> None:
        raise NotImplementedError

    async def get(self, entity_id: UUID) -> InstalledPlugin | None:
        return next((p for p in self._plugins if p.id == entity_id), None)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[InstalledPlugin]:
        return self._plugins[offset : offset + limit]

    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledPlugin | None:
        return next(
            (p for p in self._plugins if p.installation_id == installation_id and p.slug == slug),
            None,
        )

    async def list_by_installation(self, installation_id: UUID) -> list[InstalledPlugin]:
        return [p for p in self._plugins if p.installation_id == installation_id]


def _event(
    *,
    account_id: UUID | None,
    rule_ids: list[str] = _RULE_IDS,
    severity: Severity = Severity.CRITICAL,
) -> SecurityEvent:
    return SecurityEvent(
        event_type="temp_file_malicious",
        source_context="forensics",
        account_id=account_id,
        severity=severity,
        payload={"absolute_path": "/tmp/update_x.php", "matched_rule_ids": rule_ids},
        occurred_at=utcnow(),
    )


def _use_case(
    events: FakeSecurityEventRepository,
    incidents: FakeIncidentRepository,
    links: FakeIncidentAccountLinkRepository,
    timeline: FakeThreatTimelineEntryRepository,
) -> RunCorrelationUseCase:
    return RunCorrelationUseCase(
        event_repository=events,
        incident_repository=incidents,
        link_repository=links,
        timeline_repository=timeline,
        time_window_minutes=60,
    )


async def test_six_accounts_sharing_a_signature_become_one_incident() -> None:
    """The exact scenario from the spec: six different cPanel accounts, same
    malware signature, same timeline -> one incident, not six."""
    account_ids = [uuid4() for _ in range(6)]
    events = FakeSecurityEventRepository([_event(account_id=aid) for aid in account_ids])
    incidents = FakeIncidentRepository()
    links = FakeIncidentAccountLinkRepository()
    timeline = FakeThreatTimelineEntryRepository()

    result = await _use_case(events, incidents, links, timeline).execute()

    assert result.events_processed == 6
    assert result.incidents_created == 1
    assert len(incidents.by_id) == 1
    (incident,) = incidents.by_id.values()
    linked_accounts = {link.account_id for link in links.by_id.values()}
    assert linked_accounts == set(account_ids)
    assert incident.confidence > 0.9
    assert all(e.processed_at is not None for e in events.by_id.values())


async def test_lone_event_still_opens_a_lower_confidence_incident() -> None:
    events = FakeSecurityEventRepository([_event(account_id=uuid4())])
    incidents = FakeIncidentRepository()
    links = FakeIncidentAccountLinkRepository()
    timeline = FakeThreatTimelineEntryRepository()

    result = await _use_case(events, incidents, links, timeline).execute()

    assert result.incidents_created == 1
    (incident,) = incidents.by_id.values()
    assert incident.confidence < 0.9
    assert incident.status is IncidentStatus.OPEN


async def test_events_with_no_resolvable_account_get_floor_confidence() -> None:
    """A temp-file event whose owner didn't map to any known cPanel account
    (``account_id=None``) still opens an incident — just at the floor
    confidence, since there's no account to correlate across."""
    events = FakeSecurityEventRepository([_event(account_id=None), _event(account_id=None)])
    incidents = FakeIncidentRepository()
    links = FakeIncidentAccountLinkRepository()
    timeline = FakeThreatTimelineEntryRepository()

    await _use_case(events, incidents, links, timeline).execute()

    (incident,) = incidents.by_id.values()
    assert incident.confidence == 0.5
    assert len(links.by_id) == 0


async def test_second_matching_event_joins_existing_open_incident_not_a_duplicate() -> None:
    account_a = uuid4()
    events = FakeSecurityEventRepository([_event(account_id=account_a)])
    incidents = FakeIncidentRepository()
    links = FakeIncidentAccountLinkRepository()
    timeline = FakeThreatTimelineEntryRepository()
    use_case = _use_case(events, incidents, links, timeline)

    await use_case.execute()
    assert len(incidents.by_id) == 1

    account_b = uuid4()
    events.by_id[uuid4()] = _event(account_id=account_b)
    result = await use_case.execute()

    assert result.incidents_created == 0
    assert result.incidents_updated == 1
    assert len(incidents.by_id) == 1
    linked_accounts = {link.account_id for link in links.by_id.values()}
    assert linked_accounts == {account_a, account_b}


async def test_events_with_different_signatures_stay_separate_incidents() -> None:
    events = FakeSecurityEventRepository(
        [
            _event(account_id=uuid4(), rule_ids=["webshell-signature"]),
            _event(account_id=uuid4(), rule_ids=["rce-user-input"]),
        ]
    )
    incidents = FakeIncidentRepository()
    links = FakeIncidentAccountLinkRepository()
    timeline = FakeThreatTimelineEntryRepository()

    result = await _use_case(events, incidents, links, timeline).execute()

    assert result.incidents_created == 2


def _installation(account_id: UUID) -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=account_id,
        absolute_path=AbsoluteFilePath(value=f"/home/{account_id.hex}/public_html"),
        domain=DomainName(value="example.com"),
        wp_version="6.4",
        is_multisite=False,
        last_seen_at=utcnow(),
    )


def _plugin(installation_id: UUID, *, slug: str, version: str | None) -> InstalledPlugin:
    return InstalledPlugin(
        installation_id=installation_id,
        slug=slug,
        name=slug,
        version=version,
        last_seen_at=utcnow(),
    )


async def test_root_cause_identifies_shared_vulnerable_plugin() -> None:
    account_ids = [uuid4(), uuid4(), uuid4()]
    installations = [_installation(aid) for aid in account_ids]
    plugins = [
        _plugin(installation.id, slug="elementor", version="3.4") for installation in installations
    ]
    incident = Incident(
        title="Correlated activity",
        correlation_signature="temp_file_malicious:webshell-signature",
        severity=Severity.CRITICAL,
        confidence=0.8,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
    )
    incidents = FakeIncidentRepository()
    incidents.by_id[incident.id] = incident
    links = FakeIncidentAccountLinkRepository()
    for account_id in account_ids:
        link = IncidentAccountLink(incident_id=incident.id, account_id=account_id)
        links.by_id[link.id] = link

    use_case = AnalyzeRootCauseUseCase(
        incident_repository=incidents,
        link_repository=links,
        installation_repository=FakeWordPressInstallationRepository(installations),
        plugin_repository=FakeInstalledPluginRepository(plugins),
    )

    analyzed = await use_case.execute()

    assert analyzed == 1
    updated = incidents.by_id[incident.id]
    assert updated.root_cause is not None
    assert "elementor" in updated.root_cause
    assert updated.recommended_actions is not None
    assert updated.false_positive_probability == 0.1


async def test_root_cause_skips_incident_with_no_common_plugin() -> None:
    account_ids = [uuid4(), uuid4()]
    installations = [_installation(aid) for aid in account_ids]
    plugins = [_plugin(installations[0].id, slug="elementor", version="3.4")]
    incident = Incident(
        title="Correlated activity",
        correlation_signature="temp_file_malicious:webshell-signature",
        severity=Severity.CRITICAL,
        confidence=0.8,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
    )
    incidents = FakeIncidentRepository()
    incidents.by_id[incident.id] = incident
    links = FakeIncidentAccountLinkRepository()
    for account_id in account_ids:
        link = IncidentAccountLink(incident_id=incident.id, account_id=account_id)
        links.by_id[link.id] = link

    use_case = AnalyzeRootCauseUseCase(
        incident_repository=incidents,
        link_repository=links,
        installation_repository=FakeWordPressInstallationRepository(installations),
        plugin_repository=FakeInstalledPluginRepository(plugins),
    )

    analyzed = await use_case.execute()

    assert analyzed == 0
    assert incidents.by_id[incident.id].root_cause is None


async def test_root_cause_skips_single_account_incidents() -> None:
    account_id = uuid4()
    incident = Incident(
        title="Correlated activity",
        correlation_signature="temp_file_malicious:webshell-signature",
        severity=Severity.CRITICAL,
        confidence=0.6,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
    )
    incidents = FakeIncidentRepository()
    incidents.by_id[incident.id] = incident
    links = FakeIncidentAccountLinkRepository()
    link = IncidentAccountLink(incident_id=incident.id, account_id=account_id)
    links.by_id[link.id] = link

    use_case = AnalyzeRootCauseUseCase(
        incident_repository=incidents,
        link_repository=links,
        installation_repository=FakeWordPressInstallationRepository([]),
        plugin_repository=FakeInstalledPluginRepository([]),
    )

    analyzed = await use_case.execute()

    assert analyzed == 0


async def test_root_cause_skips_incident_already_analyzed() -> None:
    account_ids = [uuid4(), uuid4()]
    installations = [_installation(aid) for aid in account_ids]
    plugins = [
        _plugin(installation.id, slug="elementor", version="3.4") for installation in installations
    ]
    incident = Incident(
        title="Correlated activity",
        correlation_signature="temp_file_malicious:webshell-signature",
        severity=Severity.CRITICAL,
        confidence=0.9,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        root_cause="Already analyzed in a previous run",
    )
    incidents = FakeIncidentRepository()
    incidents.by_id[incident.id] = incident
    links = FakeIncidentAccountLinkRepository()
    for account_id in account_ids:
        link = IncidentAccountLink(incident_id=incident.id, account_id=account_id)
        links.by_id[link.id] = link

    use_case = AnalyzeRootCauseUseCase(
        incident_repository=incidents,
        link_repository=links,
        installation_repository=FakeWordPressInstallationRepository(installations),
        plugin_repository=FakeInstalledPluginRepository(plugins),
    )

    analyzed = await use_case.execute()

    assert analyzed == 0
    assert incidents.by_id[incident.id].root_cause == "Already analyzed in a previous run"


async def test_root_cause_reports_lower_confidence_when_multiple_plugins_are_shared() -> None:
    account_ids = [uuid4(), uuid4()]
    installations = [_installation(aid) for aid in account_ids]
    plugins = [
        _plugin(installation.id, slug=slug, version="1.0")
        for installation in installations
        for slug in ("akismet", "elementor")
    ]
    incident = Incident(
        title="Correlated activity",
        correlation_signature="temp_file_malicious:webshell-signature",
        severity=Severity.CRITICAL,
        confidence=0.8,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
    )
    incidents = FakeIncidentRepository()
    incidents.by_id[incident.id] = incident
    links = FakeIncidentAccountLinkRepository()
    for account_id in account_ids:
        link = IncidentAccountLink(incident_id=incident.id, account_id=account_id)
        links.by_id[link.id] = link

    use_case = AnalyzeRootCauseUseCase(
        incident_repository=incidents,
        link_repository=links,
        installation_repository=FakeWordPressInstallationRepository(installations),
        plugin_repository=FakeInstalledPluginRepository(plugins),
    )

    analyzed = await use_case.execute()

    assert analyzed == 1
    updated = incidents.by_id[incident.id]
    assert updated.false_positive_probability == 0.4
    assert "most likely candidate" in (updated.recommended_actions or "") or "akismet" in (
        updated.root_cause or ""
    )
