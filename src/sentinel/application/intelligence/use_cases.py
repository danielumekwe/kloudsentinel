from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

import structlog

from sentinel.domain.discovery.ports import WordPressInstallationRepository
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.events.ports import SecurityEventRepository
from sentinel.domain.intelligence.entities import Incident, IncidentAccountLink, ThreatTimelineEntry
from sentinel.domain.intelligence.ports import (
    IncidentAccountLinkRepository,
    IncidentRepository,
    ThreatTimelineEntryRepository,
)
from sentinel.domain.intelligence.value_objects import RootCauseConclusion
from sentinel.domain.inventory.ports import InstalledPluginRepository
from sentinel.domain.shared.entity import utcnow

logger = structlog.get_logger()


@dataclass(frozen=True)
class CorrelationResult:
    events_processed: int
    incidents_created: int
    incidents_updated: int


def _signature_for(event: SecurityEvent) -> str:
    raw_rule_ids = event.payload.get("matched_rule_ids")
    rule_ids = (
        sorted(str(rule_id) for rule_id in raw_rule_ids) if isinstance(raw_rule_ids, list) else []
    )
    return f"{event.event_type}:{'|'.join(rule_ids)}" if rule_ids else event.event_type


def _confidence_for(*, distinct_account_count: int) -> float:
    if distinct_account_count == 0:
        return 0.5
    return min(0.99, 0.5 + 0.1 * distinct_account_count)


class RunCorrelationUseCase:
    """Groups unprocessed ``SecurityEvent`` rows into ``Incident``s.

    Correlation signature = event type + sorted matched rule IDs: events
    sharing the same behavioral fingerprint within ``time_window_minutes``
    of each other are treated as one coordinated attack regardless of which
    account/file each individually came from — the deterministic stand-in
    for "same malware, same plugin, same timeline" from the spec.

    Confidence is a plain function of how many distinct accounts are now
    linked to the incident (recomputed from persisted links every run, so it
    stays correct whether this is a brand-new incident or one absorbing more
    evidence) — never an opaque model score. A lone event still opens an
    incident, just at lower confidence, rather than being silently dropped.
    """

    def __init__(
        self,
        *,
        event_repository: SecurityEventRepository,
        incident_repository: IncidentRepository,
        link_repository: IncidentAccountLinkRepository,
        timeline_repository: ThreatTimelineEntryRepository,
        time_window_minutes: int,
    ) -> None:
        self._events = event_repository
        self._incidents = incident_repository
        self._links = link_repository
        self._timeline = timeline_repository
        self._window = timedelta(minutes=time_window_minutes)

    async def execute(self) -> CorrelationResult:
        now = utcnow()
        events = await self._events.list_unprocessed(limit=200)

        clusters: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in events:
            clusters[_signature_for(event)].append(event)

        incidents_created = 0
        incidents_updated = 0

        for signature, cluster_events in clusters.items():
            incident, created = await self._get_or_create_incident(
                signature, cluster_events, at=now
            )

            for event in cluster_events:
                if event.account_id is not None:
                    await self._link_account(incident.id, event.account_id)
                await self._timeline.add(
                    ThreatTimelineEntry(
                        incident_id=incident.id,
                        stage=event.event_type.upper(),
                        description=str(
                            event.payload.get("verdict_reason")
                            or event.payload.get("absolute_path")
                            or event.event_type
                        ),
                        occurred_at=event.occurred_at,
                        source_event_id=event.id,
                    )
                )
                event.mark_processed(at=now)
                await self._events.save(event)

            linked = await self._links.list_by_incident(incident.id)
            max_severity = max((e.severity for e in cluster_events), key=lambda s: s.rank)
            confidence = _confidence_for(
                distinct_account_count=len({link.account_id for link in linked})
            )
            incident.record_new_evidence(at=now, confidence=confidence, severity=max_severity)
            await self._incidents.save(incident)

            if created:
                incidents_created += 1
            else:
                incidents_updated += 1

        logger.info(
            "correlation_completed",
            events_processed=len(events),
            incidents_created=incidents_created,
            incidents_updated=incidents_updated,
        )
        return CorrelationResult(
            events_processed=len(events),
            incidents_created=incidents_created,
            incidents_updated=incidents_updated,
        )

    async def _get_or_create_incident(
        self, signature: str, cluster_events: list[SecurityEvent], *, at: datetime
    ) -> tuple[Incident, bool]:
        since = at - self._window
        existing = await self._incidents.find_open_matching(signature, since=since)
        if existing is not None:
            return existing, False

        incident = Incident(
            title=f"Correlated {cluster_events[0].event_type} activity",
            correlation_signature=signature,
            severity=cluster_events[0].severity,
            confidence=0.5,
            first_seen_at=min(e.occurred_at for e in cluster_events),
            last_seen_at=max(e.occurred_at for e in cluster_events),
        )
        await self._incidents.add(incident)
        return incident, True

    async def _link_account(self, incident_id: UUID, account_id: UUID) -> None:
        existing = await self._links.get_by_incident_and_account(incident_id, account_id)
        if existing is None:
            await self._links.add(
                IncidentAccountLink(incident_id=incident_id, account_id=account_id)
            )


class AnalyzeRootCauseUseCase:
    """For each ``OPEN`` incident with at least two affected accounts, looks
    for a plugin+version shared by every affected account's WordPress
    installations — the deterministic root-cause check from the spec's
    worked example ("all infected websites share the same vulnerable
    Elementor version"). Reuses the existing inventory/discovery
    repositories rather than duplicating any plugin/installation data.

    No common plugin found → no root cause is set. This never guesses.
    """

    def __init__(
        self,
        *,
        incident_repository: IncidentRepository,
        link_repository: IncidentAccountLinkRepository,
        installation_repository: WordPressInstallationRepository,
        plugin_repository: InstalledPluginRepository,
    ) -> None:
        self._incidents = incident_repository
        self._links = link_repository
        self._installations = installation_repository
        self._plugins = plugin_repository

    async def execute(self) -> int:
        analyzed = 0
        for incident in await self._incidents.list_open():
            if incident.root_cause is not None:
                continue

            links = await self._links.list_by_incident(incident.id)
            account_ids = {link.account_id for link in links}
            if len(account_ids) < 2:
                continue

            conclusion = await self._analyze(account_ids)
            if conclusion is None:
                continue

            incident.apply_root_cause(conclusion)
            await self._incidents.save(incident)
            analyzed += 1

        return analyzed

    async def _analyze(self, account_ids: set[UUID]) -> RootCauseConclusion | None:
        plugin_sets: list[set[tuple[str, str | None]]] = []
        for account_id in account_ids:
            installations = await self._installations.list_by_account(account_id)
            versions: set[tuple[str, str | None]] = set()
            for installation in installations:
                plugins = await self._plugins.list_by_installation(installation.id)
                versions.update(
                    (plugin.slug, plugin.version) for plugin in plugins if plugin.is_present
                )
            plugin_sets.append(versions)

        common = set.intersection(*plugin_sets) if plugin_sets else set()
        if not common:
            return None

        candidates = sorted(common)
        slug, version = candidates[0]
        unambiguous = len(candidates) == 1
        version_label = version or "unknown version"
        account_count = len(account_ids)

        reasoning = (
            f"All {account_count} accounts linked to this incident have plugin "
            f"'{slug}' version '{version_label}' installed"
        )
        if not unambiguous:
            reasoning += (
                f"; {len(candidates)} plugins are shared across every affected account, "
                "reporting the most likely candidate — ranking by known vulnerability data "
                "is deferred to the plugin reputation engine (a later phase)"
            )

        return RootCauseConclusion(
            confidence=0.9 if unambiguous else 0.6,
            summary=f"Shared plugin {slug} ({version_label}) across all {account_count} affected accounts",
            evidence=(f"{slug} {version_label} present on every affected account",),
            reasoning=reasoning,
            recommended_action=f"Update or remove plugin '{slug}' on all affected accounts",
            false_positive_probability=0.1 if unambiguous else 0.4,
        )
