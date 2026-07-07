from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.application.discovery.queries import (
    ListCpanelAccountsQuery,
    ListWordPressInstallationsQuery,
)
from sentinel.application.integrity.queries import (
    AcknowledgeIntegrityFindingUseCase,
    ListFileBaselinesQuery,
    ListIntegrityFindingsQuery,
    ListRemediationActionsQuery,
)
from sentinel.application.integrity.use_cases import (
    DeleteFindingUseCase,
    QuarantineFindingUseCase,
    RestoreFindingUseCase,
)
from sentinel.application.intelligence.queries import (
    GetIncidentQuery,
    ListIncidentEvidenceQuery,
    ListIncidentsQuery,
    ListIncidentTimelineQuery,
)
from sentinel.application.inventory.queries import (
    ListInstalledPluginsQuery,
    ListInstalledThemesQuery,
)
from sentinel.application.monitoring.queries import ListConfigurationItemsQuery
from sentinel.application.wordpress.integrity.checksum_use_cases import VerifyCoreChecksumsUseCase
from sentinel.application.wordpress.intelligence.queries import GetWordPressIncidentReportQuery
from sentinel.application.wordpress.inventory.queries import GetWordPressInventoryQuery
from sentinel.config import Settings
from sentinel.infrastructure.filesystem.file_remediator import FilesystemFileRemediator
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models import ApiKeyModel
from sentinel.infrastructure.persistence.repositories.discovery import (
    SqlAlchemyCpanelAccountRepository,
    SqlAlchemyWordPressInstallationRepository,
)
from sentinel.infrastructure.persistence.repositories.events import SqlAlchemyEventRepository
from sentinel.infrastructure.persistence.repositories.integrity import (
    SqlAlchemyFileBaselineRepository,
    SqlAlchemyIntegrityFindingRepository,
    SqlAlchemyRemediationActionRepository,
)
from sentinel.infrastructure.persistence.repositories.intelligence import (
    SqlAlchemyIncidentAccountLinkRepository,
    SqlAlchemyIncidentRepository,
    SqlAlchemyThreatTimelineEntryRepository,
)
from sentinel.infrastructure.persistence.repositories.inventory import (
    SqlAlchemyInstalledPluginRepository,
    SqlAlchemyInstalledThemeRepository,
)
from sentinel.infrastructure.persistence.repositories.monitoring import (
    SqlAlchemyConfigurationItemRepository,
)
from sentinel.infrastructure.persistence.repositories.wordpress_integrity import (
    SqlAlchemyCoreChecksumRepository,
)
from sentinel.infrastructure.wordpress.core_checksums import WordPressOrgChecksumsClient


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


AppSettings = Annotated[Settings, Depends(get_app_settings)]


async def get_db_session(
    database: Annotated[Database, Depends(get_database)],
) -> AsyncIterator[AsyncSession]:
    """Commits after the request handler returns successfully, so write
    endpoints (e.g. acknowledging a finding) don't rely on each one
    remembering to commit itself. If the handler raises, the ``yield`` re-
    raises here too, skipping the commit — the session then rolls back on
    close, same as before."""
    async with database.session() as session:
        yield session
        await session.commit()


DbSession = Annotated[AsyncSession, Depends(get_db_session)]


async def require_api_key(
    session: DbSession,
    authorization: Annotated[str | None, Header()] = None,
) -> ApiKeyModel:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_key = authorization.removeprefix("Bearer ").strip()
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    result = await session.execute(
        select(ApiKeyModel).where(
            ApiKeyModel.key_hash == key_hash,
            ApiKeyModel.is_active.is_(True),
        )
    )
    api_key = result.scalar_one_or_none()
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return api_key


RequireApiKey = Annotated[ApiKeyModel, Depends(require_api_key)]


def require_mutations_allowed(settings: AppSettings) -> None:
    """Guards every mutation-capable endpoint (quarantine/restore/delete).
    Blocks nothing about detection or scanning — those are read-only and run
    regardless of ``mode`` — this only stops Sentinel from touching the host
    filesystem when ``SENTINEL_MODE=observe`` (the default)."""
    if settings.mode == "observe":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Sentinel is running in observe mode (SENTINEL_MODE=observe); "
                "remediation endpoints are disabled."
            ),
        )


RequireMutationsAllowed = Annotated[None, Depends(require_mutations_allowed)]


def get_list_cpanel_accounts_query(session: DbSession) -> ListCpanelAccountsQuery:
    return ListCpanelAccountsQuery(SqlAlchemyCpanelAccountRepository(session))


def get_list_wp_installations_query(session: DbSession) -> ListWordPressInstallationsQuery:
    return ListWordPressInstallationsQuery(SqlAlchemyWordPressInstallationRepository(session))


ListCpanelAccounts = Annotated[ListCpanelAccountsQuery, Depends(get_list_cpanel_accounts_query)]
ListWordPressInstallations = Annotated[
    ListWordPressInstallationsQuery, Depends(get_list_wp_installations_query)
]


def get_list_file_baselines_query(session: DbSession) -> ListFileBaselinesQuery:
    return ListFileBaselinesQuery(SqlAlchemyFileBaselineRepository(session))


def get_list_integrity_findings_query(session: DbSession) -> ListIntegrityFindingsQuery:
    return ListIntegrityFindingsQuery(SqlAlchemyIntegrityFindingRepository(session))


def get_acknowledge_integrity_finding_use_case(
    session: DbSession,
) -> AcknowledgeIntegrityFindingUseCase:
    return AcknowledgeIntegrityFindingUseCase(SqlAlchemyIntegrityFindingRepository(session))


ListFileBaselines = Annotated[ListFileBaselinesQuery, Depends(get_list_file_baselines_query)]
ListIntegrityFindings = Annotated[
    ListIntegrityFindingsQuery, Depends(get_list_integrity_findings_query)
]
AcknowledgeIntegrityFinding = Annotated[
    AcknowledgeIntegrityFindingUseCase, Depends(get_acknowledge_integrity_finding_use_case)
]


def get_quarantine_finding_use_case(
    session: DbSession, settings: AppSettings
) -> QuarantineFindingUseCase:
    return QuarantineFindingUseCase(
        finding_repository=SqlAlchemyIntegrityFindingRepository(session),
        account_repository=SqlAlchemyCpanelAccountRepository(session),
        baseline_repository=SqlAlchemyFileBaselineRepository(session),
        action_repository=SqlAlchemyRemediationActionRepository(session),
        remediator=FilesystemFileRemediator(
            quarantine_root_directory=settings.quarantine_root_directory
        ),
    )


def get_restore_finding_use_case(
    session: DbSession, settings: AppSettings
) -> RestoreFindingUseCase:
    return RestoreFindingUseCase(
        finding_repository=SqlAlchemyIntegrityFindingRepository(session),
        account_repository=SqlAlchemyCpanelAccountRepository(session),
        baseline_repository=SqlAlchemyFileBaselineRepository(session),
        action_repository=SqlAlchemyRemediationActionRepository(session),
        remediator=FilesystemFileRemediator(
            quarantine_root_directory=settings.quarantine_root_directory
        ),
    )


def get_delete_finding_use_case(session: DbSession, settings: AppSettings) -> DeleteFindingUseCase:
    return DeleteFindingUseCase(
        finding_repository=SqlAlchemyIntegrityFindingRepository(session),
        action_repository=SqlAlchemyRemediationActionRepository(session),
        remediator=FilesystemFileRemediator(
            quarantine_root_directory=settings.quarantine_root_directory
        ),
    )


def get_list_remediation_actions_query(session: DbSession) -> ListRemediationActionsQuery:
    return ListRemediationActionsQuery(SqlAlchemyRemediationActionRepository(session))


QuarantineFinding = Annotated[QuarantineFindingUseCase, Depends(get_quarantine_finding_use_case)]
RestoreFinding = Annotated[RestoreFindingUseCase, Depends(get_restore_finding_use_case)]
DeleteFinding = Annotated[DeleteFindingUseCase, Depends(get_delete_finding_use_case)]
ListRemediationActions = Annotated[
    ListRemediationActionsQuery, Depends(get_list_remediation_actions_query)
]


def get_list_installed_plugins_query(session: DbSession) -> ListInstalledPluginsQuery:
    return ListInstalledPluginsQuery(SqlAlchemyInstalledPluginRepository(session))


def get_list_installed_themes_query(session: DbSession) -> ListInstalledThemesQuery:
    return ListInstalledThemesQuery(SqlAlchemyInstalledThemeRepository(session))


ListInstalledPlugins = Annotated[
    ListInstalledPluginsQuery, Depends(get_list_installed_plugins_query)
]
ListInstalledThemes = Annotated[ListInstalledThemesQuery, Depends(get_list_installed_themes_query)]


def get_list_configuration_items_query(session: DbSession) -> ListConfigurationItemsQuery:
    return ListConfigurationItemsQuery(SqlAlchemyConfigurationItemRepository(session))


ListConfigurationItems = Annotated[
    ListConfigurationItemsQuery, Depends(get_list_configuration_items_query)
]


def get_list_incidents_query(session: DbSession) -> ListIncidentsQuery:
    return ListIncidentsQuery(SqlAlchemyIncidentRepository(session))


def get_get_incident_query(session: DbSession) -> GetIncidentQuery:
    return GetIncidentQuery(SqlAlchemyIncidentRepository(session))


def get_list_incident_timeline_query(session: DbSession) -> ListIncidentTimelineQuery:
    return ListIncidentTimelineQuery(SqlAlchemyThreatTimelineEntryRepository(session))


def get_list_incident_evidence_query(session: DbSession) -> ListIncidentEvidenceQuery:
    return ListIncidentEvidenceQuery(
        SqlAlchemyThreatTimelineEntryRepository(session), SqlAlchemyEventRepository(session)
    )


ListIncidents = Annotated[ListIncidentsQuery, Depends(get_list_incidents_query)]
GetIncident = Annotated[GetIncidentQuery, Depends(get_get_incident_query)]
ListIncidentTimeline = Annotated[
    ListIncidentTimelineQuery, Depends(get_list_incident_timeline_query)
]
ListIncidentEvidence = Annotated[
    ListIncidentEvidenceQuery, Depends(get_list_incident_evidence_query)
]


def get_wordpress_inventory_query(
    session: DbSession, settings: AppSettings
) -> GetWordPressInventoryQuery:
    return GetWordPressInventoryQuery(
        installation_repository=SqlAlchemyWordPressInstallationRepository(session),
        baseline_repository=SqlAlchemyFileBaselineRepository(session),
        dropin_relative_paths=settings.wordpress_dropin_relative_paths,
    )


def get_verify_wordpress_core_checksums_use_case(
    session: DbSession, settings: AppSettings
) -> VerifyCoreChecksumsUseCase:
    return VerifyCoreChecksumsUseCase(
        installation_repository=SqlAlchemyWordPressInstallationRepository(session),
        baseline_repository=SqlAlchemyFileBaselineRepository(session),
        checksum_repository=SqlAlchemyCoreChecksumRepository(session),
        checksums_client=WordPressOrgChecksumsClient(
            base_url=settings.wordpress_core_checksums_api_base_url,
            locale=settings.wordpress_core_checksums_locale,
        ),
        critical_relative_paths=settings.wordpress_critical_relative_paths,
    )


def get_wordpress_incident_report_query(session: DbSession) -> GetWordPressIncidentReportQuery:
    return GetWordPressIncidentReportQuery(
        incident_repository=SqlAlchemyIncidentRepository(session),
        link_repository=SqlAlchemyIncidentAccountLinkRepository(session),
        installation_repository=SqlAlchemyWordPressInstallationRepository(session),
        plugin_repository=SqlAlchemyInstalledPluginRepository(session),
        theme_repository=SqlAlchemyInstalledThemeRepository(session),
        event_repository=SqlAlchemyEventRepository(session),
    )


GetWordPressInventory = Annotated[
    GetWordPressInventoryQuery, Depends(get_wordpress_inventory_query)
]
VerifyWordPressCoreChecksums = Annotated[
    VerifyCoreChecksumsUseCase, Depends(get_verify_wordpress_core_checksums_use_case)
]
GetWordPressIncidentReport = Annotated[
    GetWordPressIncidentReportQuery, Depends(get_wordpress_incident_report_query)
]
