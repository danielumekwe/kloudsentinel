from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel

from sentinel.application.wordpress.integrity.checksum_use_cases import CoreFileVerification
from sentinel.application.wordpress.intelligence.queries import (
    SharedArtifact,
    WordPressIncidentReport,
)
from sentinel.application.wordpress.inventory.queries import DropInStatus, WordPressInventoryReport


class DropInStatusResponse(BaseModel):
    relative_path: str
    is_present: bool
    sha256: str | None

    @classmethod
    def from_report(cls, report: DropInStatus) -> DropInStatusResponse:
        return cls(
            relative_path=report.relative_path, is_present=report.is_present, sha256=report.sha256
        )


class WordPressInventoryResponse(BaseModel):
    installation_id: UUID
    wp_version: str | None
    php_version: str | None
    drop_ins: list[DropInStatusResponse]
    must_use_plugins: list[str]

    @classmethod
    def from_report(cls, report: WordPressInventoryReport) -> WordPressInventoryResponse:
        return cls(
            installation_id=report.installation_id,
            wp_version=report.wp_version,
            php_version=report.php_version,
            drop_ins=[DropInStatusResponse.from_report(item) for item in report.drop_ins],
            must_use_plugins=report.must_use_plugins,
        )


class CoreFileVerificationResponse(BaseModel):
    relative_path: str
    status: str
    expected_sha256: str | None
    actual_sha256: str | None

    @classmethod
    def from_report(cls, report: CoreFileVerification) -> CoreFileVerificationResponse:
        return cls(
            relative_path=report.relative_path,
            status=report.status,
            expected_sha256=report.expected_sha256,
            actual_sha256=report.actual_sha256,
        )


class SharedArtifactResponse(BaseModel):
    identifier: str
    account_count: int

    @classmethod
    def from_report(cls, report: SharedArtifact) -> SharedArtifactResponse:
        return cls(identifier=report.identifier, account_count=report.account_count)


class WordPressIncidentReportResponse(BaseModel):
    incident_id: UUID
    title: str
    severity: str
    confidence: float
    root_cause: str | None
    recommended_actions: str | None
    affected_account_ids: list[UUID]
    shared_plugins: list[SharedArtifactResponse]
    shared_themes: list[SharedArtifactResponse]
    shared_hashes: list[SharedArtifactResponse]

    @classmethod
    def from_report(cls, report: WordPressIncidentReport) -> WordPressIncidentReportResponse:
        return cls(
            incident_id=report.incident_id,
            title=report.title,
            severity=report.severity,
            confidence=report.confidence,
            root_cause=report.root_cause,
            recommended_actions=report.recommended_actions,
            affected_account_ids=report.affected_account_ids,
            shared_plugins=[SharedArtifactResponse.from_report(a) for a in report.shared_plugins],
            shared_themes=[SharedArtifactResponse.from_report(a) for a in report.shared_themes],
            shared_hashes=[SharedArtifactResponse.from_report(a) for a in report.shared_hashes],
        )
