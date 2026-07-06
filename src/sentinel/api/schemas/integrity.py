from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding, RemediationAction


class FileBaselineResponse(BaseModel):
    id: UUID
    account_id: UUID
    relative_path: str
    sha256: str
    size_bytes: int
    mode: str
    is_active: bool
    last_verified_at: datetime
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: FileBaseline) -> FileBaselineResponse:
        return cls(
            id=entity.id,
            account_id=entity.account_id,
            relative_path=str(entity.relative_path),
            sha256=str(entity.sha256),
            size_bytes=entity.size_bytes,
            mode=entity.mode,
            is_active=entity.is_active,
            last_verified_at=entity.last_verified_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )


class IntegrityFindingResponse(BaseModel):
    id: UUID
    account_id: UUID
    relative_path: str
    change_type: str
    severity: str
    previous_sha256: str | None
    current_sha256: str | None
    is_acknowledged: bool
    remediation_state: str
    quarantine_path: str | None
    detected_at: datetime
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: IntegrityFinding) -> IntegrityFindingResponse:
        return cls(
            id=entity.id,
            account_id=entity.account_id,
            relative_path=str(entity.relative_path),
            change_type=entity.change_type.value,
            severity=entity.severity.value,
            previous_sha256=(
                str(entity.previous_sha256) if entity.previous_sha256 is not None else None
            ),
            current_sha256=(
                str(entity.current_sha256) if entity.current_sha256 is not None else None
            ),
            is_acknowledged=entity.is_acknowledged,
            remediation_state=entity.remediation_state.value,
            quarantine_path=entity.quarantine_path,
            detected_at=entity.detected_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )


class RemediationActionResponse(BaseModel):
    id: UUID
    finding_id: UUID
    account_id: UUID
    relative_path: str
    action_type: str
    outcome: str
    detail: str | None
    performed_at: datetime
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: RemediationAction) -> RemediationActionResponse:
        return cls(
            id=entity.id,
            finding_id=entity.finding_id,
            account_id=entity.account_id,
            relative_path=str(entity.relative_path),
            action_type=entity.action_type.value,
            outcome=entity.outcome.value,
            detail=entity.detail,
            performed_at=entity.performed_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
