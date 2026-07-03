from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding


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
            detected_at=entity.detected_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
