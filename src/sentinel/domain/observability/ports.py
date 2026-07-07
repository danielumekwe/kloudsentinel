from __future__ import annotations

from typing import Protocol

from sentinel.domain.observability.entities import JobHeartbeat
from sentinel.domain.shared.ports import Repository


class JobHeartbeatRepository(Repository[JobHeartbeat], Protocol):
    async def find_by_job_id(self, job_id: str) -> JobHeartbeat | None: ...
