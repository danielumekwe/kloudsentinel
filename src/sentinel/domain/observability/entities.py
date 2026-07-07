from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sentinel.domain.observability.value_objects import JobHeartbeatStatus
from sentinel.domain.shared.entity import BaseEntity


@dataclass(kw_only=True)
class JobHeartbeat(BaseEntity):
    """Last-known outcome of one recurring scheduler job.

    The API, worker, and CLI are three separate processes sharing nothing
    but the database, so this row is the only way `sentinel health`/`status`
    can observe whether the worker's scheduler is actually running and
    which job last succeeded or failed — same DB-mediated approach already
    used for the event log, rather than adding new cross-process
    infrastructure just for observability.
    """

    job_id: str
    status: JobHeartbeatStatus
    last_run_at: datetime
    last_duration_ms: float
    last_error: str | None = None

    def record(
        self,
        *,
        status: JobHeartbeatStatus,
        at: datetime,
        duration_ms: float,
        error: str | None,
    ) -> None:
        self.status = status
        self.last_run_at = at
        self.last_duration_ms = duration_ms
        self.last_error = error
        self.touch()
