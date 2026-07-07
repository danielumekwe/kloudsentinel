from __future__ import annotations

from enum import StrEnum


class JobHeartbeatStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
