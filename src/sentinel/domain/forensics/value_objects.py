from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sentinel.domain.shared.entity import ValueObject


class TempFileVerdict(StrEnum):
    LEGITIMATE = "LEGITIMATE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass(frozen=True, kw_only=True)
class ProcessContext(ValueObject):
    """Best-effort snapshot of the process holding a temp file open at scan
    time. Every field is optional: Sentinel's temp-file watch is poll-based,
    not a live kernel hook, so a short-lived script has often already exited
    by the time a scan catches its output file — an empty ``ProcessContext``
    is the normal case, not a failure.
    """

    pid: int | None = None
    ppid: int | None = None
    executable_path: str | None = None
    command_line: str | None = None
    open_files: tuple[str, ...] = ()
    network_connections: tuple[str, ...] = ()
