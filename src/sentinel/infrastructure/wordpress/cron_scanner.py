from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sentinel.domain.discovery.entities import CpanelAccount

_SCHEDULE_FIELD_COUNT = 5
_ENV_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")


@dataclass(frozen=True)
class CrontabEntry:
    schedule_raw: str
    command: str


class SystemCrontabScanner:
    """Reads one cPanel account's system crontab
    (``{crontab_directory}/{username}``) — deliberately *not* the WP-Cron
    entries stored inside the site's own MySQL ``wp_options`` table, which
    would require database-client capability Sentinel has nowhere in its
    architecture today (see ``WordPressCronJob``'s docstring). System
    crontab entries are the persistence vector actually visible to a
    filesystem-only agent — and the one real attacks actually use to
    re-establish a webshell.
    """

    def __init__(self, *, crontab_directory: str) -> None:
        self._crontab_directory = Path(crontab_directory)

    async def scan(self, account: CpanelAccount) -> list[CrontabEntry]:
        crontab_path = self._crontab_directory / str(account.username)
        try:
            content = crontab_path.read_text(errors="ignore")
        except OSError:
            return []

        entries: list[CrontabEntry] = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _ENV_ASSIGNMENT_PATTERN.match(stripped):
                continue
            fields = stripped.split(maxsplit=_SCHEDULE_FIELD_COUNT)
            if len(fields) <= _SCHEDULE_FIELD_COUNT:
                continue
            schedule_raw = " ".join(fields[:_SCHEDULE_FIELD_COUNT])
            command = fields[_SCHEDULE_FIELD_COUNT]
            entries.append(CrontabEntry(schedule_raw=schedule_raw, command=command))
        return entries
