from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sqlalchemy import text

from sentinel.config import Settings
from sentinel.infrastructure.persistence.database import Database

CheckStatus = Literal["PASS", "WARN", "FAIL"]


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: CheckStatus
    detail: str


def check_directory_readable(name: str, path: str, *, required: bool) -> CheckResult:
    directory = Path(path)
    fail_status: CheckStatus = "FAIL" if required else "WARN"
    if not directory.is_dir():
        return CheckResult(name=name, status=fail_status, detail=f"{path} is not a directory")
    if not os.access(directory, os.R_OK):
        return CheckResult(name=name, status=fail_status, detail=f"{path} is not readable")
    return CheckResult(name=name, status="PASS", detail=f"{path} is readable")


def check_directory_writable(name: str, path: str) -> CheckResult:
    directory = Path(path)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return CheckResult(name=name, status="FAIL", detail=f"cannot create {path}: {exc}")
    if not os.access(directory, os.W_OK):
        return CheckResult(name=name, status="FAIL", detail=f"{path} is not writable")
    return CheckResult(name=name, status="PASS", detail=f"{path} is writable")


def check_configuration(settings: Settings) -> CheckResult:
    """Catches the one config mistake that would silently defeat quarantine:
    a quarantine directory nested inside a directory Sentinel scans. A
    quarantined file would then be walked right back into by the next scan
    that reaches its new location.
    """
    quarantine = Path(settings.quarantine_root_directory).resolve()
    scanned_directories = [
        settings.cpanel_home_base_directory,
        *settings.forensics_temp_directories,
    ]
    for candidate in scanned_directories:
        candidate_path = Path(candidate).resolve()
        if quarantine == candidate_path or candidate_path in quarantine.parents:
            return CheckResult(
                name="configuration",
                status="FAIL",
                detail=(
                    f"quarantine_root_directory ({quarantine}) is nested under a scanned "
                    f"directory ({candidate_path})"
                ),
            )
    return CheckResult(name="configuration", status="PASS", detail="no conflicting paths")


def check_whm_plugin_registration() -> CheckResult | None:
    """Best-effort only: on a non-WHM host (no /usr/local/cpanel) this
    check doesn't apply at all and is skipped entirely, rather than
    WARNing on every dev machine and generic AlmaLinux install. On a WHM
    host, this catches the plugin having been silently unregistered
    (e.g. an AppConfig entry removed by hand) without blocking startup —
    the internal-only API/worker are fully functional either way; only the
    WHM UI would be unreachable.
    """
    if not Path("/usr/local/cpanel").is_dir():
        return None

    conf_path = Path("/var/cpanel/apps/kloudsentinel.conf")
    cgi_path = Path("/usr/local/cpanel/whostmgr/docroot/cgi/kloudsentinel/index.cgi")
    if not conf_path.is_file():
        return CheckResult(
            name="whm_plugin",
            status="WARN",
            detail=f"{conf_path} is missing — WHM plugin is not registered (re-run install.sh)",
        )
    if not cgi_path.is_file():
        return CheckResult(
            name="whm_plugin",
            status="WARN",
            detail=f"{cgi_path} is missing — WHM plugin CGI script not installed (re-run install.sh)",
        )
    return CheckResult(name="whm_plugin", status="PASS", detail="registered")


async def check_database_connectivity(settings: Settings) -> CheckResult:
    database = Database(settings)
    try:
        async with database.session() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        return CheckResult(name="database", status="FAIL", detail=str(exc))
    finally:
        await database.dispose()
    return CheckResult(name="database", status="PASS", detail="connected")


def host_directory_checks(settings: Settings) -> list[CheckResult]:
    """Required checks gate startup (etc/home are read unconditionally by
    discovery); everything else is best-effort readiness for capabilities
    that either degrade gracefully (temp-file forensics skips a missing
    directory) or aren't wired to any current use case yet (proc/var_log/
    cpanel_binaries, reserved for future contexts) — so those WARN instead
    of blocking the whole process over an optional mount.
    """
    required = [
        ("etc", settings.cpanel_etc_directory),
        ("home", settings.cpanel_home_base_directory),
    ]
    optional = [
        ("proc", settings.proc_directory),
        ("var_log", settings.var_log_directory),
        ("cpanel_binaries", settings.cpanel_binaries_directory),
        *[(f"temp_dir:{path}", path) for path in settings.forensics_temp_directories],
    ]
    return [check_directory_readable(name, path, required=True) for name, path in required] + [
        check_directory_readable(name, path, required=False) for name, path in optional
    ]


async def run_all_checks(settings: Settings) -> list[CheckResult]:
    results = host_directory_checks(settings)
    results.append(
        check_directory_writable("quarantine_root_directory", settings.quarantine_root_directory)
    )
    results.append(check_configuration(settings))
    results.append(await check_database_connectivity(settings))
    whm_plugin_result = check_whm_plugin_registration()
    if whm_plugin_result is not None:
        results.append(whm_plugin_result)
    return results


def has_failures(results: list[CheckResult]) -> bool:
    return any(result.status == "FAIL" for result in results)


# Checks whose failure genuinely blocks the API/worker from doing anything
# useful (no accounts can be discovered without etc/home, no persistence
# without a database, and a misconfigured quarantine would corrupt scans).
# Everything else (proc/var_log/cpanel_binaries, individual temp
# directories, quarantine writability) only ever WARNs and never aborts
# startup — those capabilities either aren't wired to anything yet or
# degrade gracefully on their own.
CRITICAL_CHECK_NAMES = frozenset({"etc", "home", "database", "configuration"})


def has_critical_failures(results: list[CheckResult]) -> bool:
    return any(
        result.status == "FAIL" and result.name in CRITICAL_CHECK_NAMES for result in results
    )
