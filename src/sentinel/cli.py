from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import shutil
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID

import httpx
import structlog
import typer
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.application.heuristics.use_cases import (
    QuarantineArchiveFindingsUseCase,
    QuarantineAttempt,
    ScanArchiveUseCase,
)
from sentinel.application.integrity.use_cases import RestoreFindingUseCase
from sentinel.application.observability.queries import GetSystemStatusQuery, SystemStatus
from sentinel.application.wordpress.integrity.checksum_use_cases import VerifyCoreChecksumsUseCase
from sentinel.application.wordpress.inventory.queries import GetWordPressInventoryQuery
from sentinel.config import Settings, get_settings
from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.heuristics.value_objects import HeuristicMatch
from sentinel.domain.integrity.entities import IntegrityFinding
from sentinel.domain.integrity.value_objects import RemediationState
from sentinel.domain.observability.entities import JobHeartbeat
from sentinel.domain.observability.value_objects import JobHeartbeatStatus
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import (
    EntityNotFoundError,
    FileRemediationError,
    InvariantViolationError,
)
from sentinel.domain.shared.value_objects import Severity
from sentinel.infrastructure.filesystem import _quarantine_ops
from sentinel.infrastructure.filesystem.file_remediator import FilesystemFileRemediator
from sentinel.infrastructure.filesystem.local_file_remediator import LocalFileRemediator
from sentinel.infrastructure.heuristics.php_malware_scanner import PhpMalwareScanner
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models import AdminUserModel, ApiKeyModel
from sentinel.infrastructure.persistence.repositories.discovery import (
    SqlAlchemyCpanelAccountRepository,
    SqlAlchemyWordPressInstallationRepository,
)
from sentinel.infrastructure.persistence.repositories.events import SqlAlchemyEventRepository
from sentinel.infrastructure.persistence.repositories.forensics import (
    SqlAlchemyTempFileObservationRepository,
)
from sentinel.infrastructure.persistence.repositories.integrity import (
    SqlAlchemyFileBaselineRepository,
    SqlAlchemyIntegrityFindingRepository,
    SqlAlchemyRemediationActionRepository,
)
from sentinel.infrastructure.persistence.repositories.observability import (
    SqlAlchemyJobHeartbeatRepository,
)
from sentinel.infrastructure.persistence.repositories.wordpress_integrity import (
    SqlAlchemyCoreChecksumRepository,
)
from sentinel.infrastructure.security.passwords import hash_password
from sentinel.infrastructure.validation import (
    CheckResult,
    check_database_connectivity,
    has_failures,
    run_all_checks,
)
from sentinel.infrastructure.wordpress.core_checksums import WordPressOrgChecksumsClient
from sentinel.infrastructure.wordpress.forensic_scanner import WordPressForensicScanner

_JOB_INTERVAL_MINUTES: dict[str, Callable[[Settings], int]] = {
    "discovery": lambda s: s.discovery_scan_interval_minutes,
    "integrity": lambda s: s.integrity_scan_interval_minutes,
    "inventory": lambda s: s.inventory_scan_interval_minutes,
    "configuration": lambda s: s.monitoring_scan_interval_minutes,
    "temp_file_scan": lambda s: s.forensics_scan_interval_minutes,
    "correlation": lambda s: s.correlation_interval_minutes,
    "wordpress_inventory": lambda s: s.wordpress_inventory_scan_interval_minutes,
    "wordpress_integrity_audit": lambda s: s.wordpress_integrity_audit_interval_minutes,
    "wordpress_forensic_scan": lambda s: s.wordpress_forensic_scan_interval_minutes,
    "auto_quarantine": lambda s: s.auto_quarantine_interval_minutes,
}

app = typer.Typer(help="Kloud101 AI Sentinel command-line tools.")


class _StderrLogger:
    """Minimal structlog-compatible logger that looks up ``sys.stderr``
    fresh on every call rather than caching a reference to it.

    structlog's own ``PrintLogger`` only re-resolves *stdout* dynamically
    (it special-cases ``file=None`` and lets the builtin ``print()`` pick up
    the live ``sys.stdout``); a ``file=sys.stderr`` reference is stored and
    reused as-is. That's fine for a real, single long-lived process, but
    it's a trap under test: tools like Typer's ``CliRunner`` temporarily
    swap and then close ``sys.stderr`` around each invocation, and
    structlog's global config — plus ``cache_logger_on_first_use`` — is
    process-wide, so a later, unrelated test's first log call can end up
    writing to an already-closed stream. Always looking ``sys.stderr`` up
    at print-time sidesteps that entirely.
    """

    def msg(self, message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    log = debug = info = warning = msg
    fatal = failure = err = error = critical = exception = msg


class _StderrLoggerFactory:
    def __call__(self, *args: object) -> _StderrLogger:
        return _StderrLogger()


def _configure_cli_logging() -> None:
    """Routes structlog output to stderr, at WARNING and above only.

    The server (``bootstrap.configure_logging``) deliberately writes JSON
    logs to stdout, since a container's stdout *is* its log stream there.
    A CLI's stdout contract is different — it's the command's actual
    output (a human-readable report or, with ``--json``, a single JSON
    document a script might parse), so routine INFO-level operational logs
    like "file_quarantined" must not land on the same stream, or they'd
    corrupt that output.
    """
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
        context_class=dict,
        logger_factory=_StderrLoggerFactory(),
        cache_logger_on_first_use=True,
    )


@app.callback()
def _callback() -> None:
    """Kloud101 AI Sentinel command-line tools.

    Registering this no-op callback keeps ``scan-archive`` addressable as an
    explicit subcommand — without it, Typer collapses a single-command app
    so the subcommand name can be omitted, which would silently break as
    soon as a second command (e.g. offline database scanning) is added.
    """
    _configure_cli_logging()


@app.command()
def scan_archive(
    path: Annotated[
        Path, typer.Argument(help="Directory to scan, e.g. an extracted WordPress backup.")
    ],
    quarantine_dir: Annotated[
        Path | None,
        typer.Option(
            "--quarantine-dir",
            help=(
                "Where quarantined files are moved. Defaults to a sibling directory "
                "next to <path>, never inside it — otherwise a rescan would walk into "
                "the quarantine folder and re-flag the files it just moved out."
            ),
        ),
    ] = None,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            help="Minimum severity to report/quarantine: CRITICAL, HIGH, MEDIUM, LOW, INFO.",
        ),
    ] = "LOW",
    apply_quarantine: Annotated[
        bool,
        typer.Option(
            "--apply-quarantine",
            help="Move qualifying files into quarantine. Without this flag, only a report is printed.",
        ),
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print findings as JSON instead of a table.")
    ] = False,
) -> None:
    """Scan a local directory for malware/backdoor indicators.

    Works entirely offline against a downloaded WordPress backup: no
    server, database, or prior baseline is required, unlike the on-host
    agent's integrity monitoring.
    """
    root = path.resolve()
    if not root.is_dir():
        typer.echo(f"Not a directory: {root}", err=True)
        raise typer.Exit(code=1)

    try:
        threshold = Severity(min_severity.upper())
    except ValueError:
        typer.echo(f"Invalid --min-severity: {min_severity!r}", err=True)
        raise typer.Exit(code=1) from None

    result = asyncio.run(ScanArchiveUseCase(scanner=PhpMalwareScanner()).execute(root))
    findings = [match for match in result.findings if match.severity.rank >= threshold.rank]

    if apply_quarantine and get_settings().mode == "observe":
        typer.echo(
            "SENTINEL_MODE=observe: ignoring --apply-quarantine, printing findings only.",
            err=True,
        )
        apply_quarantine = False

    quarantine_root: Path | None = None
    attempts: list[QuarantineAttempt] = []
    if apply_quarantine:
        quarantine_root = (
            quarantine_dir.resolve()
            if quarantine_dir
            else root.parent / f"{root.name}.sentinel-quarantine"
        )
        remediator = LocalFileRemediator(root_directory=root, quarantine_directory=quarantine_root)
        attempts = asyncio.run(
            QuarantineArchiveFindingsUseCase(remediator=remediator).execute(
                findings, min_severity=threshold
            )
        )

    # Everything above only computes results — printing happens once, here,
    # so `--json` always emits a single well-formed JSON document on stdout
    # even when combined with `--apply-quarantine`.
    if json_output:
        _print_json(root, findings, quarantine_root=quarantine_root, attempts=attempts)
    else:
        _print_report(root, findings, threshold=threshold)
        if quarantine_root is not None:
            _print_quarantine_results(quarantine_root, attempts)
        elif findings:
            typer.echo("Run again with --apply-quarantine to move these files out of place.")


def _print_json(
    root: Path,
    findings: list[HeuristicMatch],
    *,
    quarantine_root: Path | None,
    attempts: list[QuarantineAttempt],
) -> None:
    payload: dict[str, object] = {
        "root": str(root),
        "affected_files": len({str(match.relative_path) for match in findings}),
        "findings": [
            {
                "relative_path": str(match.relative_path),
                "rule_id": match.rule_id,
                "description": match.description,
                "severity": match.severity.value,
                "line_number": match.line_number,
                "snippet": match.snippet,
            }
            for match in findings
        ],
    }
    if quarantine_root is not None:
        payload["quarantine_directory"] = str(quarantine_root)
        payload["quarantine_attempts"] = [
            {
                "relative_path": attempt.relative_path,
                "succeeded": attempt.succeeded,
                "detail": attempt.detail,
            }
            for attempt in attempts
        ]
    typer.echo(json.dumps(payload, indent=2))


def _print_report(root: Path, findings: list[HeuristicMatch], *, threshold: Severity) -> None:
    if not findings:
        typer.echo(f"No findings at or above {threshold.value} in {root}.")
        return

    affected_files = len({str(match.relative_path) for match in findings})
    typer.echo(f"{len(findings)} finding(s) across {affected_files} file(s) in {root}:\n")
    for match in findings:
        location = str(match.relative_path)
        if match.line_number is not None:
            location += f":{match.line_number}"
        typer.echo(f"[{match.severity.value}] {location} — {match.rule_id}")
        typer.echo(f"    {match.description}")
        typer.echo(f"    {match.snippet}\n")


def _print_quarantine_results(quarantine_root: Path, attempts: list[QuarantineAttempt]) -> None:
    typer.echo(f"\nQuarantine results ({quarantine_root}):")
    for attempt in attempts:
        if attempt.succeeded:
            typer.echo(f"  moved {attempt.relative_path} -> {attempt.detail}")
        else:
            typer.echo(f"  FAILED {attempt.relative_path}: {attempt.detail}")

    typer.echo(
        "\nReview the quarantined files above. To confirm removal, delete the quarantine "
        "folder; to undo a false positive, move the file back to its original path."
    )


@app.command()
def doctor() -> None:
    """Validate this deployment before trusting it against a live host:
    required/optional host directory mounts, database connectivity, and
    configuration conflicts (e.g. quarantine nested under a scanned path).

    Exits non-zero if any check FAILs, so it can gate a deployment script.
    """
    settings = get_settings()
    results = asyncio.run(run_all_checks(settings))
    _print_check_results(results)
    if has_failures(results):
        raise typer.Exit(code=1)


def _print_check_results(results: list[CheckResult]) -> None:
    for result in results:
        typer.echo(f"[{result.status:<4}] {result.name}: {result.detail}")

    counts = {
        status: sum(1 for r in results if r.status == status) for status in ("PASS", "WARN", "FAIL")
    }
    typer.echo(f"\n{counts['PASS']} passed, {counts['WARN']} warned, {counts['FAIL']} failed")


def _check_api(settings: Settings) -> CheckResult:
    url = f"{settings.api_base_url}/api/v1/health"
    try:
        response = httpx.get(url, timeout=3.0)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        return CheckResult(name="api", status="FAIL", detail=f"unreachable at {url}: {exc}")
    return CheckResult(name="api", status="PASS", detail=f"reachable at {url}")


def _job_freshness(heartbeat: JobHeartbeat | None, interval_minutes: int, *, now: datetime) -> str:
    """OK/STALE uses a 3x-interval grace window, since jobs run on a fixed
    schedule, not continuously — a job merely being between runs is not a
    problem, only one that's stopped running altogether is."""
    if heartbeat is None:
        return "NEVER_RUN"
    if heartbeat.status is JobHeartbeatStatus.FAILURE:
        return "FAILING"
    age_minutes = (now - heartbeat.last_run_at).total_seconds() / 60
    return "STALE" if age_minutes > interval_minutes * 3 else "OK"


async def _gather_system_status(settings: Settings) -> SystemStatus:
    database = Database(settings)
    try:
        async with database.session() as session:
            return await GetSystemStatusQuery(
                heartbeat_repository=SqlAlchemyJobHeartbeatRepository(session),
                event_repository=SqlAlchemyEventRepository(session),
                finding_repository=SqlAlchemyIntegrityFindingRepository(session),
                observation_repository=SqlAlchemyTempFileObservationRepository(session),
            ).execute()
    finally:
        await database.dispose()


@app.command()
def health() -> None:
    """Report API reachability, database connectivity, per-job scheduler
    freshness, and the correlation queue depth — a quick operational check,
    distinct from `doctor`'s deployment-time validation."""
    settings = get_settings()
    api_result = _check_api(settings)
    db_result = asyncio.run(check_database_connectivity(settings))
    status = asyncio.run(_gather_system_status(settings))

    now = utcnow()
    heartbeats_by_job = {heartbeat.job_id: heartbeat for heartbeat in status.heartbeats}

    typer.echo(f"[{api_result.status:<9}] api: {api_result.detail}")
    typer.echo(f"[{db_result.status:<9}] database: {db_result.detail}")
    for job_id, interval_fn in _JOB_INTERVAL_MINUTES.items():
        heartbeat = heartbeats_by_job.get(job_id)
        freshness = _job_freshness(heartbeat, interval_fn(settings), now=now)
        detail = (
            f"last ran {heartbeat.last_run_at.isoformat()} ({heartbeat.status.value})"
            if heartbeat is not None
            else "no heartbeat recorded yet"
        )
        typer.echo(f"[{freshness:<9}] scheduler:{job_id}: {detail}")
    typer.echo(
        f"[{'INFO':<9}] queue: {status.events_unprocessed} unprocessed event(s) "
        "awaiting correlation"
    )


@app.command()
def status() -> None:
    """Report running jobs, event/finding counts, and scan statistics —
    a summary snapshot of what Sentinel has observed on this host."""
    settings = get_settings()
    result = asyncio.run(_gather_system_status(settings))

    typer.echo("Scheduled jobs:")
    for heartbeat in sorted(result.heartbeats, key=lambda h: h.job_id):
        typer.echo(
            f"  {heartbeat.job_id}: {heartbeat.status.value}, "
            f"last ran {heartbeat.last_run_at.isoformat()}, "
            f"took {heartbeat.last_duration_ms:.1f}ms"
            + (f", error={heartbeat.last_error}" if heartbeat.last_error else "")
        )
    if not result.heartbeats:
        typer.echo("  (no jobs have run yet)")

    typer.echo("\nEvent log:")
    typer.echo(f"  {result.events_total} total, {result.events_unprocessed} unprocessed")

    typer.echo("\nFindings generated:")
    typer.echo(f"  {result.integrity_findings_total} integrity finding(s)")
    typer.echo(
        f"  {result.temp_files_malicious} malicious / "
        f"{result.temp_files_suspicious} suspicious temp file observation(s)"
    )


async def _create_api_key(settings: Settings, *, name: str, raw_key: str) -> None:
    database = Database(settings)
    try:
        async with database.session() as session:
            session.add(
                ApiKeyModel(
                    name=name,
                    key_hash=hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
                    key_prefix=raw_key[:8],
                    is_active=True,
                    created_at=utcnow(),
                )
            )
            await session.commit()
    finally:
        await database.dispose()


@app.command(name="create-api-key")
def create_api_key(
    name: Annotated[
        str, typer.Option("--name", help="Human-readable label for this key.")
    ] = "cli-generated",
) -> None:
    """Generate a new API key and store only its SHA-256 hash. The plaintext
    value is printed exactly once here — it cannot be recovered afterward,
    since only the hash is ever persisted."""
    settings = get_settings()
    raw_key = secrets.token_urlsafe(32)
    asyncio.run(_create_api_key(settings, name=name, raw_key=raw_key))

    typer.echo(f"API key created: {name!r}\n")
    typer.echo(raw_key)
    typer.echo("\nSave this now — it will not be shown again.")


async def _create_admin_user(settings: Settings, *, username: str, password: str) -> None:
    database = Database(settings)
    try:
        async with database.session() as session:
            session.add(
                AdminUserModel(
                    username=username,
                    password_hash=hash_password(password),
                    is_active=True,
                    created_at=utcnow(),
                )
            )
            await session.commit()
    finally:
        await database.dispose()


@app.command(name="create-admin-user")
def create_admin_user(
    username: Annotated[
        str, typer.Option("--username", help="Login username for the web dashboard.")
    ],
) -> None:
    """Create a dashboard login. Prompts for a password (not echoed to the
    terminal, confirmed twice) — only its bcrypt hash is ever persisted,
    same "store only a hash" principle as `create-api-key`."""
    settings = get_settings()
    password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    if len(password) < 12:
        typer.echo("Error: password must be at least 12 characters.", err=True)
        raise typer.Exit(code=1)
    asyncio.run(_create_admin_user(settings, username=username, password=password))
    typer.echo(f"Admin user created: {username!r}")


wp_app = typer.Typer(help="WordPress Security Engine commands.")
app.add_typer(wp_app, name="wp")


async def _resolve_installations(
    repository: SqlAlchemyWordPressInstallationRepository, installation_id: str | None
) -> list[WordPressInstallation]:
    if installation_id is not None:
        installation = await repository.get(UUID(installation_id))
        return [installation] if installation is not None else []
    return [
        installation
        for installation in await repository.list(limit=10_000)
        if installation.is_active
    ]


_INSTALLATION_ID_OPTION = typer.Option(
    "--installation-id", help="Limit to one installation (UUID). Defaults to every active one."
)


async def _run_wp_inventory(settings: Settings, installation_id: str | None) -> None:
    database = Database(settings)
    try:
        async with database.session() as session:
            installations_repo = SqlAlchemyWordPressInstallationRepository(session)
            query = GetWordPressInventoryQuery(
                installation_repository=installations_repo,
                baseline_repository=SqlAlchemyFileBaselineRepository(session),
                dropin_relative_paths=settings.wordpress_dropin_relative_paths,
            )
            for installation in await _resolve_installations(installations_repo, installation_id):
                report = await query.execute(installation.id)
                typer.echo(f"Installation {installation.id} ({installation.absolute_path})")
                typer.echo(f"  wp_version={report.wp_version} php_version={report.php_version}")
                for drop_in in report.drop_ins:
                    presence = "PRESENT" if drop_in.is_present else "absent"
                    typer.echo(f"  drop-in {drop_in.relative_path}: {presence}")
                if report.must_use_plugins:
                    typer.echo(f"  mu-plugins: {', '.join(report.must_use_plugins)}")
                typer.echo("")
    finally:
        await database.dispose()


@wp_app.command(name="inventory")
def wp_inventory(
    installation_id: Annotated[str | None, _INSTALLATION_ID_OPTION] = None,
) -> None:
    """Report WordPress version, PHP version, drop-ins, and must-use
    plugins for one or every discovered installation."""
    settings = get_settings()
    asyncio.run(_run_wp_inventory(settings, installation_id))


async def _run_wp_integrity(settings: Settings, installation_id: str | None) -> None:
    database = Database(settings)
    try:
        async with database.session() as session:
            installations_repo = SqlAlchemyWordPressInstallationRepository(session)
            use_case = VerifyCoreChecksumsUseCase(
                installation_repository=installations_repo,
                baseline_repository=SqlAlchemyFileBaselineRepository(session),
                checksum_repository=SqlAlchemyCoreChecksumRepository(session),
                checksums_client=WordPressOrgChecksumsClient(
                    base_url=settings.wordpress_core_checksums_api_base_url,
                    locale=settings.wordpress_core_checksums_locale,
                ),
                critical_relative_paths=settings.wordpress_critical_relative_paths,
            )
            for installation in await _resolve_installations(installations_repo, installation_id):
                typer.echo(f"Installation {installation.id} ({installation.absolute_path})")
                for verification in await use_case.execute(installation.id):
                    typer.echo(f"  [{verification.status:<11}] {verification.relative_path}")
                typer.echo("")
            await session.commit()
    finally:
        await database.dispose()


@wp_app.command(name="integrity")
def wp_integrity(
    installation_id: Annotated[str | None, _INSTALLATION_ID_OPTION] = None,
) -> None:
    """Compare critical WordPress files against WordPress.org's official
    per-release checksums (cached locally after the first check per
    version) — a stronger signal than baseline hash-diffing alone."""
    settings = get_settings()
    asyncio.run(_run_wp_integrity(settings, installation_id))


async def _run_wp_audit(settings: Settings, installation_id: str | None) -> int:
    database = Database(settings)
    try:
        async with database.session() as session:
            installations_repo = SqlAlchemyWordPressInstallationRepository(session)
            scanner = WordPressForensicScanner(
                php_malware_scanner=PhpMalwareScanner(),
                dropin_relative_paths=settings.wordpress_dropin_relative_paths,
            )
            total_findings = 0
            for installation in await _resolve_installations(installations_repo, installation_id):
                typer.echo(f"Installation {installation.id} ({installation.absolute_path})")
                findings = await scanner.scan(installation)
                if not findings:
                    typer.echo("  No findings.")
                for finding in findings:
                    typer.echo(
                        f"  [{finding.severity.value}] {finding.finding_type}: "
                        f"{finding.relative_path} — {finding.description}"
                    )
                total_findings += len(findings)
                typer.echo("")
            return 1 if total_findings else 0
    finally:
        await database.dispose()


@wp_app.command(name="audit")
def wp_audit(
    installation_id: Annotated[str | None, _INSTALLATION_ID_OPTION] = None,
) -> None:
    """Run the WordPress forensic sweep on demand instead of waiting for
    the schedule: fake plugins/themes, must-use plugins, hidden PHP under
    wp-content/uploads, and malicious drop-ins. Read-only — this does not
    persist findings as events the way the scheduled job does; use it for
    immediate inspection during an active incident."""
    settings = get_settings()
    exit_code = asyncio.run(_run_wp_audit(settings, installation_id))
    if exit_code:
        raise typer.Exit(code=exit_code)


quarantine_app = typer.Typer(help="Inspect and manage quarantined files.")
app.add_typer(quarantine_app, name="quarantine")


def _read_quarantine_metadata(quarantine_path: str | None) -> dict[str, object] | None:
    if quarantine_path is None:
        return None
    try:
        return _quarantine_ops.read_metadata(quarantine_path)
    except FileRemediationError:
        return None


async def _load_finding_or_raise(session: AsyncSession, finding_id: UUID) -> IntegrityFinding:
    finding = await SqlAlchemyIntegrityFindingRepository(session).get(finding_id)
    if finding is None:
        raise EntityNotFoundError("IntegrityFinding", finding_id)
    return finding


async def _run_quarantine_list(settings: Settings) -> list[IntegrityFinding]:
    database = Database(settings)
    try:
        async with database.session() as session:
            return await SqlAlchemyIntegrityFindingRepository(session).list_by_remediation_state(
                RemediationState.QUARANTINED, limit=500
            )
    finally:
        await database.dispose()


@quarantine_app.command(name="list")
def quarantine_list() -> None:
    """List every currently quarantined file: ID | FILE | THREAT | SCORE | DATE."""
    settings = get_settings()
    findings = asyncio.run(_run_quarantine_list(settings))

    if not findings:
        typer.echo("No quarantined files.")
        return

    typer.echo(f"{'ID':<36}  {'FILE':<40}  {'THREAT':<28}  {'SCORE':<5}  DATE")
    for finding in findings:
        metadata = _read_quarantine_metadata(finding.quarantine_path)
        threat = (
            str(metadata["detection_reason"])
            if metadata is not None
            else f"{finding.change_type.value} change"
        )
        score = _quarantine_ops.malware_score(finding.severity)
        typer.echo(
            f"{finding.id}  {str(finding.relative_path)[:40]:<40}  {threat[:28]:<28}  "
            f"{score:<5}  {finding.detected_at.isoformat()}"
        )


async def _run_quarantine_view(settings: Settings, finding_id: UUID) -> IntegrityFinding:
    database = Database(settings)
    try:
        async with database.session() as session:
            return await _load_finding_or_raise(session, finding_id)
    finally:
        await database.dispose()


@quarantine_app.command(name="view")
def quarantine_view(
    finding_id: Annotated[str, typer.Argument(help="Quarantine record ID (the finding UUID).")],
) -> None:
    """Show full metadata for one quarantined file."""
    settings = get_settings()
    try:
        finding = asyncio.run(_run_quarantine_view(settings, UUID(finding_id)))
    except EntityNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None

    typer.echo(f"ID:                {finding.id}")
    typer.echo(f"Account:           {finding.account_id}")
    typer.echo(f"Path:              {finding.relative_path}")
    typer.echo(f"Change type:       {finding.change_type.value}")
    typer.echo(f"Severity:          {finding.severity.value}")
    typer.echo(f"Malware score:     {_quarantine_ops.malware_score(finding.severity)}")
    typer.echo(f"Remediation state: {finding.remediation_state.value}")
    typer.echo(f"Detected at:       {finding.detected_at.isoformat()}")

    if finding.quarantine_path is None:
        typer.echo("\nNot currently quarantined.")
        return

    typer.echo(f"Quarantine folder: {finding.quarantine_path}")
    metadata = _read_quarantine_metadata(finding.quarantine_path)
    if metadata is None:
        typer.echo("Quarantine metadata unavailable (folder missing or unreadable).", err=True)
        raise typer.Exit(code=1)

    typer.echo("\nQuarantine metadata:")
    for key, value in metadata.items():
        typer.echo(f"  {key}: {value}")


async def _run_quarantine_inspect(settings: Settings, finding_id: UUID) -> Path:
    database = Database(settings)
    try:
        async with database.session() as session:
            finding = await _load_finding_or_raise(session, finding_id)
    finally:
        await database.dispose()

    if finding.quarantine_path is None:
        raise InvariantViolationError(f"Finding {finding_id} is not currently quarantined")

    source = _quarantine_ops.quarantined_file_path(finding.quarantine_path)
    inspect_dir = Path(tempfile.mkdtemp(prefix="sentinel-inspect-"))
    safe_copy = inspect_dir / source.name
    shutil.copyfile(source, safe_copy)
    safe_copy.chmod(0o400)
    return safe_copy


@quarantine_app.command(name="inspect")
def quarantine_inspect(
    finding_id: Annotated[str, typer.Argument(help="Quarantine record ID (the finding UUID).")],
) -> None:
    """Extract a safe, read-only, non-executable copy of a quarantined file
    for manual review. Never opens or executes the file itself — the copy
    is chmod 400 and left for the operator to inspect with their own
    editor or pager."""
    settings = get_settings()
    try:
        safe_copy = asyncio.run(_run_quarantine_inspect(settings, UUID(finding_id)))
    except (EntityNotFoundError, InvariantViolationError, FileRemediationError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None

    typer.echo(f"Safe copy extracted to: {safe_copy}")
    typer.echo("(read-only, mode 400, not executable — review with your own editor/pager)")

    preview = safe_copy.read_text(errors="replace")
    if preview:
        lines = preview.splitlines()[:40]
        typer.echo("\n--- preview (first 40 line(s)) ---")
        typer.echo("\n".join(lines))


async def _run_restore(settings: Settings, finding_id: UUID) -> IntegrityFinding:
    database = Database(settings)
    try:
        async with database.session() as session:
            use_case = RestoreFindingUseCase(
                finding_repository=SqlAlchemyIntegrityFindingRepository(session),
                account_repository=SqlAlchemyCpanelAccountRepository(session),
                baseline_repository=SqlAlchemyFileBaselineRepository(session),
                action_repository=SqlAlchemyRemediationActionRepository(session),
                remediator=FilesystemFileRemediator(
                    quarantine_root_directory=settings.quarantine_root_directory
                ),
            )
            finding = await use_case.execute(finding_id)
            await session.commit()
            return finding
    finally:
        await database.dispose()


@app.command()
def restore(
    finding_id: Annotated[
        str, typer.Argument(help="Quarantine record ID to restore (the finding UUID).")
    ],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt.")] = False,
) -> None:
    """Restore a quarantined file to its original location and ownership,
    after confirmation. Refused when SENTINEL_MODE=observe, since restoring
    is a mutation like any other."""
    settings = get_settings()
    if settings.mode == "observe":
        typer.echo("SENTINEL_MODE=observe: restore is a mutation and is refused.", err=True)
        raise typer.Exit(code=1)

    if not yes and not typer.confirm(
        f"Restore quarantined finding {finding_id} to its original path?"
    ):
        typer.echo("Aborted.")
        raise typer.Exit(code=1)

    try:
        finding = asyncio.run(_run_restore(settings, UUID(finding_id)))
    except (EntityNotFoundError, InvariantViolationError, FileRemediationError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None

    typer.echo(f"Restored {finding.relative_path} for account {finding.account_id}.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
