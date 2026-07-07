from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

import structlog

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.ports import CpanelAccountRepository
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.events.ports import SecurityEventRepository
from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding, RemediationAction
from sentinel.domain.integrity.ports import (
    FileBaselineRepository,
    FileRemediator,
    FileScanner,
    IntegrityFindingRepository,
    RemediationActionRepository,
)
from sentinel.domain.integrity.value_objects import (
    ChangeType,
    RemediationActionType,
    RemediationOutcome,
)
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import (
    EntityNotFoundError,
    FileRemediationError,
    InvariantViolationError,
)
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity, Sha256Hash
from sentinel.infrastructure.mime import guess_mime_type

logger = structlog.get_logger()

_SEVERITY_BY_CHANGE: dict[ChangeType, Severity] = {
    ChangeType.ADDED: Severity.MEDIUM,
    ChangeType.MODIFIED: Severity.HIGH,
    ChangeType.DELETED: Severity.HIGH,
    ChangeType.PERMISSIONS_CHANGED: Severity.MEDIUM,
}

#: Recorded on every ``SecurityEvent`` this use case raises. Not a rule-set
#: version like ``PhpMalwareScanner.VERSION`` — integrity scanning is a
#: hash-diff against a baseline, not a signature engine — but still worth
#: tagging so a future change to the diffing algorithm is visible in
#: forensic history.
_SCANNER_VERSION = "integrity-hash-diff@1"


@dataclass(frozen=True)
class IntegrityScanResult:
    accounts_scanned: int
    baselines_established: int
    findings_created: int
    baselines_removed: int


class RunIntegrityScanUseCase:
    """Orchestrates one full integrity scan: for every active cPanel
    account, hash its home directory and reconcile the result against the
    account's persisted ``FileBaseline`` rows.

    An account with no existing baselines at all is treated as a first run:
    every file found establishes a baseline silently, with no findings
    raised. Flagging an entire fresh account's worth of files as "added" the
    first time it's ever scanned would be pure noise, not a signal.
    """

    def __init__(
        self,
        *,
        account_repository: CpanelAccountRepository,
        baseline_repository: FileBaselineRepository,
        finding_repository: IntegrityFindingRepository,
        event_repository: SecurityEventRepository,
        scanner: FileScanner,
    ) -> None:
        self._accounts = account_repository
        self._baselines = baseline_repository
        self._findings = finding_repository
        self._events = event_repository
        self._scanner = scanner

    async def execute(self) -> IntegrityScanResult:
        now = utcnow()
        accounts_scanned = 0
        baselines_established = 0
        findings_created = 0
        baselines_removed = 0

        for account in await self._accounts.list(limit=10_000):
            if not account.is_active:
                continue
            accounts_scanned += 1
            established, created, removed = await self._scan_account(account, at=now)
            baselines_established += established
            findings_created += created
            baselines_removed += removed

        logger.info(
            "integrity_scan_completed",
            accounts_scanned=accounts_scanned,
            baselines_established=baselines_established,
            findings_created=findings_created,
            baselines_removed=baselines_removed,
        )

        return IntegrityScanResult(
            accounts_scanned=accounts_scanned,
            baselines_established=baselines_established,
            findings_created=findings_created,
            baselines_removed=baselines_removed,
        )

    async def _scan_account(self, account: CpanelAccount, *, at: datetime) -> tuple[int, int, int]:
        scanned_files = await self._scanner.scan(account)
        existing_baselines = await self._baselines.list_by_account(account.id)
        is_first_scan = len(existing_baselines) == 0
        baselines_by_path = {str(b.relative_path): b for b in existing_baselines}

        baselines_established = 0
        findings_created = 0
        baselines_removed = 0
        seen_paths: set[str] = set()

        for scanned in scanned_files:
            path_key = str(scanned.relative_path)
            seen_paths.add(path_key)
            baseline = baselines_by_path.get(path_key)

            if baseline is None:
                await self._baselines.add(
                    FileBaseline(
                        account_id=account.id,
                        relative_path=scanned.relative_path,
                        sha256=scanned.sha256,
                        size_bytes=scanned.size_bytes,
                        mode=scanned.mode,
                        last_verified_at=at,
                    )
                )
                baselines_established += 1
                if not is_first_scan:
                    await self._raise_finding(
                        account,
                        scanned.relative_path,
                        change_type=ChangeType.ADDED,
                        previous_sha256=None,
                        current_sha256=scanned.sha256,
                        size_bytes=scanned.size_bytes,
                        mode=scanned.mode,
                        at=at,
                    )
                    findings_created += 1
                continue

            if not baseline.is_active:
                baseline.reactivate(
                    sha256=scanned.sha256, size_bytes=scanned.size_bytes, mode=scanned.mode, at=at
                )
                await self._baselines.save(baseline)
                baselines_established += 1
                await self._raise_finding(
                    account,
                    scanned.relative_path,
                    change_type=ChangeType.ADDED,
                    previous_sha256=None,
                    current_sha256=scanned.sha256,
                    size_bytes=scanned.size_bytes,
                    mode=scanned.mode,
                    at=at,
                )
                findings_created += 1
                continue

            if baseline.sha256 != scanned.sha256:
                previous_sha256 = baseline.sha256
                baseline.update(
                    sha256=scanned.sha256, size_bytes=scanned.size_bytes, mode=scanned.mode, at=at
                )
                await self._baselines.save(baseline)
                await self._raise_finding(
                    account,
                    scanned.relative_path,
                    change_type=ChangeType.MODIFIED,
                    previous_sha256=previous_sha256,
                    current_sha256=scanned.sha256,
                    size_bytes=scanned.size_bytes,
                    mode=scanned.mode,
                    at=at,
                )
                findings_created += 1
            elif baseline.mode != scanned.mode:
                baseline.update(
                    sha256=scanned.sha256, size_bytes=scanned.size_bytes, mode=scanned.mode, at=at
                )
                await self._baselines.save(baseline)
                await self._raise_finding(
                    account,
                    scanned.relative_path,
                    change_type=ChangeType.PERMISSIONS_CHANGED,
                    previous_sha256=baseline.sha256,
                    current_sha256=scanned.sha256,
                    size_bytes=scanned.size_bytes,
                    mode=scanned.mode,
                    at=at,
                )
                findings_created += 1

        for path_key, baseline in baselines_by_path.items():
            if path_key in seen_paths or not baseline.is_active:
                continue
            previous_sha256 = baseline.sha256
            baseline.mark_removed(at=at)
            await self._baselines.save(baseline)
            baselines_removed += 1
            await self._raise_finding(
                account,
                baseline.relative_path,
                change_type=ChangeType.DELETED,
                previous_sha256=previous_sha256,
                current_sha256=None,
                size_bytes=baseline.size_bytes,
                mode=baseline.mode,
                at=at,
            )
            findings_created += 1

        return baselines_established, findings_created, baselines_removed

    async def _raise_finding(
        self,
        account: CpanelAccount,
        relative_path: RelativeFilePath,
        *,
        change_type: ChangeType,
        previous_sha256: Sha256Hash | None,
        current_sha256: Sha256Hash | None,
        size_bytes: int | None,
        mode: str | None,
        at: datetime,
    ) -> None:
        finding = IntegrityFinding(
            account_id=account.id,
            relative_path=relative_path,
            change_type=change_type,
            severity=_SEVERITY_BY_CHANGE[change_type],
            previous_sha256=previous_sha256,
            current_sha256=current_sha256,
            detected_at=at,
        )
        await self._findings.add(finding)

        current_or_previous_sha256 = current_sha256 or previous_sha256
        await self._events.add(
            SecurityEvent(
                event_type=f"integrity_finding_{change_type.value.lower()}",
                source_context="integrity",
                account_id=account.id,
                severity=_SEVERITY_BY_CHANGE[change_type],
                payload={
                    "relative_path": str(relative_path),
                    "sha256": str(current_or_previous_sha256)
                    if current_or_previous_sha256
                    else None,
                    "finding_id": str(finding.id),
                },
                occurred_at=at,
                server_id=account.server_id,
                file_path=str(relative_path),
                sha256=str(current_or_previous_sha256) if current_or_previous_sha256 else None,
                file_size_bytes=size_bytes,
                file_owner=str(account.username),
                file_permissions=mode,
                mime_type=guess_mime_type(str(relative_path)),
                scanner_version=_SCANNER_VERSION,
                detection_rule_id=change_type.value,
            )
        )


async def _load_finding(findings: IntegrityFindingRepository, finding_id: UUID) -> IntegrityFinding:
    finding = await findings.get(finding_id)
    if finding is None:
        logger.warning(
            "remediation_target_not_found", entity="IntegrityFinding", id=str(finding_id)
        )
        raise EntityNotFoundError("IntegrityFinding", finding_id)
    return finding


async def _load_account(accounts: CpanelAccountRepository, account_id: UUID) -> CpanelAccount:
    account = await accounts.get(account_id)
    if account is None:
        logger.warning("remediation_target_not_found", entity="CpanelAccount", id=str(account_id))
        raise EntityNotFoundError("CpanelAccount", account_id)
    return account


def _reject(finding: IntegrityFinding, exc: InvariantViolationError) -> None:
    """Logs a rejected remediation attempt before re-raising.

    No ``RemediationAction`` row is written here — that table is an audit
    trail of filesystem operations that were actually attempted, and a
    state-machine rejection never reaches the filesystem. This log line is
    what gives operators visibility into rejected attempts (e.g. a client
    retrying a stale request) that would otherwise leave no trace beyond an
    HTTP 409 the caller may not be watching.
    """
    logger.warning(
        "remediation_action_rejected",
        finding_id=str(finding.id),
        remediation_state=finding.remediation_state.value,
        reason=str(exc),
    )


async def _record_remediation_action(
    actions: RemediationActionRepository,
    finding: IntegrityFinding,
    *,
    action_type: RemediationActionType,
    outcome: RemediationOutcome,
    detail: str | None,
    at: datetime,
) -> None:
    """Writes the audit-trail row and emits a matching structured log line
    in one place, so every remediation attempt — success or failure — is
    both queryable via the API and visible to whatever's tailing the
    service's logs, without each use case having to remember to do both."""
    await actions.add(
        RemediationAction(
            finding_id=finding.id,
            account_id=finding.account_id,
            relative_path=finding.relative_path,
            action_type=action_type,
            outcome=outcome,
            detail=detail,
            performed_at=at,
        )
    )
    log = logger.info if outcome is RemediationOutcome.SUCCEEDED else logger.warning
    log(
        "remediation_action_recorded",
        finding_id=str(finding.id),
        action_type=action_type.value,
        outcome=outcome.value,
        detail=detail,
    )


class QuarantineFindingUseCase:
    """Moves the file behind an ``IntegrityFinding`` out of the account's
    home directory into quarantine, reversibly. Also marks the finding's
    ``FileBaseline`` row inactive — otherwise the next scheduled
    ``RunIntegrityScanUseCase`` pass would see the path missing from disk and
    raise a second, spurious ``DELETED`` finding for a removal Sentinel
    itself just performed.
    """

    def __init__(
        self,
        *,
        finding_repository: IntegrityFindingRepository,
        account_repository: CpanelAccountRepository,
        baseline_repository: FileBaselineRepository,
        action_repository: RemediationActionRepository,
        remediator: FileRemediator,
    ) -> None:
        self._findings = finding_repository
        self._accounts = account_repository
        self._baselines = baseline_repository
        self._actions = action_repository
        self._remediator = remediator

    async def execute(self, finding_id: UUID, *, triggered_by: str = "manual") -> IntegrityFinding:
        """``triggered_by`` is recorded as a prefix on the resulting
        ``RemediationAction.detail`` (e.g. ``"auto: <path>"`` vs the
        default ``"manual: <path>"``) so the audit trail — and
        ``sentinel quarantine view`` — can tell an operator/API-triggered
        quarantine apart from one ``AutoQuarantineCriticalFindingsUseCase``
        performed unattended, without a schema change."""
        now = utcnow()
        finding = await _load_finding(self._findings, finding_id)
        account = await _load_account(self._accounts, finding.account_id)

        try:
            finding.ensure_can_quarantine()
        except InvariantViolationError as exc:
            _reject(finding, exc)
            raise

        try:
            quarantined = await self._remediator.quarantine(
                account=account,
                relative_path=finding.relative_path,
                detection_reason=f"{finding.change_type.value} file change",
                severity=finding.severity,
                detected_at=finding.detected_at,
            )
        except FileRemediationError as exc:
            await _record_remediation_action(
                self._actions,
                finding,
                action_type=RemediationActionType.QUARANTINE,
                outcome=RemediationOutcome.FAILED,
                detail=f"{triggered_by}: {exc}",
                at=now,
            )
            raise

        finding.quarantine(
            quarantine_path=quarantined.quarantine_path,
            mode=quarantined.mode,
            size_bytes=quarantined.size_bytes,
            owner_uid=quarantined.owner_uid,
            owner_gid=quarantined.owner_gid,
            at=now,
        )
        await self._findings.save(finding)

        baseline = await self._baselines.get_by_account_and_path(
            finding.account_id, finding.relative_path
        )
        if baseline is not None and baseline.is_active:
            baseline.mark_removed(at=now)
            await self._baselines.save(baseline)

        await _record_remediation_action(
            self._actions,
            finding,
            action_type=RemediationActionType.QUARANTINE,
            outcome=RemediationOutcome.SUCCEEDED,
            detail=f"{triggered_by}: {quarantined.quarantine_path}",
            at=now,
        )
        return finding


class RestoreFindingUseCase:
    """Undoes a prior quarantine: moves the quarantined file back to its
    original path with its original mode, and reactivates the ``FileBaseline``
    row using the mode/hash already captured at quarantine time — the
    restored bytes are exactly what was quarantined, so there's no need to
    re-hash the file.
    """

    def __init__(
        self,
        *,
        finding_repository: IntegrityFindingRepository,
        account_repository: CpanelAccountRepository,
        baseline_repository: FileBaselineRepository,
        action_repository: RemediationActionRepository,
        remediator: FileRemediator,
    ) -> None:
        self._findings = finding_repository
        self._accounts = account_repository
        self._baselines = baseline_repository
        self._actions = action_repository
        self._remediator = remediator

    async def execute(self, finding_id: UUID) -> IntegrityFinding:
        now = utcnow()
        finding = await _load_finding(self._findings, finding_id)
        account = await _load_account(self._accounts, finding.account_id)

        try:
            finding.ensure_can_restore()
        except InvariantViolationError as exc:
            _reject(finding, exc)
            raise
        assert finding.quarantine_path is not None
        assert finding.quarantine_mode is not None

        try:
            await self._remediator.restore(
                account=account,
                relative_path=finding.relative_path,
                quarantine_path=finding.quarantine_path,
                mode=finding.quarantine_mode,
                owner_uid=finding.quarantine_owner_uid,
                owner_gid=finding.quarantine_owner_gid,
            )
        except FileRemediationError as exc:
            await _record_remediation_action(
                self._actions,
                finding,
                action_type=RemediationActionType.RESTORE,
                outcome=RemediationOutcome.FAILED,
                detail=str(exc),
                at=now,
            )
            raise

        baseline = await self._baselines.get_by_account_and_path(
            finding.account_id, finding.relative_path
        )
        if baseline is not None and finding.current_sha256 is not None:
            baseline.reactivate(
                sha256=finding.current_sha256,
                size_bytes=finding.quarantine_size_bytes or baseline.size_bytes,
                mode=finding.quarantine_mode,
                at=now,
            )
            await self._baselines.save(baseline)

        finding.restore(at=now)
        await self._findings.save(finding)

        await _record_remediation_action(
            self._actions,
            finding,
            action_type=RemediationActionType.RESTORE,
            outcome=RemediationOutcome.SUCCEEDED,
            detail=None,
            at=now,
        )
        return finding


class DeleteFindingUseCase:
    """Permanently purges an already-quarantined file. The ``FileBaseline``
    row was already marked inactive at quarantine time, so there's nothing
    further to reconcile there — purging only ever operates on a file that's
    already off the live filesystem.
    """

    def __init__(
        self,
        *,
        finding_repository: IntegrityFindingRepository,
        action_repository: RemediationActionRepository,
        remediator: FileRemediator,
    ) -> None:
        self._findings = finding_repository
        self._actions = action_repository
        self._remediator = remediator

    async def execute(self, finding_id: UUID) -> IntegrityFinding:
        now = utcnow()
        finding = await _load_finding(self._findings, finding_id)

        try:
            finding.ensure_can_delete()
        except InvariantViolationError as exc:
            _reject(finding, exc)
            raise
        assert finding.quarantine_path is not None

        try:
            await self._remediator.purge(quarantine_path=finding.quarantine_path)
        except FileRemediationError as exc:
            await _record_remediation_action(
                self._actions,
                finding,
                action_type=RemediationActionType.DELETE,
                outcome=RemediationOutcome.FAILED,
                detail=str(exc),
                at=now,
            )
            raise

        finding.delete(at=now)
        await self._findings.save(finding)

        await _record_remediation_action(
            self._actions,
            finding,
            action_type=RemediationActionType.DELETE,
            outcome=RemediationOutcome.SUCCEEDED,
            detail=None,
            at=now,
        )
        return finding


@dataclass(frozen=True)
class AutoQuarantineResult:
    accounts_examined: int
    findings_quarantined: int
    circuit_breaker_trips: int


class AutoQuarantineCriticalFindingsUseCase:
    """The single choke point deciding when a detection becomes an
    automatic quarantine action. Deliberately narrow: only CRITICAL,
    not-yet-remediated ``IntegrityFinding`` rows qualify — regardless of
    which upstream detector created them (``RunIntegrityScanUseCase`` +
    ``AnalyzeWordPressIntegrityUseCase``'s severity escalation, or
    ``RunWordPressForensicScanUseCase``'s materialized forensic findings)
    — and only when ``mode == "active"``. Reuses ``QuarantineFindingUseCase``
    unchanged for the actual filesystem operation and audit trail; this
    class only decides *whether* and *how many* to call it for, per
    account, per run.

    A circuit breaker caps how many files one account can have
    auto-quarantined in a single run
    (``max_per_account_per_run``). Beyond the cap, the remaining CRITICAL
    findings for that account are left untouched (``remediation_state``
    stays ``NONE``, safe — nothing destructive ever happens by omission)
    and one CRITICAL ``auto_quarantine_circuit_breaker_tripped`` event is
    raised instead of continuing to act unattended — protects against a
    misfiring rule quarantining an entire site's files in one pass.
    """

    def __init__(
        self,
        *,
        finding_repository: IntegrityFindingRepository,
        event_repository: SecurityEventRepository,
        quarantine_use_case: QuarantineFindingUseCase,
        mode: str,
        max_per_account_per_run: int,
        lookback_minutes: int,
    ) -> None:
        self._findings = finding_repository
        self._events = event_repository
        self._quarantine = quarantine_use_case
        self._mode = mode
        self._max_per_account_per_run = max_per_account_per_run
        self._lookback_minutes = lookback_minutes

    async def execute(self) -> AutoQuarantineResult:
        if self._mode != "active":
            logger.info("auto_quarantine_skipped", mode=self._mode)
            return AutoQuarantineResult(
                accounts_examined=0, findings_quarantined=0, circuit_breaker_trips=0
            )

        now = utcnow()
        since = now - timedelta(minutes=self._lookback_minutes)
        # Already ordered oldest-first by the repository query.
        findings = await self._findings.list_critical_unremediated(since, limit=500)

        by_account: dict[UUID, list[IntegrityFinding]] = {}
        for finding in findings:
            by_account.setdefault(finding.account_id, []).append(finding)

        findings_quarantined = 0
        circuit_breaker_trips = 0
        for account_id, account_findings in by_account.items():
            to_quarantine = account_findings[: self._max_per_account_per_run]
            remaining = len(account_findings) - len(to_quarantine)

            for finding in to_quarantine:
                try:
                    await self._quarantine.execute(finding.id, triggered_by="auto")
                except (FileRemediationError, InvariantViolationError, EntityNotFoundError):
                    # Already logged and audited by QuarantineFindingUseCase
                    # itself — one failure shouldn't stop the rest of this
                    # run from acting on other, unrelated findings.
                    continue
                findings_quarantined += 1

            if remaining > 0:
                circuit_breaker_trips += 1
                await self._events.add(
                    SecurityEvent(
                        event_type="auto_quarantine_circuit_breaker_tripped",
                        source_context="integrity",
                        account_id=account_id,
                        severity=Severity.CRITICAL,
                        payload={
                            "quarantined_this_run": len(to_quarantine),
                            "remaining_unremediated": remaining,
                            "max_per_account_per_run": self._max_per_account_per_run,
                        },
                        occurred_at=now,
                        detection_rule_id="auto-quarantine-circuit-breaker",
                    )
                )

        logger.info(
            "auto_quarantine_completed",
            accounts_examined=len(by_account),
            findings_quarantined=findings_quarantined,
            circuit_breaker_trips=circuit_breaker_trips,
        )
        return AutoQuarantineResult(
            accounts_examined=len(by_account),
            findings_quarantined=findings_quarantined,
            circuit_breaker_trips=circuit_breaker_trips,
        )
