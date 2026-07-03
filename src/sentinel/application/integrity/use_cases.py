from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import structlog

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.ports import CpanelAccountRepository
from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding
from sentinel.domain.integrity.ports import (
    FileBaselineRepository,
    FileScanner,
    IntegrityFindingRepository,
)
from sentinel.domain.integrity.value_objects import ChangeType
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity, Sha256Hash

logger = structlog.get_logger()

_SEVERITY_BY_CHANGE: dict[ChangeType, Severity] = {
    ChangeType.ADDED: Severity.MEDIUM,
    ChangeType.MODIFIED: Severity.HIGH,
    ChangeType.DELETED: Severity.HIGH,
    ChangeType.PERMISSIONS_CHANGED: Severity.MEDIUM,
}


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
        scanner: FileScanner,
    ) -> None:
        self._accounts = account_repository
        self._baselines = baseline_repository
        self._findings = finding_repository
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
                        account.id,
                        scanned.relative_path,
                        change_type=ChangeType.ADDED,
                        previous_sha256=None,
                        current_sha256=scanned.sha256,
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
                    account.id,
                    scanned.relative_path,
                    change_type=ChangeType.ADDED,
                    previous_sha256=None,
                    current_sha256=scanned.sha256,
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
                    account.id,
                    scanned.relative_path,
                    change_type=ChangeType.MODIFIED,
                    previous_sha256=previous_sha256,
                    current_sha256=scanned.sha256,
                    at=at,
                )
                findings_created += 1
            elif baseline.mode != scanned.mode:
                baseline.update(
                    sha256=scanned.sha256, size_bytes=scanned.size_bytes, mode=scanned.mode, at=at
                )
                await self._baselines.save(baseline)
                await self._raise_finding(
                    account.id,
                    scanned.relative_path,
                    change_type=ChangeType.PERMISSIONS_CHANGED,
                    previous_sha256=baseline.sha256,
                    current_sha256=scanned.sha256,
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
                account.id,
                baseline.relative_path,
                change_type=ChangeType.DELETED,
                previous_sha256=previous_sha256,
                current_sha256=None,
                at=at,
            )
            findings_created += 1

        return baselines_established, findings_created, baselines_removed

    async def _raise_finding(
        self,
        account_id: UUID,
        relative_path: RelativeFilePath,
        *,
        change_type: ChangeType,
        previous_sha256: Sha256Hash | None,
        current_sha256: Sha256Hash | None,
        at: datetime,
    ) -> None:
        await self._findings.add(
            IntegrityFinding(
                account_id=account_id,
                relative_path=relative_path,
                change_type=change_type,
                severity=_SEVERITY_BY_CHANGE[change_type],
                previous_sha256=previous_sha256,
                current_sha256=current_sha256,
                detected_at=at,
            )
        )
