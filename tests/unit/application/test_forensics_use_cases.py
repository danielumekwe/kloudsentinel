from __future__ import annotations

from uuid import UUID, uuid4

from sentinel.application.forensics.use_cases import ScanTempDirectoriesUseCase
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.forensics.entities import TempFileObservation
from sentinel.domain.forensics.value_objects import TempFileVerdict
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, Severity, Sha256Hash

_HASH = "a" * 64


class FakeTempFileObservationRepository:
    def __init__(self, existing: list[TempFileObservation] | None = None) -> None:
        self.by_id: dict[UUID, TempFileObservation] = {o.id: o for o in existing or []}

    async def add(self, entity: TempFileObservation) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: TempFileObservation) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> TempFileObservation | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[TempFileObservation]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_path(self, absolute_path: str) -> TempFileObservation | None:
        return next((o for o in self.by_id.values() if str(o.absolute_path) == absolute_path), None)


class FakeSecurityEventRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, SecurityEvent] = {}

    async def add(self, entity: SecurityEvent) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: SecurityEvent) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> SecurityEvent | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[SecurityEvent]:
        return list(self.by_id.values())[offset : offset + limit]

    async def list_unprocessed(self, *, limit: int = 200) -> list[SecurityEvent]:
        return [e for e in self.by_id.values() if e.processed_at is None][:limit]


class FakeTempFileScanner:
    def __init__(self, observations: list[TempFileObservation]) -> None:
        self._observations = observations

    async def scan(self) -> list[TempFileObservation]:
        return list(self._observations)


def _observation(
    path: str,
    *,
    verdict: TempFileVerdict,
    rule_ids: tuple[str, ...] = (),
    account_id: UUID | None = None,
) -> TempFileObservation:
    return TempFileObservation(
        absolute_path=AbsoluteFilePath(value=path),
        sha256=Sha256Hash(value=_HASH),
        owner="examplebob",
        size_bytes=42,
        verdict=verdict,
        verdict_reason="test",
        matched_rule_ids=rule_ids,
        process=None,
        account_id=account_id,
        detected_at=utcnow(),
    )


async def test_malicious_observation_is_persisted_and_raises_event() -> None:
    account_id = uuid4()
    observation = _observation(
        "/tmp/update_abc.php",
        verdict=TempFileVerdict.MALICIOUS,
        rule_ids=("webshell-signature",),
        account_id=account_id,
    )
    observations = FakeTempFileObservationRepository()
    events = FakeSecurityEventRepository()

    use_case = ScanTempDirectoriesUseCase(
        observation_repository=observations,
        event_repository=events,
        scanner=FakeTempFileScanner([observation]),
    )

    result = await use_case.execute()

    assert result.files_observed == 1
    assert result.events_raised == 1
    (event,) = events.by_id.values()
    assert event.event_type == "temp_file_malicious"
    assert event.source_context == "forensics"
    assert event.account_id == account_id
    assert event.severity == Severity.CRITICAL
    assert event.payload["matched_rule_ids"] == ["webshell-signature"]


async def test_legitimate_observation_is_persisted_without_event() -> None:
    observation = _observation("/tmp/README.sh", verdict=TempFileVerdict.LEGITIMATE)
    observations = FakeTempFileObservationRepository()
    events = FakeSecurityEventRepository()

    use_case = ScanTempDirectoriesUseCase(
        observation_repository=observations,
        event_repository=events,
        scanner=FakeTempFileScanner([observation]),
    )

    result = await use_case.execute()

    assert result.files_observed == 1
    assert result.events_raised == 0
    assert len(events.by_id) == 0


async def test_already_observed_path_is_not_reprocessed() -> None:
    observation = _observation("/tmp/update_abc.php", verdict=TempFileVerdict.MALICIOUS)
    observations = FakeTempFileObservationRepository(existing=[observation])
    events = FakeSecurityEventRepository()

    use_case = ScanTempDirectoriesUseCase(
        observation_repository=observations,
        event_repository=events,
        scanner=FakeTempFileScanner([observation]),
    )

    result = await use_case.execute()

    assert result.files_observed == 0
    assert result.events_raised == 0
