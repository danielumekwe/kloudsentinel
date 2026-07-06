from __future__ import annotations

from uuid import uuid4

from sentinel.domain.forensics.entities import TempFileObservation
from sentinel.domain.forensics.value_objects import ProcessContext, TempFileVerdict
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, Sha256Hash

_HASH = "a" * 64


def test_malicious_observation_carries_process_context() -> None:
    process = ProcessContext(
        pid=1234,
        ppid=1,
        executable_path="/usr/bin/php",
        command_line="php /tmp/update_abc.php",
        open_files=("/tmp/update_abc.php",),
        network_connections=(),
    )

    observation = TempFileObservation(
        absolute_path=AbsoluteFilePath(value="/tmp/update_abc.php"),
        sha256=Sha256Hash(value=_HASH),
        owner="examplebob",
        size_bytes=42,
        verdict=TempFileVerdict.MALICIOUS,
        verdict_reason="Matches a known webshell signature string",
        matched_rule_ids=("webshell-signature",),
        process=process,
        account_id=uuid4(),
        detected_at=utcnow(),
    )

    assert observation.verdict is TempFileVerdict.MALICIOUS
    assert observation.process is not None
    assert observation.process.pid == 1234
    assert observation.matched_rule_ids == ("webshell-signature",)


def test_legitimate_observation_has_no_process_context_or_account() -> None:
    observation = TempFileObservation(
        absolute_path=AbsoluteFilePath(value="/tmp/harmless.sh"),
        sha256=Sha256Hash(value=_HASH),
        owner="root",
        size_bytes=10,
        verdict=TempFileVerdict.LEGITIMATE,
        verdict_reason="No heuristic rules matched",
        matched_rule_ids=(),
        process=None,
        account_id=None,
        detected_at=utcnow(),
    )

    assert observation.verdict is TempFileVerdict.LEGITIMATE
    assert observation.process is None
    assert observation.account_id is None
    assert observation.matched_rule_ids == ()
