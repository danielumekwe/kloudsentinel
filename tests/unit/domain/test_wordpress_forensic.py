from __future__ import annotations

from sentinel.domain.shared.value_objects import Severity
from sentinel.domain.wordpress.forensic.value_objects import WordPressForensicFinding


def test_forensic_finding_defaults_to_no_matched_rules() -> None:
    finding = WordPressForensicFinding(
        finding_type="fake_plugin",
        relative_path="wp-content/plugins/totally-legit",
        description="no valid plugin header",
        severity=Severity.HIGH,
    )

    assert finding.matched_rule_ids == ()


def test_forensic_finding_holds_matched_rules() -> None:
    finding = WordPressForensicFinding(
        finding_type="dropin_present",
        relative_path="wp-content/db.php",
        description="drop-in present",
        severity=Severity.CRITICAL,
        matched_rule_ids=("rce-user-input",),
    )

    assert finding.matched_rule_ids == ("rce-user-input",)
