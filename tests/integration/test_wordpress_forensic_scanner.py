from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName
from sentinel.infrastructure.heuristics.php_malware_scanner import PhpMalwareScanner
from sentinel.infrastructure.wordpress.forensic_scanner import WordPressForensicScanner

_DROPIN_PATHS = [
    "wp-content/db.php",
    "wp-content/object-cache.php",
    "wp-content/advanced-cache.php",
]


def _installation(root: Path) -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=uuid4(),
        absolute_path=AbsoluteFilePath(value=str(root)),
        domain=DomainName(value="example.com"),
        wp_version="6.5",
        is_multisite=False,
        last_seen_at=utcnow(),
    )


def _scanner() -> WordPressForensicScanner:
    return WordPressForensicScanner(
        php_malware_scanner=PhpMalwareScanner(), dropin_relative_paths=_DROPIN_PATHS
    )


async def test_plugin_directory_without_header_is_flagged_fake(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "wp-content" / "plugins" / "totally-legit"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "index.php").write_text("<?php // no plugin header here\n")

    findings = await _scanner().scan(_installation(tmp_path))

    fake_plugin_findings = [f for f in findings if f.finding_type == "fake_plugin"]
    assert len(fake_plugin_findings) == 1
    assert fake_plugin_findings[0].relative_path == "wp-content/plugins/totally-legit"


async def test_plugin_directory_with_valid_header_is_not_flagged(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "wp-content" / "plugins" / "real-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "real-plugin.php").write_text(
        "<?php\n/*\nPlugin Name: Real Plugin\nVersion: 1.0\n*/\n"
    )

    findings = await _scanner().scan(_installation(tmp_path))

    assert [f for f in findings if f.finding_type == "fake_plugin"] == []


async def test_plugin_directory_with_multiple_matched_files_produces_one_finding_each(
    tmp_path: Path,
) -> None:
    """A directory can't be quarantined (`FileRemediator` only ever moves
    a single regular file), so each malware-matched file inside a fake
    plugin directory must be its own finding, pointing at that exact
    file — not one finding for the whole directory."""
    plugin_dir = tmp_path / "wp-content" / "plugins" / "totally-legit"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "shell1.php").write_text("<?php system($_GET['c']); ?>")
    (plugin_dir / "shell2.php").write_text("<?php passthru($_POST['cmd']); ?>")

    findings = await _scanner().scan(_installation(tmp_path))

    fake_plugin_findings = sorted(
        (f for f in findings if f.finding_type == "fake_plugin"), key=lambda f: f.relative_path
    )
    assert [f.relative_path for f in fake_plugin_findings] == [
        "wp-content/plugins/totally-legit/shell1.php",
        "wp-content/plugins/totally-legit/shell2.php",
    ]
    assert all(f.severity.value == "CRITICAL" for f in fake_plugin_findings)
    assert all(f.sha256 is not None for f in fake_plugin_findings)


async def test_empty_plugin_directory_is_not_flagged(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "wp-content" / "plugins" / "empty-dir"
    plugin_dir.mkdir(parents=True)

    findings = await _scanner().scan(_installation(tmp_path))

    assert [f for f in findings if f.finding_type == "fake_plugin"] == []


async def test_theme_directory_without_style_css_header_is_flagged_fake(tmp_path: Path) -> None:
    theme_dir = tmp_path / "wp-content" / "themes" / "fake-theme"
    theme_dir.mkdir(parents=True)
    (theme_dir / "functions.php").write_text("<?php system($_GET['c']); ?>")

    findings = await _scanner().scan(_installation(tmp_path))

    fake_theme_findings = [f for f in findings if f.finding_type == "fake_theme"]
    assert len(fake_theme_findings) == 1
    assert fake_theme_findings[0].severity.value == "CRITICAL"
    assert "rce-user-input" in fake_theme_findings[0].matched_rule_ids


async def test_theme_directory_with_valid_style_css_is_not_flagged(tmp_path: Path) -> None:
    theme_dir = tmp_path / "wp-content" / "themes" / "real-theme"
    theme_dir.mkdir(parents=True)
    (theme_dir / "style.css").write_text("/*\nTheme Name: Real Theme\nVersion: 1.0\n*/\n")
    (theme_dir / "index.php").write_text("<?php // normal theme file\n")

    findings = await _scanner().scan(_installation(tmp_path))

    assert [f for f in findings if f.finding_type == "fake_theme"] == []


async def test_mu_plugin_presence_is_always_reported(tmp_path: Path) -> None:
    mu_dir = tmp_path / "wp-content" / "mu-plugins"
    mu_dir.mkdir(parents=True)
    (mu_dir / "loader.php").write_text("<?php // benign autoloaded plugin\n")

    findings = await _scanner().scan(_installation(tmp_path))

    mu_findings = [f for f in findings if f.finding_type == "mu_plugin_present"]
    assert len(mu_findings) == 1
    assert mu_findings[0].severity.value == "MEDIUM"
    assert mu_findings[0].sha256 is None


async def test_malicious_mu_plugin_is_flagged_critical(tmp_path: Path) -> None:
    mu_dir = tmp_path / "wp-content" / "mu-plugins"
    mu_dir.mkdir(parents=True)
    (mu_dir / "backdoor.php").write_text("<?php system($_GET['c']); ?>")

    findings = await _scanner().scan(_installation(tmp_path))

    mu_findings = [f for f in findings if f.finding_type == "mu_plugin_present"]
    assert mu_findings[0].severity.value == "CRITICAL"
    assert mu_findings[0].sha256 is not None


async def test_hidden_malicious_script_in_uploads_is_flagged(tmp_path: Path) -> None:
    uploads_dir = tmp_path / "wp-content" / "uploads" / "2024" / "01"
    uploads_dir.mkdir(parents=True)
    (uploads_dir / "avatar.php").write_text("<?php system($_GET['c']); ?>")

    findings = await _scanner().scan(_installation(tmp_path))

    hidden_findings = [f for f in findings if f.finding_type == "hidden_upload_script"]
    assert len(hidden_findings) == 1
    assert hidden_findings[0].severity.value == "CRITICAL"
    assert hidden_findings[0].sha256 is not None


async def test_benign_upload_php_is_not_flagged(tmp_path: Path) -> None:
    uploads_dir = tmp_path / "wp-content" / "uploads"
    uploads_dir.mkdir(parents=True)
    (uploads_dir / "index.php").write_text("<?php // Silence is golden.\n")

    findings = await _scanner().scan(_installation(tmp_path))

    assert [f for f in findings if f.finding_type == "hidden_upload_script"] == []


async def test_dropin_presence_is_always_reported(tmp_path: Path) -> None:
    (tmp_path / "wp-content").mkdir(parents=True)
    (tmp_path / "wp-content" / "db.php").write_text("<?php // custom db layer\n")

    findings = await _scanner().scan(_installation(tmp_path))

    dropin_findings = [f for f in findings if f.finding_type == "dropin_present"]
    assert len(dropin_findings) == 1
    assert dropin_findings[0].relative_path == "wp-content/db.php"
    assert dropin_findings[0].severity.value == "HIGH"
    assert dropin_findings[0].sha256 is None


async def test_malicious_dropin_is_flagged_critical(tmp_path: Path) -> None:
    (tmp_path / "wp-content").mkdir(parents=True)
    (tmp_path / "wp-content" / "db.php").write_text("<?php system($_GET['c']); ?>")

    findings = await _scanner().scan(_installation(tmp_path))

    dropin_findings = [f for f in findings if f.finding_type == "dropin_present"]
    assert dropin_findings[0].severity.value == "CRITICAL"
    assert dropin_findings[0].sha256 is not None


async def test_no_dropins_present_produces_no_dropin_findings(tmp_path: Path) -> None:
    (tmp_path / "wp-content").mkdir(parents=True)

    findings = await _scanner().scan(_installation(tmp_path))

    assert [f for f in findings if f.finding_type == "dropin_present"] == []


async def test_clean_installation_produces_no_findings(tmp_path: Path) -> None:
    (tmp_path / "wp-content" / "plugins").mkdir(parents=True)
    (tmp_path / "wp-content" / "themes").mkdir(parents=True)

    findings = await _scanner().scan(_installation(tmp_path))

    assert findings == []
