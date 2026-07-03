from __future__ import annotations

from pathlib import Path

from sentinel.infrastructure.cpanel.trueuserdomains_reader import TrueUserDomainsReader


def _make_reader(tmp_path: Path) -> tuple[TrueUserDomainsReader, Path, Path, Path]:
    etc_dir = tmp_path / "etc"
    home_base = tmp_path / "home"
    suspended_dir = tmp_path / "suspended"
    etc_dir.mkdir()
    home_base.mkdir()
    suspended_dir.mkdir()
    reader = TrueUserDomainsReader(
        etc_directory=etc_dir, home_base_directory=home_base, suspended_directory=suspended_dir
    )
    return reader, etc_dir, home_base, suspended_dir


async def test_discover_returns_empty_when_trueuserdomains_missing(tmp_path: Path) -> None:
    reader, _, _, _ = _make_reader(tmp_path)
    assert await reader.discover() == []


async def test_discover_parses_accounts_and_derives_home_directory(tmp_path: Path) -> None:
    reader, etc_dir, home_base, _ = _make_reader(tmp_path)
    (etc_dir / "trueuserdomains").write_text("example.com: examplebob\nother.org: otheruser\n")

    accounts = await reader.discover()

    by_username = {str(a.username): a for a in accounts}
    assert set(by_username) == {"examplebob", "otheruser"}
    assert str(by_username["examplebob"].primary_domain) == "example.com"
    assert str(by_username["examplebob"].home_directory) == str(home_base / "examplebob")
    assert by_username["examplebob"].is_suspended is False


async def test_discover_marks_account_suspended_when_marker_file_exists(tmp_path: Path) -> None:
    reader, etc_dir, _, suspended_dir = _make_reader(tmp_path)
    (etc_dir / "trueuserdomains").write_text("example.com: examplebob\n")
    (suspended_dir / "examplebob").touch()

    accounts = await reader.discover()

    assert accounts[0].is_suspended is True


async def test_discover_skips_malformed_lines(tmp_path: Path) -> None:
    reader, etc_dir, _, _ = _make_reader(tmp_path)
    (etc_dir / "trueuserdomains").write_text(
        "example.com: examplebob\nnot-a-valid-line\n: missingdomain\nmissinguser:\n"
    )

    accounts = await reader.discover()

    assert len(accounts) == 1
    assert str(accounts[0].username) == "examplebob"


async def test_discover_deduplicates_by_username_keeping_first_domain(tmp_path: Path) -> None:
    reader, etc_dir, _, _ = _make_reader(tmp_path)
    (etc_dir / "trueuserdomains").write_text("primary.com: examplebob\naddon.com: examplebob\n")

    accounts = await reader.discover()

    assert len(accounts) == 1
    assert str(accounts[0].primary_domain) == "primary.com"
