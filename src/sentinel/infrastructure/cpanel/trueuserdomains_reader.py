from __future__ import annotations

from pathlib import Path

import structlog

from sentinel.domain.discovery.value_objects import DiscoveredCpanelAccount, LinuxUsername
from sentinel.domain.shared.exceptions import ValidationError
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName

logger = structlog.get_logger()


class TrueUserDomainsReader:
    """Reads cPanel accounts from ``/etc/trueuserdomains``, the file cPanel
    itself maintains as the canonical domain-to-owner map (one line per
    account's primary domain, format ``domain: username``).

    Home directory is derived from a configurable base directory rather than
    parsed out of ``/etc/passwd`` — cPanel's own convention is a flat
    ``{home_base}/{username}`` layout, and reading ``/etc/passwd`` would pull
    in shell/uid/gid fields this adapter has no use for. Suspension state is
    read from cPanel's own marker file convention
    (``{suspended_dir}/{username}`` existing means suspended) rather than
    inferred from anything in trueuserdomains, which doesn't carry it.

    All three paths are constructor parameters (not read from ``Settings``
    directly) so tests can point this adapter at a fixture tree instead of
    requiring a real cPanel server.
    """

    def __init__(
        self,
        *,
        etc_directory: Path,
        home_base_directory: Path,
        suspended_directory: Path,
    ) -> None:
        self._trueuserdomains_path = etc_directory / "trueuserdomains"
        self._home_base_directory = home_base_directory
        self._suspended_directory = suspended_directory

    async def discover(self) -> list[DiscoveredCpanelAccount]:
        if not self._trueuserdomains_path.is_file():
            logger.warning("trueuserdomains_missing", path=str(self._trueuserdomains_path))
            return []

        accounts: dict[str, DiscoveredCpanelAccount] = {}
        for line in self._trueuserdomains_path.read_text().splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue

            raw_domain, _, raw_username = line.partition(":")
            raw_domain = raw_domain.strip()
            raw_username = raw_username.strip()
            if not raw_domain or not raw_username:
                continue

            try:
                username = LinuxUsername(value=raw_username)
                domain = DomainName(value=raw_domain)
            except ValidationError:
                logger.warning("trueuserdomains_invalid_line", line=line)
                continue

            # The same username can own multiple domains; trueuserdomains
            # lists one line per domain, but a cPanel account is one Linux
            # user with one home directory, so we keep the first domain seen
            # as the account's primary domain and de-duplicate by username.
            if username.value in accounts:
                continue

            accounts[username.value] = DiscoveredCpanelAccount(
                username=username,
                primary_domain=domain,
                home_directory=AbsoluteFilePath(
                    value=str(self._home_base_directory / username.value)
                ),
                is_suspended=(self._suspended_directory / username.value).is_file(),
            )

        return list(accounts.values())
