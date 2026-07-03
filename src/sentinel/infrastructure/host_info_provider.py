from __future__ import annotations

import platform
import socket

from sentinel import __version__


class SystemHostInfoProvider:
    """Reads identifying information from the actual machine via stdlib
    ``socket``/``platform`` calls. The only adapter for ``HostInfoProvider``;
    kept separate from the cPanel/WordPress adapters since it has nothing to
    do with either."""

    def get_hostname(self) -> str:
        return socket.getfqdn()

    def get_os_info(self) -> str:
        return f"{platform.system()} {platform.release()}"

    def get_agent_version(self) -> str:
        return __version__
