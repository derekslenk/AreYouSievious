"""
ManageSieve client wrapper.
"""

import os
import socket

from auth import Session
from sievelib.managesieve import Client
from ssrf import assert_host_resolves_to


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(0.1, float(raw))
    except ValueError:
        return default


CONNECT_TIMEOUT = _env_float("AYS_SIEVE_CONNECT_TIMEOUT", 10.0)
IO_TIMEOUT = _env_float("AYS_SIEVE_IO_TIMEOUT", 30.0)


class SieveClient:
    """Wraps sievelib ManageSieve client with session credentials.

    sievelib's `Client.connect` calls `socket.create_connection` without a
    timeout, so a blackhole mail server pins the threadpool worker for
    the OS TCP timeout (~2 minutes). We set the connect timeout via the
    process-default trick for the duration of the connect, then set the
    long-lived I/O timeout on the live socket. Env overrides:
    AYS_SIEVE_CONNECT_TIMEOUT / AYS_SIEVE_IO_TIMEOUT (seconds).
    """

    def __init__(self, session: Session):
        self.session = session
        self._client = None

    def __enter__(self):
        assert_host_resolves_to(self.session.host, self.session.host_ip)

        previous_default = socket.getdefaulttimeout()
        socket.setdefaulttimeout(CONNECT_TIMEOUT)
        try:
            self._client = Client(self.session.host, self.session.port_sieve)
            self._client.connect(
                self.session.username,
                self.session.password,
                starttls=True,
            )
        finally:
            socket.setdefaulttimeout(previous_default)

        if self._client.sock is not None:
            self._client.sock.settimeout(IO_TIMEOUT)
        return self

    def __exit__(self, *args):
        if self._client:
            try:
                self._client.logout()
            except Exception:
                pass

    def list_scripts(self) -> list[dict]:
        """Return list of {name, active} dicts."""
        active, inactive = self._client.listscripts()
        scripts = []
        if active:
            scripts.append({"name": active, "active": True})
        for name in inactive:
            scripts.append({"name": name, "active": False})
        return scripts

    def get_script(self, name: str) -> str:
        """Get script content by name."""
        result = self._client.getscript(name)
        if isinstance(result, tuple):
            return result[-1]
        return result

    def put_script(self, name: str, content: str):
        """Upload/update a script."""
        self._client.putscript(name, content)

    def activate_script(self, name: str):
        """Set a script as active."""
        self._client.setactive(name)

    def delete_script(self, name: str):
        """Delete a script."""
        self._client.deletescript(name)
