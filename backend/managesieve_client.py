"""
ManageSieve client wrapper.

Dialling policy — rebinding re-check, pinned connect, SNI split, timeouts —
lives in `mail_dial`. This module owns the script operations.
"""

from auth import Session
from mail_dial import open_sieve
from sieve_names import validate_script_name


class SieveClient:
    """Wraps a sievelib ManageSieve client with session credentials."""

    def __init__(self, session: Session):
        self.session = session
        self._client = None

    def __enter__(self):
        self._client = open_sieve(
            self.session.host,
            self.session.host_ip,
            self.session.port_sieve,
            self.session.username,
            self.session.password,
        )
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
        validate_script_name(name)
        result = self._client.getscript(name)
        if isinstance(result, tuple):
            return result[-1]
        return result

    def put_script(self, name: str, content: str):
        """Upload/update a script."""
        validate_script_name(name)
        self._client.putscript(name, content)

    def activate_script(self, name: str):
        """Set a script as active."""
        validate_script_name(name)
        self._client.setactive(name)

    def delete_script(self, name: str):
        """Delete a script."""
        validate_script_name(name)
        self._client.deletescript(name)
