"""
ManageSieve client wrapper.
"""

from sievelib.managesieve import Client
from auth import Session


class SieveClient:
    """Wraps sievelib ManageSieve client with session credentials."""

    def __init__(self, session: Session):
        self.session = session
        self._client = None

    def __enter__(self):
        self._client = Client(self.session.host, self.session.port_sieve)
        self._client.connect(
            self.session.username,
            self.session.password,
            starttls=True,
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
