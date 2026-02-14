"""
IMAP client for folder operations.
"""

import imaplib
import re
from auth import Session


class IMAPClient:
    """Minimal IMAP client for folder listing."""

    def __init__(self, session: Session):
        self.session = session
        self._conn = None

    def __enter__(self):
        self._conn = imaplib.IMAP4_SSL(self.session.host, self.session.port_imap)
        self._conn.login(self.session.username, self.session.password)
        return self

    def __exit__(self, *args):
        if self._conn:
            try:
                self._conn.logout()
            except Exception:
                pass

    def list_folders(self) -> list[dict]:
        """Return flat list of {name, delimiter, flags} dicts."""
        status, data = self._conn.list()
        folders = []
        if status != "OK":
            return folders

        for item in data:
            if isinstance(item, bytes):
                item = item.decode("utf-8", errors="replace")
            # Parse IMAP LIST response: (flags) "delimiter" "name"
            match = re.match(r'\(([^)]*)\)\s+"([^"]+)"\s+"?([^"]*)"?', item)
            if match:
                flags_str, delimiter, name = match.groups()
                flags = [f.strip() for f in flags_str.split() if f.strip()]
                folders.append({
                    "name": name.strip('"'),
                    "delimiter": delimiter,
                    "flags": flags,
                })

        folders.sort(key=lambda f: f["name"].lower())
        return folders

    def create_folder(self, name: str) -> bool:
        """Create a new IMAP folder."""
        status, _ = self._conn.create(f'"{name}"')
        if status == "OK":
            self._conn.subscribe(f'"{name}"')
        return status == "OK"
