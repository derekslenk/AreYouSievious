"""
IMAP client for folder operations.

Dialling policy — rebinding re-check, pinned connect, TLS context, timeouts —
lives in `mail_dial`. This module owns what to say once connected.
"""

import re

from auth import Session
from mail_dial import open_imap

# IMAP command framing is line-based: CR, LF, NUL, double-quote, and backslash
# in an unquoted folder name would let a caller inject additional IMAP commands
# (CWE-77 / CWE-93). Reject them in create_folder.
_FORBIDDEN_FOLDER_CHARS = re.compile(r'[\r\n\x00"\\]')


class IMAPClient:
    """Minimal IMAP client for folder listing."""

    def __init__(self, session: Session):
        self.session = session
        self._conn = None

    def __enter__(self):
        self._conn = open_imap(
            self.session.host,
            self.session.host_ip,
            self.session.port_imap,
        )
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
                folders.append(
                    {
                        "name": name.strip('"'),
                        "delimiter": delimiter,
                        "flags": flags,
                    }
                )

        folders.sort(key=lambda f: f["name"].lower())
        return folders

    def create_folder(self, name: str) -> bool:
        """Create a new IMAP folder.

        Rejects names containing CR, LF, NUL, double-quote, or backslash to
        block IMAP command injection via folder name (CWE-77 / CWE-93).
        """
        if not name or _FORBIDDEN_FOLDER_CHARS.search(name):
            raise ValueError("Folder name contains forbidden characters")
        status, _ = self._conn.create(f'"{name}"')
        if status == "OK":
            self._conn.subscribe(f'"{name}"')
        return status == "OK"
