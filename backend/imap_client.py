"""
IMAP client for folder operations.

Dialling policy — rebinding re-check, pinned connect, TLS context, timeouts —
lives in `mail_dial`. This module owns what to say once connected.
"""

import re

from auth import Session
from config import Settings
from mail_dial import open_imap
from mail_errors import FolderRejected, relayed, server_text
from protocol_names import validate_folder_name


class IMAPClient:
    """Minimal IMAP client for folder listing."""

    def __init__(self, session: Session, cfg: Settings):
        self.session = session
        self.cfg = cfg
        self._conn = None

    def __enter__(self):
        self._conn = open_imap(
            self.session.host,
            self.session.host_ip,
            self.session.port_imap,
            cfg=self.cfg,
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

    def create_folder(self, name: str) -> None:
        """Create a new IMAP folder, and subscribe it.

        Returns nothing: failure raises, per the FolderStore seam. The bool
        this replaced made the router ask "did that work?" and answer 400 for
        every cause alike, so an unreachable server and a refused name were
        indistinguishable.

        Both statuses are checked. Subscribing was previously fire-and-forget
        while create's status was checked two lines above, so a refused
        subscribe still reported success — for a folder most mail clients
        will not display, which is indistinguishable from the folder never
        having been created.

        The framing guard lives in `protocol_names`, shared with the
        ManageSieve script-name sink — same hazard, same rule, one place.
        """
        validate_folder_name(name)
        status, detail = self._conn.create(f'"{name}"')
        if status != "OK":
            raise relayed(FolderRejected, server_text(detail))
        status, detail = self._conn.subscribe(f'"{name}"')
        if status != "OK":
            raise relayed(FolderRejected, server_text(detail))
