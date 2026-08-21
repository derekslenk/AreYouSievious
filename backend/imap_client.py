"""
IMAP client for folder operations.

Dialling policy — rebinding re-check, pinned connect, TLS context, timeouts —
lives in `mail_dial`. This module owns what to say once connected.
"""

import imaplib
import re

from auth import Session
from config import Settings
from mail_dial import open_imap, transport_failures_are_semantic
from mail_errors import AuthFailed, FolderRejected, MailServerUnavailable, relayed, server_text
from protocol_names import validate_folder_name


def _login(conn, username: str, password: str, *, rejected: str | None = None) -> None:
    """Say LOGIN, and report the two ways it fails in the mail vocabulary.

    One place, because two callers need it: the store's `__enter__` and the
    credential check the login route performs before any session exists.
    """
    # Nesting matters. The protocol's own errors are handled INSIDE the
    # transport net, because the net reads an IMAP4.error as "the server would
    # not talk to us" — true at the dial, where no credentials have been sent,
    # and wrong here, where it means exactly the opposite: the server talked
    # and refused these. Outside-in, a mistyped password answered 502 "could
    # not be reached".
    #
    # The net still wraps this, because imaplib does not wrap OSError: a reset
    # socket raises straight through. It passes our AuthFailed out untouched
    # via its MailStoreError exemption.
    with transport_failures_are_semantic():
        try:
            conn.login(username, password)
        except imaplib.IMAP4.abort as exc:
            # MUST precede IMAP4.error, which it subclasses. A dropped socket
            # is not a rejected password, and telling the user to reset a
            # working one sends them somewhere that cannot help.
            raise MailServerUnavailable("The connection to the mail server was lost.") from exc
        except imaplib.IMAP4.error as exc:
            raise AuthFailed(rejected) from exc


def verify_credentials(
    host: str, host_ip: str, port: int, username: str, password: str, *, cfg: Settings
) -> None:
    """Prove these credentials open a mailbox, then hang up.

    What the login route needs and a FolderStore cannot give it: there is no
    session yet, so there is nothing to build a store around. Speaking IMAP
    lives here rather than in the router, which is what lets `routers/auth.py`
    stop importing imaplib and stop deciding what a protocol error means.
    """
    conn = open_imap(host, host_ip, port, cfg=cfg)
    try:
        _login(conn, username, password, rejected="Authentication failed")
    finally:
        try:
            conn.logout()
        except Exception:
            # Already said what we came to say; a failed goodbye is not the
            # caller's problem and must not mask the reason we are leaving.
            pass


class ImapFolderStore:
    """The FolderStore adapter.

    Named for the seam rather than the protocol. This class was `IMAPClient`;
    `imapclient.IMAPClient` is the LIST parser `.12` introduces into this very
    module, and two different classes of that name in one file is a mistake
    waiting to be made.
    """

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
        try:
            _login(self._conn, self.session.username, self.session.password)
        except Exception:
            # `__exit__` only runs if `__enter__` RETURNED, so a failed login
            # would leave this socket open — one leaked connection per
            # request, which stale credentials plus a polling client turns
            # into a steady drip.
            self._close()
            raise
        return self

    def __exit__(self, *args):
        self._close()

    def _close(self):
        """Hang up, and never let the goodbye mask why we are leaving."""
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
