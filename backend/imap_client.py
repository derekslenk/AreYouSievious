"""
IMAP client for folder operations.
"""

import imaplib
import logging
import os
import re
import ssl

from auth import Session
from ssrf import assert_host_resolves_to

_log = logging.getLogger("ays.imap")


def _build_tls_context() -> ssl.SSLContext:
    """
    Build the TLS context used for every outbound IMAP connection.

    Defaults: verify the server certificate chain against the system root
    store and check the hostname (CWE-295, CWE-297). Without this, the
    stdlib default (`imaplib.IMAP4_SSL` with no `ssl_context`) accepts ANY
    certificate, including self-signed certs from an on-path MITM, and
    immediately sends the user's plaintext password.

    Opt-out: `AYS_IMAP_INSECURE=1` falls back to an unverified context for
    self-signed test setups. Emits a warning so the operator cannot miss it.
    """
    if os.environ.get("AYS_IMAP_INSECURE", "").lower() in ("1", "true", "yes"):
        _log.warning(
            "AYS_IMAP_INSECURE is set — outbound IMAP TLS is NOT verified. "
            "Use only for self-signed test setups."
        )
        return ssl._create_unverified_context()
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# Built once at import time so a missing system CA store fails fast at startup
# rather than on first user login.
TLS_CONTEXT = _build_tls_context()

# Connection / read timeout in seconds. A slow or hung mail server would
# otherwise pin the FastAPI worker for the OS TCP timeout (~2 minutes).
IMAP_TIMEOUT = 10


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
        assert_host_resolves_to(self.session.host, self.session.host_ip)
        self._conn = imaplib.IMAP4_SSL(
            self.session.host,
            self.session.port_imap,
            ssl_context=TLS_CONTEXT,
            timeout=IMAP_TIMEOUT,
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
