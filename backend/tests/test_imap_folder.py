"""
Regression tests locking in the IMAP folder-name CRLF injection guard
(Phase-CP1, Sec H-3 / CWE-77 / CWE-93).

Without the `_FORBIDDEN_FOLDER_CHARS` validator in `create_folder()`, a
folder name containing CR/LF/NUL/"/\\ would let the IMAP server interpret
the suffix as a separate command (CRLF command injection). Quoting alone
does NOT block this because IMAP literals/quoted strings still terminate
on unescaped `"` or line breaks in the unquoted-style fallback paths.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_imap_folder.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from auth import Session  # noqa: E402
from imap_client import IMAPClient  # noqa: E402


def _client_with_mock_conn() -> IMAPClient:
    """Build an IMAPClient with a stubbed connection so validation can be
    exercised without an actual IMAP server."""
    session = Session(
        token="t",
        host="imap.example.com",
        port_imap=993,
        port_sieve=4190,
        username="user@example.com",
        password="hunter2",
        created_at=0.0,
        last_used=0.0,
    )
    client = IMAPClient(session)
    client._conn = MagicMock()
    client._conn.create.return_value = ("OK", [b"created"])
    client._conn.subscribe.return_value = ("OK", [b"subscribed"])
    return client


# ── Injection payloads MUST be rejected ──

INJECTION_PAYLOADS = [
    pytest.param("Inbox\r", id="bare-CR"),
    pytest.param("Inbox\n", id="bare-LF"),
    pytest.param("Inbox\r\n", id="CRLF"),
    pytest.param("Inbox\r\nDELETE \"Other\"", id="CRLF-then-command"),
    pytest.param("Inbox\x00", id="NUL"),
    pytest.param("Inbox\x00DELETE \"Other\"", id="NUL-then-command"),
    pytest.param('Inbox"', id="trailing-doublequote"),
    pytest.param('Bad" CREATE "Evil', id="quote-break-then-command"),
    pytest.param("Inbox\\", id="trailing-backslash"),
    pytest.param("Bad\\\" CREATE \"Evil", id="escaped-quote-injection"),
]


@pytest.mark.parametrize("name", INJECTION_PAYLOADS)
def test_create_folder_rejects_injection(name):
    client = _client_with_mock_conn()
    with pytest.raises(ValueError, match="forbidden characters"):
        client.create_folder(name)
    client._conn.create.assert_not_called()
    client._conn.subscribe.assert_not_called()


def test_create_folder_rejects_empty_name():
    client = _client_with_mock_conn()
    with pytest.raises(ValueError):
        client.create_folder("")
    client._conn.create.assert_not_called()


# ── Benign names MUST pass through ──

BENIGN_NAMES = [
    "Inbox",
    "Archive/2026",
    "Lists.golang-nuts",
    "INBOX/Sub Folder",
    "📥 Inbox",  # unicode is fine — only the IMAP framing chars are forbidden
    "INBOX.Sent",
]


@pytest.mark.parametrize("name", BENIGN_NAMES)
def test_create_folder_accepts_benign(name):
    client = _client_with_mock_conn()
    assert client.create_folder(name) is True
    client._conn.create.assert_called_once_with(f'"{name}"')
    client._conn.subscribe.assert_called_once_with(f'"{name}"')
