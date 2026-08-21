"""
Protocol-framing name guards, for every sink at once.

This replaces tests/test_imap_folder.py and tests/test_sieve_name_injection.py,
which tested the same rule against two sinks with two copies of the payload
matrix. The Sieve copy carried this comment:

    "If either payload matrix drifts, both suites should drift together —
     please keep them aligned."

There is now one matrix, applied to every sink by parametrisation, so they
cannot drift. Adding a sink means adding one line to SINKS.

Wire evidence for why the guard exists (from the original PoC):
    putscript(name='x"\\r\\nDELETESCRIPT "primary-filter', content='keep;')
    -> b'PUTSCRIPT "x"\\r\\nDELETESCRIPT "primary-filter" {6+}\\r\\nkeep;\\n\\r\\n'
    -> the server parses TWO commands: PUTSCRIPT (fails), DELETESCRIPT (runs)

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_protocol_names.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock

import managesieve_client
import pytest
from auth import Session
from config import Settings
from imap_store import ImapFolderStore
from protocol_names import MAX_SCRIPT_NAME_BYTES, ProtocolNameError

# `managesieve_client` is looked up dynamically (not `from ... import
# SieveClient`) because test_managesieve_timeout.py reloads modules; a
# `from X import Y` would freeze a pre-reload reference.


def _session() -> Session:
    return Session(
        token="t",
        host="mail.example.com",
        host_ip="93.184.216.34",
        port_imap=993,
        port_sieve=4190,
        username="user@example.com",
        password="hunter2",
        created_at=0.0,
        last_used=0.0,
    )


# ── The sinks ──
#
# Each entry is (id, call, assert_untouched). `call` applies the sink to a
# name; `assert_untouched` proves the underlying protocol library was never
# reached — rejecting AFTER the frame hits the wire would be no defence.


# A REAL adapter over a stubbed socket library.
#
# The guards under test live in the adapter, so the adapter has to be the real
# one — a bare mock store would swallow the very thing being tested. Only the
# library beneath it is replaced.


def _sieve_client(**client_attrs):
    client = managesieve_client.SieveClient(_session(), Settings())
    client._client = MagicMock(**{"getscript.return_value": ("OK", {}, "keep;\n"), **client_attrs})
    return client


def _imap_client(**conn_attrs):
    client = ImapFolderStore(_session(), Settings())
    client._conn = MagicMock(
        **{
            "create.return_value": ("OK", [b"created"]),
            "subscribe.return_value": ("OK", [b"subscribed"]),
            **conn_attrs,
        }
    )
    return client


SINKS = [
    pytest.param(
        lambda c, n: c.get_script(n),
        _sieve_client,
        lambda c: c._client.getscript.assert_not_called(),
        id="sieve-get_script",
    ),
    pytest.param(
        lambda c, n: c.put_script(n, "keep;\n"),
        _sieve_client,
        lambda c: c._client.putscript.assert_not_called(),
        id="sieve-put_script",
    ),
    pytest.param(
        lambda c, n: c.activate_script(n),
        _sieve_client,
        lambda c: c._client.setactive.assert_not_called(),
        id="sieve-activate_script",
    ),
    pytest.param(
        lambda c, n: c.delete_script(n),
        _sieve_client,
        lambda c: c._client.deletescript.assert_not_called(),
        id="sieve-delete_script",
    ),
    pytest.param(
        lambda c, n: c.create_folder(n),
        _imap_client,
        lambda c: (c._conn.create.assert_not_called(), c._conn.subscribe.assert_not_called()),
        id="imap-create_folder",
    ),
]


# ── One payload matrix, every sink ──

INJECTION_PAYLOADS = [
    pytest.param("name\r", id="bare-CR"),
    pytest.param("name\n", id="bare-LF"),
    pytest.param("name\r\n", id="CRLF"),
    pytest.param('name\r\nDELETESCRIPT "primary"', id="CRLF-then-command"),
    pytest.param("name\x00", id="NUL"),
    pytest.param("name\x00LOGOUT", id="NUL-then-command"),
    pytest.param('name"', id="trailing-doublequote"),
    pytest.param('bad" DELETESCRIPT "primary', id="quote-break-then-command"),
    pytest.param('bad"\r\nSETACTIVE "backdoor', id="quote-crlf-backdoor"),
    pytest.param("name\\", id="trailing-backslash"),
    pytest.param('bad\\" DELETESCRIPT "primary', id="escaped-quote-then-command"),
]

BENIGN_NAMES = [
    "primary",
    "backup-2026",
    "MyFilters.sieve",
    "test_script",
    "Archive/2026",
    "INBOX.Sent",
    "INBOX/Sub Folder",
    "list.golang-nuts",
    "\U0001f4e5",  # unicode is fine — only framing characters are forbidden
]


@pytest.mark.parametrize("call,build,assert_untouched", SINKS)
@pytest.mark.parametrize("name", INJECTION_PAYLOADS)
def test_sink_rejects_injection(call, build, assert_untouched, name):
    client = build()
    with pytest.raises(ProtocolNameError, match=r"forbidden|too long|required"):
        call(client, name)
    assert_untouched(client)


@pytest.mark.parametrize("call,build,assert_untouched", SINKS)
def test_sink_rejects_empty_name(call, build, assert_untouched):
    """Empty is both a UX defect and, on some servers, a NO-OP that still
    reaches the wire."""
    client = build()
    with pytest.raises(ProtocolNameError, match="required"):
        call(client, "")
    assert_untouched(client)


@pytest.mark.parametrize("call,build,assert_untouched", SINKS)
@pytest.mark.parametrize("name", BENIGN_NAMES)
def test_sink_accepts_benign(call, build, assert_untouched, name):
    """The guard must not become a false-positive machine. Every sink accepts
    the same benign set, including unicode and hierarchy separators."""
    client = build()
    call(client, name)  # must not raise


# ── Per-sink specifics ──


def test_script_name_length_is_capped():
    """RFC 5804 §1.6 recommends 128 bytes for a script name."""
    client = _sieve_client()
    client.get_script("a" * MAX_SCRIPT_NAME_BYTES)  # exactly at the limit is fine
    with pytest.raises(ProtocolNameError, match="too long"):
        client.get_script("a" * (MAX_SCRIPT_NAME_BYTES + 1))


def test_folder_name_is_not_length_capped_by_the_guard():
    """IMAP sets no limit, and CreateFolderRequest already caps the API
    surface at 200. A second, different limit here would be exactly the
    duplication this module exists to end."""
    client = _imap_client()
    client.create_folder("a" * 500)  # must not raise


def test_benign_names_reach_the_protocol_unchanged():
    """The guard rejects; it must never rewrite."""
    sieve = _sieve_client()
    sieve.put_script("primary", "keep;\n")
    sieve._client.putscript.assert_called_once_with("primary", "keep;\n")

    imap = _imap_client()
    imap.create_folder("Archive/2026")
    imap._conn.create.assert_called_once_with('"Archive/2026"')
    imap._conn.subscribe.assert_called_once_with('"Archive/2026"')


# ── One HTTP mapping, every sink ──


def test_malicious_script_name_is_400_via_the_shared_handler(authed_client):
    """A REAL SieveClient is injected with its sievelib client stubbed, so the
    genuine put_script — and therefore the genuine name guard — runs. A bare
    mock store would swallow the guard under test."""
    with authed_client(script_store=_sieve_client()) as http:
        r = http.post(
            "/api/scripts/import",
            data={"name": 'x"\r\nDELETESCRIPT "primary'},
            files={"file": ("x.sieve", b"keep;\n", "application/sieve")},
        )
    assert r.status_code == 400, r.text
    assert "forbidden" in r.json()["detail"].lower()


def test_malicious_script_name_in_the_url_is_400(authed_client):
    with authed_client(script_store=_sieve_client()) as http:
        r = http.post("/api/scripts/x%22%0D%0ASETACTIVE%20%22backdoor/activate")
    assert r.status_code == 400, r.text


def test_benign_folder_name_still_creates(authed_client):
    """The guard must not cost the happy path. Absorbed from
    test_folders_error_mapping.py, whose other two tests duplicated the
    rejection cases above and whose premise (a local try/except in the
    folders router) no longer exists."""
    with authed_client(folder_store=_imap_client()) as http:
        r = http.post("/api/folders", json={"name": "Archive/2026"})
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "name": "Archive/2026"}


def test_malicious_folder_name_is_400_via_the_same_handler(authed_client):
    """REGRESSION: folders.py used to carry its own `except ValueError ->
    HTTPException(400)`. Both sinks now share one app-level handler, and this
    proves removing the local one did not regress the status."""
    with authed_client(folder_store=_imap_client()) as http:
        r = http.post("/api/folders", json={"name": 'Inbox\r\nDELETE "Other"'})
    assert r.status_code == 400, r.text
    assert "forbidden" in r.json()["detail"].lower()
    assert "traceback" not in r.text.lower()
    assert "valueerror" not in r.text.lower()
