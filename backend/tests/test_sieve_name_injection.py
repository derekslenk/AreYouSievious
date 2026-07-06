"""
Regression tests locking in the ManageSieve script-name injection guard
(areyousievious-2j9, F-P0, CWE-77 / CWE-93).

Without a script-name validator in SieveClient.{get,put,activate,delete}_script,
sievelib's upstream `Client.__prepare_args` wraps user-supplied name bytes as
`b'"' + name + b'"'` with ZERO escaping. A name containing CR, LF, NUL, double-
quote, or backslash lets the ManageSieve server interpret the suffix as a
separate command (line-oriented protocol, RFC 5804). Exact same defect class
as the IMAP folder-name injection fixed in areyousievious-sv3 — same defense
pattern applied here.

Sample wire evidence (from PoC, %TEMP%\\opencode\\poc_sievelib_injection.py):
    putscript(name='x"\\r\\nDELETESCRIPT "primary-filter', content='keep;')
    → wire: b'PUTSCRIPT "x"\\r\\nDELETESCRIPT "primary-filter" {6+}\\r\\nkeep;\\n\\r\\n'
    → server parses TWO commands: PUTSCRIPT (fails), DELETESCRIPT (executes)

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_sieve_name_injection.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import managesieve_client
from auth import Session, sessions
from dependencies import SESSION_COOKIE
from sieve_names import ScriptNameError

# `managesieve_client` is looked up dynamically (not `from ... import SieveClient`)
# because `test_managesieve_timeout.py` reloads it — a `from X import Y` would
# freeze the pre-reload reference. `ScriptNameError` lives in `sieve_names`
# which no test reloads, so it can be imported directly.


# ── Direct-sink defense: SieveClient methods raise BEFORE reaching sievelib ──


def _client_with_mock_sievelib():
    """Build a SieveClient with the sievelib inner client stubbed so we can
    exercise the name validator without touching the network. Mirrors
    _client_with_mock_conn() in tests/test_imap_folder.py."""
    session = Session(
        token="t",
        host="sieve.example.com",
        host_ip="93.184.216.34",
        port_imap=993,
        port_sieve=4190,
        username="user@example.com",
        password="hunter2",
        created_at=0.0,
        last_used=0.0,
    )
    client = managesieve_client.SieveClient(session)
    client._client = MagicMock()
    # sievelib.getscript returns tuple; SieveClient.get_script accepts either.
    client._client.getscript.return_value = ("OK", {}, "keep;\n")
    client._client.putscript.return_value = True
    client._client.setactive.return_value = True
    client._client.deletescript.return_value = True
    return client


# Same payload matrix as tests/test_imap_folder.py — same protocol-framing
# class of bug, same defense set. If either payload matrix drifts, both suites
# should drift together — please keep them aligned.
INJECTION_PAYLOADS = [
    pytest.param("script\r", id="bare-CR"),
    pytest.param("script\n", id="bare-LF"),
    pytest.param("script\r\n", id="CRLF"),
    pytest.param('script\r\nDELETESCRIPT "primary"', id="CRLF-then-DELETESCRIPT"),
    pytest.param("script\x00", id="NUL"),
    pytest.param("script\x00LOGOUT", id="NUL-then-command"),
    pytest.param('script"', id="trailing-doublequote"),
    pytest.param('bad" DELETESCRIPT "primary', id="quote-break-then-DELETESCRIPT"),
    pytest.param('bad"\r\nSETACTIVE "backdoor', id="quote-crlf-SETACTIVE-backdoor"),
    pytest.param("script\\", id="trailing-backslash"),
    pytest.param('bad\\" DELETESCRIPT "primary', id="escaped-quote-then-command"),
]


@pytest.mark.parametrize("name", INJECTION_PAYLOADS)
def test_get_script_rejects_injection(name):
    client = _client_with_mock_sievelib()
    with pytest.raises(ScriptNameError, match=r"forbidden|too long|required"):
        client.get_script(name)
    client._client.getscript.assert_not_called()


@pytest.mark.parametrize("name", INJECTION_PAYLOADS)
def test_put_script_rejects_injection(name):
    client = _client_with_mock_sievelib()
    with pytest.raises(ScriptNameError, match=r"forbidden|too long|required"):
        client.put_script(name, "keep;\n")
    client._client.putscript.assert_not_called()


@pytest.mark.parametrize("name", INJECTION_PAYLOADS)
def test_activate_script_rejects_injection(name):
    client = _client_with_mock_sievelib()
    with pytest.raises(ScriptNameError, match=r"forbidden|too long|required"):
        client.activate_script(name)
    client._client.setactive.assert_not_called()


@pytest.mark.parametrize("name", INJECTION_PAYLOADS)
def test_delete_script_rejects_injection(name):
    client = _client_with_mock_sievelib()
    with pytest.raises(ScriptNameError, match=r"forbidden|too long|required"):
        client.delete_script(name)
    client._client.deletescript.assert_not_called()


def test_empty_name_rejected_by_all_sinks():
    """Empty name is both a UX defect and (on some servers) a NO-OP that
    still hits the wire — reject before any sievelib call."""
    for method_name, extra_args in [
        ("get_script", ()),
        ("put_script", ("keep;\n",)),
        ("activate_script", ()),
        ("delete_script", ()),
    ]:
        client = _client_with_mock_sievelib()
        with pytest.raises(ScriptNameError):
            getattr(client, method_name)("", *extra_args)


def test_oversize_name_rejected():
    """RFC 5804 §1.6 recommends 128 bytes for script names; we enforce that
    as the ceiling so an oversized name can't waste ManageSieve socket time."""
    client = _client_with_mock_sievelib()
    huge = "a" * 129
    with pytest.raises(ScriptNameError, match=r"too long|forbidden"):
        client.get_script(huge)
    client._client.getscript.assert_not_called()


# ── Benign names MUST pass through to sievelib unchanged ──

BENIGN_NAMES = [
    "primary",
    "backup-2026",
    "MyFilters.sieve",
    "test_script",
    "list.golang-nuts",
    "\U0001f4e5",  # unicode inbox emoji — only ManageSieve framing chars are forbidden
    "a" * 128,  # exactly at the RFC 5804 limit
]


@pytest.mark.parametrize("name", BENIGN_NAMES)
def test_get_script_accepts_benign(name):
    client = _client_with_mock_sievelib()
    client.get_script(name)
    client._client.getscript.assert_called_once_with(name)


@pytest.mark.parametrize("name", BENIGN_NAMES)
def test_put_script_accepts_benign(name):
    client = _client_with_mock_sievelib()
    client.put_script(name, "keep;\n")
    client._client.putscript.assert_called_once_with(name, "keep;\n")


@pytest.mark.parametrize("name", BENIGN_NAMES)
def test_activate_script_accepts_benign(name):
    client = _client_with_mock_sievelib()
    client.activate_script(name)
    client._client.setactive.assert_called_once_with(name)


@pytest.mark.parametrize("name", BENIGN_NAMES)
def test_delete_script_accepts_benign(name):
    client = _client_with_mock_sievelib()
    client.delete_script(name)
    client._client.deletescript.assert_called_once_with(name)


# ── Router integration: HTTP 400 (not 500) via app.py exception handler ──


def _authed_client_cookies() -> tuple[str, str, dict[str, str]]:
    """Create a real session and matched CSRF cookie so router integration
    tests reach the SieveClient sink. Returns (token, csrf, cookies)."""
    token = sessions.create(
        host="sieve.example.com",
        host_ip="93.184.216.34",
        username="user@example.com",
        password="hunter2",
    )
    csrf_token = "csrf-test-token-value"
    cookies = {SESSION_COOKIE: token, "ays_csrf": csrf_token}
    return token, csrf_token, cookies


def _bypass_sieve_setup(self):
    return self


def _bypass_sieve_teardown(*_args):
    return None


def test_router_returns_400_on_malicious_import_name():
    """POST /api/scripts/import with malicious form-field name — the
    ScriptNameError handler in app.py must map it to HTTP 400.

    Without the handler, the ScriptNameError (a ValueError) would surface
    as HTTP 500 — same defect pattern as F-12 for folders.py.

    We patch SieveClient.__enter__/__exit__ (not the class itself) so the
    REAL put_script method — which now calls _validate_name — actually runs.
    Otherwise a full mock would swallow the guard we're trying to verify.
    """
    import app as app_mod
    from routers import scripts as scripts_mod

    token, csrf, cookies = _authed_client_cookies()
    try:
        malicious_name = 'x"\r\nDELETESCRIPT "primary'
        with (
            patch.object(scripts_mod.SieveClient, "__enter__", _bypass_sieve_setup),
            patch.object(scripts_mod.SieveClient, "__exit__", _bypass_sieve_teardown),
        ):
            with TestClient(app_mod.app, cookies=cookies) as http_client:
                r = http_client.post(
                    "/api/scripts/import",
                    data={"name": malicious_name},
                    files={"file": ("x.sieve", b"keep;\n", "application/sieve")},
                    headers={"X-CSRF-Token": csrf},
                )
        assert r.status_code == 400, (
            f"Expected 400 from ScriptNameError handler, got {r.status_code}: "
            f"{r.text!r} — did the exception_handler get registered in app.py?"
        )
        body = r.json()
        assert "detail" in body
        assert "forbidden" in body["detail"].lower() or "required" in body["detail"].lower()
    finally:
        sessions.destroy(token)


def test_router_returns_400_on_malicious_activate_path():
    """POST /api/scripts/{name}/activate with URL-encoded CRLF in {name}
    must return 400 via the ScriptNameError handler."""
    import app as app_mod
    from routers import scripts as scripts_mod

    token, csrf, cookies = _authed_client_cookies()
    try:
        path = "/api/scripts/x%22%0D%0ASETACTIVE%20%22backdoor/activate"
        with (
            patch.object(scripts_mod.SieveClient, "__enter__", _bypass_sieve_setup),
            patch.object(scripts_mod.SieveClient, "__exit__", _bypass_sieve_teardown),
        ):
            with TestClient(app_mod.app, cookies=cookies) as http_client:
                r = http_client.post(path, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 400, (
            f"Expected 400 from ScriptNameError handler, got {r.status_code}: {r.text!r}"
        )
    finally:
        sessions.destroy(token)
