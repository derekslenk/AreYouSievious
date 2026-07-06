"""
Regression test for the create_folder ValueError -> HTTPException(400)
mapping (areyousievious-twg, F-12, CWE-209).

The IMAP folder CRLF guard at `imap_client.create_folder` (shipped by
areyousievious-sv3) raises `ValueError("Folder name contains forbidden
characters")` for malformed names. The router previously let that
ValueError bubble to Starlette's default 500 handler, exposing a
traceback under `AYS_ENV=dev` and giving users a confusing "Internal
Server Error" for what is really a user-input problem.

This test locks the fix: try/except in the router maps the guard's
ValueError to a clean HTTPException(400) with a readable detail body.
Same pattern applied to F-P0 script-name injection (areyousievious-2j9)
via app-level exception_handler; here we scope the wrap to the specific
handler since the IMAP guard is the only ValueError source in the folders
router path.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_folders_error_mapping.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from auth import sessions
from dependencies import SESSION_COOKIE


def _authed_client_cookies() -> tuple[str, str, dict[str, str]]:
    """Create a real session + matching CSRF cookie so router integration
    tests reach the create_folder handler past middleware."""
    token = sessions.create(
        host="imap.example.com",
        host_ip="93.184.216.34",
        username="user@example.com",
        password="hunter2",
    )
    csrf_token = "csrf-test-token-value"
    cookies = {SESSION_COOKIE: token, "ays_csrf": csrf_token}
    return token, csrf_token, cookies


def _bypass_imap_teardown(*_args):
    return None


def test_create_folder_forbidden_name_returns_400_not_500():
    """F-12 fix: malformed folder name reaches the guard at
    imap_client.create_folder, which raises ValueError. Router MUST catch
    it and return HTTP 400 with a clean detail body, not 500."""
    import app as app_mod
    from routers import folders as folders_mod

    def bypass_and_stub_enter(self):
        self._conn = MagicMock()
        return self

    token, csrf, cookies = _authed_client_cookies()
    try:
        with (
            patch.object(folders_mod.IMAPClient, "__enter__", bypass_and_stub_enter),
            patch.object(folders_mod.IMAPClient, "__exit__", _bypass_imap_teardown),
        ):
            with TestClient(app_mod.app, cookies=cookies) as http_client:
                r = http_client.post(
                    "/api/folders",
                    json={"name": 'Inbox\r\nDELETE "Other"'},
                    headers={"X-CSRF-Token": csrf},
                )
        assert r.status_code == 400, (
            f"Expected 400 from ValueError->HTTPException wrap, got "
            f"{r.status_code}: {r.text!r} -- did the router's try/except get added?"
        )
        body = r.json()
        assert "detail" in body
        assert "forbidden" in body["detail"].lower()
    finally:
        sessions.destroy(token)


def test_create_folder_benign_name_still_works():
    """Regression sanity: the ValueError wrap must not affect the happy path.
    A benign folder name still succeeds with 200 + {"ok": True, "name": ...}."""
    import app as app_mod
    from routers import folders as folders_mod

    def bypass_and_stub_enter(self):
        self._conn = MagicMock()
        self._conn.create.return_value = ("OK", [b"created"])
        self._conn.subscribe.return_value = ("OK", [b"subscribed"])
        return self

    token, csrf, cookies = _authed_client_cookies()
    try:
        with (
            patch.object(folders_mod.IMAPClient, "__enter__", bypass_and_stub_enter),
            patch.object(folders_mod.IMAPClient, "__exit__", _bypass_imap_teardown),
        ):
            with TestClient(app_mod.app, cookies=cookies) as http_client:
                r = http_client.post(
                    "/api/folders",
                    json={"name": "Archive/2026"},
                    headers={"X-CSRF-Token": csrf},
                )
        assert r.status_code == 200, (
            f"Expected 200 for benign name, got {r.status_code}: {r.text!r}"
        )
        body = r.json()
        assert body.get("ok") is True
        assert body.get("name") == "Archive/2026"
    finally:
        sessions.destroy(token)


def test_create_folder_400_response_has_no_traceback():
    """Under AYS_ENV=dev, Starlette exposes tracebacks on 500 responses.
    The fix maps to HTTPException(400) which formats {"detail": ...} with
    NO traceback / class name / raise-chain leak. This test locks that
    (info-disclosure prevention -- CWE-209)."""
    import app as app_mod
    from routers import folders as folders_mod

    def bypass_and_stub_enter(self):
        self._conn = MagicMock()
        return self

    token, csrf, cookies = _authed_client_cookies()
    try:
        with (
            patch.object(folders_mod.IMAPClient, "__enter__", bypass_and_stub_enter),
            patch.object(folders_mod.IMAPClient, "__exit__", _bypass_imap_teardown),
        ):
            with TestClient(app_mod.app, cookies=cookies) as http_client:
                r = http_client.post(
                    "/api/folders",
                    json={"name": "bad\x00null"},
                    headers={"X-CSRF-Token": csrf},
                )
        assert r.status_code == 400
        text_lower = r.text.lower()
        assert "traceback" not in text_lower, r.text
        assert "valueerror" not in text_lower, r.text
    finally:
        sessions.destroy(token)
