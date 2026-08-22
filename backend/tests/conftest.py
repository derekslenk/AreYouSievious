"""
Shared fixtures for the backend suite (areyousievious-8fg.2).

The sys.path insert below runs before pytest imports any test module, so it
replaces the preamble every test file used to carry — and the blanket E402
exemption that preamble forced onto pyproject.toml.

Session-creating fixtures destroy their session on teardown: the store is
process-global, so a leaked session outlives its test for the whole run.
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import httpx  # noqa: E402
import pytest  # noqa: E402
from app import create_app  # noqa: E402
from auth import sessions  # noqa: E402
from config import Settings  # noqa: E402
from dependencies import (  # noqa: E402
    SESSION_COOKIE,
    get_folder_store,
    get_script_store,
)
from fastapi.testclient import TestClient  # noqa: E402

# One CSRF literal. Three inline copies had drifted ("csrf-test-token-value"
# twice, "test-csrf-token-value" once) — the value is arbitrary; cookie and
# header matching is what the middleware checks.
CSRF = "csrf-test-token-value"


@pytest.fixture
def make_app():
    """The app factory: build an app from explicit Settings (or defaults).

    dependency_overrides lives on the app object, so a test that needs one
    must build its own app rather than share the ambient `app.app`.
    """
    return create_app


@pytest.fixture
def asgi_client_for():
    """Factory: an httpx.AsyncClient speaking ASGI straight to the given app."""

    def _make(app, **kwargs) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", **kwargs
        )

    return _make


@pytest.fixture
def authed_session():
    """(token, csrf, cookies) for a real session in the process-global store,
    destroyed on teardown."""
    token = sessions.create(
        host="mail.example.com",
        host_ip="93.184.216.34",
        username="user@example.com",
        password="hunter2",
    )
    cookies = {SESSION_COOKIE: token, "ays_csrf": CSRF}
    yield token, CSRF, cookies
    sessions.destroy(token)


@pytest.fixture
def authed_client(authed_session):
    """Factory: a TestClient over a fresh app, session and CSRF preloaded.

    Pass `script_store` / `folder_store` to substitute a seam. They go in
    through `dependency_overrides`, which is why they can be anything with
    the right methods — no patching of SieveClient/ImapFolderStore internals, and
    nothing for the substitute to accidentally inherit.
    """

    def _make(
        settings: Settings | None = None,
        *,
        script_store=None,
        folder_store=None,
    ) -> TestClient:
        _token, csrf, cookies = authed_session
        app = create_app(settings)
        if script_store is not None:
            app.dependency_overrides[get_script_store] = lambda: script_store
        if folder_store is not None:
            app.dependency_overrides[get_folder_store] = lambda: folder_store
        client = TestClient(app, cookies=cookies)
        client.headers["X-CSRF-Token"] = csrf
        return client

    return _make


# ── A real IMAP server on a real socket ──


@pytest.fixture
def imap_server():
    """Factory: a loopback IMAP listener, and the lines the client sent it.

    Some behaviour cannot be observed through a MagicMock, because the thing
    under test is what the LIBRARY does with what we hand it. `imaplib`
    encodes command arguments itself (`bytes(arg, self._encoding)`, ascii by
    default), so a mock conn accepts a folder name that the real one refuses —
    the exact shape of a passing test that means nothing.

    Returns `(connect, sent)`: call `connect(handle=None)` for a real
    `imaplib.IMAP4` already logged in, and read `sent` afterwards for the raw
    bytes that arrived.

    `handle(conn, stream, tag, line)` may answer a command itself. Return
    TRUTHY to say "I replied to this one" — the loop then writes nothing and
    keeps serving. Return None to fall through to a tagged OK. A handler that
    wants the session to end closes `conn`; the next read sees EOF.

    That return value is load-bearing, not a style choice. A handler that
    wrote its own reply and returned None got a SECOND tagged OK appended,
    which imaplib reads as `unexpected tagged response` and turns into an
    abort on the NEXT command — a corrupted session presenting as a
    `MailServerUnavailable` several lines from the cause.

    No TLS and no network: 127.0.0.1 on an ephemeral port, a daemon thread,
    and a timeout on every read so nothing here can hang CI.
    """
    import imaplib
    import socket
    import threading

    timeout = 5.0
    connections: list = []

    def _make(handle=None):
        sent: list[bytes] = []
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(timeout)
        port = listener.getsockname()[1]

        def run() -> None:
            try:
                conn, _ = listener.accept()
            except OSError:
                listener.close()
                return
            conn.settimeout(timeout)
            stream = conn.makefile("rwb")
            stream.write(b"* OK [CAPABILITY IMAP4REV1 AUTH=PLAIN] ready\r\n")
            stream.flush()
            try:
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    sent.append(line)
                    tag = line.split(b" ", 1)[0]
                    if handle is not None and handle(conn, stream, tag, line):
                        continue
                    if b"CAPABILITY" in line.upper():
                        stream.write(b"* CAPABILITY IMAP4REV1\r\n" + tag + b" OK done\r\n")
                    else:
                        stream.write(tag + b" OK done\r\n")
                    stream.flush()
            except OSError:
                pass
            finally:
                for closeable in (conn, listener):
                    try:
                        closeable.close()
                    except OSError:
                        pass

        threading.Thread(target=run, daemon=True).start()
        client = imaplib.IMAP4("127.0.0.1", port, timeout=timeout)
        # Registered BEFORE login: a failed login would otherwise leave the
        # socket and its thread behind, unreachable by the teardown below.
        connections.append(client)
        client.login("user", "pass")
        return client, sent

    yield _make
    for client in connections:
        try:
            client.shutdown()
        except Exception:
            pass
