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
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import httpx  # noqa: E402
import pytest  # noqa: E402
from app import create_app  # noqa: E402
from auth import sessions  # noqa: E402
from dependencies import SESSION_COOKIE  # noqa: E402
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
    """Factory: a TestClient over a fresh app, with the session and CSRF
    cookies preloaded and the X-CSRF-Token header preset on every request."""

    def _make(settings=None) -> TestClient:
        _token, csrf, cookies = authed_session
        client = TestClient(create_app(settings), cookies=cookies)
        client.headers["X-CSRF-Token"] = csrf
        return client

    return _make


@pytest.fixture
def sieve_client_passthrough():
    """Neutralise SieveClient's context manager (no network dial) while keeping
    its methods real, so the code under test runs against the actual class.
    Patch a method on top if the test does not want the real one.

    Yields the scripts router module, looked up lazily — a `from X import Y`
    here would freeze a pre-reload reference (test_managesieve_timeout reloads
    modules).
    """
    from routers import scripts as scripts_mod

    with (
        patch.object(scripts_mod.SieveClient, "__enter__", lambda self: self),
        patch.object(scripts_mod.SieveClient, "__exit__", lambda *_a: None),
    ):
        yield scripts_mod
