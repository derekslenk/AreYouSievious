"""
Tests for the liveness endpoint and the import size cap.

Both were bugs of omission rather than logic:

  - `routers/health.py` declared an APIRouter that `app.py` never included, so
    it was unreachable code and the Dockerfile probed `/api/auth/status`
    instead — an endpoint that runs session lookup and answers 200 regardless.
  - `routers/scripts.py` hardcoded a 1 MiB import cap while the body-size
    middleware read `AYS_MAX_BODY_BYTES`, so raising the env var left imports
    capped at the old value.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_health_and_limits.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app import app
from auth import sessions
from config import Settings
from dependencies import SESSION_COOKIE


async def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


# ── /healthz ──


@pytest.mark.asyncio
async def test_healthz_is_reachable_without_auth():
    """The probe must not require a session — a health check that needs
    credentials cannot report on a process that has none."""
    async with await _client() as client:
        r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_healthz_is_not_swallowed_by_the_spa_catch_all():
    """REGRESSION: the static router ends with GET /{full_path:path}. If the
    health router is registered after it, /healthz silently becomes a 404 (or
    an index.html) instead of a liveness signal."""
    async with await _client() as client:
        r = await client.get("/healthz")
    assert r.status_code == 200, (
        "/healthz was captured by the SPA catch-all — check include_router order in app.py"
    )
    assert r.headers.get("content-type", "").startswith("application/json")


@pytest.mark.asyncio
async def test_healthz_leaks_no_configuration():
    """The body is deliberately a bare status. A liveness endpoint is
    unauthenticated, so anything it returns is public."""
    async with await _client() as client:
        r = await client.get("/healthz")
    assert set(r.json().keys()) == {"status"}


# ── import cap follows the configured body limit ──
#
# This used to reach for `_max_upload_bytes()` and reload the module, because
# the cap was a module-level constant. It is now a Settings field read from
# `request.app.state.settings`, so these tests exercise the ACTUAL wiring —
# a real request against a real cap — which the previous shape could not do at
# all. AYS_MAX_BODY_BYTES had no test of its wiring for that reason.


def _authed_app(cfg: Settings):
    from app import create_app

    token = sessions.create(
        host="mail.example.com",
        host_ip="93.184.216.34",
        username="u",
        password="p",
    )
    csrf = "csrf-test-token-value"
    cookies = {SESSION_COOKIE: token, "ays_csrf": csrf}
    return create_app(cfg), token, csrf, cookies


def _import_of_size(app, csrf, cookies, size: int):
    from routers import scripts as scripts_mod

    def _enter(self):
        return self

    def _exit(*_a):
        return None

    with (
        patch.object(scripts_mod.SieveClient, "__enter__", _enter),
        patch.object(scripts_mod.SieveClient, "__exit__", _exit),
        patch.object(scripts_mod.SieveClient, "put_script", lambda self, n, c: None),
    ):
        with TestClient(app, cookies=cookies) as http:
            return http.post(
                "/api/scripts/import",
                data={"name": "s"},
                files={"file": ("s.sieve", b"a" * size, "application/sieve")},
                headers={"X-CSRF-Token": csrf},
            )


def test_import_under_the_configured_cap_succeeds():
    app, token, csrf, cookies = _authed_app(Settings(max_body_bytes=4096))
    try:
        assert _import_of_size(app, csrf, cookies, 1000).status_code == 200
    finally:
        sessions.destroy(token)


def test_import_over_the_configured_cap_is_413():
    """A raised cap must actually raise the import limit — the whole point.
    Previously the route hardcoded 1 MiB while the middleware read the env var,
    so the smaller of the two silently won."""
    app, token, csrf, cookies = _authed_app(Settings(max_body_bytes=4096))
    try:
        r = _import_of_size(app, csrf, cookies, 5000)
        assert r.status_code == 413, r.text
    finally:
        sessions.destroy(token)


def test_a_raised_cap_admits_a_body_the_default_would_reject():
    """Regression for the two-limits-disagree bug, stated as behaviour: a body
    larger than the 1 MiB default is accepted when the cap is raised."""
    big = Settings(max_body_bytes=4 * 1024 * 1024)
    app, token, csrf, cookies = _authed_app(big)
    try:
        r = _import_of_size(app, csrf, cookies, 2 * 1024 * 1024)
        assert r.status_code == 200, r.text
    finally:
        sessions.destroy(token)


def test_body_limit_defaults_to_1mib():
    assert Settings().max_body_bytes == 1 * 1024 * 1024


def test_body_limit_reads_the_env_var(monkeypatch):
    monkeypatch.setenv("AYS_MAX_BODY_BYTES", str(5 * 1024 * 1024))
    assert Settings.from_env().max_body_bytes == 5 * 1024 * 1024


def test_body_limit_falls_back_on_garbage(monkeypatch):
    monkeypatch.setenv("AYS_MAX_BODY_BYTES", "not-a-number")
    assert Settings.from_env().max_body_bytes == 1 * 1024 * 1024
