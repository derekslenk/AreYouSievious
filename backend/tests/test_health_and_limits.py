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

import pytest
from config import Settings

from tests.fakes import FakeScriptStore

# ── /healthz ──


@pytest.mark.asyncio
async def test_healthz_is_reachable_without_auth(make_app, asgi_client_for):
    """The probe must not require a session — a health check that needs
    credentials cannot report on a process that has none."""
    async with asgi_client_for(make_app()) as client:
        r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_healthz_is_not_swallowed_by_the_spa_catch_all(make_app, asgi_client_for):
    """REGRESSION: the static router ends with GET /{full_path:path}. If the
    health router is registered after it, /healthz silently becomes a 404 (or
    an index.html) instead of a liveness signal."""
    async with asgi_client_for(make_app()) as client:
        r = await client.get("/healthz")
    assert r.status_code == 200, (
        "/healthz was captured by the SPA catch-all — check include_router order in app.py"
    )
    assert r.headers.get("content-type", "").startswith("application/json")


@pytest.mark.asyncio
async def test_healthz_leaks_no_configuration(make_app, asgi_client_for):
    """The body is deliberately a bare status. A liveness endpoint is
    unauthenticated, so anything it returns is public."""
    async with asgi_client_for(make_app()) as client:
        r = await client.get("/healthz")
    assert set(r.json().keys()) == {"status"}


# ── import cap follows the configured body limit ──
#
# This used to reach for `_max_upload_bytes()` and reload the module, because
# the cap was a module-level constant. It is now a Settings field read from
# `request.app.state.settings`, so these tests exercise the ACTUAL wiring —
# a real request against a real cap — which the previous shape could not do at
# all. AYS_MAX_BODY_BYTES had no test of its wiring for that reason.


def _import_of_size(http, size: int):
    """POST an import of `size` bytes through an already-authed client."""
    return http.post(
        "/api/scripts/import",
        data={"name": "s"},
        files={"file": ("s.sieve", b"a" * size, "application/sieve")},
    )


def test_import_under_the_configured_cap_succeeds(authed_client):
    with authed_client(Settings(max_body_bytes=4096), script_store=FakeScriptStore()) as http:
        assert _import_of_size(http, 1000).status_code == 200


def test_import_over_the_configured_cap_is_413(authed_client):
    """A raised cap must actually raise the import limit — the whole point.
    Previously the route hardcoded 1 MiB while the middleware read the env var,
    so the smaller of the two silently won."""
    with authed_client(Settings(max_body_bytes=4096), script_store=FakeScriptStore()) as http:
        r = _import_of_size(http, 5000)
        assert r.status_code == 413, r.text


def test_a_raised_cap_admits_a_body_the_default_would_reject(authed_client):
    """Regression for the two-limits-disagree bug, stated as behaviour: a body
    larger than the 1 MiB default is accepted when the cap is raised."""
    with authed_client(
        Settings(max_body_bytes=4 * 1024 * 1024), script_store=FakeScriptStore()
    ) as http:
        r = _import_of_size(http, 2 * 1024 * 1024)
        assert r.status_code == 200, r.text


def test_body_limit_defaults_to_1mib():
    assert Settings().max_body_bytes == 1 * 1024 * 1024


def test_body_limit_reads_the_env_var(monkeypatch):
    monkeypatch.setenv("AYS_MAX_BODY_BYTES", str(5 * 1024 * 1024))
    assert Settings.from_env().max_body_bytes == 5 * 1024 * 1024


def test_body_limit_falls_back_on_garbage(monkeypatch):
    monkeypatch.setenv("AYS_MAX_BODY_BYTES", "not-a-number")
    assert Settings.from_env().max_body_bytes == 1 * 1024 * 1024
