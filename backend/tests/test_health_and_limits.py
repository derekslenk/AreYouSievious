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

import importlib
import sys
from pathlib import Path

import httpx
import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app import app


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


# ── import cap follows AYS_MAX_BODY_BYTES ──


def _reload_scripts_router():
    import routers.scripts as scripts_mod

    importlib.reload(scripts_mod)
    return scripts_mod


def test_import_cap_defaults_to_1mib(monkeypatch):
    monkeypatch.delenv("AYS_MAX_BODY_BYTES", raising=False)
    mod = _reload_scripts_router()
    assert mod._max_upload_bytes() == 1 * 1024 * 1024


def test_import_cap_follows_env_var(monkeypatch):
    """REGRESSION: this was a hardcoded constant, so an operator who raised
    AYS_MAX_BODY_BYTES got a larger middleware limit and an unchanged import
    limit — the smaller of the two silently won."""
    monkeypatch.setenv("AYS_MAX_BODY_BYTES", str(5 * 1024 * 1024))
    mod = _reload_scripts_router()
    assert mod._max_upload_bytes() == 5 * 1024 * 1024


def test_import_cap_falls_back_on_garbage(monkeypatch):
    """An unparseable value must not take the process down at request time."""
    monkeypatch.setenv("AYS_MAX_BODY_BYTES", "not-a-number")
    mod = _reload_scripts_router()
    assert mod._max_upload_bytes() == 1 * 1024 * 1024


def test_import_cap_matches_middleware_default(monkeypatch):
    """The two limits must agree by construction, not by coincidence: both
    read the same env var with the same default."""
    monkeypatch.delenv("AYS_MAX_BODY_BYTES", raising=False)
    import app as app_mod

    importlib.reload(app_mod)
    mod = _reload_scripts_router()
    assert mod._max_upload_bytes() == app_mod._max_body_bytes
