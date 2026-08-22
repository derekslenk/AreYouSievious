"""
Gating for /docs, /redoc and /openapi.json (areyousievious-y61, Sec M-5).

`AYS_ENV=dev` exposes them; anything else — including the default and a typo
like `staging` — returns 404, so a default deploy does not hand an attacker a
map of the API.

This used to reload the app module ten times and mutate os.environ directly,
because the gate was computed at import. It now builds an app from an explicit
Settings.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_docs_gating.py -v
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from app import create_app
from config import Settings
from routers import static as static_router_mod

DOC_PATHS = ["/docs", "/redoc", "/openapi.json"]


async def _status(app, path: str) -> int:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get(path)
    return r.status_code


@pytest.mark.parametrize("env", ["prod", "", "staging", "develop", "DEVELOPMENT"])
@pytest.mark.parametrize("path", DOC_PATHS)
@pytest.mark.asyncio
async def test_non_dev_env_blocks_docs(env: str, path: str):
    """Only an exact `dev` opens the docs. A near-miss fails closed."""
    app = create_app(Settings(env=env))
    assert await _status(app, path) == 404


@pytest.mark.parametrize("path", DOC_PATHS)
@pytest.mark.asyncio
async def test_dev_env_exposes_docs(path: str):
    app = create_app(Settings(env="dev"))
    assert await _status(app, path) == 200


@pytest.mark.parametrize("env", ["dev", "DEV", " Dev "])
@pytest.mark.asyncio
async def test_dev_detection_is_case_and_space_insensitive(env: str):
    app = create_app(Settings(env=env))
    assert await _status(app, "/docs") == 200


@pytest.mark.asyncio
async def test_default_settings_block_docs():
    """The default — what a deploy gets with no AYS_ENV set at all."""
    app = create_app(Settings())
    assert await _status(app, "/openapi.json") == 404


# ── The shape a deploy actually runs in (docs/DEPLOY.md) ──


@pytest.mark.parametrize("path", DOC_PATHS)
@pytest.mark.asyncio
async def test_the_schema_is_still_withheld_when_the_spa_is_served(
    path: str, tmp_path: Path
) -> None:
    """Every test above builds an app with NO static directory, and asserts a
    404. A DEPLOYED app serves the SPA, and its catch-all
    `GET /{full_path:path}` answers anything unmatched — so in production
    these paths come back 200 with the SPA shell, not 404.

    Found by running the container rather than the suite: `AYS_ENV=prod` and
    `curl /openapi.json` gave `200 text/html`, which read like a gate failure
    and was not one. The gate holds; the STATUS CODE just cannot be what says
    so once a catch-all exists.

    So this asserts the property the 404 was standing in for: whatever comes
    back, it is not the schema. A status-code assertion that stops being true
    the moment the app is deployed is a test whose green means less than it
    appears.
    """
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<!doctype html><title>spa</title>")

    static_router_mod.configure(static_dir)
    try:
        app = create_app(Settings(env="prod"))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get(path)
    finally:
        static_router_mod.configure(None)

    assert r.status_code == 200, "the SPA catch-all answers, which is the point"
    assert "text/html" in r.headers["content-type"]
    assert "spa" in r.text
    for leaked in ("openapi", "swagger", "redoc", '"paths"'):
        assert leaked not in r.text.lower(), f"{path} leaked {leaked!r}"


@pytest.mark.asyncio
async def test_dev_still_serves_the_real_schema_past_the_catch_all(tmp_path: Path) -> None:
    """The other half: with a static dir configured, `dev` must still reach
    the REAL schema rather than being swallowed by the catch-all. Route order
    is what decides that, and route order is easy to change by accident."""
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<!doctype html><title>spa</title>")

    static_router_mod.configure(static_dir)
    try:
        app = create_app(Settings(env="dev"))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/openapi.json")
    finally:
        static_router_mod.configure(None)

    assert r.status_code == 200
    assert "application/json" in r.headers["content-type"]
    assert "paths" in r.json()
