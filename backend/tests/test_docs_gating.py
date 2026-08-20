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

import sys
from pathlib import Path

import httpx
import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app import create_app
from config import Settings

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
