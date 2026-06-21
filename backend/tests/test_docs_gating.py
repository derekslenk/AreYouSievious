"""
Regression test for the docs/redoc/openapi gating
(areyousievious-y61, Sec M-5).

`AYS_ENV=dev` enables /docs, /redoc, /openapi.json. Anything else
(default `prod`) returns 404 so an attacker can't recon the API
surface from a default deploy.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_docs_gating.py -v
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import httpx
import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))


def _reload_app(env_value: str | None):
    """Reload backend.app under the chosen AYS_ENV value and return the
    FastAPI instance with current gating applied."""
    import os

    if env_value is None:
        os.environ.pop("AYS_ENV", None)
    else:
        os.environ["AYS_ENV"] = env_value
    import app as app_mod

    importlib.reload(app_mod)
    return app_mod


async def _hit(app, path: str) -> int:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get(path)
    return r.status_code


@pytest.mark.asyncio
async def test_prod_default_blocks_docs():
    mod = _reload_app(None)
    try:
        assert await _hit(mod.app, "/docs") == 404
        assert await _hit(mod.app, "/redoc") == 404
        assert await _hit(mod.app, "/openapi.json") == 404
    finally:
        _reload_app(None)


@pytest.mark.asyncio
async def test_prod_explicit_blocks_docs():
    mod = _reload_app("prod")
    try:
        assert await _hit(mod.app, "/docs") == 404
        assert await _hit(mod.app, "/openapi.json") == 404
    finally:
        _reload_app(None)


@pytest.mark.asyncio
async def test_unknown_env_value_treated_as_prod():
    mod = _reload_app("staging")
    try:
        assert await _hit(mod.app, "/docs") == 404
    finally:
        _reload_app(None)


@pytest.mark.asyncio
async def test_dev_env_exposes_docs():
    mod = _reload_app("dev")
    try:
        assert await _hit(mod.app, "/docs") == 200
        assert await _hit(mod.app, "/openapi.json") == 200
    finally:
        _reload_app(None)


@pytest.mark.asyncio
async def test_dev_env_is_case_insensitive():
    mod = _reload_app("DEV")
    try:
        assert await _hit(mod.app, "/docs") == 200
    finally:
        _reload_app(None)
