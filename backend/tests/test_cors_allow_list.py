"""
Regression test for the tightened CORS allow-lists
(areyousievious-pzl, Sec H-5 / Fwk H-5).

`allow_methods=['*']` + `allow_headers=['*']` with credentialed CORS
expanded the cross-origin attack surface unnecessarily. The fix
replaces both wildcards with explicit allow-lists.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_cors_allow_list.py -v
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import httpx
import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))


def _reload_app():
    os.environ.setdefault("AYS_CORS_ORIGINS", "https://areyousievious.com")
    import app as app_mod

    importlib.reload(app_mod)
    return app_mod


ALLOWED_ORIGIN = "https://areyousievious.com"


@pytest.mark.asyncio
async def test_preflight_for_allowed_method_succeeds():
    mod = _reload_app()
    transport = httpx.ASGITransport(app=mod.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.request(
            "OPTIONS",
            "/api/scripts",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
    assert r.status_code == 200
    assert "GET" in r.headers.get("access-control-allow-methods", "")


@pytest.mark.asyncio
async def test_preflight_for_disallowed_method_rejected():
    """PATCH is not in the explicit allow-list; preflight must not return
    PATCH in Access-Control-Allow-Methods."""
    mod = _reload_app()
    transport = httpx.ASGITransport(app=mod.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.request(
            "OPTIONS",
            "/api/scripts",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "PATCH",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
    allowed = r.headers.get("access-control-allow-methods", "")
    assert "PATCH" not in allowed, (
        f"PATCH leaked into Access-Control-Allow-Methods: {allowed!r} "
        "(did allow_methods regress to ['*']?)"
    )


@pytest.mark.asyncio
async def test_preflight_for_disallowed_header_rejected():
    """X-Tracker is not in allow_headers; preflight must not list it."""
    mod = _reload_app()
    transport = httpx.ASGITransport(app=mod.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.request(
            "OPTIONS",
            "/api/scripts",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-Tracker",
            },
        )
    allowed = r.headers.get("access-control-allow-headers", "")
    assert "X-Tracker" not in allowed.lower(), (
        f"X-Tracker leaked into Access-Control-Allow-Headers: {allowed!r}"
    )


@pytest.mark.asyncio
async def test_csrf_header_in_allow_list():
    """X-CSRF-Token MUST be allowed — the SPA needs to send it to clear
    the CSRF middleware on every mutating call."""
    mod = _reload_app()
    transport = httpx.ASGITransport(app=mod.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.request(
            "OPTIONS",
            "/api/scripts",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-CSRF-Token",
            },
        )
    allowed = r.headers.get("access-control-allow-headers", "").lower()
    assert "x-csrf-token" in allowed, (
        f"X-CSRF-Token NOT in Access-Control-Allow-Headers: {allowed!r}"
    )


@pytest.mark.asyncio
async def test_credentialed_cors_still_allowed():
    """allow_credentials=True survives the tightening so cookie auth works."""
    mod = _reload_app()
    transport = httpx.ASGITransport(app=mod.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.request(
            "OPTIONS",
            "/api/scripts",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
    assert r.headers.get("access-control-allow-credentials") == "true"
