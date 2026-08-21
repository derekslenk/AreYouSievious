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

import pytest
from config import Settings

ALLOWED_ORIGIN = "https://areyousievious.com"


@pytest.fixture
def cors_client(make_app, asgi_client_for):
    """A client against an app whose CORS list is stated outright, rather than
    reached by setting an environment variable and reloading the module."""
    return asgi_client_for(make_app(Settings(cors_origins=(ALLOWED_ORIGIN,))))


@pytest.mark.asyncio
async def test_preflight_for_allowed_method_succeeds(cors_client):
    async with cors_client as client:
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
async def test_preflight_for_disallowed_method_rejected(cors_client):
    """PATCH is not in the explicit allow-list; preflight must not return
    PATCH in Access-Control-Allow-Methods."""
    async with cors_client as client:
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
async def test_preflight_for_disallowed_header_rejected(cors_client):
    """X-Tracker is not in allow_headers; preflight must not list it."""
    async with cors_client as client:
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
async def test_csrf_header_in_allow_list(cors_client):
    """X-CSRF-Token MUST be allowed — the SPA needs to send it to clear
    the CSRF middleware on every mutating call."""
    async with cors_client as client:
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
async def test_credentialed_cors_still_allowed(cors_client):
    """allow_credentials=True survives the tightening so cookie auth works."""
    async with cors_client as client:
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
