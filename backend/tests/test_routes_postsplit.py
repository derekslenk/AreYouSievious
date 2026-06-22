"""
Regression test locking the FastAPI route surface across the
backend/app.py → backend/routers/* split (areyousievious-u40).

Two angles:
  1. Route REGISTRY introspection — every (method, path) currently
     declared on `app.routes` must still appear after the refactor.
     A dropped route is the most expensive bug we could ship; the
     introspection assert catches it the moment a router fails to
     register.
  2. HTTP STATUS round-trip — every public endpoint, hit with no
     session, returns the exact status it returned pre-refactor.
     CSRF-protected mutating routes return 403 (CSRF check runs
     before auth); CSRF-exempt safe-GET routes return 401 when
     they need auth, 200 for /api/auth/status (which never raises),
     and 404 for the SPA fallback when no static_dir is configured.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_routes_postsplit.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from fastapi.routing import APIRoute

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app import app

# ── Expected route surface (the contract this refactor must preserve) ──

EXPECTED_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        # Auth
        ("POST", "/api/auth/login"),
        ("POST", "/api/auth/logout"),
        ("GET", "/api/auth/status"),
        # Scripts
        ("GET", "/api/scripts"),
        ("GET", "/api/scripts/{name}"),
        ("GET", "/api/scripts/{name}/raw"),
        ("GET", "/api/scripts/{name}/export"),
        ("POST", "/api/scripts/import"),
        ("PUT", "/api/scripts/{name}"),
        ("PUT", "/api/scripts/{name}/raw"),
        ("POST", "/api/scripts/{name}/activate"),
        ("DELETE", "/api/scripts/{name}"),
        # Folders
        ("GET", "/api/folders"),
        ("POST", "/api/folders"),
        # SPA fallback (catch-all)
        ("GET", "/{full_path:path}"),
    }
)


def _registered_routes() -> set[tuple[str, str]]:
    """Return every (method, path) pair currently mounted on the app."""
    pairs: set[tuple[str, str]] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods or set():
            if method in {"HEAD", "OPTIONS"}:
                continue
            pairs.add((method, route.path))
    return pairs


def test_every_expected_route_is_registered():
    """REGRESSION LOCK: if a router drops a handler or a path moves,
    this assert names the missing pair explicitly."""
    registered = _registered_routes()
    missing = EXPECTED_ROUTES - registered
    assert not missing, f"Routes vanished from app.routes: {sorted(missing)}"


def test_no_unexpected_routes_appeared():
    """Symmetric guard: if the refactor silently ADDS a route (e.g. a
    new debug endpoint), surface it so the maintainer chooses whether
    to widen EXPECTED_ROUTES on purpose."""
    registered = _registered_routes()
    extra = registered - EXPECTED_ROUTES
    assert not extra, f"Unexpected routes registered: {sorted(extra)}"


# ── HTTP status round-trip ──


async def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )


# Safe GETs (no CSRF check). Auth-required routes return 401, status
# returns 200 (it swallows HTTPException and reports authenticated=false),
# SPA fallback returns 404 when no static_dir is set.
@pytest.mark.parametrize(
    "path,expected",
    [
        ("/api/auth/status", 200),
        ("/api/scripts", 401),
        ("/api/scripts/whatever", 401),
        ("/api/scripts/whatever/raw", 401),
        ("/api/scripts/whatever/export", 401),
        ("/api/folders", 401),
        ("/", 404),
        ("/some-spa-deeplink", 404),
    ],
)
@pytest.mark.asyncio
async def test_get_route_status(path: str, expected: int):
    async with await _client() as client:
        r = await client.get(path)
    assert r.status_code == expected, f"GET {path} → {r.status_code} (expected {expected})"


# CSRF-protected mutating routes return 403 BEFORE auth check when no
# CSRF cookie+header is supplied — the middleware runs first.
@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/auth/logout"),
        ("POST", "/api/scripts/import"),
        ("PUT", "/api/scripts/whatever"),
        ("PUT", "/api/scripts/whatever/raw"),
        ("POST", "/api/scripts/whatever/activate"),
        ("DELETE", "/api/scripts/whatever"),
        ("POST", "/api/folders"),
    ],
)
@pytest.mark.asyncio
async def test_csrf_protected_route_returns_403(method: str, path: str):
    async with await _client() as client:
        r = await client.request(method, path)
    assert r.status_code == 403, (
        f"{method} {path} → {r.status_code} (expected 403 from CSRF middleware)"
    )


# /api/auth/login is CSRF-exempt (chicken-and-egg). With an empty body
# Pydantic rejects it → 422. The point is the route IS reachable past
# CSRF middleware, which is the regression we're locking.
@pytest.mark.asyncio
async def test_login_route_reachable_past_csrf():
    async with await _client() as client:
        r = await client.post("/api/auth/login", json={})
    assert r.status_code == 422, (
        f"POST /api/auth/login → {r.status_code} (expected 422 from empty body)"
    )
