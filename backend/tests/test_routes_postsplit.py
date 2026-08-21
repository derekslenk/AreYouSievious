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

import pytest
from fastapi.routing import APIRoute

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
        # Health
        ("GET", "/healthz"),
        # SPA fallback (catch-all)
        ("GET", "/{full_path:path}"),
    }
)


@pytest.fixture
def app(make_app):
    """This module's own app — route introspection needs the object itself."""
    return make_app()


def _flatten_routes(routes):
    """Yield every APIRoute, descending through FastAPI's _IncludedRouter
    wrappers. FastAPI wraps include_router() calls in a _IncludedRouter
    whenever middleware was added before the include — the actual
    APIRoute instances live on `wrapper.original_router.routes`."""
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            yield from _flatten_routes(original.routes)
        else:
            yield route


def _registered_routes(app) -> set[tuple[str, str]]:
    """Return every (method, path) pair currently mounted on the app."""
    pairs: set[tuple[str, str]] = set()
    for route in _flatten_routes(app.routes):
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods or set():
            if method in {"HEAD", "OPTIONS"}:
                continue
            pairs.add((method, route.path))
    return pairs


def test_every_expected_route_is_registered(app):
    """REGRESSION LOCK: if a router drops a handler or a path moves,
    this assert names the missing pair explicitly."""
    registered = _registered_routes(app)
    missing = EXPECTED_ROUTES - registered
    assert not missing, f"Routes vanished from app.routes: {sorted(missing)}"


def test_no_unexpected_routes_appeared(app):
    """Symmetric guard: if the refactor silently ADDS a route (e.g. a
    new debug endpoint), surface it so the maintainer chooses whether
    to widen EXPECTED_ROUTES on purpose."""
    registered = _registered_routes(app)
    extra = registered - EXPECTED_ROUTES
    assert not extra, f"Unexpected routes registered: {sorted(extra)}"


# ── HTTP status round-trip ──


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
        # Liveness: unauthenticated by design, and registered before the SPA
        # catch-all — if it were registered after, this would be a 404.
        ("/healthz", 200),
        ("/", 404),
        ("/some-spa-deeplink", 404),
    ],
)
@pytest.mark.asyncio
async def test_get_route_status(path: str, expected: int, app, asgi_client_for):
    async with asgi_client_for(app) as client:
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
async def test_csrf_protected_route_returns_403(method: str, path: str, app, asgi_client_for):
    async with asgi_client_for(app) as client:
        r = await client.request(method, path)
    assert r.status_code == 403, (
        f"{method} {path} → {r.status_code} (expected 403 from CSRF middleware)"
    )


# /api/auth/login is CSRF-exempt (chicken-and-egg). With an empty body
# Pydantic rejects it → 422. The point is the route IS reachable past
# CSRF middleware, which is the regression we're locking.
@pytest.mark.asyncio
async def test_login_route_reachable_past_csrf(app, asgi_client_for):
    async with asgi_client_for(app) as client:
        r = await client.post("/api/auth/login", json={})
    assert r.status_code == 422, (
        f"POST /api/auth/login → {r.status_code} (expected 422 from empty body)"
    )


# ── /api/auth/status reports, it does not gate (areyousievious-8fg.7) ──


def test_status_reports_an_authenticated_session(authed_client):
    """The authenticated arm of `get_optional_session`.

    This endpoint answers rather than 401s, so it takes the optional session
    dependency — it used to call `get_session` inside the handler and catch
    the HTTPException, which is the reach-out the seam work removed.
    """
    with authed_client() as http:
        r = http.get("/api/auth/status")
    assert r.status_code == 200
    assert r.json()["authenticated"] is True
    assert r.json()["username"] == "user@example.com"


def test_status_reports_no_session_without_raising(app, asgi_client_for):
    import anyio

    async def _call():
        async with asgi_client_for(app) as client:
            return await client.get("/api/auth/status")

    r = anyio.run(_call)
    assert r.status_code == 200
    assert r.json() == {"authenticated": False}
