"""
Regression tests for the CSRF double-submit-cookie middleware
(areyousievious-oqj, Sec H-6 / CWE-352).

Mounts CSRFMiddleware on a stub FastAPI app so the test is independent
of the production routing graph. The middleware rejects mutating
requests whose `X-CSRF-Token` header doesn't match the `ays_csrf`
cookie; safe methods, non-`/api/*` paths, and `POST /api/auth/login`
are exempt.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_csrf.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from middleware import CSRFMiddleware


@pytest.fixture
def stub_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.post("/api/scripts/test")
    def _post():
        return {"ok": True}

    @app.put("/api/scripts/test")
    def _put():
        return {"ok": True}

    @app.delete("/api/scripts/test")
    def _delete():
        return {"ok": True}

    @app.get("/api/scripts/test")
    def _get():
        return {"ok": True}

    @app.post("/api/auth/login")
    def _login():
        return {"ok": True}

    @app.post("/static/whatever")
    def _static():
        return {"ok": True}

    return app


async def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )


# ── Mutating requests REQUIRE matching cookie+header ──


@pytest.mark.asyncio
async def test_post_without_csrf_pair_returns_403(stub_app):
    async with await _client(stub_app) as client:
        r = await client.post("/api/scripts/test")
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_post_with_cookie_only_returns_403(stub_app):
    """Cookie alone is insufficient — that's exactly what a CSRF attack
    has (browser auto-attaches the cookie). The matching header proves
    the request originated from same-origin JS that COULD read it."""
    async with await _client(stub_app) as client:
        r = await client.post("/api/scripts/test", cookies={"ays_csrf": "abc"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_post_with_header_only_returns_403(stub_app):
    async with await _client(stub_app) as client:
        r = await client.post("/api/scripts/test", headers={"X-CSRF-Token": "abc"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_post_with_mismatched_cookie_and_header_returns_403(stub_app):
    async with await _client(stub_app) as client:
        r = await client.post(
            "/api/scripts/test",
            cookies={"ays_csrf": "real-token"},
            headers={"X-CSRF-Token": "forged-by-attacker"},
        )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_post_with_matching_pair_passes_through(stub_app):
    async with await _client(stub_app) as client:
        r = await client.post(
            "/api/scripts/test",
            cookies={"ays_csrf": "matching-token"},
            headers={"X-CSRF-Token": "matching-token"},
        )
    assert r.status_code == 200


@pytest.mark.parametrize("method", ["put", "delete"])
@pytest.mark.asyncio
async def test_put_delete_also_enforced(stub_app, method):
    async with await _client(stub_app) as client:
        r = await getattr(client, method)("/api/scripts/test")
    assert r.status_code == 403


# ── Exemptions ──


@pytest.mark.asyncio
async def test_safe_method_get_unaffected(stub_app):
    async with await _client(stub_app) as client:
        r = await client.get("/api/scripts/test")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_login_path_exempt(stub_app):
    """Pre-auth: no session yet, so the user can't have the cookie. Login
    is what ISSUES it — chicken-and-egg if we required it here."""
    async with await _client(stub_app) as client:
        r = await client.post("/api/auth/login")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_non_api_path_unaffected(stub_app):
    """SPA static files (`/`, `/assets/…`) live outside /api and have no
    cookies-vs-headers concern — CSRF middleware ignores them."""
    async with await _client(stub_app) as client:
        r = await client.post("/static/whatever")
    assert r.status_code == 200


# ── Constant-time comparison ──


@pytest.mark.asyncio
async def test_comparison_uses_constant_time(stub_app):
    """Sanity: the middleware uses secrets.compare_digest. Tested only
    indirectly — both equal and unequal long tokens behave the same
    response-wise (we'd need timing analysis to truly verify constant
    time, but rejecting the wrong token via the same code path is the
    structural guarantee.)"""
    async with await _client(stub_app) as client:
        ok = await client.post(
            "/api/scripts/test",
            cookies={"ays_csrf": "x" * 64},
            headers={"X-CSRF-Token": "x" * 64},
        )
        bad = await client.post(
            "/api/scripts/test",
            cookies={"ays_csrf": "x" * 64},
            headers={"X-CSRF-Token": "y" * 64},
        )
    assert ok.status_code == 200
    assert bad.status_code == 403
