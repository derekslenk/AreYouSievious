"""
Regression test locking path-traversal containment on the SPA
catch-all route (areyousievious-3ok).

`serve_frontend` accepts a fully user-controlled `{full_path:path}`
and joins it onto the static directory. Escapes are stopped by two
DIFFERENT layers, which produce two DIFFERENT status codes:

  1. Starlette normalizes the request path before routing, so raw
     `../` and `....//` collapse and never reach the handler. They
     arrive as an ordinary miss and fall through to the SPA fallback
     (200 + index.html).
  2. Percent-encoded variants (`%2e%2e/`, `%252e%252e/`, `..%2f`)
     survive normalization and reach the handler as literal `..`
     segments. `resolve() + relative_to()` catches those and returns
     403.

Both layers are pinned here on purpose. The asymmetry looks like a
bug at a glance, and a well-meaning "make traversal always 404"
change would either break the SPA fallback or paper over layer 1.

The invariant that actually matters is the leak assert: no payload,
by any route, may return the contents of a file outside static_dir.

Before this test the guard's only evidence of correctness was an
untracked audit artifact, which is to say: none.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_static_traversal.py -v
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from routers import static as static_router_mod
from routers.static import router as static_router

SECRET = "traversal-canary-do-not-leak"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    """Serve tmp_path/public, with a secret file planted one level above it."""
    public = tmp_path / "public"
    public.mkdir()
    (public / "index.html").write_text("<!doctype html>SPA")
    (public / "app.js").write_text("console.log('real asset')")
    (tmp_path / "secret.txt").write_text(SECRET)

    previous = static_router_mod.static_dir
    static_router_mod.configure(public)

    app = FastAPI()
    app.include_router(static_router)
    try:
        yield TestClient(app)
    finally:
        static_router_mod.configure(previous)


# Payloads that Starlette collapses before routing. The escape never
# happens, so these land on the SPA fallback rather than the guard.
NORMALIZED_AWAY = [
    "../secret.txt",
    "../../secret.txt",
    "../../../../../../etc/passwd",
    "....//secret.txt",
    "/etc/passwd",
]

# Payloads that survive normalization and must be caught by the
# resolve() + relative_to() containment check inside the handler.
REACHES_GUARD = [
    "%2e%2e/secret.txt",
    "%2e%2e%2fsecret.txt",
    "%252e%252e/secret.txt",
    "..%2fsecret.txt",
    "..%252fsecret.txt",
]

ALL_PAYLOADS = NORMALIZED_AWAY + REACHES_GUARD


@pytest.mark.parametrize("payload", ALL_PAYLOADS)
def test_traversal_payload_never_leaks_outside_static_dir(client: TestClient, payload: str):
    """The one invariant that matters: nothing outside static_dir comes back."""
    r = client.get(f"/{payload}")
    assert SECRET not in r.text, (
        f"{payload!r} leaked a file outside static_dir (HTTP {r.status_code})"
    )


@pytest.mark.parametrize("payload", NORMALIZED_AWAY)
def test_normalized_payloads_fall_through_to_spa_fallback(client: TestClient, payload: str):
    """Layer 1: Starlette already collapsed these, so they are just unknown routes."""
    r = client.get(f"/{payload}")
    assert r.status_code == 200, f"{payload!r} → {r.status_code}, expected SPA fallback"
    assert "SPA" in r.text


@pytest.mark.parametrize("payload", REACHES_GUARD)
def test_encoded_payloads_are_rejected_by_the_containment_check(client: TestClient, payload: str):
    """Layer 2: these reach the handler as literal `..` and must be refused."""
    r = client.get(f"/{payload}")
    assert r.status_code == 403, (
        f"{payload!r} → {r.status_code}, expected 403 from relative_to() guard"
    )


def test_real_asset_is_served(client: TestClient):
    """Control: containment must not break ordinary static serving."""
    r = client.get("/app.js")
    assert r.status_code == 200
    assert "real asset" in r.text


def test_unknown_route_serves_index_for_client_side_routing(client: TestClient):
    """Control: the SPA fallback still works for genuine client-side routes."""
    r = client.get("/dashboard/rule/42")
    assert r.status_code == 200
    assert "SPA" in r.text


def test_returns_404_when_no_static_dir_configured():
    """With no --static flag the router serves nothing at all."""
    previous = static_router_mod.static_dir
    static_router_mod.configure(None)
    app = FastAPI()
    app.include_router(static_router)
    try:
        assert TestClient(app).get("/anything").status_code == 404
    finally:
        static_router_mod.configure(previous)
