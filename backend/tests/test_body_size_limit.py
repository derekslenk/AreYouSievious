"""
Regression tests for the request-body size limit middleware
(areyousievious-9a2, Sec H-4 / CWE-770).

Two defences:
  1. Content-Length header check — rejects on the spot when the declared
     size exceeds the cap.
  2. Stream count during receive() — catches missing/lying headers by
     measuring the actual bytes that arrived; we swap the route's
     response for our own 413 in the send-side wrapper.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_body_size_limit.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from middleware import BodySizeLimitMiddleware

CAP = 1024


@pytest.fixture
def stub_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=CAP)

    @app.post("/echo")
    async def _echo(req_body: dict):
        return {"received": len(req_body.get("payload", ""))}

    return app


async def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )


# ── Content-Length declared too large ──


@pytest.mark.asyncio
async def test_oversized_content_length_returns_413(stub_app):
    """A request that declares a body larger than the cap MUST be
    rejected before the route handler sees it."""
    payload = '{"payload":"' + "a" * (CAP * 2) + '"}'
    async with await _client(stub_app) as client:
        r = await client.post(
            "/echo",
            content=payload,
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 413


@pytest.mark.asyncio
async def test_at_cap_passes(stub_app):
    """Exact-cap requests succeed (the middleware uses strict-greater)."""
    inner_len = CAP - len('{"payload":""}')
    payload = '{"payload":"' + "a" * inner_len + '"}'
    assert len(payload) == CAP
    async with await _client(stub_app) as client:
        r = await client.post(
            "/echo",
            content=payload,
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_under_cap_passes(stub_app):
    payload = '{"payload":"hello"}'
    async with await _client(stub_app) as client:
        r = await client.post(
            "/echo",
            content=payload,
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 200


# ── Stream-side enforcement when Content-Length is missing/wrong ──


@pytest.mark.asyncio
async def test_stream_overflow_rejected_when_no_content_length():
    """No Content-Length header (chunked transfer) — middleware counts
    bytes as they arrive and 413s on overflow.

    We test the middleware at the ASGI level so we can omit
    Content-Length cleanly."""
    received_messages: list[dict] = []

    async def downstream(scope, receive, send):
        # If the middleware lets the request through, we'd record it.
        while True:
            msg = await receive()
            received_messages.append(msg)
            if not msg.get("more_body"):
                break
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b"ok",
                "more_body": False,
            }
        )

    middleware = BodySizeLimitMiddleware(downstream, max_bytes=CAP)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [(b"content-type", b"application/json")],
    }

    chunks = iter(
        [
            {"type": "http.request", "body": b"a" * (CAP // 2), "more_body": True},
            {"type": "http.request", "body": b"b" * (CAP // 2 + 5), "more_body": False},
        ]
    )

    async def receive():
        return next(chunks)

    sent_responses: list[dict] = []

    async def send(message):
        sent_responses.append(message)

    await middleware(scope, receive, send)

    statuses = [m["status"] for m in sent_responses if m["type"] == "http.response.start"]
    assert 413 in statuses


@pytest.mark.asyncio
async def test_lying_content_length_does_not_bypass():
    """An attacker claims Content-Length: 10 but sends 100KB of body. The
    declared-length check passes (10 < cap), but the stream count
    catches the overflow."""

    async def downstream(scope, receive, send):
        while True:
            msg = await receive()
            if not msg.get("more_body"):
                break
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [],
            }
        )
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    middleware = BodySizeLimitMiddleware(downstream, max_bytes=CAP)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [(b"content-length", b"10")],
    }

    chunks = iter(
        [
            {"type": "http.request", "body": b"a" * (CAP + 100), "more_body": False},
        ]
    )

    async def receive():
        return next(chunks)

    sent_responses: list[dict] = []

    async def send(message):
        sent_responses.append(message)

    await middleware(scope, receive, send)

    statuses = [m["status"] for m in sent_responses if m["type"] == "http.response.start"]
    assert 413 in statuses


@pytest.mark.asyncio
async def test_non_http_scope_passes_through():
    """WebSocket / lifespan scopes must not be filtered."""
    seen_scope_type: list[str] = []

    async def downstream(scope, receive, send):
        seen_scope_type.append(scope["type"])

    middleware = BodySizeLimitMiddleware(downstream, max_bytes=CAP)

    async def receive():
        return {"type": "websocket.connect"}

    async def send(_message):
        pass

    await middleware({"type": "websocket"}, receive, send)
    assert seen_scope_type == ["websocket"]
