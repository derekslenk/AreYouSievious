"""
Custom ASGI middleware for body-size limiting and CSRF protection
(areyousievious-9a2 / areyousievious-oqj).

Both run BEFORE the route so a rejected request never touches the
authenticated app surface — auth + Sieve clients + IMAP connect.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable

Scope = dict
Message = dict
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


CSRF_COOKIE = "ays_csrf"
CSRF_HEADER = "x-csrf-token"


def generate_csrf_token() -> str:
    """Cryptographically-random 32-byte URL-safe token for the
    double-submit cookie. Same entropy budget as the session token."""
    return secrets.token_urlsafe(32)


class BodySizeLimitMiddleware:
    """Reject requests whose body exceeds `max_bytes`.

    Two checks (Sec H-4 / CWE-770):
      1. Declared Content-Length larger than the cap → immediate 413.
      2. Stream count during receive() so a missing or lying header
         can't bypass the cap — once we cross the limit we swap the
         app's response for our own 413 in the send-side wrapper.
    """

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        await _send_plain(send, 413, b"Request body too large")
                        return
                except ValueError:
                    pass
                break

        received = 0
        rejected = False

        async def safe_receive() -> Message:
            nonlocal received, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    rejected = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        sent_413_start = False

        async def safe_send(message: Message) -> None:
            nonlocal sent_413_start
            if not rejected:
                await send(message)
                return
            kind = message.get("type")
            if kind == "http.response.start" and not sent_413_start:
                sent_413_start = True
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                    }
                )
                return
            if kind == "http.response.body":
                await send(
                    {
                        "type": "http.response.body",
                        "body": b"Request body too large",
                        "more_body": False,
                    }
                )
                return

        await self.app(scope, safe_receive, safe_send)


class CSRFMiddleware:
    """Double-submit cookie CSRF protection (Sec H-6 / CWE-352).

    On login the server sets `ays_csrf` as a NON-httponly cookie with a
    fresh random token. The SPA reads the cookie via JavaScript and
    sends it back as `X-CSRF-Token` on every mutating request. A
    cross-origin attacker's page CANNOT read the cookie (same-origin
    policy) so they cannot forge the matching header — even though the
    browser auto-attaches the cookie. Mismatch ⇒ 403.

    Exemptions:
      - safe methods (`GET`/`HEAD`/`OPTIONS`) — never state-changing.
      - non-`/api/*` paths — static SPA files, no app surface.
      - `POST /api/auth/login` — pre-auth: there's no session yet, so
        the user CAN'T have the cookie; login itself issues it.
    """

    SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
    EXEMPT_PATHS = frozenset({"/api/auth/login"})

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")

        if method in self.SAFE_METHODS:
            await self.app(scope, receive, send)
            return
        if not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return
        if path in self.EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        cookie_token = _cookie_value(scope, CSRF_COOKIE)
        header_token = _header_value(scope, CSRF_HEADER)

        if not cookie_token or not header_token:
            await _send_plain(send, 403, b"CSRF token missing")
            return
        if not secrets.compare_digest(cookie_token, header_token):
            await _send_plain(send, 403, b"CSRF token mismatch")
            return

        await self.app(scope, receive, send)


# ── helpers ──


async def _send_plain(send: Send, status: int, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        }
    )


def _cookie_value(scope: Scope, name: str) -> str:
    for hname, hvalue in scope.get("headers", []):
        if hname == b"cookie":
            for pair in hvalue.decode("ascii", errors="ignore").split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    if k == name:
                        return v
    return ""


def _header_value(scope: Scope, name: str) -> str:
    needle = name.lower().encode("ascii")
    for hname, hvalue in scope.get("headers", []):
        if hname == needle:
            return hvalue.decode("ascii", errors="ignore")
    return ""
