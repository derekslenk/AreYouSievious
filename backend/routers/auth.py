"""
Authentication router (areyousievious-u40 split from app.py).

Owns POST /api/auth/login, POST /api/auth/logout, GET /api/auth/status
plus every helper they need:
  - in-memory IP-keyed RateLimiter for login throttling.
  - AYS_TRUSTED_PROXIES-aware client-IP resolution (Sec H-7).
  - HTTPS detection for the Secure-cookie flag.

Behavior is byte-identical to the pre-u40 inline handlers in app.py.
"""

from __future__ import annotations

import imaplib
import ipaddress
import os
import ssl
import time
from collections import defaultdict

from api_models import AuthStatusResponse, LoginRequest, OkResponse
from auth import sessions
from dependencies import SESSION_COOKIE, get_session
from fastapi import APIRouter, HTTPException, Request, Response
from imap_client import IMAP_TIMEOUT, TLS_CONTEXT
from middleware import CSRF_COOKIE, generate_csrf_token
from ssrf import assert_host_resolves_to, validate_host

router = APIRouter(prefix="/api/auth")


# ── Rate limiter ──


class RateLimiter:
    """Simple in-memory rate limiter by IP."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str) -> bool:
        """Return True if allowed, False if rate limited."""
        now = time.time()
        attempts = self._attempts[key]
        # Prune old attempts
        self._attempts[key] = [t for t in attempts if now - t < self.window]
        if len(self._attempts[key]) >= self.max_attempts:
            return False
        self._attempts[key].append(now)
        return True


_login_limiter = RateLimiter(max_attempts=5, window_seconds=300)


# ── Rate-limit client-IP detection (areyousievious-jt2) ──


def _parse_trusted_networks() -> list[ipaddress._BaseNetwork]:
    """Parse AYS_TRUSTED_PROXIES (CSV of CIDRs) into a list of networks.

    Invalid entries are silently skipped — operator typo shouldn't take the
    app down. Empty env → empty list → proxy headers are NEVER trusted.
    """
    raw = os.environ.get("AYS_TRUSTED_PROXIES", "").strip()
    networks: list[ipaddress._BaseNetwork] = []
    for cidr in (c.strip() for c in raw.split(",") if c.strip()):
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def _ip_in_networks(ip_str: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in networks)


def _get_client_ip(request: Request) -> str:
    """Determine the rate-limit key (real client IP) honoring AYS_TRUSTED_PROXIES.

    A direct client (no trusted proxy in front) controls its own request
    headers, so X-Forwarded-For / X-Real-IP are spoofable and would let
    any caller bypass the login throttle by rotating fake IPs (Sec H-7).
    We honor those headers ONLY when the immediate peer
    (`request.client.host`) is itself in an AYS_TRUSTED_PROXIES CIDR.

    When trusted, we walk X-Forwarded-For right-to-left, skipping further
    trusted-proxy hops — the first untrusted entry is the real client.
    """
    direct_ip = request.client.host if request.client else "unknown"
    trusted = _parse_trusted_networks()
    if not trusted or not _ip_in_networks(direct_ip, trusted):
        return direct_ip

    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff:
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        for hop in reversed(hops):
            if not _ip_in_networks(hop, trusted):
                return hop
        return hops[0] if hops else direct_ip

    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    return direct_ip


def _is_secure(request: Request) -> bool:
    """Detect if the request arrived over HTTPS (directly or via reverse proxy)."""
    if os.environ.get("AYS_SECURE_COOKIES", "").lower() in ("1", "true", "yes"):
        return True
    proto = request.headers.get("x-forwarded-proto", "")
    return proto == "https"


# ── Routes ──


@router.post("/login", response_model=OkResponse, response_model_exclude_none=True)
def login(req: LoginRequest, request: Request, response: Response):
    """Authenticate with IMAP credentials."""
    client_ip = _get_client_ip(request)
    if not _login_limiter.check(client_ip):
        raise HTTPException(429, "Too many login attempts. Try again in 5 minutes.")

    host_ip = validate_host(req.host)
    assert_host_resolves_to(req.host, host_ip)

    try:
        conn = imaplib.IMAP4_SSL(
            req.host,
            req.port_imap,
            ssl_context=TLS_CONTEXT,
            timeout=IMAP_TIMEOUT,
        )
        conn.login(req.username, req.password)
        conn.logout()
    except imaplib.IMAP4.error:
        raise HTTPException(401, "Authentication failed")  # noqa: B904
    except ssl.SSLCertVerificationError:
        raise HTTPException(502, "Mail server TLS certificate could not be verified")  # noqa: B904
    except Exception:
        raise HTTPException(502, "Cannot connect to mail server")  # noqa: B904

    token = sessions.create(
        host=req.host,
        host_ip=host_ip,
        username=req.username,
        password=req.password,
        port_imap=req.port_imap,
        port_sieve=req.port_sieve,
    )
    secure = _is_secure(request)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        max_age=1800,
        secure=secure,
    )
    response.set_cookie(
        CSRF_COOKIE,
        generate_csrf_token(),
        httponly=False,
        samesite="strict",
        max_age=1800,
        secure=secure,
    )
    return {"ok": True, "username": req.username}


@router.post("/logout", response_model=OkResponse, response_model_exclude_none=True)
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sessions.destroy(token)
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    return {"ok": True}


@router.get("/status", response_model=AuthStatusResponse, response_model_exclude_none=True)
async def auth_status(request: Request):
    try:
        session = get_session(request)
        return {
            "authenticated": True,
            "username": session.username,
            "host": session.host,
        }
    except HTTPException:
        return {"authenticated": False}
