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

import ipaddress
import math
import time
from collections import defaultdict

from api_models import AuthStatusResponse, LoginRequest, OkResponse
from auth import Session, SessionManager
from config import Settings
from dependencies import SESSION_COOKIE, get_optional_session, get_sessions, get_settings
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from imap_store import verify_credentials
from middleware import CSRF_COOKIE, generate_csrf_token
from ssrf import validate_host

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


def _ip_in_networks(ip_str: str, networks) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in networks)


def _get_client_ip(request: Request, cfg: Settings) -> str:
    """Determine the rate-limit key (real client IP) honoring AYS_TRUSTED_PROXIES.

    A direct client (no trusted proxy in front) controls its own request
    headers, so X-Forwarded-For / X-Real-IP are spoofable and would let
    any caller bypass the login throttle by rotating fake IPs (Sec H-7).
    We honor those headers ONLY when the immediate peer
    (`request.client.host`) is itself in an AYS_TRUSTED_PROXIES CIDR.

    Precedence when the peer is trusted (areyousievious-1vp / F-10):
      1. `X-Real-IP` — trusted proxies set this from `$remote_addr`, so the
         client cannot spoof it. Preferred whenever present.
      2. `X-Forwarded-For` walk right-to-left, skipping further trusted-proxy
         hops. Only safe when the proxy sanitises XFF via
         `$proxy_add_x_forwarded_for`; sloppy configs (HAProxy transparent,
         `X-Forwarded-For $http_x_forwarded_for`) pass attacker-supplied
         values through unchanged, so the first untrusted hop can be
         attacker-chosen. Kept as a fallback for deployments that only
         forward XFF.
      3. `direct_ip` — the trusted proxy itself. Safe default when no
         forwarding header is present or the loop exhausts all trusted hops.
    """
    direct_ip = request.client.host if request.client else "unknown"
    trusted = cfg.trusted_proxies
    if not trusted or not _ip_in_networks(direct_ip, trusted):
        return direct_ip

    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip

    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff:
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        for hop in reversed(hops):
            if not _ip_in_networks(hop, trusted):
                return hop
        return direct_ip

    return direct_ip


def _is_secure(request: Request, cfg: Settings) -> bool:
    """Detect if the request arrived over HTTPS (directly or via reverse proxy).

    F-2 fix (areyousievious-av5 / CWE-290 + CWE-346): the previous
    implementation trusted `X-Forwarded-Proto` from ANY client, so an
    attacker over HTTP could send `X-Forwarded-Proto: https` to force
    Secure cookies (self-DoS: browser refuses to send Secure cookies over
    HTTP -> session breaks after login). Mirror `_get_client_ip`'s
    trusted-proxy gate: honor the header only when the immediate peer is
    in an AYS_TRUSTED_PROXIES CIDR.

    `AYS_SECURE_COOKIES=1|true|yes` still forces True regardless of peer,
    as the deploy escape hatch for HTTPS reverse-proxy setups that don't
    forward `X-Forwarded-Proto`.
    """
    if cfg.secure_cookies:
        return True
    trusted = cfg.trusted_proxies
    if not trusted:
        return False
    direct_ip = request.client.host if request.client else "unknown"
    if not _ip_in_networks(direct_ip, trusted):
        return False
    return request.headers.get("x-forwarded-proto", "") == "https"


# ── Routes ──


@router.post("/login", response_model=OkResponse, response_model_exclude_none=True)
def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    cfg: Settings = Depends(get_settings),
    store: SessionManager = Depends(get_sessions),
):
    """Authenticate with IMAP credentials."""
    client_ip = _get_client_ip(request, cfg)
    if not _login_limiter.check(client_ip):
        raise HTTPException(429, "Too many login attempts. Try again in 5 minutes.")

    host_ip = validate_host(req.host)

    # Goes through mail_dial like every other connection, and reports failure
    # in the shared vocabulary. There is no try/except here on purpose: the
    # ladder this replaced decided for itself what a protocol error meant, in
    # wording that drifted from every other sink, and its bare
    # `except Exception -> 502` blamed the mail server for our own bugs.
    # app.py maps AuthFailed to 401, MailServerUnavailable to 502 and
    # HostValidationError to 400 — the same statuses, decided in one place.
    verify_credentials(req.host, host_ip, req.port_imap, req.username, req.password, cfg=cfg)

    token = store.create(
        host=req.host,
        host_ip=host_ip,
        username=req.username,
        password=req.password,
        port_imap=req.port_imap,
        port_sieve=req.port_sieve,
    )
    secure = _is_secure(request, cfg)
    # `max_age` follows the store's idle timeout rather than repeating 1800.
    # The cookie is a HINT the browser may honour; the store is what actually
    # enforces expiry, and two numbers that mean the same thing drift apart —
    # a cookie outliving its session logs the user out mid-action, and one
    # dying early throws away a session the server still holds.
    # Rounded UP, and never below 1: `int(0.1)` is 0, and browsers read
    # `Max-Age=0` as delete-this-now — so a sub-second timeout answered 200
    # OK with a cookie the browser threw away, and the session never stuck.
    cookie_max_age = max(1, math.ceil(cfg.session_idle_timeout))
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        max_age=cookie_max_age,
        secure=secure,
    )
    response.set_cookie(
        CSRF_COOKIE,
        generate_csrf_token(),
        httponly=False,
        samesite="strict",
        max_age=cookie_max_age,
        secure=secure,
    )
    return {"ok": True, "username": req.username}


@router.post("/logout", response_model=OkResponse, response_model_exclude_none=True)
def logout(
    request: Request,
    response: Response,
    store: SessionManager = Depends(get_sessions),
):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        store.destroy(token)
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    return {"ok": True}


@router.get("/status", response_model=AuthStatusResponse, response_model_exclude_none=True)
async def auth_status(session: Session | None = Depends(get_optional_session)):
    """Report whether this request carries a live session.

    Never 401s — an unauthenticated caller is the answer, not an error, which
    is why this takes `get_optional_session` rather than `get_session`.
    """
    if session is None:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "username": session.username,
        "host": session.host,
    }
