#!/usr/bin/env python3
"""
AreYouSievious - FastAPI backend.

Serves the Svelte frontend as static files and provides
REST API for ManageSieve + IMAP operations.
"""

import argparse
import imaplib
import ipaddress
import os
import re
import ssl
import time
from collections import defaultdict
from pathlib import Path

from api_models import (
    AuthStatusResponse,
    CreateFolderRequest,
    FolderListItem,
    LoginRequest,
    OkResponse,
    SaveRawRequest,
    SaveScriptRequest,
    ScriptListItem,
    ScriptRawResponse,
    ScriptResponse,
)
from dependencies import SESSION_COOKIE, get_session
from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from imap_client import IMAP_TIMEOUT, TLS_CONTEXT, IMAPClient
from managesieve_client import SieveClient
from middleware import (
    CSRF_COOKIE,
    BodySizeLimitMiddleware,
    CSRFMiddleware,
    generate_csrf_token,
)
from auth import sessions
from sieve_transform import (
    generate_sieve,
    json_to_script,
    parse_sieve,
    script_to_json,
)
from ssrf import HostValidationError, assert_host_resolves_to, validate_host

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


_is_dev = os.environ.get("AYS_ENV", "prod").strip().lower() == "dev"
_max_body_bytes = int(os.environ.get("AYS_MAX_BODY_BYTES", str(1 * 1024 * 1024)))


app = FastAPI(
    title="AreYouSievious",
    version="0.1.0",
    docs_url="/docs" if _is_dev else None,
    redoc_url="/redoc" if _is_dev else None,
    openapi_url="/openapi.json" if _is_dev else None,
)


@app.exception_handler(HostValidationError)
async def _host_validation_handler(_request: Request, exc: HostValidationError):
    """Surface SSRF-guard rejections as 400s instead of generic 500s."""
    return JSONResponse(status_code=400, content={"detail": str(exc)})


app.add_middleware(CSRFMiddleware)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=_max_body_bytes)
_cors_origins = os.environ.get("AYS_CORS_ORIGINS", "https://areyousievious.com")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins.split(",")],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Cookie", "X-CSRF-Token"],
    allow_credentials=True,
)

MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB


def _is_secure(request: Request) -> bool:
    """Detect if the request arrived over HTTPS (directly or via reverse proxy)."""
    if os.environ.get("AYS_SECURE_COOKIES", "").lower() in ("1", "true", "yes"):
        return True
    proto = request.headers.get("x-forwarded-proto", "")
    return proto == "https"


# ── Auth endpoints ──


@app.post("/api/auth/login", response_model=OkResponse, response_model_exclude_none=True)
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


@app.post("/api/auth/logout", response_model=OkResponse, response_model_exclude_none=True)
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sessions.destroy(token)
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    return {"ok": True}


@app.get("/api/auth/status", response_model=AuthStatusResponse, response_model_exclude_none=True)
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


# ── Script endpoints ──


@app.get("/api/scripts", response_model=list[ScriptListItem])
def list_scripts(request: Request):
    session = get_session(request)
    with SieveClient(session) as client:
        return client.list_scripts()


@app.get("/api/scripts/{name}", response_model=ScriptResponse)
def get_script(name: str, request: Request):
    """Get script parsed as JSON rules."""
    session = get_session(request)
    with SieveClient(session) as client:
        sieve_text = client.get_script(name)
    script = parse_sieve(sieve_text)
    return script_to_json(script)


@app.get("/api/scripts/{name}/raw", response_model=ScriptRawResponse)
def get_script_raw(name: str, request: Request):
    """Get raw Sieve text."""
    session = get_session(request)
    with SieveClient(session) as client:
        return {"name": name, "content": client.get_script(name)}


@app.get("/api/scripts/{name}/export")
def export_script(name: str, request: Request):
    """Download script as a .sieve file."""
    session = get_session(request)
    with SieveClient(session) as client:
        content = client.get_script(name)
    return Response(
        content=content,
        media_type="application/sieve",
        headers={
            "Content-Disposition": f'attachment; filename="{re.sub(r"[^a-zA-Z0-9._-]", "_", name)}.sieve"'
        },
    )


@app.post("/api/scripts/import", response_model=OkResponse, response_model_exclude_none=True)
def import_script(
    request: Request,
    name: str = Form(...),
    file: UploadFile = File(...),
):
    """Import a .sieve file as a new script.

    ponytail: sync handler so FastAPI runs it in a threadpool — the slow
    ManageSieve PUT no longer blocks the event loop (Perf C1 / Fwk C-1).
    """
    raw = file.file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (max {MAX_UPLOAD_BYTES // 1024}KB)")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be valid UTF-8 text")  # noqa: B904
    session = get_session(request)
    with SieveClient(session) as client:
        client.put_script(name, content)
    return {"ok": True, "name": name}


@app.put("/api/scripts/{name}", response_model=OkResponse, response_model_exclude_none=True)
def save_script(name: str, req: SaveScriptRequest, request: Request):
    """Save script from JSON rules (generates Sieve)."""
    session = get_session(request)
    script = json_to_script(req.model_dump())
    sieve_text = generate_sieve(script)
    with SieveClient(session) as client:
        client.put_script(name, sieve_text)
    return {"ok": True, "sieve": sieve_text}


@app.put("/api/scripts/{name}/raw", response_model=OkResponse, response_model_exclude_none=True)
def save_script_raw(name: str, req: SaveRawRequest, request: Request):
    """Save raw Sieve text directly."""
    session = get_session(request)
    with SieveClient(session) as client:
        client.put_script(name, req.content)
    return {"ok": True}


@app.post(
    "/api/scripts/{name}/activate", response_model=OkResponse, response_model_exclude_none=True
)
def activate_script(name: str, request: Request):
    session = get_session(request)
    with SieveClient(session) as client:
        client.activate_script(name)
    return {"ok": True}


@app.delete("/api/scripts/{name}", response_model=OkResponse, response_model_exclude_none=True)
def delete_script(name: str, request: Request):
    session = get_session(request)
    with SieveClient(session) as client:
        client.delete_script(name)
    return {"ok": True}


# ── Folder endpoints ──


@app.get("/api/folders", response_model=list[FolderListItem])
def list_folders(request: Request):
    session = get_session(request)
    with IMAPClient(session) as client:
        return client.list_folders()


@app.post("/api/folders", response_model=OkResponse, response_model_exclude_none=True)
def create_folder(req: CreateFolderRequest, request: Request):
    session = get_session(request)
    with IMAPClient(session) as client:
        ok = client.create_folder(req.name)
    if not ok:
        raise HTTPException(400, "Failed to create folder")
    return {"ok": True, "name": req.name}


# ── Static file serving ──

static_dir: Path | None = None


@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    """Serve Svelte build files, fallback to index.html for SPA routing."""
    if not static_dir:
        raise HTTPException(404)

    file_path = (static_dir / full_path).resolve()
    try:
        file_path.relative_to(static_dir.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")  # noqa: B904
    if file_path.is_file():
        return FileResponse(file_path)

    index = static_dir / "index.html"
    if index.is_file():
        return FileResponse(index)

    raise HTTPException(404)


def main():
    import uvicorn

    parser = argparse.ArgumentParser(description="AreYouSievious server")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--static", type=str, help="Path to frontend build dir")
    args = parser.parse_args()

    global static_dir
    if args.static:
        static_dir = Path(args.static).resolve()
        if not static_dir.is_dir():
            print(f"Warning: static dir {static_dir} not found")
            static_dir = None

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
