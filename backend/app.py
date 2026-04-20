#!/usr/bin/env python3
"""
AreYouSievious - FastAPI backend.

Serves the Svelte frontend as static files and provides
REST API for ManageSieve + IMAP operations.
"""

import argparse
import imaplib
import ipaddress
import logging
import os
import re
import socket
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
from starlette.middleware.base import BaseHTTPMiddleware

from auth import sessions, Session
from managesieve_client import SieveClient
from imap_client import IMAPClient
from sieve_transform import (
    parse_sieve, generate_sieve, script_to_json, json_to_script,
)


# ── Logging Configuration ──

def setup_logging(level: str = "INFO"):
    """Configure structured logging for the application."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Create formatter with structured output
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # Reduce noise from uvicorn
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    return logging.getLogger("areyousievious")


logger = setup_logging(os.environ.get("AYS_LOG_LEVEL", "INFO"))


# ── Configuration Constants ──

RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 300  # 5 minutes
MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB
MAX_HOSTNAME_LENGTH = 253  # RFC 1035
SESSION_COOKIE_NAME = "ays_session"
SESSION_COOKIE_MAX_AGE = 1800  # 30 minutes


# ── Rate limiter ──

class RateLimiter:
    """Simple in-memory rate limiter by IP."""

    def __init__(self, max_attempts: int = RATE_LIMIT_MAX_ATTEMPTS, window_seconds: int = RATE_LIMIT_WINDOW_SECONDS):
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


_login_limiter = RateLimiter()


# ── SSRF protection ──

def _validate_host(host: str) -> str:
    """Validate that host is not a private/reserved IP (SSRF protection)."""
    try:
        # Resolve hostname to IP
        resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in resolved:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                raise HTTPException(400, "Connection to private/internal addresses is not allowed")
    except socket.gaierror:
        raise HTTPException(400, f"Cannot resolve hostname: {host}")
    return host

app = FastAPI(title="AreYouSievious", version="0.1.0")


# ── Security Headers Middleware ──

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Content Security Policy - restrict resource loading
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Enable XSS protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # HSTS - force HTTPS (only if request came via HTTPS)
        if _is_secure(request):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


app.add_middleware(SecurityHeadersMiddleware)

_cors_origins = os.environ.get("AYS_CORS_ORIGINS", "https://areyousievious.com")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)



def _is_secure(request: Request) -> bool:
    """Detect if the request arrived over HTTPS (directly or via reverse proxy)."""
    if os.environ.get("AYS_SECURE_COOKIES", "").lower() in ("1", "true", "yes"):
        return True
    proto = request.headers.get("x-forwarded-proto", "")
    return proto == "https"


# ── Helpers ──

def get_session(request: Request) -> Session:
    """Extract and validate session from cookie or header."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        # Also check Authorization header
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "Not authenticated")
    session = sessions.get(token)
    if not session:
        raise HTTPException(401, "Session expired")
    return session


# ── Health check endpoint ──

@app.get("/health")
def health_check():
    """Health check endpoint for monitoring and load balancers."""
    return {"status": "ok", "version": "0.1.0"}


# ── Auth endpoints ──

class LoginRequest(BaseModel):
    host: str
    username: str
    password: str
    port_imap: int = 993
    port_sieve: int = 4190

    @field_validator("host")
    @classmethod
    def host_must_be_valid(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or len(v) > MAX_HOSTNAME_LENGTH:
            raise ValueError("Invalid hostname")
        # Block local/private addresses (SSRF protection)
        blocked_hosts = {
            "localhost", "0.0.0.0",
            "[::]", "::1", "[::1]",  # IPv6 localhost variants
            "127.0.0.1", "[127.0.0.1]",
        }
        if v in blocked_hosts:
            raise ValueError("Connection to local addresses is not allowed")
        return v

    @field_validator("port_imap", "port_sieve")
    @classmethod
    def port_must_be_valid(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("Invalid port number")
        return v


@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    """Authenticate with IMAP credentials."""
    # Rate limit by IP
    client_ip = request.headers.get("x-real-ip", request.client.host if request.client else "unknown")
    if not _login_limiter.check(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(429, "Too many login attempts. Try again in 5 minutes.")

    # SSRF protection — reject private/internal IPs
    _validate_host(req.host)

    # Validate credentials against IMAP
    try:
        logger.info(f"Login attempt for user={req.username} host={req.host}")
        conn = imaplib.IMAP4_SSL(req.host, req.port_imap)
        conn.login(req.username, req.password)
        conn.logout()
        logger.info(f"Successful login for user={req.username} host={req.host}")
    except imaplib.IMAP4.error as e:
        logger.warning(f"Authentication failed for user={req.username} host={req.host}")
        raise HTTPException(401, "Authentication failed")
    except Exception as e:
        logger.error(f"Connection error for host={req.host}: {type(e).__name__}")
        raise HTTPException(502, "Cannot connect to mail server")

    token = sessions.create(
        host=req.host,
        username=req.username,
        password=req.password,
        port_imap=req.port_imap,
        port_sieve=req.port_sieve,
    )
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        httponly=True, samesite="strict", max_age=SESSION_COOKIE_MAX_AGE,
        secure=_is_secure(request),
    )
    return {"ok": True, "username": req.username}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        session = sessions.get(token)
        if session:
            logger.info(f"Logout for user={session.username}")
        sessions.destroy(token)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"ok": True}


@app.get("/api/auth/status")
async def auth_status(request: Request):
    try:
        session = get_session(request)
        return {"authenticated": True, "username": session.username, "host": session.host}
    except HTTPException:
        return {"authenticated": False}


# ── Script endpoints ──

@app.get("/api/scripts")
def list_scripts(request: Request):
    session = get_session(request)
    with SieveClient(session) as client:
        return client.list_scripts()


@app.get("/api/scripts/{name}")
def get_script(name: str, request: Request):
    """Get script parsed as JSON rules."""
    session = get_session(request)
    with SieveClient(session) as client:
        sieve_text = client.get_script(name)
    script = parse_sieve(sieve_text)
    return script_to_json(script)


@app.get("/api/scripts/{name}/raw")
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
        headers={"Content-Disposition": f'attachment; filename="{re.sub(r"[^a-zA-Z0-9._-]", "_", name)}.sieve"'},
    )


@app.post("/api/scripts/import")
async def import_script(request: Request):
    """Import a .sieve file as a new script."""
    form = await request.form()
    file = form.get("file")
    name = form.get("name")
    if not file or not name:
        raise HTTPException(400, "name and file required")
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (max {MAX_UPLOAD_BYTES // 1024}KB)")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be valid UTF-8 text")
    session = get_session(request)
    with SieveClient(session) as client:
        client.put_script(name, content)
    return {"ok": True, "name": name}


class SaveScriptRequest(BaseModel):
    rules: list
    raw_blocks: list = []
    order: list = []
    requires: list = []


@app.put("/api/scripts/{name}")
def save_script(name: str, req: SaveScriptRequest, request: Request):
    """Save script from JSON rules (generates Sieve)."""
    session = get_session(request)
    try:
        script = json_to_script(req.model_dump())
        sieve_text = generate_sieve(script)
        with SieveClient(session) as client:
            client.put_script(name, sieve_text)
        logger.info(f"Saved script '{name}' for user={session.username}")
        return {"ok": True, "sieve": sieve_text}
    except Exception as e:
        logger.error(f"Error saving script '{name}': {type(e).__name__} - {str(e)}")
        raise


class SaveRawRequest(BaseModel):
    content: str


@app.put("/api/scripts/{name}/raw")
def save_script_raw(name: str, req: SaveRawRequest, request: Request):
    """Save raw Sieve text directly."""
    session = get_session(request)
    with SieveClient(session) as client:
        client.put_script(name, req.content)
    return {"ok": True}


@app.post("/api/scripts/{name}/activate")
def activate_script(name: str, request: Request):
    session = get_session(request)
    with SieveClient(session) as client:
        client.activate_script(name)
    return {"ok": True}


@app.delete("/api/scripts/{name}")
def delete_script(name: str, request: Request):
    session = get_session(request)
    with SieveClient(session) as client:
        client.delete_script(name)
    logger.info(f"Deleted script '{name}' for user={session.username}")
    return {"ok": True}


# ── Folder endpoints ──

@app.get("/api/folders")
def list_folders(request: Request):
    session = get_session(request)
    with IMAPClient(session) as client:
        return client.list_folders()


class CreateFolderRequest(BaseModel):
    name: str


@app.post("/api/folders")
def create_folder(req: CreateFolderRequest, request: Request):
    session = get_session(request)
    with IMAPClient(session) as client:
        ok = client.create_folder(req.name)
    if not ok:
        raise HTTPException(400, "Failed to create folder")
    return {"ok": True, "name": req.name}


# ── Static file serving ──

static_dir: Optional[Path] = None


@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    """Serve Svelte build files, fallback to index.html for SPA routing."""
    if not static_dir:
        raise HTTPException(404)

    file_path = (static_dir / full_path).resolve()
    try:
        file_path.relative_to(static_dir.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
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
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    # Reconfigure logging with CLI arg
    global logger
    logger = setup_logging(args.log_level)

    global static_dir
    if args.static:
        static_dir = Path(args.static).resolve()
        if not static_dir.is_dir():
            logger.warning(f"Static dir {static_dir} not found")
            static_dir = None
        else:
            logger.info(f"Serving static files from {static_dir}")

    logger.info(f"Starting AreYouSievious server on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level.lower())


if __name__ == "__main__":
    main()
