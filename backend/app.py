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
import socket
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator

from auth import sessions, Session
from managesieve_client import SieveClient
from imap_client import IMAPClient
from sieve_transform import (
    parse_sieve, generate_sieve, script_to_json, json_to_script,
)


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

_cors_origins = os.environ.get("AYS_CORS_ORIGINS", "https://areyousievious.com")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

SESSION_COOKIE = "ays_session"
MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB


def _is_secure(request: Request) -> bool:
    """Detect if the request arrived over HTTPS (directly or via reverse proxy)."""
    if os.environ.get("AYS_SECURE_COOKIES", "").lower() in ("1", "true", "yes"):
        return True
    proto = request.headers.get("x-forwarded-proto", "")
    return proto == "https"


# ── Helpers ──

def get_session(request: Request) -> Session:
    """Extract and validate session from cookie or header."""
    token = request.cookies.get(SESSION_COOKIE)
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
        if not v or len(v) > 253:
            raise ValueError("Invalid hostname")
        # Block obviously bad patterns
        if v in ("localhost", "0.0.0.0", "[::]"):
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
        raise HTTPException(429, "Too many login attempts. Try again in 5 minutes.")

    # SSRF protection — reject private/internal IPs
    _validate_host(req.host)

    # Validate credentials against IMAP
    try:
        conn = imaplib.IMAP4_SSL(req.host, req.port_imap)
        conn.login(req.username, req.password)
        conn.logout()
    except imaplib.IMAP4.error as e:
        raise HTTPException(401, "Authentication failed")
    except Exception as e:
        raise HTTPException(502, "Cannot connect to mail server")

    token = sessions.create(
        host=req.host,
        username=req.username,
        password=req.password,
        port_imap=req.port_imap,
        port_sieve=req.port_sieve,
    )
    response.set_cookie(
        SESSION_COOKIE, token,
        httponly=True, samesite="strict", max_age=1800,
        secure=_is_secure(request),
    )
    return {"ok": True, "username": req.username}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sessions.destroy(token)
    response.delete_cookie(SESSION_COOKIE)
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
    script = json_to_script(req.model_dump())
    sieve_text = generate_sieve(script)
    with SieveClient(session) as client:
        client.put_script(name, sieve_text)
    return {"ok": True, "sieve": sieve_text}


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
