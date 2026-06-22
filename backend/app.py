#!/usr/bin/env python3
"""
AreYouSievious - FastAPI backend.

Serves the Svelte frontend as static files and provides
REST API for ManageSieve + IMAP operations.
"""

import argparse
import os
import re
from pathlib import Path

from api_models import (
    CreateFolderRequest,
    FolderListItem,
    OkResponse,
    SaveRawRequest,
    SaveScriptRequest,
    ScriptListItem,
    ScriptRawResponse,
    ScriptResponse,
)
from dependencies import get_session
from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from imap_client import IMAPClient
from managesieve_client import SieveClient
from middleware import (
    BodySizeLimitMiddleware,
    CSRFMiddleware,
)
from routers.auth import router as auth_router
from sieve_transform import (
    generate_sieve,
    json_to_script,
    parse_sieve,
    script_to_json,
)
from ssrf import HostValidationError

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

app.include_router(auth_router)

MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB


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
