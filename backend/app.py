#!/usr/bin/env python3
"""
AreYouSievious - FastAPI backend.

Serves the Svelte frontend as static files and provides
REST API for ManageSieve + IMAP operations.
"""

import argparse
import os
from pathlib import Path

from api_models import (
    CreateFolderRequest,
    FolderListItem,
    OkResponse,
)
from dependencies import get_session
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from imap_client import IMAPClient
from middleware import (
    BodySizeLimitMiddleware,
    CSRFMiddleware,
)
from routers.auth import router as auth_router
from routers.scripts import router as scripts_router
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
app.include_router(scripts_router)


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
