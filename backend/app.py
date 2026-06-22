#!/usr/bin/env python3
"""
AreYouSievious — FastAPI composition root.

This file composes the application from independent pieces; it
contains no business logic of its own. Routes live under
backend/routers/ (auth, scripts, folders, static, health). Shared
per-request dependencies live in backend/dependencies.py. Custom
ASGI middleware lives in backend/middleware.py.
"""

import argparse
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from middleware import (
    BodySizeLimitMiddleware,
    CSRFMiddleware,
)
from routers import static as static_router_mod
from routers.auth import router as auth_router
from routers.folders import router as folders_router
from routers.scripts import router as scripts_router
from routers.static import router as static_router
from ssrf import HostValidationError

# ── Environment config ──
_is_dev = os.environ.get("AYS_ENV", "prod").strip().lower() == "dev"
_max_body_bytes = int(os.environ.get("AYS_MAX_BODY_BYTES", str(1 * 1024 * 1024)))
_cors_origins = os.environ.get("AYS_CORS_ORIGINS", "https://areyousievious.com")

# ── App construction ──
app = FastAPI(
    title="AreYouSievious",
    version="0.1.0",
    docs_url="/docs" if _is_dev else None,
    redoc_url="/redoc" if _is_dev else None,
    openapi_url="/openapi.json" if _is_dev else None,
)


# ── Exception handlers ──
@app.exception_handler(HostValidationError)
async def _host_validation_handler(_request: Request, exc: HostValidationError):
    """Surface SSRF-guard rejections as 400s instead of generic 500s."""
    return JSONResponse(status_code=400, content={"detail": str(exc)})


# ── Middleware (last-added runs first — CORS outermost, CSRF innermost) ──
app.add_middleware(CSRFMiddleware)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=_max_body_bytes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins.split(",")],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Cookie", "X-CSRF-Token"],
    allow_credentials=True,
)

# ── Routers ──
app.include_router(auth_router)
app.include_router(scripts_router)
app.include_router(folders_router)
app.include_router(static_router)


# ── Entry point ──
def main():
    import uvicorn

    parser = argparse.ArgumentParser(description="AreYouSievious server")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--static", type=str, help="Path to frontend build dir")
    args = parser.parse_args()

    if args.static:
        resolved = Path(args.static).resolve()
        if resolved.is_dir():
            static_router_mod.configure(resolved)
        else:
            print(f"Warning: static dir {resolved} not found")

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
