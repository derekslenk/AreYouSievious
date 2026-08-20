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
from pathlib import Path

from config import Settings, settings
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from middleware import (
    BodySizeLimitMiddleware,
    CSRFMiddleware,
)
from protocol_names import ProtocolNameError
from routers import static as static_router_mod
from routers.auth import router as auth_router
from routers.folders import router as folders_router
from routers.health import router as health_router
from routers.scripts import router as scripts_router
from routers.static import router as static_router
from ssrf import HostValidationError

# ── Exception handlers ──


async def _host_validation_handler(_request: Request, exc: Exception):
    """Surface SSRF-guard rejections as 400s instead of generic 500s."""
    return JSONResponse(status_code=400, content={"detail": str(exc)})


async def _protocol_name_handler(_request: Request, exc: Exception):
    """Surface protocol-framing name rejections as 400s.

    Covers BOTH sinks — Sieve script names and IMAP folder names. Each guard
    raises before any protocol call, so the malformed frame never reaches the
    wire; this maps that rejection to a clean 400 body in one place, so no
    router needs its own try/except (folders.py used to carry one)."""
    return JSONResponse(status_code=400, content={"detail": str(exc)})


# ── App construction ──


def create_app(config: Settings | None = None) -> FastAPI:
    """Build an app from an explicit configuration.

    Configuration arrives as an argument rather than being read out of the
    ambient environment at import. That is the whole point: a test wanting
    dev-mode docs or a different CORS list constructs a Settings and calls
    this, instead of mutating os.environ and reloading the module.
    """
    cfg = config or settings()

    app = FastAPI(
        title="AreYouSievious",
        version="0.1.0",
        docs_url="/docs" if cfg.is_dev else None,
        redoc_url="/redoc" if cfg.is_dev else None,
        openapi_url="/openapi.json" if cfg.is_dev else None,
    )

    # Reachable from any handler as `request.app.state.settings`, so a request
    # reads the configuration its app was built with — not whatever the
    # environment happens to say at that moment.
    app.state.settings = cfg

    app.add_exception_handler(HostValidationError, _host_validation_handler)
    app.add_exception_handler(ProtocolNameError, _protocol_name_handler)

    # Middleware: last-added runs first — CORS outermost, CSRF innermost.
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=cfg.max_body_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cfg.cors_origins),
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Cookie", "X-CSRF-Token"],
        allow_credentials=True,
    )

    # Order matters: the static router ends with a catch-all
    # GET /{full_path:path}, so every real route must be registered before it
    # or the SPA fallback swallows it.
    app.include_router(auth_router)
    app.include_router(scripts_router)
    app.include_router(folders_router)
    app.include_router(health_router)
    app.include_router(static_router)

    return app


# The default instance, for `python app.py` and `uvicorn app:app`.
app = create_app()


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
