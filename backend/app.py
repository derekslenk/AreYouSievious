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

from auth import SessionManager
from config import Settings, settings
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mail_dial import build_tls_context
from mail_errors import (
    AuthFailed,
    FolderRejected,
    MailServerUnavailable,
    MailStoreError,
    QuotaExceeded,
    ScriptNotFound,
    ScriptRejected,
)
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


# What each semantic mail-store failure means to a client. This table is the
# ONLY place that decision is made: adapters raise in domain terms and routers
# carry no try/except, so a status can never drift between two sinks the way
# the folders/scripts 400s once did.
_MAIL_ERROR_STATUS: dict[type[MailStoreError], int] = {
    ScriptNotFound: 404,
    ScriptRejected: 400,
    FolderRejected: 400,
    QuotaExceeded: 507,
    MailServerUnavailable: 502,
    AuthFailed: 401,
}


def _status_for(exc: BaseException) -> int:
    """The status for a semantic failure, most-derived mapping first.

    Walking the MRO rather than reading `type(exc)` means a future subclass
    inherits its parent's status instead of silently falling back. The
    fallback itself is 502, not 500: an unclassified mail-store failure is
    still the upstream server's, and must not read like a bug in this app.
    """
    for cls in type(exc).__mro__:
        if cls in _MAIL_ERROR_STATUS:
            return _MAIL_ERROR_STATUS[cls]
    return 502


async def _mail_store_handler(_request: Request, exc: Exception):
    """Surface a mail-server failure as the status its meaning deserves."""
    return JSONResponse(status_code=_status_for(exc), content={"detail": str(exc)})


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

    # The session store belongs to THIS app for the same reason: it was a
    # module-level dict shared by every app in the process, so a session
    # created by one test was visible to the next and the suite needed
    # teardown to stop it. Reached through `dependencies.get_sessions`.
    app.state.sessions = SessionManager(
        idle_timeout=cfg.session_idle_timeout,
        max_lifetime=cfg.session_max_lifetime,
    )

    # Build the outbound TLS context now, so a missing or broken system CA
    # store fails while the app is being constructed rather than on a user's
    # first login. Keyed on cfg, so this is the context every dial for THIS
    # app will get.
    build_tls_context(cfg)

    app.add_exception_handler(HostValidationError, _host_validation_handler)
    app.add_exception_handler(ProtocolNameError, _protocol_name_handler)
    # One registration for the whole vocabulary: Starlette resolves a handler
    # by walking the exception's MRO, so every MailStoreError subclass lands
    # here and gets its status from the table above.
    app.add_exception_handler(MailStoreError, _mail_store_handler)

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
