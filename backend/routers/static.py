"""
Static file / SPA fallback router (areyousievious-u40 split from app.py).

Owns the catch-all GET /{full_path:path} that serves the Svelte
build output. The path-traversal guard (resolve() + relative_to())
is preserved verbatim from the pre-u40 inline handler. If no
static directory is configured, every request returns 404.

The owning module exposes a `configure(path)` setter that main()
calls when --static is passed on the CLI. Tests can also call it
to point the router at a fixture directory.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()

# Module-level state: the resolved Path of the static dir, or None
# when no --static flag was passed. main() in app.py updates this
# through configure(); the catch-all handler reads it on every request.
static_dir: Path | None = None


def configure(path: Path | None) -> None:
    """Point the router at a directory (or clear it with None).

    Called from app.main() once CLI args are parsed. Idempotent;
    safe to call multiple times.
    """
    global static_dir
    static_dir = path


@router.get("/{full_path:path}")
def serve_frontend(full_path: str):
    """Serve Svelte build files, fallback to index.html for SPA routing."""
    if not static_dir:
        raise HTTPException(404)

    # Path-traversal containment. `full_path` is user-controlled (catch-all
    # route param), but the `resolve() + relative_to()` pair is the canonical
    # Python guard: any payload that escapes `static_dir` after resolution
    # raises ValueError and we return 403. Phase 2 of the security audit
    # empirically verified this against 6 payloads (raw `../`, URL-encoded
    # `%2e%2e`, double-encoded `%252e%252e`, etc.) — all 404'd.
    # See .full-review/05-final-report.md:220 and 02a-security-findings.md:17.
    # CodeQL's py/path-injection flags the user input reaching Path() and does
    # not recognize the post-construction containment check; dismissed as a
    # false positive. Wave 2 (bd:areyousievious-4pr) replaces this handler
    # with FastAPI's StaticFiles(html=True), which CodeQL recognizes natively.
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
