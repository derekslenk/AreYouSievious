"""
Sieve script router (areyousievious-u40 split from app.py).

Owns the nine /api/scripts/* endpoints that read, write, import,
export, activate, and delete Sieve scripts via ManageSieve. The
1MiB MAX_UPLOAD_BYTES cap lives here because only import_script
consults it. Behavior is byte-identical to the pre-u40 inline
handlers in app.py.
"""

from __future__ import annotations

import re

from api_models import (
    OkResponse,
    SaveRawRequest,
    SaveScriptRequest,
    ScriptListItem,
    ScriptRawResponse,
    ScriptResponse,
)
from dependencies import get_session
from fastapi import APIRouter, File, Form, HTTPException, Request, Response, UploadFile
from managesieve_client import SieveClient
from sieve_transform import (
    generate_sieve,
    json_to_script,
    parse_sieve,
    script_to_json,
)

router = APIRouter(prefix="/api/scripts")

MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB


@router.get("", response_model=list[ScriptListItem])
def list_scripts(request: Request):
    session = get_session(request)
    with SieveClient(session) as client:
        return client.list_scripts()


@router.get("/{name}", response_model=ScriptResponse)
def get_script(name: str, request: Request):
    """Get script parsed as JSON rules."""
    session = get_session(request)
    with SieveClient(session) as client:
        sieve_text = client.get_script(name)
    script = parse_sieve(sieve_text)
    return script_to_json(script)


@router.get("/{name}/raw", response_model=ScriptRawResponse)
def get_script_raw(name: str, request: Request):
    """Get raw Sieve text."""
    session = get_session(request)
    with SieveClient(session) as client:
        return {"name": name, "content": client.get_script(name)}


@router.get("/{name}/export")
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


@router.post("/import", response_model=OkResponse, response_model_exclude_none=True)
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


@router.put("/{name}", response_model=OkResponse, response_model_exclude_none=True)
def save_script(name: str, req: SaveScriptRequest, request: Request):
    """Save script from JSON rules (generates Sieve)."""
    session = get_session(request)
    script = json_to_script(req.model_dump())
    sieve_text = generate_sieve(script)
    with SieveClient(session) as client:
        client.put_script(name, sieve_text)
    return {"ok": True, "sieve": sieve_text}


@router.put("/{name}/raw", response_model=OkResponse, response_model_exclude_none=True)
def save_script_raw(name: str, req: SaveRawRequest, request: Request):
    """Save raw Sieve text directly."""
    session = get_session(request)
    with SieveClient(session) as client:
        client.put_script(name, req.content)
    return {"ok": True}


@router.post("/{name}/activate", response_model=OkResponse, response_model_exclude_none=True)
def activate_script(name: str, request: Request):
    session = get_session(request)
    with SieveClient(session) as client:
        client.activate_script(name)
    return {"ok": True}


@router.delete("/{name}", response_model=OkResponse, response_model_exclude_none=True)
def delete_script(name: str, request: Request):
    session = get_session(request)
    with SieveClient(session) as client:
        client.delete_script(name)
    return {"ok": True}
