"""
Sieve script router (areyousievious-u40 split from app.py).

Owns the ten /api/scripts/* endpoints that read, write, import,
export, activate, and delete Sieve scripts via ManageSieve.

`preview` is the one that does not touch ManageSieve at all: it renders a
Rule with the same generator a save uses and answers. It exists so the SPA
does not have to carry a second implementation of that generator, which it
did, and which had diverged five ways (areyousievious-8fg.17).

The import size cap comes from `request.app.state.settings.max_body_bytes`,
the same value the body-size middleware uses. It was a local constant here,
which meant raising AYS_MAX_BODY_BYTES moved one limit and not the other.
"""

from __future__ import annotations

import re

from api_models import (
    OkResponse,
    PreviewRequest,
    PreviewResponse,
    SaveRawRequest,
    SaveScriptRequest,
    ScriptListItem,
    ScriptRawResponse,
    ScriptResponse,
)
from auth import Session
from config import Settings
from dependencies import get_script_store, get_session, get_settings
from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile
from mail_stores import ScriptStore
from sieve_transform import (
    generate_rule,
    generate_sieve,
    json_to_script,
    parse_sieve,
    rule_from_json,
    script_to_json,
)

router = APIRouter(prefix="/api/scripts")


@router.get("", response_model=list[ScriptListItem])
def list_scripts(store: ScriptStore = Depends(get_script_store)):
    return store.list_scripts()


@router.get("/{name}", response_model=ScriptResponse)
def get_script(name: str, store: ScriptStore = Depends(get_script_store)):
    """Get script parsed as JSON rules."""
    script = parse_sieve(store.get_script(name))
    return script_to_json(script)


@router.get("/{name}/raw", response_model=ScriptRawResponse)
def get_script_raw(name: str, store: ScriptStore = Depends(get_script_store)):
    """Get raw Sieve text."""
    return {"name": name, "content": store.get_script(name)}


@router.get("/{name}/export")
def export_script(name: str, store: ScriptStore = Depends(get_script_store)):
    """Download script as a .sieve file."""
    content = store.get_script(name)
    return Response(
        content=content,
        media_type="application/sieve",
        headers={
            "Content-Disposition": f'attachment; filename="{re.sub(r"[^a-zA-Z0-9._-]", "_", name)}.sieve"'
        },
    )


@router.post("/import", response_model=OkResponse, response_model_exclude_none=True)
def import_script(
    name: str = Form(...),
    file: UploadFile = File(...),
    store: ScriptStore = Depends(get_script_store),
    cfg: Settings = Depends(get_settings),
):
    """Import a .sieve file as a new script.

    ponytail: sync handler so FastAPI runs it in a threadpool — the slow
    ManageSieve PUT no longer blocks the event loop (Perf C1 / Fwk C-1).
    """
    cap = cfg.max_body_bytes
    raw = file.file.read()
    if len(raw) > cap:
        raise HTTPException(413, f"File too large (max {cap // 1024}KB)")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be valid UTF-8 text")  # noqa: B904
    store.put_script(name, content)
    return {"ok": True, "name": name}


@router.post("/preview", response_model=PreviewResponse)
def preview_rule(req: PreviewRequest, _session: Session = Depends(get_session)):
    """Render one Rule as the Sieve a save would write.

    NO MAIL-SERVER DIAL. It depends on `get_session` and not on
    `get_script_store`, so it authenticates without opening a ManageSieve
    connection — this runs on every keystroke behind a debounce, and a
    connection per keystroke would be a self-inflicted denial of service
    against the user's own mail server.

    It replaces `previewRule` in the SPA, which was a second implementation of
    `SieveGenerator` that had already diverged five ways. Declared BEFORE the
    `/{name}` routes so `preview` is read as a literal path segment.
    """
    return {"sieve": generate_rule(rule_from_json(req.rule.model_dump()))}


@router.put("/{name}", response_model=OkResponse, response_model_exclude_none=True)
def save_script(name: str, req: SaveScriptRequest, store: ScriptStore = Depends(get_script_store)):
    """Save script from JSON rules (generates Sieve)."""
    script = json_to_script(req.model_dump())
    sieve_text = generate_sieve(script)
    store.put_script(name, sieve_text)
    return {"ok": True, "sieve": sieve_text}


@router.put("/{name}/raw", response_model=OkResponse, response_model_exclude_none=True)
def save_script_raw(name: str, req: SaveRawRequest, store: ScriptStore = Depends(get_script_store)):
    """Save raw Sieve text directly."""
    store.put_script(name, req.content)
    return {"ok": True}


@router.post("/{name}/activate", response_model=OkResponse, response_model_exclude_none=True)
def activate_script(name: str, store: ScriptStore = Depends(get_script_store)):
    store.activate_script(name)
    return {"ok": True}


@router.delete("/{name}", response_model=OkResponse, response_model_exclude_none=True)
def delete_script(name: str, store: ScriptStore = Depends(get_script_store)):
    store.delete_script(name)
    return {"ok": True}
