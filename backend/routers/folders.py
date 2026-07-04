"""
IMAP folder router (areyousievious-u40 split from app.py).

Owns GET /api/folders (list) and POST /api/folders (create). Both
proxy directly to the per-session IMAPClient. Behavior is
byte-identical to the pre-u40 inline handlers in app.py.
"""

from __future__ import annotations

from api_models import CreateFolderRequest, FolderListItem, OkResponse
from dependencies import get_session
from fastapi import APIRouter, HTTPException, Request
from imap_client import IMAPClient

router = APIRouter(prefix="/api/folders")


@router.get("", response_model=list[FolderListItem])
def list_folders(request: Request):
    session = get_session(request)
    with IMAPClient(session) as client:
        return client.list_folders()


@router.post("", response_model=OkResponse, response_model_exclude_none=True)
def create_folder(req: CreateFolderRequest, request: Request):
    session = get_session(request)
    with IMAPClient(session) as client:
        ok = client.create_folder(req.name)
    if not ok:
        raise HTTPException(400, "Failed to create folder")
    return {"ok": True, "name": req.name}
