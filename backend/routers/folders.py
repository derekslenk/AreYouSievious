"""
IMAP folder router (areyousievious-u40 split from app.py).

Owns GET /api/folders (list) and POST /api/folders (create). Both
proxy directly to the per-session IMAPClient. Behavior is
byte-identical to the pre-u40 inline handlers in app.py.
"""

from __future__ import annotations

from api_models import CreateFolderRequest, FolderListItem, OkResponse
from dependencies import get_folder_store
from fastapi import APIRouter, Depends
from mail_stores import FolderStore

router = APIRouter(prefix="/api/folders")


@router.get("", response_model=list[FolderListItem])
def list_folders(store: FolderStore = Depends(get_folder_store)):
    return store.list_folders()


@router.post("", response_model=OkResponse, response_model_exclude_none=True)
def create_folder(req: CreateFolderRequest, store: FolderStore = Depends(get_folder_store)):
    # No local try/except and no status decision: create_folder raises
    # ProtocolNameError for a malformed name and FolderRejected for a server
    # refusal, and app.py maps each in one place. This used to read a bool and
    # answer 400 for every cause alike, which made an unreachable server look
    # like the user's mistake.
    store.create_folder(req.name)
    return {"ok": True, "name": req.name}
