"""
Regression tests for the typed-DTO response_model coverage
(areyousievious-7mr, Fwk H-2 / Fwk H-4).

Two angles:
  1. Pydantic ConfigDict(extra="forbid") rejects unknown fields on every
     request DTO — so a typo or attack payload can't silently widen the
     accepted schema.
  2. /openapi.json (enabled with AYS_ENV=dev) declares a response_model
     for every route that returns data.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_response_models.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from api_models import (
    ActionDTO,
    ConditionDTO,
    CreateFolderRequest,
    LoginRequest,
    RawBlockDTO,
    RuleDTO,
    SaveRawRequest,
    SaveScriptRequest,
)

# ── ConfigDict(extra="forbid") — unknown fields rejected on every DTO ──


@pytest.mark.parametrize(
    "model,base",
    [
        (
            SaveScriptRequest,
            {"entries": [], "requires": []},
        ),
        (SaveRawRequest, {"content": ""}),
        (CreateFolderRequest, {"name": "Inbox"}),
        (
            LoginRequest,
            {"host": "imap.example.com", "username": "u", "password": "p"},
        ),
        (ConditionDTO, {"header": "from", "match_type": "is"}),
        (ActionDTO, {"type": "fileinto"}),
        (RuleDTO, {}),
        (RawBlockDTO, {}),
    ],
)
def test_extra_field_rejected(model, base):
    payload = dict(base, mystery_field="value")
    with pytest.raises(ValidationError):
        model(**payload)


def test_save_script_rejects_unknown_rule_field():
    """The original bug: `SaveScriptRequest.rules: list[Any]` accepted any
    shape. Now: every entry is parsed against its DTO, and an unknown field
    anywhere in the tree is rejected."""
    payload = {
        "entries": [
            {
                "kind": "rule",
                "name": "test",
                "match": "anyof",
                "conditions": [{"header": "from", "match_type": "is", "secret_backdoor": "x"}],
                "actions": [],
            }
        ],
        "requires": [],
    }
    with pytest.raises(ValidationError):
        SaveScriptRequest(**payload)


def test_save_script_accepts_a_well_formed_editor_payload():
    """Companion to the rejection test above: the exact shape the SPA sends
    MUST validate. Without this, the rejection tests can stay green while the
    save path is broken for every real client — which is what shipped between
    2026-06-21 and this change (HTTP 422 on every visual-editor save)."""
    payload = {
        "requires": ["fileinto"],
        "entries": [
            {
                "kind": "rule",
                "name": "GitHub",
                "enabled": True,
                "match": "anyof",
                "conditions": [
                    {
                        "header": "from",
                        "match_type": "contains",
                        "value": "notifications@github.com",
                        "address_test": True,
                        "negate": False,
                    }
                ],
                "actions": [{"type": "fileinto", "argument": "Notifications/GitHub"}],
            },
            {"kind": "raw", "text": "# untouched", "comment": ""},
        ],
    }
    req = SaveScriptRequest(**payload)
    assert [e.kind for e in req.entries] == ["rule", "raw"]


def test_save_script_rejects_client_minted_identity():
    """ADR-0001: identity is view state. A client that forgets to strip its
    render keys is a hard 422 rather than a silent write of junk fields."""
    payload = {
        "requires": [],
        "entries": [
            {
                "kind": "rule",
                "name": "x",
                "match": "anyof",
                "conditions": [
                    {"id": "c1", "header": "from", "match_type": "is", "value": "a@x.com"}
                ],
                "actions": [],
            }
        ],
    }
    with pytest.raises(ValidationError):
        SaveScriptRequest(**payload)


def test_save_script_max_lengths_enforced():
    """Field(max_length=…) on the entries list caps the per-DTO blast radius
    (areyousievious-9a2 defense-in-depth)."""
    too_many_entries = [
        {"kind": "rule", "name": "x", "match": "anyof", "conditions": [], "actions": []}
        for _ in range(1001)
    ]
    with pytest.raises(ValidationError):
        SaveScriptRequest(entries=too_many_entries, requires=[])


def test_login_rejects_oversized_password():
    """Field(max_length=1024) on LoginRequest.password — a 100KB password
    can't waste IMAP socket time."""
    with pytest.raises(ValidationError):
        LoginRequest(
            host="imap.example.com",
            username="u",
            password="p" * 5000,
        )


# ── OpenAPI schema coverage ──


def _dev_app():
    """OpenAPI is only served in dev. Building the app with that Settings beats
    setting AYS_ENV and reloading, which used to leave the variable set for
    every later test file."""
    from app import create_app
    from config import Settings

    return create_app(Settings(env="dev"))


@pytest.mark.asyncio
async def test_openapi_declares_response_models_for_every_route():
    """Each `@app.X` decorator now carries response_model=… so the OpenAPI
    schema exposes a concrete return shape, not the empty default."""
    transport = httpx.ASGITransport(app=_dev_app())
    if True:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        paths = schema["paths"]

        # Spot-check the security-relevant routes — each MUST have a schema
        # for its 200 response (not the empty fallback).
        for path, method in [
            ("/api/auth/login", "post"),
            ("/api/auth/logout", "post"),
            ("/api/auth/status", "get"),
            ("/api/scripts", "get"),
            ("/api/scripts/{name}", "get"),
            ("/api/scripts/{name}", "put"),
            ("/api/scripts/{name}", "delete"),
            ("/api/folders", "get"),
            ("/api/folders", "post"),
        ]:
            op = paths[path][method]
            schema_block = op["responses"]["200"].get("content", {})
            assert schema_block, (
                f"{method.upper()} {path} has no response schema (missing response_model=?)"
            )
