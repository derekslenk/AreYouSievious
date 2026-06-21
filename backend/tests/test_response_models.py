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

import importlib
import os
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
            {"rules": [], "raw_blocks": [], "order": [], "requires": []},
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
    shape. Now: every rule is a RuleDTO, and an unknown field anywhere in
    the tree is rejected."""
    payload = {
        "rules": [
            {
                "id": "r1",
                "name": "test",
                "match": "anyof",
                "conditions": [{"header": "from", "match_type": "is", "secret_backdoor": "x"}],
                "actions": [],
            }
        ],
        "raw_blocks": [],
        "order": [],
        "requires": [],
    }
    with pytest.raises(ValidationError):
        SaveScriptRequest(**payload)


def test_save_script_max_lengths_enforced():
    """Field(max_length=…) on the rules list caps the per-DTO blast radius
    (areyousievious-9a2 defense-in-depth)."""
    too_many_rules = [
        {"id": str(i), "name": "x", "match": "anyof", "conditions": [], "actions": []}
        for i in range(501)
    ]
    with pytest.raises(ValidationError):
        SaveScriptRequest(
            rules=too_many_rules,
            raw_blocks=[],
            order=[],
            requires=[],
        )


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


def _reload_app_dev():
    os.environ["AYS_ENV"] = "dev"
    import app as app_mod

    importlib.reload(app_mod)
    return app_mod


def _reload_app_prod():
    os.environ.pop("AYS_ENV", None)
    import app as app_mod

    importlib.reload(app_mod)
    return app_mod


@pytest.mark.asyncio
async def test_openapi_declares_response_models_for_every_route():
    """Each `@app.X` decorator now carries response_model=… so the OpenAPI
    schema exposes a concrete return shape, not the empty default."""
    mod = _reload_app_dev()
    try:
        transport = httpx.ASGITransport(app=mod.app)
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
    finally:
        _reload_app_prod()
