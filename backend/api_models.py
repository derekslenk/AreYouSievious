"""
Typed request + response models for the JSON API
(areyousievious-7mr / areyousievious-9a2).

Every Pydantic field carries a max_length cap so a malformed payload
can't grow unbounded inside the process even when the body-size
middleware lets it through (defence in depth). The caps are picked
generously against the existing test_scripts/ fixtures — they bite on
abuse, not on real usage.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

_STRICT = ConfigDict(extra="forbid")


# ── Sieve domain models (request side) ──


class ConditionDTO(BaseModel):
    model_config = _STRICT

    header: str = Field(min_length=1, max_length=120)
    match_type: str = Field(min_length=1, max_length=40)
    value: str = Field(default="", max_length=4096)
    address_test: bool = False
    negate: bool = False


class ActionDTO(BaseModel):
    model_config = _STRICT

    type: str = Field(min_length=1, max_length=40)
    argument: str = Field(default="", max_length=4096)


class RuleDTO(BaseModel):
    model_config = _STRICT

    id: str = Field(default="", max_length=64)
    name: str = Field(default="", max_length=200)
    enabled: bool = True
    match: str = Field(default="anyof", max_length=10)
    conditions: list[ConditionDTO] = Field(default_factory=list, max_length=64)
    actions: list[ActionDTO] = Field(default_factory=list, max_length=64)


class RawBlockDTO(BaseModel):
    model_config = _STRICT

    text: str = Field(default="", max_length=65536)
    comment: str = Field(default="", max_length=4096)


# ── Request DTOs ──


class LoginRequest(BaseModel):
    model_config = _STRICT

    host: str = Field(min_length=1, max_length=253)
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    port_imap: int = 993
    port_sieve: int = 4190

    @field_validator("host")
    @classmethod
    def host_must_be_valid(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or len(v) > 253:
            raise ValueError("Invalid hostname")
        if v in ("localhost", "0.0.0.0", "[::]"):
            raise ValueError("Connection to local addresses is not allowed")
        return v

    @field_validator("port_imap", "port_sieve")
    @classmethod
    def port_must_be_valid(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("Invalid port number")
        return v


class SaveScriptRequest(BaseModel):
    """Typed save body. `rules: list` was the original `list[Any]` — any
    extra/wrong field silently corrupted the saved Sieve. Now: every rule
    is parsed against `RuleDTO`, every raw block against `RawBlockDTO`,
    and an unknown field anywhere in the tree is a hard 422."""

    model_config = _STRICT

    rules: list[RuleDTO] = Field(default_factory=list, max_length=500)
    raw_blocks: list[RawBlockDTO] = Field(default_factory=list, max_length=500)
    order: list[tuple[str, int]] = Field(default_factory=list, max_length=1000)
    requires: list[str] = Field(default_factory=list, max_length=64)


class SaveRawRequest(BaseModel):
    model_config = _STRICT

    content: str = Field(default="", max_length=262144)


class CreateFolderRequest(BaseModel):
    model_config = _STRICT

    name: str = Field(min_length=1, max_length=200)


# ── Response models ──


class OkResponse(BaseModel):
    """Generic mutating-endpoint response. `name` / `sieve` are populated
    by individual routes; `response_model_exclude_none=True` keeps the
    payload minimal."""

    ok: bool = True
    name: str | None = None
    sieve: str | None = None
    username: str | None = None


class AuthStatusResponse(BaseModel):
    authenticated: bool
    username: str | None = None
    host: str | None = None


class ScriptListItem(BaseModel):
    name: str
    active: bool


class FolderListItem(BaseModel):
    name: str
    delimiter: str
    flags: list[str] = Field(default_factory=list)


class ScriptResponse(BaseModel):
    """GET /api/scripts/{name} — mirrors what `script_to_json` emits."""

    requires: list[str] = Field(default_factory=list)
    rules: list[RuleDTO] = Field(default_factory=list)
    raw_blocks: list[RawBlockDTO] = Field(default_factory=list)
    order: list[tuple[str, int]] = Field(default_factory=list)


class ScriptRawResponse(BaseModel):
    name: str
    content: str
