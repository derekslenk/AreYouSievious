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

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_STRICT = ConfigDict(extra="forbid")


# ── Closed vocabularies (areyousievious-8fg.18) ──
#
# These three sets are closed BY THE TRANSFORM: `_TEST_RE` and `_ACTION_RE` can
# only ever emit these values, and `_parse_if_block` only ever sets `match` to
# one of the three below. Spelling them as `Literal` costs nothing on the read
# path and closes a real hole on the write path — before this, a body of
#
#     {"match": "xyzzy", "match_type": "bogus",
#      "actions": [{"type": "vacation", "argument": "..."}]}
#
# was accepted with no 422 and generated a Rule whose only Action was the
# comment `# unknown action: vacation`. For `vacation` that is VALID Sieve with
# the Action silently deleted. The vocabulary was enforced on one field in four
# — `address_part` — and free text on the rest.
#
# `header` is deliberately NOT here: any quoted string is a legal Sieve header
# name (`_Q`, sieve_transform.py). See ConditionDTO.header.
#
# tests/test_wire_vocabulary.py pins each of these against the transform's own
# patterns, so a vocabulary that grows there cannot silently stay 422 here.

MatchType = Literal["contains", "is", "matches", "regex"]

ActionType = Literal[
    "fileinto",
    "fileinto_copy",
    "redirect",
    "addflag",
    "reject",
    "keep",
    "discard",
    "stop",
]

# "" is the bare `if <test> {` shape — no anyof/allof wrapper in the source.
# Inventing one made `if anyof (x)` come back as allof, so the empty string is
# a real member of this vocabulary, not a missing value.
MatchOperator = Literal["", "anyof", "allof"]


# ── Sieve domain models (request side) ──


class ConditionDTO(BaseModel):
    model_config = _STRICT

    # Free text on purpose. Any quoted string is a legal Sieve header, and the
    # builder offers the common ones as suggestions rather than as a closed
    # list — an enum here would turn a display bug into a hard restriction and
    # make `x-spam-flag` unsendable.
    header: str = Field(min_length=1, max_length=120)
    match_type: MatchType
    value: str = Field(default="", max_length=4096)
    address_test: bool = False
    negate: bool = False
    # RFC 5228 tagged arguments, preserved so a round-trip can't change what a
    # rule matches. Not editable in the visual builder yet — they round-trip.
    address_part: Literal["", "all", "localpart", "domain"] = ""
    comparator: str = Field(default="", max_length=80)


class ActionDTO(BaseModel):
    model_config = _STRICT

    type: ActionType
    argument: str = Field(default="", max_length=4096)


class RuleDTO(BaseModel):
    """A Rule entry on the wire.

    Carries no `id` — identity is view state (docs/adr/0001-identity-is-view-state.md).
    Clients mint their own render keys and strip them before saving.
    """

    model_config = _STRICT

    kind: Literal["rule"] = "rule"
    name: str = Field(default="", max_length=200)
    enabled: bool = True
    match: MatchOperator = "anyof"
    conditions: list[ConditionDTO] = Field(default_factory=list, max_length=64)
    actions: list[ActionDTO] = Field(default_factory=list, max_length=64)


class RawBlockDTO(BaseModel):
    """A Raw Block entry on the wire — Sieve the parser didn't recognise."""

    model_config = _STRICT

    kind: Literal["raw"] = "raw"
    text: str = Field(default="", max_length=65536)
    comment: str = Field(default="", max_length=4096)


# One ordered sequence; position is the evaluation order. Discriminated on `kind`
# so the generated OpenAPI carries a proper oneOf + discriminator for the client.
EntryDTO = Annotated[RuleDTO | RawBlockDTO, Field(discriminator="kind")]


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
    """Typed save body. Every entry is parsed against its DTO and an unknown
    field anywhere in the tree is a hard 422.

    `entries` is one ordered sequence — position is the evaluation order. It
    replaced parallel rules/raw_blocks/order arrays, where an order array that
    omitted one of its own rules caused that rule to be silently dropped."""

    model_config = _STRICT

    entries: list[EntryDTO] = Field(default_factory=list, max_length=1000)
    requires: list[str] = Field(default_factory=list, max_length=64)


class SaveRawRequest(BaseModel):
    """`content` is required and non-empty: an empty raw save destroys the
    user's script, and the one observed way to send one was a bug, not an
    intent (areyousievious-8fg.20). Clearing a script is expressed by
    deleting it, not by overwriting it with nothing."""

    model_config = _STRICT

    content: str = Field(min_length=1, max_length=262144)


class CreateFolderRequest(BaseModel):
    model_config = _STRICT

    name: str = Field(min_length=1, max_length=200)


class PreviewRequest(BaseModel):
    """One Rule to render as Sieve (areyousievious-8fg.18 vocabularies apply).

    Deliberately one Rule and not a whole script: the editor previews the rule
    the user is looking at, and asking for a script would make the endpoint
    need `requires`, which is a property of the script rather than of any Rule.
    """

    model_config = _STRICT

    rule: RuleDTO


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
    # None for a server whose namespace is flat: RFC 3501 reports that as NIL
    # rather than a quoted character. Required `str` here would have answered
    # a ResponseValidationError — a 500 — for the very rows .12 stopped the
    # LIST parser from silently dropping.
    delimiter: str | None = None
    flags: list[str] = Field(default_factory=list)


class ScriptResponse(BaseModel):
    """GET /api/scripts/{name} — mirrors what `script_to_json` emits."""

    requires: list[str] = Field(default_factory=list)
    entries: list[EntryDTO] = Field(default_factory=list)


class ScriptRawResponse(BaseModel):
    name: str
    content: str


class PreviewResponse(BaseModel):
    """POST /api/scripts/preview — the exact bytes a save would write for this
    Rule, minus the script-level `require` line."""

    sieve: str
