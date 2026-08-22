"""
The closed vocabularies, enforced at the wire (areyousievious-8fg.18).

`match`, `match_type` and an Action's `type` are closed BY THE TRANSFORM —
`_MATCH_OPERATOR_RE`, `_TEST_RE` and `_ACTION_RE` can only ever emit the values
listed in sieve_transform's vocabulary tuples. The wire DTOs used to spell only
ONE of the four such fields as a `Literal` (`address_part`); the rest were free
`str`, so a body naming constructs that do not exist was accepted with no 422.

Two halves, and both are needed:

  - Closing them must not break READING. Every fixture is parsed and validated
    against the response model, so a vocabulary that is too narrow answers a
    500 here rather than in front of a user with an unusual script.
  - Closing them must actually bite on WRITING, which is the test at the bottom
    with the body that used to be accepted.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_wire_vocabulary.py -v
"""

from __future__ import annotations

from pathlib import Path
from typing import get_args

import api_models
import pytest
import sieve_transform as st
from api_models import ScriptResponse

from tests.fakes import FakeScriptStore

BACKEND = Path(__file__).resolve().parent.parent
FIXTURES = sorted(p for p in (BACKEND / "test_scripts").rglob("*.sieve") if p.stat().st_size > 0)


# ── The Literals say what the transform says ──


@pytest.mark.parametrize(
    ("literal", "vocabulary"),
    [
        (api_models.MatchType, set(st.MATCH_TYPES)),
        (api_models.ActionType, set(st.ACTION_TYPES)),
        # "" is the bare `if <test> {` shape, which the parser records as an
        # absent wrapper rather than inventing one. It is a real member.
        (api_models.MatchOperator, set(st.MATCH_OPERATORS) | {""}),
        (
            # Already closed before this bead — pinned here so all four closed
            # fields are held to the same source.
            api_models.ConditionDTO.model_fields["address_part"].annotation,
            set(st.ADDRESS_PARTS) | {""},
        ),
    ],
    ids=["match_type", "action type", "match", "address_part"],
)
def test_each_literal_says_what_the_transform_says(literal: object, vocabulary: set[str]) -> None:
    """A `Literal` here is a claim about what sieve_transform emits. Check it.

    The alternative — trusting the two lists to stay in step — is how
    `address_part` ended up the only closed field of four in the first place.
    sieve_transform BUILDS its regexes from these tuples, so this is the whole
    chain: one declaration, the recogniser, and the wire.
    """
    assert set(get_args(literal)) == vocabulary


def test_a_new_action_type_would_fail_this_suite_rather_than_the_user() -> None:
    """The pin above only bites if the transform's tuple is the real source.

    `ACTION_TYPES` is derived from `_QUOTED_ACTIONS` + `_BARE_ACTIONS`, the same
    pair `_parse_actions` dispatches on, so adding an action to the parser moves
    it — and the parametrized test above goes red until the DTO is widened too.
    Nothing here can be satisfied by editing one side.
    """
    dispatched = {action for _, action in st._QUOTED_ACTIONS} | set(st._BARE_ACTIONS)
    assert set(st.ACTION_TYPES) == dispatched


# ── Closing them must not break reading ──


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_every_fixture_survives_the_response_model(path: Path) -> None:
    """Parse a real script, serialise it, validate it as the route would.

    A `Literal` on the read path is a promise that the recogniser cannot emit
    anything outside it. If that promise is wrong the failure is a
    ResponseValidationError — a 500 on a script the user could open yesterday —
    so it is checked against every fixture rather than argued about.
    """
    ScriptResponse.model_validate(st.script_to_json(st.parse_sieve(path.read_text())))


# ── Closing them must bite on writing ──

_CONDITION = {
    "header": "from",
    "match_type": "contains",
    "value": "newsletter@",
    "address_test": True,
    "negate": False,
    "address_part": "",
    "comparator": "",
}
_RULE = {
    "kind": "rule",
    "name": "Newsletters",
    "enabled": True,
    "match": "anyof",
    "conditions": [_CONDITION],
    "actions": [{"type": "fileinto", "argument": "Lists"}],
}


def _body(rule: dict) -> dict:
    return {"requires": ["fileinto"], "entries": [rule]}


def test_the_body_that_used_to_be_accepted_is_now_a_422(authed_client) -> None:
    """Three bogus vocabulary values at once. Measured against the old DTOs
    this validated with no 422 and generated

        if xyzzy (
            address :bogus "from" "newsletter@"
        ) {
            # unknown action: vacation
        }

    which is not Sieve at all — a PUT of it is refused by the server, so the
    user's save fails with whatever the server says rather than with the 422
    that names the field they got wrong.
    """
    rule = {
        **_RULE,
        "match": "xyzzy",
        "conditions": [{**_CONDITION, "match_type": "bogus"}],
        "actions": [{"type": "vacation", "argument": "on holiday"}],
    }
    store = FakeScriptStore()
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/filters", json=_body(rule))
    assert r.status_code == 422, r.text
    assert store.scripts == {}, "a refused body must not reach the store"


def test_an_unknown_action_alone_is_the_dangerous_one(authed_client) -> None:
    """Only the action type wrong, and it is worse than all three.

    The old DTOs accepted it and the generator emitted a Rule whose entire body
    was `# unknown action: vacation`. Measured: sievelib accepts that script, so
    a REAL SERVER TAKES IT. The save succeeds, the rule is listed, and it does
    nothing — the failure mode with no error message anywhere.
    """
    rule = {**_RULE, "actions": [{"type": "vacation", "argument": "on holiday"}]}
    store = FakeScriptStore(validate=True)
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/filters", json=_body(rule))
    assert r.status_code == 422, r.text
    assert store.scripts == {}


@pytest.mark.parametrize(
    ("field", "rule"),
    [
        ("match", {**_RULE, "match": "either"}),
        ("match_type", {**_RULE, "conditions": [{**_CONDITION, "match_type": "startswith"}]}),
        ("action type", {**_RULE, "actions": [{"type": "vacation", "argument": ""}]}),
        ("address_part", {**_RULE, "conditions": [{**_CONDITION, "address_part": "detail"}]}),
    ],
)
def test_each_closed_field_refuses_a_value_outside_its_vocabulary(
    authed_client, field: str, rule: dict
) -> None:
    """One field at a time, so a single over-broad DTO cannot hide behind
    another field's 422."""
    store = FakeScriptStore()
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/filters", json=_body(rule))
    assert r.status_code == 422, f"{field}: {r.text}"
    assert store.scripts == {}


def test_the_header_field_stays_open(authed_client) -> None:
    """Headers are NOT a vocabulary: any quoted string is a legal Sieve header.

    Closing this one would turn a display bug — a Condition on `x-spam-flag`
    rendering as an empty dropdown — into a hard restriction, and make the
    rules a user already has unsendable.
    """
    rule = {**_RULE, "conditions": [{**_CONDITION, "header": "x-spam-flag", "address_test": False}]}
    store = FakeScriptStore()
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/filters", json=_body(rule))
    assert r.status_code == 200, r.text
    assert '"x-spam-flag"' in store.scripts["filters"]
