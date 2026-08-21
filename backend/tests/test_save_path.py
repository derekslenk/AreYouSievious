"""
The save path, exercised end to end with in-memory stores
(areyousievious-8fg.8).

Nothing anywhere issued a real `PUT /api/scripts/{name}` with a body before
this, so the whole path — JSON in, generate, hand to the store, answer —
was untested. The fakes make that affordable: a test states what the server
holds, or what it will refuse, and then asserts what the ROUTE told the user.

The question these exist to answer is the false-success one: WHEN THE SERVER
REJECTS, THE ROUTE MUST NOT ANSWER OK.

The first section pins the fakes' own fidelity, because everything below it
is only as trustworthy as they are.
"""

from __future__ import annotations

import pytest
from mail_errors import MailServerUnavailable, QuotaExceeded, ScriptNotFound, ScriptRejected
from protocol_names import ProtocolNameError

from tests.fakes import FakeFolderStore, FakeScriptStore, sieve_errors

# A minimal well-formed rule, as the SPA sends it.
RULE = {
    "kind": "rule",
    "name": "Newsletters",
    "enabled": True,
    "match": "anyof",
    "conditions": [
        {
            "header": "from",
            "match_type": "contains",
            "value": "newsletter@",
            "address_test": True,
            "negate": False,
            "address_part": "",
            "comparator": "",
        }
    ],
    "actions": [{"type": "fileinto", "argument": "Lists"}],
}


def _body(*entries) -> dict:
    return {"requires": ["fileinto"], "entries": list(entries)}


# ── The fakes behave as the real sink behaves ──
#
# Whether they offer the whole seam is checked alongside the shipped adapters
# in test_store_seams.py. What matters here is FIDELITY: every divergence
# between a fake and a real server is a test that can pass while the product
# is broken.


def test_the_script_store_holds_what_was_put():
    store = FakeScriptStore()
    store.put_script("filters", "keep;\n")
    assert store.get_script("filters") == "keep;\n"
    store.activate_script("filters")
    assert store.list_scripts() == [{"name": "filters", "active": True}]


def test_the_active_script_is_listed_first():
    """As the adapter reports it — sievelib returns the active name separately
    from the rest, so a fake in insertion order would let a test assert an
    ordering no real server produces."""
    store = FakeScriptStore({"a": "keep;", "b": "keep;", "c": "keep;"}, active="c")
    assert [s["name"] for s in store.list_scripts()] == ["c", "a", "b"]


def test_the_active_script_cannot_be_deleted():
    """RFC 5804 ACTIVE: a real server refuses. A lenient fake would let a test
    prove behaviour no server permits."""
    store = FakeScriptStore({"filters": "keep;"}, active="filters")
    with pytest.raises(ScriptRejected):
        store.delete_script("filters")
    assert "filters" in store.scripts

    store.active = None
    store.delete_script("filters")
    assert store.scripts == {}


@pytest.mark.parametrize(
    "store,call",
    [
        (FakeScriptStore(), lambda s: s.put_script('x"\r\nDELETESCRIPT "y', "keep;")),
        (FakeScriptStore(), lambda s: s.get_script('x"\r\nGETSCRIPT "y')),
        (FakeScriptStore(), lambda s: s.activate_script('x"\r\nSETACTIVE "y')),
        (FakeScriptStore(), lambda s: s.delete_script('x"\r\nDELETESCRIPT "y')),
        (FakeFolderStore(), lambda s: s.create_folder('Inbox\r\nDELETE "Other"')),
    ],
    ids=["put", "get", "activate", "delete", "create-folder"],
)
def test_the_fakes_run_the_same_name_guard_as_the_real_sink(store, call):
    """Every real operation validates the name before touching the wire. A
    fake that skipped it would answer 200 for a name the real adapter rejects
    — a passing test that means nothing, and these fakes are what AGENTS.md
    now recommends for route tests."""
    with pytest.raises(ProtocolNameError):
        call(store)


def test_absent_scripts_raise_rather_than_return_none():
    store = FakeScriptStore()
    for call in (
        lambda: store.get_script("ghost"),
        lambda: store.activate_script("ghost"),
        lambda: store.delete_script("ghost"),
    ):
        with pytest.raises(ScriptNotFound):
            call()


# ── When the server rejects, the route must not answer OK ──


@pytest.mark.parametrize(
    "error,status",
    [
        (ScriptRejected("line 4: unknown command 'vacation'"), 400),
        (QuotaExceeded(), 507),
        (MailServerUnavailable(), 502),
    ],
    ids=["rejected", "quota", "unavailable"],
)
def test_a_refused_save_is_never_reported_as_saved(authed_client, error, status):
    store = FakeScriptStore()
    store.reject_next(error)
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/filters", json=_body(RULE))
    assert r.status_code == status, r.text
    assert r.json().get("ok") is not True
    assert store.scripts == {}, "a refused save must not have written anything"


def test_an_armed_failure_fires_once_and_then_clears(authed_client):
    """So a test can assert the retry succeeds, which is what a user does."""
    store = FakeScriptStore()
    store.reject_next(MailServerUnavailable())
    with authed_client(script_store=store) as http:
        assert http.put("/api/scripts/filters", json=_body(RULE)).status_code == 502
        assert http.put("/api/scripts/filters", json=_body(RULE)).status_code == 200
    assert "filters" in store.scripts


# ── The save path itself ──


def test_saving_rules_stores_generated_sieve(authed_client):
    store = FakeScriptStore()
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/filters", json=_body(RULE))
    assert r.status_code == 200, r.text
    saved = store.scripts["filters"]
    assert 'fileinto "Lists";' in saved
    assert r.json()["sieve"] == saved, "the body must report what was actually stored"


def test_what_the_route_reports_is_what_a_reload_returns(authed_client):
    """Save then read back: the round trip a user performs without thinking."""
    store = FakeScriptStore()
    with authed_client(script_store=store) as http:
        http.put("/api/scripts/filters", json=_body(RULE))
        r = http.get("/api/scripts/filters/raw")
    assert r.json()["content"] == store.scripts["filters"]


# ── The independent oracle, opt in ──


def test_validation_refuses_a_rule_whose_last_condition_was_deleted(authed_client):
    """The concrete defect the fakes were built to catch.

    Deleting a Rule's last Condition makes the generator emit `if anyof ( ) {`
    — invalid Sieve, refused by a real server, and reported as saved today.
    With the oracle armed the route answers 400 instead, carrying sievelib's
    own complaint.

    Stopping it reaching the server at all is `.13`'s runtime pre-flight; this
    is the test that makes the defect visible in the first place.
    """
    store = FakeScriptStore(validate=True)
    conditionless = {**RULE, "conditions": []}
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/filters", json=_body(conditionless))
    assert r.status_code == 400, r.text
    assert "parsing error" in r.json()["detail"]
    assert store.scripts == {}


def test_validation_is_off_by_default(authed_client):
    """Because sievelib's grammar has real gaps, a mandatory validator would
    refuse scripts a real server accepts. Off unless a test asks for it.

    WARNING — this asserts today's false success. The 200 here is the route
    accepting a script a real server would refuse, and it is expected only
    because nothing yet validates before the PUT. `.13` adds that pre-flight,
    at which point this assertion MUST become a rejection. It is a
    characterisation test, not a statement of desired behaviour.
    """
    store = FakeScriptStore()
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/filters", json=_body({**RULE, "conditions": []}))
    assert r.status_code == 200, r.text


@pytest.mark.parametrize(
    "extension,script",
    [
        ("include", 'require ["include"];\ninclude :personal "shared";\n'),
        ("addheader", 'require ["editheader"];\naddheader "X-Tag" "v";\n'),
        ("spamtest", 'require ["spamtest"];\nif spamtest :value "eq" "5" {\n    discard;\n}\n'),
    ],
)
def test_the_oracle_has_gaps_which_is_why_it_is_opt_in(extension, script):
    """Pins the reason. If sievelib grows these, this test says so and the
    opt-in can be revisited — rather than the rationale quietly rotting."""
    complaint = sieve_errors(script)
    assert complaint is not None and "unknown command" in complaint, (
        f"sievelib now understands {extension}; revisit whether validation must stay opt-in"
    )


def test_the_oracle_accepts_what_our_generator_normally_produces(authed_client):
    """The other half: validation on must not reject ordinary output, or the
    opt-in would be useless rather than merely cautious."""
    store = FakeScriptStore(validate=True)
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/filters", json=_body(RULE))
    assert r.status_code == 200, r.text
    assert sieve_errors(store.scripts["filters"]) is None


# ── The folder seam ──
#
# The happy path is already covered through the real adapter
# (test_protocol_names.py) and at the adapter boundary
# (test_adapter_failures.py). What neither reaches is a server REFUSING a
# create over HTTP, which is what the fake makes cheap.


def test_creating_a_folder_that_exists_is_refused_not_silently_ok(authed_client):
    store = FakeFolderStore(["Lists"])
    with authed_client(folder_store=store) as http:
        r = http.post("/api/folders", json={"name": "Lists"})
    assert r.status_code == 400, r.text
    assert store.folders == ["Lists"], "a refused create must not have added anything"
