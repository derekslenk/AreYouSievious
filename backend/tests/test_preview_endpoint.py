"""
POST /api/scripts/preview — one generator, not two (areyousievious-8fg.17).

The SPA used to render its own preview with `previewRule`, a second
implementation of `SieveGenerator`. Both modules said in a comment that the
two "must agree"; nothing checked it, and five divergences shipped. This
endpoint deletes the duplicate: the editor asks the server what a save would
write, and the server answers with the bytes a save writes.

The headline test is `test_the_preview_is_the_bytes_a_save_writes`. It is the
assertion that could not exist while there were two generators — an agreement
test needs one side to be authoritative.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_preview_endpoint.py -v
"""

from __future__ import annotations

import pytest
from dependencies import get_script_store

from tests.fakes import FakeScriptStore

_CONDITION = {
    "header": "from",
    "match_type": "contains",
    "value": "newsletter@",
    "address_test": True,
    "negate": False,
    "address_part": "",
    "comparator": "",
}


def _rule(**overrides) -> dict:
    return {
        "kind": "rule",
        "name": "Newsletters",
        "enabled": True,
        "match": "anyof",
        "conditions": [dict(_CONDITION)],
        "actions": [{"type": "fileinto", "argument": "Lists"}],
        **overrides,
    }


# Each of these is a shape the deleted `previewRule` got wrong, plus the
# ordinary ones. They are exercised twice: once for what the preview says, and
# once for whether a save agrees with it.
RULES = {
    "plain": _rule(),
    # previewRule dropped `negate` entirely, so a NOT condition previewed as
    # its opposite — the preview told the user the inverse of what it filed.
    "negated": _rule(conditions=[{**_CONDITION, "negate": True}]),
    # previewRule did no quote escaping, so this previewed as Sieve that would
    # not parse while the save wrote correctly escaped text.
    "quotes": _rule(
        conditions=[{**_CONDITION, "value": 'he said "hi"'}],
        actions=[{"type": "fileinto", "argument": 'Odd\\Folder "x"'}],
    ),
    # previewRule showed a disabled rule as live — no `## ` anywhere.
    "disabled": _rule(enabled=False),
    # A bare `if <test> {`: match="" must not become anyof.
    "bare_if": _rule(match="", conditions=[dict(_CONDITION)]),
    "multi_condition": _rule(
        match="allof",
        conditions=[dict(_CONDITION), {**_CONDITION, "header": "subject", "value": "sale"}],
    ),
    "every_action": _rule(
        actions=[
            {"type": "fileinto", "argument": "A"},
            {"type": "fileinto_copy", "argument": "B"},
            {"type": "redirect", "argument": "x@example.com"},
            {"type": "addflag", "argument": "\\Seen"},
            {"type": "reject", "argument": "no"},
            {"type": "keep", "argument": ""},
            {"type": "discard", "argument": ""},
            {"type": "stop", "argument": ""},
        ]
    ),
    # The divergence with the worst consequence: previewRule returned '' for a
    # Rule whose last Condition was deleted, so the editor showed NOTHING while
    # a save wrote `if anyof ( ) {` — Sieve a real server refuses.
    "no_conditions": _rule(conditions=[]),
}


def _preview(http, rule: dict) -> str:
    r = http.post("/api/scripts/preview", json={"rule": rule})
    assert r.status_code == 200, r.text
    return r.json()["sieve"]


# ── The agreement that could not be asserted before ──


@pytest.mark.parametrize("name", sorted(RULES))
def test_the_preview_is_the_bytes_a_save_writes(authed_client, name: str) -> None:
    """Preview a Rule, then save that same Rule, and require the preview to be
    a literal substring of what the store now holds.

    Substring rather than equality because a save also emits the script-level
    `require [...]` line, which is a property of the script and not of any one
    Rule. Everything else must match byte for byte.
    """
    rule = RULES[name]
    store = FakeScriptStore()
    with authed_client(script_store=store) as http:
        previewed = _preview(http, rule)
        saved = http.put("/api/scripts/filters", json={"requires": [], "entries": [rule]})
    assert saved.status_code == 200, saved.text
    assert previewed in store.scripts["filters"], (
        f"{name}: preview and save disagree\n--- preview ---\n{previewed}\n"
        f"--- saved ---\n{store.scripts['filters']}"
    )


# ── The five divergences, named ──


def test_the_name_comment_is_in_the_preview(authed_client) -> None:
    """previewRule omitted the `# --- name ---` line the generator emits, so
    the preview was missing the only place a Rule's name is stored."""
    with authed_client(script_store=FakeScriptStore()) as http:
        assert "# --- Newsletters ---" in _preview(http, RULES["plain"])


def test_a_conditionless_rule_previews_the_invalid_sieve_it_would_write(authed_client) -> None:
    """The worst of the five. previewRule returned '' here, so the editor
    showed an empty preview for a Rule that a save turns into `if anyof ( ) {`
    — refused by a real server. Showing the truth is the fix; refusing to SAVE
    it is `.13`'s runtime pre-flight."""
    with authed_client(script_store=FakeScriptStore()) as http:
        sieve = _preview(http, RULES["no_conditions"])
    assert sieve, "an empty preview is the lie this endpoint exists to stop telling"
    assert "if anyof (" in sieve


def test_a_negated_condition_previews_as_negated(authed_client) -> None:
    with authed_client(script_store=FakeScriptStore()) as http:
        assert "not header" in _preview(http, RULES["negated"]) or "not address" in _preview(
            http, RULES["negated"]
        )


def test_quotes_and_backslashes_are_escaped(authed_client) -> None:
    with authed_client(script_store=FakeScriptStore()) as http:
        sieve = _preview(http, RULES["quotes"])
    assert r"he said \"hi\"" in sieve
    assert r"Odd\\Folder \"x\"" in sieve


def test_a_disabled_rule_previews_commented_out(authed_client) -> None:
    with authed_client(script_store=FakeScriptStore()) as http:
        sieve = _preview(http, RULES["disabled"])
    assert all(line.startswith("##") for line in sieve.split("\n") if line), sieve


# ── What the endpoint must NOT do ──


def test_previewing_never_dials_the_mail_server(authed_client) -> None:
    """The point of depending on `get_session` and not `get_script_store`.

    The store dependency OPENS a ManageSieve connection (see
    dependencies.get_script_store), and the editor calls this on every
    keystroke behind a debounce. A connection per keystroke would be a
    denial of service the user aimed at their own mail server.

    Asserted by making the store dependency fatal: if preview reaches for it,
    this test fails rather than quietly costing a connection.
    """

    def _explode():
        raise AssertionError("preview must not open a ScriptStore")

    with authed_client(script_store=FakeScriptStore()) as http:
        http.app.dependency_overrides[get_script_store] = _explode
        r = http.post("/api/scripts/preview", json={"rule": RULES["plain"]})
    assert r.status_code == 200, r.text


def test_the_store_dependency_really_is_fatal_when_used(authed_client) -> None:
    """The guard above is only worth anything if the sabotage bites.

    It does: a route that DOES take the store raises straight through the
    TestClient under the same override. Without this, `test_previewing_never
    _dials_the_mail_server` would pass just as happily against an override
    that had quietly stopped being wired up."""

    def _explode():
        raise AssertionError("boom")

    with authed_client(script_store=FakeScriptStore()) as http:
        http.app.dependency_overrides[get_script_store] = _explode
        with pytest.raises(AssertionError, match="boom"):
            http.get("/api/scripts")


def test_preview_requires_a_session(authed_client) -> None:
    """Generation is cheap, but it is still the user's rule content.

    The CSRF pair is left intact and only the session cookie is dropped, so
    the 401 comes from `get_session` rather than from the CSRF middleware
    refusing the request one layer earlier — which is what a bare
    unauthenticated POST gets, and which would pass this test without proving
    the route is guarded at all.
    """
    with authed_client(script_store=FakeScriptStore()) as http:
        http.cookies.delete("ays_session")
        r = http.post("/api/scripts/preview", json={"rule": RULES["plain"]})
    assert r.status_code == 401, r.text


def test_a_bare_unauthenticated_post_is_refused_by_csrf_first(authed_client) -> None:
    """Recorded because it is the answer a caller with no cookies at all gets,
    and because it is what makes the test above need its careful setup."""
    with authed_client(script_store=FakeScriptStore()) as http:
        http.cookies.clear()
        del http.headers["X-CSRF-Token"]
        r = http.post("/api/scripts/preview", json={"rule": RULES["plain"]})
    assert r.status_code == 403, r.text


def test_the_closed_vocabularies_apply_here_too(authed_client) -> None:
    """Preview shares `RuleDTO` with save, so a Rule the save path refuses
    cannot be previewed into looking legitimate first (`.18`)."""
    with authed_client(script_store=FakeScriptStore()) as http:
        r = http.post(
            "/api/scripts/preview",
            json={"rule": _rule(actions=[{"type": "vacation", "argument": "away"}])},
        )
    assert r.status_code == 422, r.text


def test_a_render_key_is_refused(authed_client) -> None:
    """`RuleDTO` is `extra="forbid"`, so the SPA must strip render keys here
    exactly as it does for a save. One projection, one set of rules."""
    with authed_client(script_store=FakeScriptStore()) as http:
        r = http.post("/api/scripts/preview", json={"rule": {**_rule(), "key": "k1"}})
    assert r.status_code == 422, r.text


def test_a_script_may_still_be_called_preview(authed_client) -> None:
    """The hazard of putting a literal segment inside a collection namespace.

    `/api/scripts/preview` is a POST and the script routes under `/{name}` are
    GET/PUT/DELETE, so nothing is shadowed — but that is worth pinning rather
    than reasoning about, because the day someone adds `POST /{name}` the
    shadowing is silent and the symptom is a user unable to open one script.
    """
    store = FakeScriptStore()
    with authed_client(script_store=store) as http:
        saved = http.put("/api/scripts/preview", json={"requires": [], "entries": [RULES["plain"]]})
        fetched = http.get("/api/scripts/preview/raw")
        listed = http.get("/api/scripts")
        deleted = http.delete("/api/scripts/preview")
    assert saved.status_code == 200, saved.text
    assert fetched.status_code == 200, fetched.text
    assert 'fileinto "Lists";' in fetched.json()["content"]
    assert "preview" in [item["name"] for item in listed.json()]
    assert deleted.status_code == 200, deleted.text
