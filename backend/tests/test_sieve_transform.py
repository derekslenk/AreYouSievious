"""
Regression tests locking in the Critical-finding fixes from the
2026-06-21 comprehensive review.

Coverage:
  - Quality C-2: parser handling of else/elsif chains and address-test modifiers
  - Security C-2: ReDoS on unterminated quoted strings (CWE-1333)
  - Round-trip stability across every test_scripts/*.sieve fixture

Run from the backend/ directory:
    cd backend && python -m pytest tests/ -v
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import sieve_transform as st

# ── Round-trip stability ──

TEST_SCRIPTS = sorted(p for p in (BACKEND / "test_scripts").glob("*.sieve") if p.stat().st_size > 0)


@pytest.mark.parametrize("path", TEST_SCRIPTS, ids=lambda p: p.name)
def test_round_trip_stable(path: Path) -> None:
    """parse -> generate -> parse must be a fixed point (rule + raw counts).

    The project's hard invariant is "lossless round-trip for supported
    constructs." This test catches Quality C-2 regressions: dropping `else`,
    `elsif`, `:domain`, or `:comparator` would change rule/raw counts on the
    second parse.
    """
    original = path.read_text()
    first = st.parse_sieve(original)
    regenerated = st.generate_sieve(first)
    second = st.parse_sieve(regenerated)

    assert len(second.rules) == len(first.rules), (
        f"{path.name}: rule count drifted ({len(first.rules)} -> {len(second.rules)}) on re-parse"
    )
    assert len(second.raw_blocks) == len(first.raw_blocks), (
        f"{path.name}: raw_block count drifted on re-parse"
    )


# ── Quality C-2: else / elsif rejection ──


def test_else_block_falls_to_raw() -> None:
    """An if/else chain has no Rule-AST representation; the whole block
    must be preserved verbatim as a RawBlock or the else body silently
    merges into the if body and changes mail routing."""
    src = (
        'require ["fileinto"];\n'
        'if header :contains "subject" "spam" {\n'
        '    fileinto "Junk";\n'
        "} else {\n"
        "    keep;\n"
        "}\n"
    )
    parsed = st.parse_sieve(src)
    assert len(parsed.rules) == 0
    assert len(parsed.raw_blocks) >= 1


def test_elsif_chain_falls_to_raw() -> None:
    src = (
        'require ["fileinto"];\n'
        'if header :is "subject" "a" {\n'
        '    fileinto "A";\n'
        '} elsif header :is "subject" "b" {\n'
        '    fileinto "B";\n'
        "}\n"
    )
    parsed = st.parse_sieve(src)
    assert len(parsed.rules) == 0
    assert len(parsed.raw_blocks) >= 1


# ── Quality C-2: address-part + comparator ──


def test_address_domain_modifier_parses() -> None:
    """Roundcube emits `address :domain :is "from" "..."`; previously the
    intervening `:domain` made the condition regex miss and the whole rule
    was silently demoted to RawBlock with no telemetry."""
    src = (
        'require ["fileinto"];\n'
        'if address :domain :is "from" "example.com" {\n'
        '    fileinto "Example";\n'
        "}\n"
    )
    parsed = st.parse_sieve(src)
    assert len(parsed.rules) == 1
    rule = parsed.rules[0]
    assert len(rule.conditions) == 1
    cond = rule.conditions[0]
    assert cond.header == "from"
    assert cond.value == "example.com"
    assert cond.match_type == "is"
    assert cond.address_test is True


def test_address_localpart_modifier_parses() -> None:
    src = (
        'require ["fileinto"];\n'
        'if address :localpart :is "from" "alice" {\n'
        '    fileinto "Alice";\n'
        "}\n"
    )
    parsed = st.parse_sieve(src)
    assert len(parsed.rules) == 1


def test_comparator_option_parses() -> None:
    """RFC 5228 `:comparator "i;ascii-casemap"` was silently dropping rules."""
    src = (
        'require ["fileinto"];\n'
        'if header :comparator "i;ascii-casemap" :is "subject" "foo" {\n'
        '    fileinto "Foo";\n'
        "}\n"
    )
    parsed = st.parse_sieve(src)
    assert len(parsed.rules) == 1


# ── Security C-2: ReDoS ──

REDOS_BUDGET_SECONDS = 0.5


@pytest.mark.parametrize("n", [25, 50, 100, 200])
def test_parse_does_not_redos_on_unterminated_quoted_string(n: int) -> None:
    """The previous quoted-string regex `"([^"]*(?:\\.[^"]*)*)"` was
    catastrophic-backtracking on inputs lacking a closing quote.
    Empirically, n=25 took ~1s and n>=30 was effectively infinite. The
    replacement `"((?:[^"\\]|\\.)*)"` is linear: each char belongs to
    exactly one alternative. This test fails closed (timing) so a future
    regression is caught even without a perf profile.
    """
    redos = 'if address :contains "from" "' + "a\\" * n
    start = time.perf_counter()
    st.parse_sieve(redos)
    elapsed = time.perf_counter() - start
    assert elapsed < REDOS_BUDGET_SECONDS, (
        f"parse_sieve on n={n} escapes took {elapsed:.3f}s "
        f"(budget {REDOS_BUDGET_SECONDS}s) — likely ReDoS regression"
    )


def test_parse_does_not_redos_on_unterminated_action_string() -> None:
    """Same catastrophic-backtracking pattern was reused in `_parse_actions`
    via the `Q` constant. Cover that ingress path too."""
    redos = 'if header :is "subject" "x" {\n    fileinto "' + "b\\" * 100
    start = time.perf_counter()
    st.parse_sieve(redos)
    elapsed = time.perf_counter() - start
    assert elapsed < REDOS_BUDGET_SECONDS


# ── T-11: script_to_json / json_to_script round-trip (areyousievious-4fo) ──
#
# script_to_json + json_to_script are the boundary where frontend JSON
# becomes a Sieve AST and vice versa. A regression here silently corrupts
# user rules on save/load through the API.


@pytest.mark.parametrize("path", TEST_SCRIPTS, ids=lambda p: p.name)
def test_json_round_trip_stable(path: Path) -> None:
    """parse -> script_to_json -> json_to_script -> generate must produce
    the same Sieve text as parse -> generate (direct path).
    """
    original = path.read_text()
    script_a = st.parse_sieve(original)
    sieve_direct = st.generate_sieve(script_a)

    restored = st.json_to_script(st.script_to_json(script_a))
    sieve_via_json = st.generate_sieve(restored)

    assert sieve_direct == sieve_via_json, f"{path.name}: JSON round-trip altered Sieve text"


def test_json_round_trip_empty_script() -> None:
    """A script with zero entries must round-trip cleanly (no key errors,
    no spurious entries)."""
    script = st.SieveScript(requires=["fileinto"])
    restored = st.json_to_script(st.script_to_json(script))
    assert restored == script


def test_json_round_trip_raw_blocks_only() -> None:
    """A script whose only content is unparseable Sieve (RawBlocks only)
    must preserve every block verbatim, in order."""
    raw_a = st.RawBlock(text='if anyof (true) { fileinto "X"; }', comment="weird")
    raw_b = st.RawBlock(text="# trailing marker", comment="")
    script = st.SieveScript(requires=["fileinto"], entries=[raw_a, raw_b])
    restored = st.json_to_script(st.script_to_json(script))
    assert restored == script
    assert restored.raw_blocks == [raw_a, raw_b]


def test_json_round_trip_preserves_mixed_rule_and_raw_order() -> None:
    """`entries` interleaves Rules and RawBlocks — the JSON path MUST preserve
    the exact sequence, because position IS the evaluation order."""
    rule = st.Rule(name="rule one")
    raw = st.RawBlock(text="# inline marker", comment="")
    script = st.SieveScript(entries=[raw, rule])
    restored = st.json_to_script(st.script_to_json(script))
    assert restored.entries == [raw, rule]
    assert isinstance(restored.entries[0], st.RawBlock)
    assert isinstance(restored.entries[1], st.Rule)


def test_script_to_json_emits_all_top_level_keys() -> None:
    """Deliberate-breakage invariant: dropping `requires` or `entries` from
    script_to_json would still let the round-trip tests above pass via
    .get(...) defaults in json_to_script. This test catches that drop."""
    script = st.SieveScript(
        requires=["fileinto", "envelope"],
        entries=[st.Rule(name="r"), st.RawBlock(text="# c")],
    )
    payload = st.script_to_json(script)
    assert {"requires", "entries"}.issubset(payload.keys())
    assert payload["requires"] == ["fileinto", "envelope"]
    assert [e["kind"] for e in payload["entries"]] == ["rule", "raw"]


def test_script_to_json_is_pure() -> None:
    """No identity is minted on the wire (ADR-0001), so the same SieveScript
    always serialises to the same payload. Reintroducing a server-minted id
    would make this non-deterministic and break exact-payload assertions."""
    src = (BACKEND / "test_scripts" / "sogo.sieve").read_text()
    assert st.script_to_json(st.parse_sieve(src)) == st.script_to_json(st.parse_sieve(src))


def test_wire_payload_carries_no_identity() -> None:
    """ADR-0001 regression lock: no entry, condition or action may carry an
    `id` on the wire. Clients mint their own render keys and strip them."""
    src = (BACKEND / "test_scripts" / "grak.sieve").read_text()
    payload = st.script_to_json(st.parse_sieve(src))
    for entry in payload["entries"]:
        assert "id" not in entry, entry
        for c in entry.get("conditions", []):
            assert "id" not in c
        for a in entry.get("actions", []):
            assert "id" not in a


def test_entry_cannot_be_orphaned_from_its_ordering() -> None:
    """The candidate-03 regression: the old representation let `order` omit a
    rule that was present in `rules`, and the generator silently dropped it.
    With one ordered sequence there is no index to disagree with."""
    payload = {
        "requires": ["fileinto"],
        "entries": [
            {
                "kind": "rule",
                "name": "first",
                "enabled": True,
                "match": "anyof",
                "conditions": [{"header": "from", "match_type": "is", "value": "a@x.com"}],
                "actions": [{"type": "fileinto", "argument": "A"}],
            },
            {
                "kind": "rule",
                "name": "second",
                "enabled": True,
                "match": "anyof",
                "conditions": [{"header": "from", "match_type": "is", "value": "b@x.com"}],
                "actions": [{"type": "fileinto", "argument": "B"}],
            },
        ],
    }
    out = st.generate_sieve(st.json_to_script(payload))
    assert "a@x.com" in out
    assert "b@x.com" in out, "second rule was dropped — ordering desync regression"
