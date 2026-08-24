"""
Regression tests locking in the Critical-finding fixes from the
2026-06-21 comprehensive review.

Coverage:
  - Quality C-2: parser handling of else/elsif chains and address-test modifiers
  - Security C-2: ReDoS on unterminated quoted strings (CWE-1333)
  - Round-trip stability across every fixture under test_scripts/ (areyousievious-8fg.3)
  - Recognition census pinning the rules/raw split per fixture (areyousievious-8fg.1)
  - Recogniser reach over the vendored third-party corpus (areyousievious-8fg.3)

Run from the backend/ directory:
    cd backend && python -m pytest tests/ -v
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
import sieve_transform as st
from sievelib.parser import Parser as SieveLibParser

from tests.conftest import CORPUS, corpus_id

BACKEND = Path(__file__).resolve().parent.parent

# ── Fixture corpus (areyousievious-8fg.3) ──
#
# Two tiers, both parametrized by every test below:
#
#   test_scripts/*.sieve         Three scripts captured from real servers, plus
#                                twelve hand-written files with one construct
#                                family each. Written to be read: if you need to
#                                know what the parser does with `:comparator`,
#                                modifiers-comparator.sieve is the answer.
#   test_scripts/vendor/*.sieve  sievelib's own parser corpus, vendored under MIT
#                                (see vendor/LICENSE-sievelib). This tier is a
#                                RECOGNISER-REACH BENCHMARK, not a wish list.
#                                Most of it lands in RawBlock today; the exact
#                                reach is pinned below by
#                                test_vendor_corpus_reach_is_pinned rather than
#                                asserted in a comment that can rot.

# The corpus itself lives in `tests/conftest.py` — one definition, because it
# is the oracle every property in this suite is asserted over.
VENDOR_SCRIPTS = [p for p in CORPUS if p.parent.name == "vendor"]


def _corpus(known_red: dict[str, str] | None = None) -> list[object]:
    """Every fixture as a param, xfailing the ones with a defect someone owns.

    A fixture that reproduces a defect is NOT edited until it passes — see
    test_scripts/AGENTS.md. It stays truthful and is pinned `xfail(strict=True)`
    naming the bead that owns the fix. Strict is the whole point: the day the
    fix lands the XPASS breaks this suite, so a pin cannot outlive its defect.
    """
    red = known_red or {}
    params = []
    for path in CORPUS:
        fixture_id = corpus_id(path)
        marks = (
            [pytest.mark.xfail(strict=True, reason=red[fixture_id])] if fixture_id in red else []
        )
        params.append(pytest.param(path, id=fixture_id, marks=marks))
    return params


# Both fixtures that were pinned here are green: areyousievious-8fg.15 fixed
# the disabled-Rule name accretion and the require losses they reproduced. The
# pins were `xfail(strict=True)` precisely so they could not outlive the
# defects, and this is them not outliving them.

# ── Round-trip stability ──


@pytest.mark.parametrize("path", _corpus())
def test_round_trip_is_idempotent(path: Path) -> None:
    """parse -> generate must reach a fixed point, in TEXT and in AST.

    This replaced a pair of count assertions (`len(rules)`, `len(raw_blocks)`).
    Counts are far too weak to express "lossless round-trip": they stayed green
    while `stop; fileinto "X";` was silently reordered into
    `fileinto "X"; stop;` — same count, different mail routing.

    Generation normalises (it sorts `require` and picks one layout), so the
    fixed point is asserted from the first generation onward rather than
    against the original file.
    """
    original = path.read_text()

    gen1 = st.generate_sieve(st.parse_sieve(original))
    ast2 = st.parse_sieve(gen1)
    gen2 = st.generate_sieve(ast2)
    ast3 = st.parse_sieve(gen2)
    gen3 = st.generate_sieve(ast3)

    assert gen2 == gen1, f"{path.name}: generated Sieve is not a fixed point"
    assert gen3 == gen2, f"{path.name}: generated Sieve destabilises on a third pass"
    assert ast3 == ast2, f"{path.name}: parsed AST is not a fixed point"


def _without_spans(entries: list[st.Entry]) -> list[st.Entry]:
    """The entries compared by meaning alone, with their spans cleared.

    Defers to the module's own `_without_span`, which is the exclusion the
    verbatim guard compares by. Two spellings of "ignore the span" could drift
    apart, and then a test would be asserting a different notion of sameness
    than the code it is meant to hold to.
    """
    return [st._without_span(e) for e in entries]


@pytest.mark.parametrize("path", _corpus())
def test_round_trip_preserves_every_entry_and_require(path: Path) -> None:
    """Nothing may be dropped by the first normalising pass.

    The entry sequence must match exactly.

    `require` used to be asserted equal as a set. It cannot be, since
    areyousievious-8fg.15 made the set a function of CONTENT rather than a
    floor: a script declaring `envelope` and never testing one now stops
    declaring it, which is the point. So the assertion is the two properties
    that survive that change —

      SHRINK ONLY. The first pass may drop an extension nothing uses, and may
      never invent one.

      THEN STABLE. Whatever the first pass settled on, the second must agree.
      A derivation that pruned a little more on each pass would satisfy
      "shrink only" forever while quietly emptying the list.

      AND STILL VALID SIEVE. Those two alone are satisfied by dropping EVERY
      require on the first pass and then holding steady — raised in review, and
      correct. Neither says a require that is USED survived, and no assertion
      written in terms of our own derivation could say it without being
      circular. sievelib can: it treats a command whose extension was not
      required as a hard parse failure, so it refuses exactly the script an
      over-eager prune would produce. Checked, so the oracle is known to bite:

          require ["fileinto"]; if header :is "a" "b" { fileinto "X"; }  -> True
                                if header :is "a" "b" { fileinto "X"; }  -> False
    """
    original = path.read_text()
    first = st.parse_sieve(original)
    second = st.parse_sieve(st.generate_sieve(first))
    third = st.parse_sieve(st.generate_sieve(second))

    # Compared WITHOUT `source`, which is provenance rather than content: the
    # bytes an entry was parsed from, not what it means. `first` was parsed
    # from the user's file and `second` from our regeneration of it, so their
    # spans differ wherever house style differs from the original — a leading
    # blank line, an indent — while every field that decides what the filter
    # DOES is identical. Asserting the spans equal here would be asserting that
    # generation is byte-identical, which is a different property with its own
    # test over this same corpus (`test_verbatim_reemission.py`); folding it in
    # here would make one failure mean either of two unrelated things.
    assert _without_spans(second.entries) == _without_spans(first.entries), (
        f"{path.name}: entries changed on round-trip"
    )
    assert set(second.requires) <= set(first.requires), (
        f"{path.name}: the round trip INVENTED a require: "
        f"{sorted(set(second.requires) - set(first.requires))}"
    )
    assert set(third.requires) == set(second.requires), (
        f"{path.name}: requires still shrinking on the second pass — "
        f"lost {sorted(set(second.requires) - set(third.requires))}"
    )
    regenerated = st.generate_sieve(first)
    assert SieveLibParser().parse(regenerated.encode()), (
        f"{path.name}: the regenerated script does not parse — the likeliest "
        f"cause is a require that IS used being pruned away:\n{regenerated}"
    )


# ── Recognition census (areyousievious-8fg.1) ──

# Pinned (rules, raw_blocks) per fixture. The fixed-point tests above are
# vacuous for anything the parser declines to recognise — a RawBlock is a
# trivial fixed point, text in, same text out — so a change that makes the
# recogniser strictly WORSE keeps them green. This census is what fails
# instead. If a count changes on purpose (recogniser upgrade, fixture edit),
# re-measure and update the pin here.
RECOGNITION_CENSUS = {
    "actions-all.sieve": (2, 0),
    "disabled-rules.sieve": (2, 0),
    "escaping.sieve": (2, 0),
    "grak.sieve": (26, 0),
    "layout-variants.sieve": (2, 0),
    "lexical-brace-in-a-string.sieve": (2, 0),
    "lexical-commented-action.sieve": (1, 0),
    "lexical-nested-if.sieve": (0, 1),
    "match-regex.sieve": (2, 0),
    "modifiers-address-part.sieve": (3, 0),
    "modifiers-comparator.sieve": (2, 0),
    "modifiers-either-order.sieve": (2, 0),
    "multiple-requires.sieve": (1, 0),
    "negation.sieve": (2, 0),
    "raw-else-chain.sieve": (0, 1),
    "raw-unparseable-if.sieve": (0, 2),
    "roundcube.sieve": (0, 1),
    "sogo.sieve": (14, 0),
    "vendor/address-regex.sieve": (1, 0),
    "vendor/body-content-regex.sieve": (0, 1),
    "vendor/body-extension-2.sieve": (0, 1),
    "vendor/body-extension-3.sieve": (0, 1),
    "vendor/body-extension.sieve": (0, 1),
    "vendor/body-raw-regex.sieve": (0, 1),
    "vendor/bracket-comment.sieve": (0, 1),
    "vendor/complex-allof-with-not.sieve": (0, 1),
    "vendor/currentdate-command-timezone.sieve": (0, 1),
    "vendor/currentdate-command.sieve": (0, 1),
    "vendor/currentdate-norel.sieve": (0, 1),
    "vendor/date-command.sieve": (0, 1),
    "vendor/envelope-regex.sieve": (0, 1),
    "vendor/environment-test.sieve": (0, 1),
    "vendor/exists-get-string-or-list-2.sieve": (0, 1),
    "vendor/exists-get-string-or-list.sieve": (0, 1),
    "vendor/explicit-comparator.sieve": (1, 0),
    "vendor/fileinto-create.sieve": (0, 1),
    "vendor/fileinto-with-copy.sieve": (1, 0),
    "vendor/hash-comment.sieve": (0, 1),
    "vendor/header-regex.sieve": (1, 0),
    "vendor/imap4flags-extension.sieve": (0, 1),
    "vendor/imap4flags-hasflag.sieve": (0, 3),
    "vendor/just-one-command.sieve": (0, 1),
    "vendor/multiline-string.sieve": (0, 1),
    "vendor/multiple-not.sieve": (0, 1),
    "vendor/multitest-testlist.sieve": (0, 1),
    "vendor/nested-blocks.sieve": (0, 1),
    "vendor/non-ordered-args.sieve": (1, 0),
    "vendor/notify-extension.sieve": (0, 1),
    "vendor/redirect-with-copy.sieve": (0, 1),
    "vendor/reject-extension.sieve": (0, 1),
    "vendor/rfc5228-extended.sieve": (1, 15),
    "vendor/set-command.sieve": (0, 2),
    "vendor/singletest-testlist.sieve": (0, 1),
    "vendor/string-with-bracket-comment.sieve": (1, 0),
    "vendor/true-test.sieve": (0, 1),
    "vendor/truefalse-testlist.sieve": (0, 1),
    "vendor/utf8.sieve": (0, 1),
    "vendor/vacation-seconds.sieve": (0, 1),
    "vendor/vacationext-basic.sieve": (0, 1),
    "vendor/vacationext-medium.sieve": (0, 1),
    "vendor/vacationext-with-limit.sieve": (0, 1),
    "vendor/vacationext-with-multiline.sieve": (0, 1),
    "vendor/vacationext-with-single-mail-address.sieve": (0, 1),
}


@pytest.mark.parametrize("path", _corpus())
def test_recognition_does_not_regress(path: Path) -> None:
    """Every fixture keeps its recognised rules/raw split; new fixtures must be censused."""
    fixture_id = corpus_id(path)
    assert fixture_id in RECOGNITION_CENSUS, (
        f"{fixture_id}: uncensused fixture — measure (len(rules), len(raw_blocks)) "
        "and add it to RECOGNITION_CENSUS"
    )
    script = st.parse_sieve(path.read_text())
    got = (len(script.rules), len(script.raw_blocks))
    assert got == RECOGNITION_CENSUS[fixture_id], (
        f"{fixture_id}: recognition changed: (rules, raw_blocks) = {got}, "
        f"pinned {RECOGNITION_CENSUS[fixture_id]}"
    )


# The headline number for the vendored corpus, kept separate from the per-file
# census because it is the one figure a recogniser upgrade is supposed to move.
# It has moved twice, and NOT MONOTONICALLY, which is the point of tracking it:
#   8  after .10 gave the parser a lexical model
#   7  after .11 — two scripts lost because we were projecting them WRONG
#      (`date` and `notify` blocks came back missing constructs), one gained
#      because the modifier-ordering fix made it readable at last.
# A number going down can be the recogniser getting more honest. Re-measure and
# say which it was; do not assume either direction is the good one.
VENDOR_RULES_RECOGNISED = 7


def test_vendor_corpus_reach_is_pinned() -> None:
    """The recogniser's reach over third-party Sieve may not silently shrink.

    Per-file pins already catch a file changing shape, but this asserts the
    total a human reads in a review: 'the wrap moved reach from N to M'. A
    census where one file gains a Rule and another loses one leaves both file
    pins wrong in opposite directions and this total unchanged, so both checks
    earn their keep.
    """
    assert VENDOR_SCRIPTS, "the vendored sievelib corpus is missing"
    total = sum(len(st.parse_sieve(p.read_text()).rules) for p in VENDOR_SCRIPTS)
    assert total == VENDOR_RULES_RECOGNISED, (
        f"vendor corpus reach changed: {total} Rules recognised across "
        f"{len(VENDOR_SCRIPTS)} scripts, pinned {VENDOR_RULES_RECOGNISED}"
    )


# ── Construct coverage (areyousievious-8fg.3) ──


def _alternation(pattern: str, prefix: str) -> set[str]:
    """The alternatives inside `<prefix>a|b|c)` of a compiled pattern's source.

    Read out of sieve_transform rather than copied into a list here. A copied
    list is a claim about the vocabulary; this is the vocabulary. If the pattern
    is ever reshaped the assert below fires rather than the set quietly
    shrinking to something the corpus already satisfies.
    """
    start = pattern.index(prefix) + len(prefix)
    options = pattern[start : pattern.index(")", start)].split("|")
    assert all(re.fullmatch(r"[a-z]+", option) for option in options), (
        f"{prefix!r} no longer introduces a plain alternation: {options}"
    )
    return set(options)


SUPPORTED_ACTIONS = {action for _, action in st._QUOTED_ACTIONS} | set(st._BARE_ACTIONS)
SUPPORTED_MATCH_TYPES = _alternation(st._TEST_RE.pattern, "(?P<match_type>")
SUPPORTED_ADDRESS_PARTS = _alternation(st._ADDRESS_PART_RE.pattern, ":(")


def test_the_corpus_exercises_every_supported_construct() -> None:
    """Every construct the transform claims to support must appear in a fixture.

    The census pins how MUCH is recognised; this pins WHAT. Without it a fixture
    edit can drop the only `addflag` in the corpus and nothing goes red — the
    counts still add up, and `addflag` quietly stops being tested. That is the
    gap this corpus was built to close: before it, 17 of the ~33 supported
    constructs had no round-trip fixture at all.
    """
    actions: set[str] = set()
    match_types: set[str] = set()
    address_parts: set[str] = set()
    comparators: set[str] = set()
    negated = disabled = address_tests = header_tests = bare_ifs = wrapped_ifs = raw_blocks = 0

    for path in CORPUS:
        script = st.parse_sieve(path.read_text())
        raw_blocks += len(script.raw_blocks)
        for rule in script.rules:
            disabled += not rule.enabled
            wrapped_ifs += bool(rule.match)
            bare_ifs += not rule.match
            actions |= {action.action_type for action in rule.actions}
            for cond in rule.conditions:
                match_types.add(cond.match_type)
                address_parts.add(cond.address_part)
                comparators.add(cond.comparator)
                negated += cond.negate
                address_tests += cond.address_test
                header_tests += not cond.address_test

    assert SUPPORTED_ACTIONS <= actions, f"no fixture uses {SUPPORTED_ACTIONS - actions}"
    assert SUPPORTED_MATCH_TYPES <= match_types, (
        f"no fixture uses {SUPPORTED_MATCH_TYPES - match_types}"
    )
    assert SUPPORTED_ADDRESS_PARTS <= address_parts, (
        f"no fixture uses {SUPPORTED_ADDRESS_PARTS - address_parts}"
    )
    assert comparators - {""}, "no fixture carries a :comparator"
    assert negated, "no fixture carries a negated test"
    assert disabled, "no fixture carries a ## disabled rule"
    assert address_tests and header_tests, "the corpus needs both address and header tests"
    assert bare_ifs and wrapped_ifs, "the corpus needs both a bare `if` and an anyof/allof wrapper"
    assert raw_blocks, "no fixture lands in a RawBlock"


# ── Round-trip fidelity (architecture candidate 02) ──
#
# Five defects, one root cause: parse and generate did not represent what they
# consumed. Each of these went undetected because the old round-trip test only
# compared rule and raw-block COUNTS.


def _rule(body: str, cond: str = 'header :is "s" "x"') -> str:
    return f'require ["fileinto"];\nif {cond} {{\n{body}\n}}\n'


def test_action_order_is_preserved() -> None:
    """`stop;` before `fileinto` must stay before it. The old parser ran one
    pass per action type and appended in a hardcoded order, so this rule came
    back as `fileinto "A"; stop;` — the stop stopped preventing the filing and
    the message got filed."""
    parsed = st.parse_sieve(_rule('    stop;\n    fileinto "A";'))
    assert [a.action_type for a in parsed.rules[0].actions] == ["stop", "fileinto"]
    assert st.generate_sieve(parsed).index("stop;") < st.generate_sieve(parsed).index(
        'fileinto "A"'
    )


@pytest.mark.parametrize("folder", ["keep;", "discard;", "stop;", "a keep; b"])
def test_folder_named_like_a_bare_action_does_not_invent_one(folder: str) -> None:
    """A folder called `keep;` must not materialise a `keep` action.

    The bare-word passes searched the whole block body, including inside
    quoted arguments, so `fileinto "keep;"` grew a real `keep;` on save — an
    action the user never wrote, changing delivery."""
    parsed = st.parse_sieve(_rule(f'    fileinto "{folder}";'))
    actions = parsed.rules[0].actions
    assert [a.action_type for a in actions] == ["fileinto"]
    assert actions[0].argument == folder


def test_repeated_bare_actions_are_all_preserved() -> None:
    """`keep; keep;` is two actions. The old code used `re.search`, which is a
    boolean — every repeat after the first was dropped."""
    parsed = st.parse_sieve(_rule("    keep;\n    keep;"))
    assert [a.action_type for a in parsed.rules[0].actions] == ["keep", "keep"]


@pytest.mark.parametrize(
    "test_src,expected",
    [
        ('address :domain :is "from" "example.com"', ":domain"),
        ('address :localpart :is "from" "alice"', ":localpart"),
        ('address :all :is "from" "a@example.com"', ":all"),
        ('header :comparator "i;octet" :is "subject" "x"', ':comparator "i;octet"'),
        ('header :comparator "i;ascii-casemap" :contains "subject" "y"', ":comparator"),
    ],
)
def test_tagged_arguments_survive_generation(test_src: str, expected: str) -> None:
    """`:domain` etc. were consumed by the parser and dropped by the generator,
    so `address :domain :is "from" "example.com"` came back as
    `address :is "from" "example.com"` — which stops matching
    alice@example.com entirely. Roundcube and SOGo both emit :domain."""
    out = st.generate_sieve(st.parse_sieve(_rule('    fileinto "F";', cond=test_src)))
    assert expected in out


def test_tagged_arguments_parse_in_either_order() -> None:
    """RFC 5228 lets the tagged arguments appear in any order."""
    a = st.parse_sieve(
        _rule('    fileinto "F";', cond='address :domain :comparator "i;octet" :is "from" "x.com"')
    ).rules[0]
    b = st.parse_sieve(
        _rule('    fileinto "F";', cond='address :comparator "i;octet" :domain :is "from" "x.com"')
    ).rules[0]
    assert a.conditions[0].address_part == b.conditions[0].address_part == "domain"
    assert a.conditions[0].comparator == b.conditions[0].comparator == "i;octet"


def test_rule_name_case_is_not_mangled() -> None:
    """The name is stored only in the `# --- ... ---` comment, and the
    generator used to upper-case it — so one save turned a user's
    "GitHub notifications" into "GITHUB NOTIFICATIONS", permanently."""
    src = 'require ["fileinto"];\n# --- GitHub notifications ---\nif header :is "s" "x" {\n    fileinto "F";\n}\n'
    parsed = st.parse_sieve(src)
    assert parsed.rules[0].name == "GitHub notifications"
    assert "GitHub notifications" in st.generate_sieve(parsed)


@pytest.mark.parametrize(
    "cond_src,expected_match",
    [
        ('anyof (header :is "s" "x")', "anyof"),
        ('allof (header :is "s" "x")', "allof"),
        ('header :is "s" "x"', ""),
    ],
)
def test_match_shape_survives_round_trip(cond_src: str, expected_match: str) -> None:
    """A single-condition `allof (...)` used to come back as `anyof`, because
    the generator dropped the wrapper and the parser then defaulted. Harmless
    while there is one condition — but the moment a user adds a second, their
    AND has silently become an OR."""
    src = f'require ["fileinto"];\nif {cond_src} {{\n    fileinto "F";\n}}\n'
    once = st.parse_sieve(src)
    assert once.rules[0].match == expected_match
    twice = st.parse_sieve(st.generate_sieve(once))
    assert twice.rules[0].match == expected_match


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


@pytest.mark.parametrize("path", CORPUS, ids=corpus_id)
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
