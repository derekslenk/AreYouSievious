"""
Round-trip fidelity: the four losses that survive a parse (areyousievious-8fg.15).

Each of these is a FIRST-PASS loss, which is why the existing round-trip tests
never saw them: both of those compare gen1 against gen2, and by gen1 the
information is already gone from both sides. `.3` added two fixtures that DO
see them and pinned them `xfail(strict=True)` naming this bead; those pins come
off here.

  1. A disabled Rule's name accretes one `# --- ` per save, forever.
  2. A second `require` statement REPLACES the first.
  3. A multi-line `require` is read as one line and the rest becomes raw text,
     emitted after the regenerated require — Sieve a server refuses.
  4. `require` accumulates and never prunes.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_round_trip_fidelity.py -v
"""

from __future__ import annotations

import pytest
import sieve_transform as st
from sievelib.parser import Parser as SieveLibParser


def _round_trips(text: str, times: int = 3) -> list[str]:
    """Successive generations, as a user gets from repeated saves."""
    out = []
    current = text
    for _ in range(times):
        current = st.generate_sieve(st.parse_sieve(current))
        out.append(current)
    return out


def _regenerated(text: str) -> str:
    """What a save writes when every entry has actually been edited.

    An unedited script is now re-emitted byte for byte
    (docs/adr/0002-the-file-is-a-sequence-of-spans.md), so the canonical
    renderer — and with it `require` pruning and the one-statement rule — is
    only reached by an entry that regenerates. Clearing the span is precisely
    the state a Rule the builder minted is in: no pristine copy to compare
    against, so nothing to re-emit.
    """
    script = st.parse_sieve(text)
    for entry in script.entries:
        entry.source = ""
    return st.generate_sieve(script)


# ── 1. The disabled-Rule name ──

DISABLED = """require ["fileinto"];

# --- GitHub notifications ---
## if header :contains "from" "notifications@github.com" {
##     fileinto "GitHub";
## }
"""


def test_a_disabled_rule_keeps_its_name_across_saves() -> None:
    """The accretion. Measured before this fix, one `# --- ` added per save:

        save 1: ## # --- GitHub notifications ---
        save 2: ## # --- # --- GitHub notifications ---
        save 3: ## # --- # --- # --- GitHub notifications ---

    Root cause: `_generate_rule` emitted the name comment INSIDE the block,
    and `generate` then prefixed the whole block with `## `. On reparse that
    line found no `if`, fell through to the generic comment handler, and
    `lstrip("#").strip()` baked the marker into the name.
    """
    for generated in _round_trips(DISABLED):
        (rule,) = st.parse_sieve(generated).rules
        assert rule.name == "GitHub notifications", generated
        assert not rule.enabled


def test_the_name_is_emitted_outside_the_commented_block() -> None:
    """Not merely fixed — made unrepresentable.

    The name line is now written BEFORE the block that gets commented, so
    there is no longer any path by which `## ` can be prefixed onto it. A fix
    that kept the name inside and stripped harder on the way back in would
    have left the bug one regex change away from returning.
    """
    generated = st.generate_sieve(st.parse_sieve(DISABLED))
    name_line = next(line for line in generated.split("\n") if "GitHub notifications" in line)
    assert name_line == "# --- GitHub notifications ---", generated
    assert not name_line.startswith("##")


def test_the_legacy_poisoned_shape_is_normalised_on_the_way_in() -> None:
    """Scripts already carry the old shape, and we do not own the file.

    A Rule saved by any previous version reads back as `# --- name`. The reader
    accepts both spellings and normalises, so opening a poisoned script shows
    the right name.

    Normalisation happens ON THE WAY IN, and only there. An UNEDITED save now
    re-emits the original bytes — the poisoned line comes back exactly as it
    was — because a file nobody asked us to change is not one we rewrite. The
    clean shape appears on the REGENERATING path: edit the rule and the
    accretion unwinds to `# --- name ---`.

    That is still a fix rather than a freeze, and the reason is the accretion's
    mechanism: every deepening required a rewrite on every save, and there is
    no longer a rewrite on every save. The shape stops getting worse whether or
    not anyone edits it, and is corrected the moment anyone does.
    """
    legacy = """require ["fileinto"];

## # --- # --- GitHub notifications ---
## if header :contains "from" "notifications@github.com" {
##     fileinto "GitHub";
## }
"""
    (rule,) = st.parse_sieve(legacy).rules
    assert rule.name == "GitHub notifications"
    assert not rule.enabled
    # A save that edits nothing no longer rewrites the file at all, so the
    # poisoned line comes back exactly as it was. That FIXES the accretion
    # rather than leaving it: every deepening needed a rewrite on every save,
    # and there is no longer one.
    assert st.generate_sieve(st.parse_sieve(legacy)) == legacy
    # Editing the rule puts it on the regenerating path, and that is where the
    # accretion unwinds to the clean shape.
    assert "## # ---" not in _regenerated(legacy)


def test_an_enabled_rule_still_carries_its_name_inside_nothing() -> None:
    """The enabled shape is unchanged — the name comment sits above the block
    exactly as it always did. Moving it for the disabled case must not move it
    for this one."""
    src = 'require ["fileinto"];\n\n# --- Live one ---\nif header :is "a" "b" {\n    fileinto "X";\n}\n'
    generated = st.generate_sieve(st.parse_sieve(src))
    assert "# --- Live one ---\nif header" in generated


# ── 2 & 3. `require` is a statement, not a line ──


def test_a_second_require_statement_extends_rather_than_replaces() -> None:
    """RFC 5228 §3.2 shows multiple requires, and Horde/Ingo emits them.

    `parse` ASSIGNED per require line, so the last one won and everything
    named earlier was gone before the first generation — invisible to both
    round-trip tests, because both sides had already lost it.
    """
    script = st.parse_sieve('require ["fileinto", "envelope"];\nrequire ["imap4flags"];\n\nkeep;\n')
    assert set(script.requires) == {"fileinto", "envelope", "imap4flags"}


def test_a_multi_line_require_is_read_whole() -> None:
    """Roundcube and SOGo both emit this shape.

    Reading one line gave `requires == []` and turned the continuation lines
    into RawBlocks, which the generator then emitted AFTER its own regenerated
    require:

        require ["fileinto"];
            "copy",
            "reject"
        ];

    That is not Sieve, and it was PUT to the mail server.
    """
    script = st.parse_sieve('require [\n    "fileinto",\n    "imap4flags"\n];\n\nkeep;\n')
    assert set(script.requires) == {"fileinto", "imap4flags"}
    # `keep;` is a top-level command and legitimately raw. What must NOT be
    # here is a fragment of the require statement itself.
    raw = [block.text for block in script.raw_blocks]
    assert raw == ["keep;"], raw


def test_the_regenerated_script_has_exactly_one_require_line() -> None:
    """Whatever shape went in, one statement comes out — and nothing that was
    named in any of them is missing from it."""
    generated = _regenerated(
        'require ["fileinto"];\nrequire [\n    "copy",\n    "reject"\n];\n\n'
        'if header :is "a" "b" {\n    fileinto :copy "X";\n    reject "no";\n}\n'
    )
    require_lines = [line for line in generated.split("\n") if line.startswith("require")]
    assert len(require_lines) == 1, generated
    for extension in ("fileinto", "copy", "reject"):
        assert f'"{extension}"' in require_lines[0]


def test_a_require_inside_a_comment_is_not_a_require() -> None:
    """The statement scan reads the lexical map, so this is a comment and
    nothing else — the same guarantee `.10` gave block extent."""
    script = st.parse_sieve('require ["fileinto"];\n# require ["vacation"];\n\nkeep;\n')
    assert set(script.requires) == {"fileinto"}


# ── 4. Pruning ──


def test_an_extension_no_longer_used_is_dropped() -> None:
    """`_compute_requires` seeded from the parsed set, so it was a FLOOR.

    Swap a `reject` action for `keep`, save, and `require ["fileinto",
    "reject"]` outlives the action that needed it — the script keeps claiming
    an extension it does not use, and a server that does not offer `reject`
    refuses a script that no longer needs it.
    """
    # The swap is performed here rather than baked into the input, because
    # pruning is now a property of REGENERATION: an untouched over-declared
    # file keeps saying so rather than having a line rewritten that nobody
    # asked us to touch.
    script = st.parse_sieve(
        'require ["fileinto", "reject"];\n\nif header :is "a" "b" {\n    reject "no";\n}\n'
    )
    (rule,) = script.rules
    rule.actions = [st.Action(action_type="keep")]
    generated = st.generate_sieve(script)
    # On the REQUIRE LINE, not anywhere in the text: the name this rule was
    # given at parse time is derived from what it did then, so it still reads
    # `... \u2192 reject no`. That is a label, not a declaration, and it is the
    # declaration that makes a server refuse the script.
    assert [ln for ln in generated.split("\n") if ln.startswith("require")] == [], generated


def test_pruning_stops_at_the_first_thing_we_do_not_understand() -> None:
    """THE CARVE-OUT, and the reason pruning is not simply "derive from
    content".

    A RawBlock's requirements are unknowable — we did not recognise the block,
    so we cannot say which extensions it needs. Measured: an `envelope` test
    lands in a RawBlock, and deriving requires purely from Rules would drop
    `require ["envelope"]` and leave behind a script the server rejects.

    So pruning happens only when EVERY entry is a Rule. One RawBlock and the
    original set is preserved whole, which is what the old floor did for every
    script.
    """
    src = 'require ["envelope"];\n\nif envelope :is "to" "x@y.com" {\n    keep;\n}\n'
    script = st.parse_sieve(src)
    assert script.rules == [] and len(script.raw_blocks) == 1, "premise: this is raw"
    assert "envelope" in st.generate_sieve(script)


def test_a_rule_still_gains_the_extension_its_actions_need() -> None:
    """Pruning must not become "emit only what was declared" — an action added
    in the builder still brings its extension with it."""
    script = st.SieveScript(
        entries=[
            st.Rule(
                name="N",
                conditions=[st.Condition(header="a", match_type="is", value="b")],
                actions=[st.Action(action_type="fileinto_copy", argument="X")],
            )
        ]
    )
    generated = st.generate_sieve(script)
    assert '"copy"' in generated and '"fileinto"' in generated


@pytest.mark.parametrize(
    "src",
    [
        pytest.param('require ["fileinto"];\n\nkeep;\n', id="raw keep"),
        pytest.param(
            'require ["fileinto"];\n\nif header :is "a" "b" {\n    fileinto "X";\n}\n',
            id="rule that needs it",
        ),
        pytest.param(
            'require ["fileinto"];\nrequire ["imap4flags"];\n\n'
            'if header :is "a" "b" {\n    fileinto "X";\n    addflag "\\\\Seen";\n}\n',
            id="two statements, both needed",
        ),
    ],
)
def test_every_shape_still_reaches_a_fixed_point(src: str) -> None:
    """Pruning changes what the first generation emits, so it is exactly the
    kind of change that can destabilise the round trip: prune, reparse, prune
    again, and lose one more each pass."""
    gen1, gen2, gen3 = _round_trips(src)
    assert gen2 == gen1
    assert gen3 == gen2


# ── Raised in review of this change ──


def test_an_unterminated_require_does_not_eat_the_next_statement() -> None:
    """The worst thing this module can do is DELETE something.

    `require` was consumed up to its terminating `;`, and a `require` without
    one ran on to the next `;` anywhere in the file. Reproduced:

        require ["fileinto"]
        if header :is "a" "b" { fileinto "x"; }

    regenerated to `"\\n"` — the rule gone. A `require` holds strings,
    brackets, commas and its semicolon; a line with a brace or a bare word
    belongs to the next statement, so the scan stops there.
    """
    src = 'require ["fileinto"]\nif header :is "a" "b" { fileinto "x"; }\n'
    script = st.parse_sieve(src)

    assert len(script.rules) == 1, "the rule after an unterminated require was deleted"
    assert 'fileinto "x";' in st.generate_sieve(script)

    # And the malformed `require` itself is PRESERVED rather than read. An
    # earlier version of this fix read it anyway; refusing is the same call
    # made for every other unclean statement below — we do not guess at
    # something we cannot parse, we hand back its bytes.
    assert script.requires == []
    assert any('require ["fileinto"]' in raw.text for raw in script.raw_blocks)


def test_a_script_that_is_only_requires_keeps_them() -> None:
    """`all(...)` over an empty sequence is True, so a script with no entries
    counted as fully understood and had every extension pruned — regenerating
    `require ["fileinto"];` to nothing at all. A script with nothing in it is
    not one we understand; it is one with nothing to derive from."""
    generated = st.generate_sieve(st.parse_sieve('require ["fileinto", "imap4flags"];\n'))
    assert '"fileinto"' in generated and '"imap4flags"' in generated


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        pytest.param("# --- # --- # --- Boss ---", "Boss", id="three saves of accretion"),
        pytest.param("# --- Boss ---", "Boss", id="one marker"),
        pytest.param("# -- important -- stuff", "# -- important -- stuff", id="two dashes, a name"),
        pytest.param("-- a -- b", "-- a -- b", id="unbalanced, a name"),
        pytest.param("# 1 priority", "# 1 priority", id="leading hash, a name"),
        pytest.param("Alpha - Beta", "Alpha - Beta", id="a dash in the middle"),
    ],
)
def test_only_the_accretion_shape_is_peeled(name: str, expected: str) -> None:
    """The peel ran two independent `re.sub`s, so the leading one could fire
    with no trailing marker to balance it and `# -- important -- stuff` came
    back as `important -- stuff` — a name quietly edited. Raised in review.

    Both ends must match in ONE pattern, and the accretion's own asymmetric
    layer (`# --- `, exactly as the generator wrote it) is peeled separately.
    """
    assert st.SieveParser._clean_comment_name(name) == expected


def test_re_entry_is_bounded(monkeypatch) -> None:
    """Parsing the uncommented text as a whole script is what accepts both name
    shapes — and it means `parse` can call itself. A parser that recurses on
    text a user can supply, with no bound, is a denial of service waiting to be
    found. Raised in review of this change.

    Asserted by watching PARSER CONSTRUCTION, because neither the output nor
    the call depth can see the bound: the output is identical either way, and
    `_try_parse_disabled_block` is only entered where `## ` lines exist, so an
    unbounded run never records a deeper call. Two earlier versions of this
    test watched those and the mutation survived both.

    The input is mixed-depth on purpose: a uniform `## ## ` run never reaches
    the guard, because the peek strips one layer, finds no `if`, and gives up
    before any re-entry.
    """
    depths = []
    original = st.SieveParser.__init__

    def watched(self, text, depth=0):
        depths.append(depth)
        original(self, text, depth)

    monkeypatch.setattr(st.SieveParser, "__init__", watched)

    st.parse_sieve(
        '## if header :is "a" "b" {\n##     fileinto "X";\n## }\n'
        '## ## if header :is "c" "d" {\n## ##     fileinto "Y";\n## ## }\n'
    )

    assert max(depths) == st._MAX_DISABLED_DEPTH, (
        f"expected re-entry to stop at depth {st._MAX_DISABLED_DEPTH}, "
        f"saw {max(depths)} — if this is 0 the input no longer reaches the guard, "
        "and if it is higher the guard is not holding"
    )


def test_a_long_run_of_disabled_lines_does_not_blow_up() -> None:
    """The retry path: a `## ` run whose parse fails is re-attempted from each
    line, so cost grows with the square of the run. Bounded here rather than
    argued about — the body-size limit lets a 1 MiB script through, and this
    runs on an HTTP request.
    """
    import time

    body = (
        ['## if header :is "a" "b" {']
        + [f'##     vacation "x{i}";' for i in range(2000)]
        + ["## }"]
    )
    started = time.perf_counter()
    st.parse_sieve("\n".join(body) + "\n")
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"{elapsed:.2f}s for {len(body)} commented lines"


def test_many_failing_disabled_fragments_do_not_blow_up() -> None:
    """The EXPENSIVE retry path, which the test above does not reach.

    Raised in review of this PR, and the review was right: above, the peek
    finds no `if` and gives up immediately, so every retry is cheap. Here each
    retry position DOES find an `if` ahead, so each one built a fresh
    `SieveParser` and re-lexed the rest of the file. Measured before the fix:

        200 fragments  0.092s
        400 fragments  0.383s      <- four times the work for twice the input
        800 fragments  1.532s

    A `## ` run that fails is now tried ONCE, not once per line, so this is
    linear. The body-size limit admits a 1 MiB script and this runs on an HTTP
    request, which is what made the difference worth having.
    """
    import time

    fragments = "\n".join(f'## if header :is "a{i}" "b" {{' for i in range(3000))
    started = time.perf_counter()
    st.parse_sieve(fragments + "\n")
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"{elapsed:.2f}s for 3000 failing fragments"


def test_a_name_that_looks_like_accretion_is_indistinguishable_from_it() -> None:
    """A known ambiguity, pinned rather than papered over.

    A rule a user genuinely names `# --- urgent` is written back by
    `generate_entry` as `# --- # --- urgent ---` — byte-identical to what the
    old accretion produced from the name `urgent`. Nothing in the text can tell
    the two apart, so the peel takes it back to `urgent`.

    Raised in review of this PR. It is not fixable by reading harder; it would
    need a different on-disk shape for names, which is a format change and a
    bigger decision than this bead. The trigger is narrow — a name has to begin
    with exactly `# --- ` — and the peel exists to unwind real damage from
    every script saved before `.15`. Recorded here so the next person meets it
    as a decision rather than as a surprise.
    """
    src = (
        'require ["fileinto"];\n\n# --- # --- urgent ---\n'
        'if header :is "a" "b" {\n    fileinto "X";\n}\n'
    )
    (rule,) = st.parse_sieve(src).rules
    assert rule.name == "urgent"


@pytest.mark.parametrize(
    ("label", "src"),
    [
        pytest.param("shared line", 'require ["fileinto"]; keep;\n', id="shared line"),
        pytest.param("multi-line shared", 'require [\n    "fileinto"\n]; keep;\n', id="multi-line"),
        pytest.param("no terminator", 'require ["fileinto"]\nkeep;\n', id="unterminated"),
    ],
)
def test_a_require_sharing_its_line_loses_nothing(label: str, src: str) -> None:
    """Whole LINES are consumed, so a statement sharing the terminator's line
    went with it. Raised in review of this PR and reproduced both ways:

        require ["fileinto"]; keep;     ->  the `keep;` simply GONE
        require [\n "fileinto"\n]; keep;  ->  an orphan `]; keep;` line, with
                                            no matching `[` — invalid Sieve

    Splitting a line is not available to a line-shaped parser, so an unclean
    statement is refused and kept verbatim instead. The `require` stops being
    read; nothing stops existing.
    """
    generated = st.generate_sieve(st.parse_sieve(src))
    assert "keep;" in generated, f"{label}: the statement after the require was lost"
    # Valid-in, valid-out. An earlier version of this test looked for a line
    # starting `];`, which flagged the CORRECT output too — the fixed code
    # keeps the whole fragment together, so its `[` is two lines above. The
    # real property is that we did not turn parseable Sieve into unparseable
    # Sieve, and sievelib is the one that can say so.
    if SieveLibParser().parse(src.encode()):
        assert SieveLibParser().parse(generated.encode()), (
            f"{label}: valid Sieve in, invalid out:\n{generated}"
        )


def test_a_comparator_keeps_the_require_it_needs() -> None:
    """RFC 5228 §2.7.3: only `i;octet` and `i;ascii-casemap` are built in.

    `_generate_test` emits the `:comparator` tag, but the derivation never
    looked at `cond.comparator` — so pruning dropped the declaration and left
    the tag, on an UNEDITED re-save. Raised in review of this PR; a compliant
    server (Dovecot Pigeonhole) refuses the result.
    """
    src = (
        'require ["fileinto", "comparator-i;ascii-numeric"];\n\n'
        'if header :comparator "i;ascii-numeric" :is "x-priority" "10" {\n'
        '    fileinto "Urgent";\n}\n'
    )
    generated = st.generate_sieve(st.parse_sieve(src))
    assert ':comparator "i;ascii-numeric"' in generated
    assert '"comparator-i;ascii-numeric"' in generated, generated


@pytest.mark.parametrize("comparator", ["i;octet", "i;ascii-casemap"])
def test_a_builtin_comparator_needs_no_require(comparator: str) -> None:
    """The other half. Requiring these would be noise a server has to ignore,
    and would make the derivation wrong in the opposite direction."""
    src = (
        f'require ["fileinto"];\n\nif header :comparator "{comparator}" :is "a" "b" {{\n'
        '    fileinto "X";\n}}\n'
    )
    assert f'"comparator-{comparator}"' not in st.generate_sieve(st.parse_sieve(src))
