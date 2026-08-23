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


def _round_trips(text: str, times: int = 3) -> list[str]:
    """Successive generations, as a user gets from repeated saves."""
    out = []
    current = text
    for _ in range(times):
        current = st.generate_sieve(st.parse_sieve(current))
        out.append(current)
    return out


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

    A Rule saved by any previous version reads back as `# --- name`. The
    reader accepts both spellings and normalises, so opening a poisoned script
    shows the right name and saving it writes the clean shape — the accretion
    unwinds rather than being frozen at whatever depth it reached.
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
    assert "## # ---" not in st.generate_sieve(st.parse_sieve(legacy))


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
    generated = st.generate_sieve(
        st.parse_sieve(
            'require ["fileinto"];\nrequire [\n    "copy",\n    "reject"\n];\n\n'
            'if header :is "a" "b" {\n    fileinto :copy "X";\n    reject "no";\n}\n'
        )
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
    generated = st.generate_sieve(
        st.parse_sieve('require ["fileinto", "reject"];\n\nif header :is "a" "b" {\n    keep;\n}\n')
    )
    assert "reject" not in generated
    assert "fileinto" not in generated, "nothing here files anything either"


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
