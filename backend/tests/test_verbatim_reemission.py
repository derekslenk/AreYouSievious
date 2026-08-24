"""
Verbatim re-emission of unedited entries (areyousievious-8fg.14).

Opening a Roundcube- or SOGo-authored script and editing one Rule used to
rewrite EVERY Rule into our house style. The file is now a sequence of
spans: parse records the bytes each entry came from, and the generator
re-emits that span byte-identical unless the entry has actually changed.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_verbatim_reemission.py -v
"""

from __future__ import annotations

import sieve_transform as st


def test_new_entries_carry_an_empty_span():
    """A Rule the builder minted was never parsed from anything, so it has no
    span and must regenerate. `""` is that state — not None, so no caller has
    to reason about two kinds of absent."""
    assert st.Rule().source == ""
    assert st.RawBlock(text="keep;").source == ""


def test_a_fresh_script_has_no_preamble_requires_source_or_tail():
    script = st.SieveScript()
    assert script.preamble == ""
    assert script.requires_source == ""
    assert script.tail == ""


def test_spans_survive_the_json_round_trip():
    """The span crosses the wire and comes back. If `script_to_json` drops it,
    every save regenerates and the whole feature is silently inert."""
    script = st.SieveScript(
        requires=["fileinto"],
        entries=[st.Rule(name="Spam", source="# --- Spam ---\nif true {\n  keep;\n}\n")],
        preamble="# hand-written header\n",
        requires_source='require ["fileinto"];\n',
        tail="\n# trailing note\n",
    )
    back = st.json_to_script(st.script_to_json(script))
    assert back.preamble == script.preamble
    assert back.requires_source == script.requires_source
    assert back.tail == script.tail
    assert back.entries[0].source == script.entries[0].source


def test_raw_block_spans_survive_the_json_round_trip():
    script = st.SieveScript(entries=[st.RawBlock(text="keep;", source="\nkeep;\n")])
    back = st.json_to_script(st.script_to_json(script))
    assert back.entries[0].source == "\nkeep;\n"
