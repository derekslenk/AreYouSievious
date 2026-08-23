"""
An INDEPENDENT oracle: does generation preserve MEANING? (areyousievious-8fg.13)

Every other round-trip test in this suite is written in terms of our own
parser, so it can only catch what our parser can see. That is precisely the
blind spot the multiple-`require` loss lived in for as long as it did: both
sides of every comparison had already lost the extension, so both sides
agreed.

This asks a different program. sievelib parses the ORIGINAL and the
REGENERATED script and we compare its ASTs — a tree built by code that has
never heard of `Rule`, `RawBlock` or any assumption of ours.

WHAT IS NORMALISED, AND WHY EACH IS SAFE
----------------------------------------
An oracle that flags deliberate normalisation is an oracle nobody keeps. Three
differences are ours on purpose:

  `require`   — `.15` made it a function of content, so it is legitimately
                pruned, sorted and merged into one statement. It has its own
                checks: the shrink-only/stable pair in test_sieve_transform,
                and sievelib's own refusal to parse a script whose command
                lacks its extension.
  header case — RFC 5322 §3.6.8 makes field names case-insensitive, and the
                parser lowercases them. `Subject` and `subject` select the
                same header on every server.
  escaping    — `"\\."` and `"."` are the same string (RFC 5228 §2.4.2), so
                strings are compared UNESCAPED. Comparing them as written
                would be comparing spelling, not meaning.

Nothing else is normalised. Anything the oracle still flags is a change to
what the script DOES.

WHAT IT FOUND, before it was even finished
------------------------------------------
Three defects, all silent, all shipped:

  1. `:regex "^test@example\\.org$"` regenerated as `"^test@example\\\\.org$"`.
     Per RFC 5228 §2.4.2 the first is the regex `^test@example.org$`, where
     the dot matches ANY character; the second makes it a literal dot. One
     save, a different filter.
  2. `addflag "\\Flagged Big"` — the flag `Flagged Big` — regenerated as
     `"\\\\Flagged Big"`, i.e. the flag `\\Flagged Big`.
  3. A multi-line `vacation` command was read one LINE at a time into four
     RawBlocks, and generation puts a blank line between entries — so a blank
     line was injected INTO the vacation message. The text a sender would have
     received was not the text the user wrote.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_ast_oracle.py -v
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest
import sieve_transform as st
from sievelib.parser import Parser as SieveLibParser

BACKEND = Path(__file__).resolve().parent.parent
FIXTURES = sorted(p for p in (BACKEND / "test_scripts").rglob("*.sieve") if p.stat().st_size > 0)

_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_ESCAPE = re.compile(r"\\(.)", re.DOTALL)
_TESTS_WITH_A_HEADER_NAME = ("header", "address")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _unescape_strings(line: str) -> str:
    """Compare what a string MEANS, not how it was spelled."""
    return _QUOTED.sub(lambda m: '"' + _ESCAPE.sub(r"\1", m.group(1)) + '"', line)


def _normalise(dump: str) -> list[str]:
    """sievelib's dump, minus the differences we make on purpose."""
    lines = dump.splitlines()
    out: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        # `require` and its argument lines.
        if stripped.startswith("require "):
            depth = _indent(line)
            index += 1
            while index < len(lines) and _indent(lines[index]) > depth:
                index += 1
            continue

        out.append(_unescape_strings(line))
        index += 1

        # A header/address test ends with its header name and then its value,
        # whatever tags came before. Counting from the END is why: an earlier
        # version walked FORWARD looking for the first argument that was not a
        # tag, special-casing `:comparator` as the one tag with a value of its
        # own — and a relational `header :count "eq" :is "Subject" "1"` would
        # have read `"eq"` as the header name.
        #
        # Raised in review of this PR as unreachable, and checked: it is more
        # unreachable than that, because sievelib cannot parse a relational
        # test AT ALL, so `meaning()` returns None and the comparison never
        # happens. This is therefore robustness in the normaliser, not a bug
        # fix — worth having anyway, since the oracle is what every other
        # claim in this suite leans on, and counting from the end is simpler
        # than special-casing which tags carry arguments.
        if not any(stripped.startswith(f"{name} ") for name in _TESTS_WITH_A_HEADER_NAME):
            continue
        depth = _indent(line)
        arguments = []
        while index < len(lines) and _indent(lines[index]) > depth:
            arguments.append(_unescape_strings(lines[index]))
            index += 1
        if len(arguments) >= 2:
            # Second from last is the header name. Case is not part of its
            # meaning (RFC 5322 §3.6.8).
            arguments[-2] = arguments[-2].lower()
        out.extend(arguments)
    return out


def meaning(text: str) -> list[str] | None:
    """What sievelib thinks this script does, or None if it cannot read it."""
    parser = SieveLibParser()
    if not parser.parse(text.encode()):
        return None
    target = io.StringIO()
    parser.dump(target)
    return _normalise(target.getvalue())


# ── The oracle ──


@pytest.mark.parametrize(
    "path", FIXTURES, ids=lambda p: str(p.relative_to(BACKEND / "test_scripts"))
)
def test_regeneration_preserves_meaning(path: Path) -> None:
    """Parse it, generate it, and ask sievelib whether it still says the same.

    A failure here is not a formatting complaint. It means the script we would
    PUT to the user's mail server behaves differently from the one we read.
    """
    original = path.read_text()
    before = meaning(original)
    if before is None:
        pytest.skip("sievelib cannot read the original; nothing to compare against")

    regenerated = st.generate_sieve(st.parse_sieve(original))
    after = meaning(regenerated)

    assert after is not None, f"regeneration produced Sieve sievelib cannot parse:\n{regenerated}"
    assert after == before, "regeneration changed what the script does\n" + "\n".join(
        __import__("difflib").unified_diff(before, after, "original", "regenerated", lineterm="")
    )


def test_every_fixture_is_readable_by_the_oracle() -> None:
    """The skip above is a safety valve, not a plan. If it starts firing, the
    oracle is quietly covering less than it appears to."""
    unreadable = [p.name for p in FIXTURES if meaning(p.read_text()) is None]
    assert not unreadable, f"sievelib cannot parse: {unreadable}"


# ── The oracle itself has to bite ──


@pytest.mark.parametrize(
    ("label", "original", "regenerated", "flagged"),
    [
        pytest.param(
            "a dropped test",
            'if allof (header :is "a" "b", header :is "c" "d") { keep; }\n',
            'if allof (header :is "a" "b") { keep; }\n',
            True,
            id="dropped condition",
        ),
        pytest.param(
            "a changed action",
            'require ["fileinto"];\nif header :is "a" "b" { fileinto "X"; }\n',
            'require ["fileinto"];\nif header :is "a" "b" { fileinto "Y"; }\n',
            True,
            id="changed folder",
        ),
        pytest.param(
            "anyof turned into allof",
            'if anyof (header :is "a" "b", header :is "c" "d") { keep; }\n',
            'if allof (header :is "a" "b", header :is "c" "d") { keep; }\n',
            True,
            id="changed operator",
        ),
        pytest.param(
            "an escape that changes a regex",
            'require ["regex"];\nif header :regex "a" "^x\\.y$" { keep; }\n',
            'require ["regex"];\nif header :regex "a" "^x\\\\.y$" { keep; }\n',
            True,
            id="escape changes meaning",
        ),
        pytest.param(
            "header case",
            'if header :is "Subject" "b" { keep; }\n',
            'if header :is "subject" "b" { keep; }\n',
            False,
            id="header case is not meaning",
        ),
        pytest.param(
            "escaping that does not change meaning",
            'if header :is "a" "x\\.y" { keep; }\n',
            'if header :is "a" "x.y" { keep; }\n',
            False,
            id="same string, different spelling",
        ),
        pytest.param(
            "require pruned and sorted",
            'require ["envelope", "fileinto"];\nif header :is "a" "b" { keep; }\n',
            'require ["fileinto"];\nif header :is "a" "b" { keep; }\n',
            False,
            id="require is normalised on purpose",
        ),
    ],
)
def test_the_oracle_flags_meaning_and_ignores_spelling(
    label: str, original: str, regenerated: str, flagged: bool
) -> None:
    """An oracle nobody can trust in both directions is worse than none.

    Half of these MUST be flagged — they are the failures it exists to catch.
    The other half must NOT be, because they are normalisations this codebase
    makes deliberately, and an oracle that cries about those is one somebody
    eventually deletes.
    """
    differs = meaning(original) != meaning(regenerated)
    assert differs is flagged, label


# ── The runtime pre-flight ──


def test_the_preflight_needs_the_lock_it_has() -> None:
    """Reproduced rather than taken on trust.

    sievelib's Parser resets `RequireCommand.loaded_extensions` — a CLASS
    attribute — on every parse, so two concurrent parses race and one sees the
    other's extensions. Unlocked, with each thread parsing a script needing a
    DIFFERENT extension:

        24,000 parses across 16 threads -> 30 spurious rejections

    FastAPI runs sync handlers on a threadpool, so that race is two HTTP
    requests apart. On this path a spurious rejection tells a user their
    perfectly good script is invalid, which is worse than not checking at all.
    """
    import concurrent.futures

    from sievelib.commands import RequireCommand

    assert "loaded_extensions" in vars(RequireCommand), (
        "the shared state this lock exists for has moved; re-check the claim"
    )

    scripts = [
        'require ["fileinto"];\nif header :is "a" "b" { fileinto "X"; }\n',
        'require ["imap4flags"];\nif header :is "a" "b" { addflag "\\\\Seen"; }\n',
        'require ["reject"];\nif header :is "a" "b" { reject "no"; }\n',
    ]

    def once(index: int) -> bool:
        return st.sieve_is_parseable(scripts[index % len(scripts)]) is None

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(once, range(6000)))

    assert all(results), f"{results.count(False)} spurious rejections under contention"


def test_the_preflight_refuses_what_a_server_would() -> None:
    """A Rule whose last Condition was deleted generates `if anyof ( ) {`."""
    empty = st.SieveScript(entries=[st.Rule(name="N", actions=[st.Action("keep")])])
    assert st.preflight_error(empty) is not None


def test_the_preflight_judges_only_regenerated_spans() -> None:
    """The scoping, at the transform level. sievelib rejects `include`; a real
    server does not. It reaches us as a RawBlock, is re-emitted byte-identical,
    and was already accepted once — so it is not ours to judge."""
    script = st.parse_sieve('require ["include"];\ninclude :personal "shared";\n')
    assert script.rules == [], "premise: this is raw"
    assert st.preflight_error(script) is None


@pytest.mark.parametrize(
    "path", FIXTURES, ids=lambda p: str(p.relative_to(BACKEND / "test_scripts"))
)
def test_no_fixture_is_refused_by_its_own_preflight(path: Path) -> None:
    """The pre-flight is mandatory on the save path, so a false positive is a
    user locked out of saving. Every fixture in the corpus — including all 45
    third-party ones — must pass it."""
    assert st.preflight_error(st.parse_sieve(path.read_text())) is None


@pytest.mark.parametrize(
    ("change", "flagged"),
    [
        pytest.param(('"Subject"', '"subject"'), False, id="header case"),
        pytest.param(('"one"', '"two"'), True, id="the value"),
        pytest.param(("i;octet", "i;ascii-casemap"), True, id="the comparator"),
        pytest.param((":is", ":contains"), True, id="the match type"),
        pytest.param(('"Subject"', '"From"'), True, id="a different header"),
    ],
)
def test_the_normaliser_folds_case_and_nothing_else(change: tuple[str, str], flagged: bool) -> None:
    """Every argument of a header test, one at a time.

    The normaliser lowercases the header NAME, and that is a licence to hide
    things if it reaches one argument too far — a comparator or a value folded
    to lowercase would make a real difference invisible. So each position is
    checked separately rather than trusting the one that motivated the code.
    """
    base = 'if header :comparator "i;octet" :is "Subject" "one" { keep; }\n'
    assert meaning(base) is not None, "premise: sievelib reads this"
    assert (meaning(base) != meaning(base.replace(*change))) is flagged
