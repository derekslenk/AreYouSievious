"""
Bidirectional Sieve <-> JSON rule transform.

Parses Sieve scripts into structured JSON rules for UI editing,
and generates valid Sieve scripts from JSON rules.

Design principles:
- Lossless round-trip for supported constructs
- Unsupported/complex blocks preserved as raw Sieve text
- Comments preserved as rule names or raw blocks
"""

import bisect
import re
import threading
from dataclasses import dataclass, field, replace

from sievelib.parser import Lexer, Parser
from sievelib.parser import ParseError as SieveLibParseError

# ── Data Model ──


@dataclass
class Condition:
    header: str  # "from", "to", "subject", "cc", etc.
    match_type: str  # one of MATCH_TYPES
    value: str
    address_test: bool = False  # True = address test, False = header test
    negate: bool = False
    # RFC 5228 tagged arguments. Previously consumed by the parser and dropped
    # by the generator, which silently changed what a rule matched: an
    # `address :domain :is "from" "example.com"` rule became
    # `address :is "from" "example.com"` and stopped matching alice@example.com
    # entirely. Roundcube and SOGo both emit :domain, so this hit real scripts.
    address_part: str = ""  # one of ADDRESS_PARTS, or "" for none
    comparator: str = ""  # e.g. "i;ascii-casemap"


@dataclass
class Action:
    action_type: str  # one of ACTION_TYPES
    argument: str = ""  # folder name, address, flag value, etc.


@dataclass
class Rule:
    """An Entry the visual builder can edit.

    Carries no identity: see docs/adr/0001-identity-is-view-state.md. Sieve text
    cannot persist an id, so any the server minted would be a fresh value on every
    parse. Clients mint their own render keys and strip them at the wire. Dropping
    the id also makes Rule comparable by value, which is what lets tests assert
    exact round-trip fidelity rather than mere stability. `source` joins that
    value equality while being content-of-origin rather than meaning, so a
    comparison asking whether two Rules DO the same thing must clear it first —
    two Rules identical in every effect differ here whenever they were written
    down differently.
    """

    name: str = ""
    enabled: bool = True
    match: str = "anyof"  # one of MATCH_OPERATORS, or "" for a bare `if <test> {`
    conditions: list[Condition] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    source: str = ""
    """The exact bytes this Rule was parsed from, including its leading gap.

    Empty for a Rule the builder minted: it was never parsed from anything, so
    there is nothing to re-emit and it regenerates. This is CONTENT, not
    identity (docs/adr/0001-identity-is-view-state.md) — two identical Rules
    legitimately carry identical spans, and nothing here distinguishes them.
    """


@dataclass
class RawBlock:
    """An Entry the parser doesn't recognise, preserved verbatim."""

    text: str
    comment: str = ""
    source: str = ""
    """The exact bytes this block was parsed from, including its leading gap.

    Same field, same rules and same reasons as `Rule.source` — a RawBlock is an
    Entry too, and the decomposition covers every entry or it covers none.
    """


Entry = Rule | RawBlock


@dataclass
class SieveScript:
    """Full parsed representation of a Sieve script.

    `entries` is a single ordered sequence — position IS the evaluation order.
    This replaced parallel `rules` / `raw_blocks` / `order` arrays that had to
    agree by index; when they disagreed, a Rule missing from `order` was silently
    dropped on save. That state is now unrepresentable.
    """

    requires: list[str] = field(default_factory=list)
    entries: list[Entry] = field(default_factory=list)
    preamble: str = ""
    """Bytes before the first `require`. Immovable: reordering Rules never
    moves the file's header.

    Empty when the file has no `require`, and deliberately so — those leading
    bytes go into the FIRST ENTRY'S span instead. A comment at the top of a
    file with no `require` is a rule's `# --- name ---` far more often than it
    is a file header, and a span that carries its own name is what lets a
    reordered Rule take that name with it."""
    requires_source: str = ""
    """The exact bytes of the `require` statement(s), which may be several and
    may span lines. Re-emitted verbatim only when nothing in the file changed."""
    tail: str = ""
    """Bytes after the last entry's span. Blank lines and trailing comments."""

    @property
    def rules(self) -> list[Rule]:
        """Read-only view of just the Rule entries, in order."""
        return [e for e in self.entries if isinstance(e, Rule)]

    @property
    def raw_blocks(self) -> list[RawBlock]:
        """Read-only view of just the RawBlock entries, in order."""
        return [e for e in self.entries if isinstance(e, RawBlock)]


# ── Regexes ──
#
# `_Q(name)` is the linear-time quoted-string fragment: each character is
# consumed by exactly one branch (a non-escape char OR a complete `\X` escape),
# so there is no nested `*` to backtrack catastrophically on an unterminated
# string (CWE-1333).


def _Q(name: str) -> str:
    return rf'"(?P<{name}>(?:[^"\\]|\\.)*)"'


# One alternation, scanned left to right, so actions come back in source order
# and bare-word actions can never match inside a quoted argument. `fileinto
# :copy` must precede plain `fileinto` — at a shared start position the earlier
# alternative wins.
_ACTION_RE = re.compile(
    rf"fileinto\s+:copy\s+{_Q('copy')}"
    rf"|fileinto\s+{_Q('fileinto')}"
    rf"|redirect\s+{_Q('redirect')}"
    rf"|addflag\s+{_Q('addflag')}"
    rf"|reject\s+{_Q('reject')}"
    r"|\b(?P<keep>keep)\s*;"
    r"|\b(?P<discard>discard)\s*;"
    r"|\b(?P<stop>stop)\s*;"
)

_QUOTED_ACTIONS = (
    ("copy", "fileinto_copy"),
    ("fileinto", "fileinto"),
    ("redirect", "redirect"),
    ("addflag", "addflag"),
    ("reject", "reject"),
)

_BARE_ACTIONS = ("keep", "discard", "stop")

# ── Closed vocabularies ──
#
# Declared once, here, and the regexes below are BUILT from them. Everything
# that needs to know what the transform can emit — the wire DTOs' `Literal`s,
# the builder's dropdowns — is pinned against these rather than restating them,
# so a vocabulary cannot grow in one place and stay closed in another
# (areyousievious-8fg.18).
#
# `header` is NOT one of these: any quoted string is a legal Sieve header name.

ACTION_TYPES: tuple[str, ...] = tuple(a for _, a in _QUOTED_ACTIONS) + _BARE_ACTIONS
MATCH_TYPES: tuple[str, ...] = ("contains", "is", "matches", "regex")
MATCH_OPERATORS: tuple[str, ...] = ("anyof", "allof")
ADDRESS_PARTS: tuple[str, ...] = ("all", "localpart", "domain")

# The two comparators every implementation has (RFC 5228 §2.7.3). Any other one
# has to be named in `require ["comparator-..."]`.
_BUILTIN_COMPARATORS = frozenset({"i;octet", "i;ascii-casemap"})

# The tests the visual builder can render. `header` and `address` and nothing
# else — `envelope`, `size`, `date`, `body`, `exists` and the rest are all
# legal Sieve we have no Condition for (areyousievious-8fg.11).
TEST_TYPES: tuple[str, ...] = ("header", "address")

# The command words that appear in SIEVE SOURCE.
#
# Deliberately NOT derived from ACTION_TYPES, which is the WIRE vocabulary:
# `fileinto_copy` is a wire name for what the source spells `fileinto :copy`,
# so the Lexer can never emit it as an identifier. Deriving one from the other
# would also couple them the wrong way round — a DTO widened for the builder
# (.18) would silently widen what the PARSER is willing to project. The two are
# pinned to each other by a test instead, which is a check rather than a
# coupling.
COMMAND_NAMES: tuple[str, ...] = (
    "fileinto",
    "redirect",
    "addflag",
    "reject",
    "keep",
    "discard",
    "stop",
)

# Every bare word that may appear inside a span we project onto a Rule. An
# identifier outside this set means the span holds something we cannot
# represent, and the whole span stays a RawBlock rather than being narrowed to
# the part we happen to understand.
_MODELLED_IDENTIFIERS = frozenset({"if", "not", *MATCH_OPERATORS, *TEST_TYPES, *COMMAND_NAMES})

_PARTS = "|".join(ADDRESS_PARTS)


# Tagged arguments on a test. RFC 5228 lets ADDRESS-PART, COMPARATOR and
# MATCH-TYPE appear in any order, so the run of modifiers is captured as one
# blob and picked apart afterwards rather than pinned to a fixed sequence.
#
# A function because the run appears TWICE in `_TEST_RE`, once either side of
# the match-type, and each occurrence needs its own group name. Renaming the
# group by `.replace()` on the pattern source was the first version of that and
# it is a trap: a second named group in here would silently produce a
# duplicate-group compile error at import.
def _modifier_run(name: str) -> str:
    return rf'(?P<{name}>(?:\s+:(?:{_PARTS})|\s+:comparator\s+"(?:[^"\\]|\\.)*")*)'


# RFC 5228 §2.7.1 puts no order on tagged arguments, and the RFC's OWN example
# (rfc5228.txt line 1351) writes the address-part AFTER the match-type. The
# modifier run therefore appears on BOTH sides: capturing only the leading one
# made `address :domain :is "from" "x"` a Rule and `address :is :all "from"
# "x"` a RawBlock, while the docstring claimed any order was handled
# (areyousievious-8fg.11).
_TEST_RE = re.compile(
    r"(?P<negate>not\s+)?"
    + rf"(?P<test_type>{'|'.join(TEST_TYPES)})"
    + _modifier_run("mods")
    + rf"\s+:(?P<match_type>{'|'.join(MATCH_TYPES)})"
    + _modifier_run("mods_after")
    + rf"\s+{_Q('header')}"
    + rf"\s+{_Q('value')}"
)

_ADDRESS_PART_RE = re.compile(rf":({_PARTS})\b")
_COMPARATOR_RE = re.compile(r':comparator\s+"((?:[^"\\]|\\.)*)"')

# The test-list wrappers. `_parse_if_block` records Rule.match as one of these,
# or as "" for a bare `if <test> {` that carried no wrapper at all.
# A rule-name decoration: `--- x ---`, or `# --- x ---` before a leading `## `
# has been stripped. BOTH ends required, in one match (areyousievious-8fg.15).
# RFC 5228 §2.4.2: a backslash before ANY character is that character.
_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)

_NAME_MARKER_RE = re.compile(r"^#?\s*-{2,}\s*(?P<name>.+?)\s*-{2,}$")

# One layer of the accretion, and only that. `_generate_rule` used to write
# `# --- {name} ---` INSIDE the block; `## `-prefixing it and reading it back
# left `# --- name`, with the LEADING marker doubling on each save while the
# trailing one stayed single. So the two ends are asymmetric and no
# both-ends-required rule can unwind it — which is why this is a second, exact
# pattern rather than a looser first one. Three dashes and a space, exactly as
# the generator wrote them: `# -- important -- stuff` is a name, not a marker.
_ACCRETED_NAME_PREFIX = "# --- "

_MATCH_OPERATOR_RE = re.compile(rf"if\s+({'|'.join(MATCH_OPERATORS)})\s*\((.*?)\)\s*\{{", re.DOTALL)


# ── Lexical map (areyousievious-8fg.10) ──

_BOM = b"\xef\xbb\xbf"

# How many `## ` layers `_try_parse_disabled_block` will unwrap. One: a
# disabled Rule was commented out once. See the guard for why it is bounded.
_MAX_DISABLED_DEPTH = 1

# Tokens whose CONTENTS must never be read as Sieve. Masked to spaces before
# any regex scans a block, so a commented-out action stays commented out and a
# `text:` body cannot contribute one.
_OPAQUE_TOKENS = frozenset({"hash_comment", "bracket_comment", "multiline"})


class _LexicalMap:
    """Where the braces and comments REALLY are, per line.

    The parser used to answer both questions by looking at characters:
    `line.count("{") - line.count("}")` for block extent, and the action regex
    over raw block text. Neither knows what a string or a comment is, and all
    three of the corrupting defects this class exists to kill came from that:

      1. `fileinto "Weird{Folder";` — the brace inside the STRING was counted,
         so the block never closed and the NEXT rule was swallowed into it.
         Measured: the second rule's condition vanished and its `fileinto`
         fired on the first rule's match.
      2. A nested `if` had its condition dropped, leaving the inner action
         firing on the outer condition alone.
      3. `# fileinto "Disabled";` inside a block came back as a LIVE action.

    None of the three tripped the RawBlock safety net, because the parser did
    not fail — it succeeded and misread, then regenerated valid Sieve that
    routed mail somewhere else.

    sievelib's Lexer has the lexical model we lacked: a `{` inside a string is
    part of one `string` token, and `# ...` is one `hash_comment` token. Only
    its LEXER is used here. Its Parser is a different question (its `tosieve()`
    is a normaliser that regenerates roundcube.sieve to the empty string), and
    its projection onto our AST is areyousievious-8fg.11.

    `usable` is False when the Lexer refuses the text outright — an unknown
    token anywhere, which no fixture in the corpus produces. The parser then
    falls back to the old character counting, which is what it did before this
    existed: worse, but not worse than yesterday.
    """

    __slots__ = (
        "brace_delta",
        "bracket_comment_lines",
        "identifiers",
        "masked_lines",
        "open_braces",
        "open_parens",
        "semicolons",
        "usable",
    )

    @staticmethod
    def _scan(text: str) -> tuple[bytes, list[tuple[int, str, bytes]]]:
        """The bytes, and every token in them with its byte offset.

        Raises exactly where the input is the problem: `ParseError` when the
        Lexer meets a token it has no rule for, `UnicodeEncodeError` when the
        text cannot be bytes at all. Both are the caller's cue to fall back.
        """
        raw = text.encode("utf-8")
        # A BOM kills the Lexer for the WHOLE file — verified: it reports the
        # entire remaining text as one unknown token. Skipped rather than
        # removed, so `text` and every offset into it stay as the caller sees.
        start_at = len(_BOM) if raw.startswith(_BOM) else 0

        lexer = Lexer(Parser.lrules)
        # `lexer.pos` is the START of the token just yielded: `scan` suspends
        # at the yield and advances only afterwards. This is not a documented
        # API — test_lexical_map.py pins it, so a sievelib upgrade that changes
        # it fails loudly rather than silently mis-segmenting someone's script.
        tokens = [(start_at + lexer.pos, name, value) for name, value in lexer.scan(raw[start_at:])]
        return raw, tokens

    def __init__(self, text: str) -> None:
        lines = text.split("\n")
        self.open_braces = [0] * len(lines)
        self.brace_delta = [0] * len(lines)
        self.semicolons = [0] * len(lines)
        self.open_parens = [0] * len(lines)
        self.identifiers: list[list[str]] = [[] for _ in lines]
        self.bracket_comment_lines = [False] * len(lines)
        self.masked_lines = lines
        self.usable = False

        try:
            raw, tokens = self._scan(text)
        except (SieveLibParseError, UnicodeEncodeError):
            # The Lexer refused the text, or it is not encodable at all — a
            # lone surrogate reaches us intact through `json.loads`, and the
            # character-counting parser this replaced never needed the text to
            # be bytes. A PARTIAL map would be worse than none, since lines
            # past the failure would report zero braces and a block would run
            # to end of file, so the whole map is abandoned.
            return

        # Deliberately NOT inside the try. Everything below is OUR arithmetic
        # over tokens we already hold: a failure here is a bug in this class,
        # and swallowing it would silently drop the lexical model and let the
        # three defects back in with no signal. Loud is the safer failure.
        line_starts = [0] + [i + 1 for i, byte in enumerate(raw) if byte == 0x0A]
        masked = bytearray(raw)
        for begin, name, value in tokens:
            line = bisect.bisect_right(line_starts, begin) - 1
            if name == "left_cbracket":
                self.open_braces[line] += 1
                self.brace_delta[line] += 1
            elif name == "right_cbracket":
                self.brace_delta[line] -= 1
            elif name == "left_parenthesis":
                # A test LIST opens exactly one. A second means the list holds
                # another list — `allof(anyof(a, b), c)` — and a Rule has one
                # flat `match` with no way to say that (areyousievious-8fg.11).
                self.open_parens[line] += 1
            elif name == "identifier":
                # Every bare word the Lexer saw, which is how the projection
                # answers "is there anything in this block I do not model"
                # (areyousievious-8fg.11). Comments and strings are their own
                # token types, so a word inside either is never counted.
                self.identifiers[line].append(value.decode("utf-8", "replace"))
            elif name == "semicolon":
                # Where a STATEMENT ends, which is not the same question as
                # where a line ends. `require` spans lines in scripts Roundcube
                # and SOGo emit, and a `;` inside a comment or a string is not
                # a terminator (areyousievious-8fg.15).
                self.semicolons[line] += 1
            elif name in _OPAQUE_TOKENS:
                # Same length, so every offset into the text still lands where
                # it did. Newlines are kept: a multiline token spans lines, and
                # collapsing them would renumber the file.
                for i in range(begin, begin + len(value)):
                    if masked[i] != 0x0A:
                        masked[i] = 0x20
                if name == "bracket_comment":
                    # WHICH lines a `/* ... */` occupies, which masking alone
                    # cannot say — a masked line is indistinguishable from a
                    # blank one, and the parser needs to consume the comment as
                    # a UNIT (areyousievious-hr6). Marked from the line the
                    # token opens on through the line its last byte lands on;
                    # `value` is the whole comment, so its newlines are the
                    # extent. A token is never empty, hence the -1.
                    last = bisect.bisect_right(line_starts, begin + len(value) - 1) - 1
                    for i in range(line, last + 1):
                        self.bracket_comment_lines[i] = True

        # Masking only ever replaces whole tokens with ASCII spaces, so the
        # result is still the same valid UTF-8 line for line.
        self.masked_lines = masked.decode("utf-8").split("\n")
        self.usable = True


# ── Parser (Sieve text -> SieveScript) ──


class SieveParser:
    """
    Hand-rolled projection because sievelib's AST is hard to work with for
    bidirectional transforms. We parse the common patterns we support and
    preserve everything else as raw blocks.

    Hand-rolled is not the same as text-munging: since `.10` the LEXICAL
    questions — where a block ends, which bytes are a comment — are answered by
    `_LexicalMap`, i.e. by sievelib's Lexer. What stays ours is the PROJECTION
    onto Rule/Condition/Action, which is what sievelib's AST is a poor fit for.
    """

    def __init__(self, text: str, depth: int = 0):
        self.text = text
        self.pos = 0
        self.lines = text.split("\n")
        self.line_idx = 0
        self.depth = depth
        self.lex = _LexicalMap(text)
        # First line not yet claimed by the preamble, the requires or an
        # entry's span. Moves ONLY on a successful consumption, in `_append`
        # and `_record_requires`; the backtracking helpers reset `line_idx`
        # without touching it, which is what leaves a refused attempt's bytes
        # available to whichever entry eventually claims them.
        self._span_start = 0

    def _span(self, start: int, end: int) -> str:
        """The exact bytes of lines[start:end], separators included.

        `text.split("\\n")` drops the separators, so joining a range back needs
        a trailing "\\n" for every line EXCEPT one ending at the true end of a
        file that does not end in a newline. Getting this wrong shifts every
        subsequent span by one byte and the reassembly invariant catches it.
        """
        if start >= end:
            return ""
        chunk = "\n".join(self.lines[start:end])
        return chunk if end == len(self.lines) else chunk + "\n"

    def _append(self, script: SieveScript, entry: Entry) -> None:
        """Append an entry and hand it every byte since the last one.

        The leading gap — blank lines, the `# --- name ---` line, any comment
        above it — is part of the span, so a reordered Rule takes its name with
        it. There is no separate "filler" category: a byte is either preamble,
        part of the requires, inside exactly one entry's span, or tail.
        """
        entry.source = self._span(self._span_start, self.line_idx)
        self._span_start = self.line_idx
        script.entries.append(entry)

    def _record_requires(self, script: SieveScript, statement_start: int) -> None:
        """Split the region [span_start, line_idx) at the `require` statement.

        Everything before the statement is preamble on the FIRST require and
        part of `requires_source` on any later one — a comment sitting between
        two `require` statements belongs with them, not with the rule after.
        """
        if not script.requires_source:
            script.preamble += self._span(self._span_start, statement_start)
            script.requires_source = self._span(statement_start, self.line_idx)
        else:
            script.requires_source += self._span(self._span_start, self.line_idx)
        self._span_start = self.line_idx

    def parse(self) -> SieveScript:
        if not self.lex.usable:
            # The Lexer refused this text, so we have no trustworthy answer to
            # "where does this block end" — and the three defects `.10` closed
            # were all about answering that wrongly. Guessing with character
            # counting would put them straight back, for exactly the file we
            # understand least.
            #
            # So: the whole file, as one RawBlock, content intact
            # (areyousievious-8fg.11). Zero Rules plus one whole-file RawBlock
            # is a READABLE state meaning "understood nothing" — the caller
            # tells outcomes apart from the result, never from an exception,
            # because raising here would lock a user out of their own filters
            # over one stray byte.
            #
            # `text` is stripped of its trailing newlines and `source` is not:
            # the span has to be the WHOLE text or the decomposition loses the
            # bytes `rstrip` took, on exactly the file we understand least.
            body = self.text.rstrip("\n")
            if not body.strip():
                return SieveScript(tail=self.text)
            return SieveScript(entries=[RawBlock(text=body, source=self.text)])

        script = SieveScript()
        pending_comment = ""
        # Past this line index, a `## ` run has already been tried and refused.
        failed_run_end = 0

        while self.line_idx < len(self.lines):
            line = self.lines[self.line_idx].strip()

            # Skip empty lines
            if not line:
                self.line_idx += 1
                continue

            # A bracketed comment (RFC 5228 §2.3), taken whole. BEFORE every
            # other handler, because none of them knows where one ends: the
            # `/*` line fell through to `_consume_raw_statement`, which scans
            # forward to the next `;` — and the comment has no `;` of its own,
            # so it ran on past the `*/` and fused the next LIVE rule into the
            # same opaque RawBlock. A rule the server executes became
            # un-editable text because a comment appeared above it
            # (areyousievious-hr6).
            comment_end = self._bracket_comment_run()
            if comment_end:
                raw_text = "\n".join(self.lines[self.line_idx : comment_end])
                self.line_idx = comment_end
                self._append(script, RawBlock(text=raw_text, comment=pending_comment))
                pending_comment = ""
                continue

            # Require statement
            if line.startswith("require"):
                # EXTEND, never assign. Assigning meant a second `require`
                # replaced the first and everything it named was gone before
                # the first generation — invisible to both round-trip tests,
                # since by gen1 both sides had already lost it. RFC 5228 §3.2
                # shows multiple statements and Horde/Ingo emits them
                # (areyousievious-8fg.15).
                statement_start = self.line_idx
                statement, clean = self._consume_statement()
                if not clean:
                    # Not a `require` we can read. Keep its bytes rather than
                    # guess at them.
                    self._append(script, RawBlock(text=statement, comment=pending_comment))
                    pending_comment = ""
                    continue
                if script.entries:
                    # A `require` that follows a command. RFC 5228 §3.2 says
                    # every `require` precedes every other command, so this file
                    # is already invalid Sieve — which is not a reason to drop
                    # it. We do not own these files, and a RawBlock is what this
                    # module does with a construct it cannot place in its model.
                    #
                    # It must not go to `requires_source`. That term is
                    # concatenated AHEAD of every entry, so bytes routed there
                    # once an entry has already claimed its span come back above
                    # it, and `preamble + requires_source + Σ source + tail`
                    # stops reproducing the file — the same bytes, in the wrong
                    # order, which the reassembly invariant is stated to forbid.
                    #
                    # Its extensions are deliberately NOT harvested. Harvesting
                    # them would make a later regenerating save emit a canonical
                    # `require [...]` at the top AND re-emit this block, so the
                    # file would declare the same extension twice. Left
                    # unharvested the declaration survives exactly once, in the
                    # verbatim bytes that already carry it.
                    self._append(script, RawBlock(text=statement, comment=pending_comment))
                    pending_comment = ""
                    continue
                for extension in self._parse_require(statement):
                    if extension not in script.requires:
                        script.requires.append(extension)
                self._record_requires(script, statement_start)
                continue

            # Disabled rule (commented out with ## prefix) — check before comment handler
            if line.startswith("## ") and self.line_idx >= failed_run_end:
                disabled_rule = self._try_parse_disabled_block(pending_comment)
                if disabled_rule:
                    self._append(script, disabled_rule)
                    pending_comment = ""
                    continue
                # Not a disabled rule. Do not try again at every line of the
                # SAME `## ` run: each attempt builds a fresh SieveParser and
                # re-lexes everything from that line on, so retrying per line
                # made a long run cost the square of its length — 800 fragments
                # took 1.5s, and the body-size limit admits a 1 MiB script on an
                # HTTP request. Raised in review of this PR. One attempt per
                # run; the rest of it is comments.
                failed_run_end = self._end_of_disabled_run()
                # Fall through to comment handler

            # Comments - accumulate as potential rule name
            if line.startswith("#"):
                comment_text = line.lstrip("#").strip()
                # Skip decorator lines (=== --- etc.)
                if comment_text and not re.match(r"^[=\-\s]+$", comment_text):
                    pending_comment = self._clean_comment_name(comment_text)
                self.line_idx += 1
                continue

            # If/elsif/else block - try to parse as a rule
            if line.startswith("if ") or line.startswith("if\t"):
                rule = self._try_parse_rule(pending_comment)
                if rule:
                    self._auto_name_rule(rule)
                    self._append(script, rule)
                else:
                    # Couldn't parse - store as raw block
                    raw_text = self._consume_block()
                    self._append(script, RawBlock(text=raw_text, comment=pending_comment))
                pending_comment = ""
                continue

            # Anything else is a raw block — the WHOLE statement, not one
            # line of it. Taking a line at a time shattered a multi-line
            # command into N RawBlocks, and generation puts a blank line
            # between entries, so a `vacation` message spanning lines came back
            # with a blank line injected INTO its string. Found by the AST
            # oracle (areyousievious-8fg.13): the message text a user would
            # receive was not the message text they wrote.
            raw_text = self._consume_raw_statement()
            self._append(script, RawBlock(text=raw_text, comment=pending_comment))
            pending_comment = ""

        # Whatever is left is the tail: blank lines and trailing comments that
        # no entry claimed.
        script.tail = self._span(self._span_start, len(self.lines))
        return script

    @staticmethod
    def _clean_comment_name(comment_text: str) -> str:
        """Reduce `# --- x ---` decoration down to `x`.

        REPEATEDLY, which is the whole point. One pass is what the reader did
        before, and one pass leaves a marker behind on a name that accreted
        several — which is exactly what a script saved by any version before
        areyousievious-8fg.15 carries:

            ## # --- # --- # --- GitHub notifications ---

        Each save added one. Peeling until stable is what lets opening such a
        script show the real name, and saving it write the clean shape, so the
        accretion unwinds instead of being frozen at whatever depth it reached.

        A marker is peeled only when BOTH ends are there, in ONE match. The
        first version ran two independent `re.sub`s, which made the docstring's
        own claim false — raised in review, and reproduced: `# -- important --
        stuff` came back as `important -- stuff`, because the leading sub fired
        with no trailing marker to balance it. One anchored pattern cannot do
        that, so a rule a user actually named `# 1 priority` or `-- a -- b`
        keeps its name.

        Each pass strictly shortens the string, so the loop terminates; the
        bound is belt and braces on a parser that runs on request.
        """
        clean = comment_text.strip()
        for _ in range(len(comment_text) + 1):
            match = _NAME_MARKER_RE.match(clean)
            if not match:
                break
            inner = match.group("name").strip()
            if not inner or inner == clean:
                break
            clean = inner
        while clean.startswith(_ACCRETED_NAME_PREFIX):
            peeled = clean[len(_ACCRETED_NAME_PREFIX) :].strip()
            if not peeled:
                break
            clean = peeled
        return clean or comment_text

    def _consume_statement(self) -> tuple[str, bool]:
        """The lines of the statement starting here, up to its terminating `;`.

        A statement is not a line. `require [\n "fileinto",\n "imap4flags"\n];`
        is one statement over four lines, and reading only the first gave
        `requires == []` while the continuation lines became RawBlocks — which
        the generator then emitted AFTER its own regenerated require:

            require ["fileinto"];
                "copy",
                "reject"
            ];

        That is not Sieve, and it was PUT to the mail server. Roundcube and
        SOGo both emit the multi-line shape.

        The terminator comes from the lexical map, so a `;` inside a comment or
        a quoted string does not end the statement. Without a usable map this
        falls back to one line, which is what it always did.
        """
        start = self.line_idx
        end = start
        terminated = False
        while end < len(self.lines):
            # A `require` holds strings, brackets, commas and its `;` — nothing
            # else. So a line carrying a brace, or a bare word other than the
            # opening `require` itself, belongs to a DIFFERENT statement.
            #
            # Stopping matters: without this, `require ["fileinto"]` with no
            # semicolon ran on to the next `;` anywhere in the file and ate the
            # rule after it, which regenerated to nothing at all. Deletion is
            # the worst thing this module can do.
            words = self.lex.identifiers[end]
            extra_words = words[1:] if end == start else words
            if self.lex.open_braces[end] or extra_words:
                break
            terminated = self.lex.semicolons[end] > 0
            end += 1
            if terminated:
                break

        # Whole LINES are consumed, so a second statement sharing the
        # terminator's line would be swallowed with it — `require ["fileinto"];
        # keep;` regenerated with the `keep;` simply gone, and its multi-line
        # cousin left an orphan `];` line behind. Both raised in review, both
        # reproduced.
        #
        # Rather than split a line, which this whole parser is line-shaped
        # around, an unclean statement is REFUSED and handed back for the raw
        # path: the `require` stops being READ, but nothing is LOST. Reach is
        # much the cheaper thing to give up.
        if terminated:
            self.line_idx = end
            return "\n".join(self.lines[start:end]), True

        # Unclean. Consume through the line that ends the statement anyway, so
        # the fragment stays together and comes back as the bytes it arrived
        # as — splitting it across entries is what produced the orphan `];`.
        end = start
        while end < len(self.lines) and not self.lex.open_braces[end]:
            has_semicolon = self.lex.semicolons[end] > 0
            end += 1
            if has_semicolon:
                break
        self.line_idx = max(end, start + 1)
        return "\n".join(self.lines[start : self.line_idx]), False

    def _bracket_comment_run(self) -> int:
        """Exclusive end line of the run of bracketed comment starting here, or 0.

        Driven off the LEXER's tokens, never off the text: `fileinto "a/*b";`
        contains no comment, and any scan for a literal `/*` would say it does
        and swallow the rest of the file. `test_scripts/vendor/`
        `string-with-bracket-comment.sieve` is that case, and it stays one Rule.

        Zero — no run — for a comment that SHARES its line with code, in either
        direction: `discard; /*` opens a comment the statement handler is
        already taking, and `*/ discard;` closes one on a line whose live
        statement we must not swallow. The masked line answers both at once,
        since masking leaves a comment as spaces: if every line of the run is
        blank once masked, the run holds nothing but comment and is ours to
        take. Otherwise nothing fires and the line keeps the handler it had.

        A run rather than a single token so that `*/ /*` on one line — a
        comment closing and another opening — comes out as one entry instead of
        leaving the second one's tail orphaned.

        Returns an exclusive end line, so 0 is unambiguously "no": a run
        starting at line 0 still ends at 1 or later.
        """
        start = self.line_idx
        if not self.lex.bracket_comment_lines[start]:
            return 0
        end = start
        while end < len(self.lines) and self.lex.bracket_comment_lines[end]:
            end += 1
        if any(self.lex.masked_lines[i].strip() for i in range(start, end)):
            return 0
        return end

    def _consume_raw_statement(self) -> str:
        """The lines of the top-level statement starting here, verbatim.

        Bounded to a statement, so it stops at the terminating `;` from the
        lexical map — a `;` inside a string or a comment is not one. If a
        block opens, or nothing terminates, it falls back to the single line
        this always took, which keeps the degenerate cases where they were.
        """
        start = self.line_idx
        end = start
        while end < len(self.lines):
            if self.lex.open_braces[end]:
                break
            has_terminator = self.lex.semicolons[end] > 0
            end += 1
            if has_terminator:
                self.line_idx = end
                return "\n".join(self.lines[start:end])
        self.line_idx = start + 1
        return self.lines[start]

    def _parse_require(self, text: str) -> list[str]:
        """Parse: require ["fileinto", "envelope", "regex"];"""
        return re.findall(r'"([^"]+)"', text)

    @staticmethod
    def _auto_name_rule(rule: Rule):
        """Generate a default name from the first condition + action if no comment."""
        if not rule.name and rule.conditions:
            c = rule.conditions[0]
            action_summary = rule.actions[0].action_type if rule.actions else "?"
            arg = rule.actions[0].argument if rule.actions and rule.actions[0].argument else ""
            rule.name = f"{c.header} {c.match_type} {c.value}"
            if arg:
                rule.name += f" → {action_summary} {arg}"

    def _try_parse_rule(self, comment: str) -> Rule | None:
        """Try to parse current position as a rule. Returns None if too complex."""
        start_line = self.line_idx
        try:
            rule = self._parse_if_block(comment)
            return rule
        except (ParseError, IndexError):
            # Reset and let caller handle as raw block
            self.line_idx = start_line
            return None

    def _end_of_disabled_run(self) -> int:
        """One past the last line of the `## ` run starting at the cursor."""
        index = self.line_idx
        while index < len(self.lines):
            stripped = self.lines[index].strip()
            if not stripped.startswith("## ") and stripped != "##":
                break
            index += 1
        return index

    def _try_parse_disabled_block(self, comment: str) -> Rule | None:
        """Try to parse a ## commented-out block as a disabled rule."""
        if self.depth >= _MAX_DISABLED_DEPTH:
            # A disabled Rule is a Rule that was commented out ONCE. Something
            # commented out twice is not a doubly-disabled rule — there is no
            # such thing in the model — so it stays raw.
            #
            # This is also the bound on re-entry. Parsing the uncommented text
            # as a whole script is what accepts both name shapes, but it means
            # `parse` can call itself, and a parser that recurses on attacker-
            # supplied text with no bound is a denial of service waiting to be
            # found. Raised in review of this change.
            return None
        start_line = self.line_idx
        # Peek ahead to see if there's an 'if' line in this ## block
        has_if = False
        peek = self.line_idx
        while peek < len(self.lines):
            stripped = self.lines[peek].strip()
            if not stripped.startswith("## ") and stripped != "##":
                break
            content = stripped[3:] if stripped.startswith("## ") else ""
            if content.startswith("if ") or content.startswith("if\t"):
                has_if = True
                break
            peek += 1
        if not has_if:
            return None
        # Collect all ## lines that form this disabled block
        disabled_lines = []
        while self.line_idx < len(self.lines):
            stripped = self.lines[self.line_idx].strip()
            if stripped.startswith("## "):
                disabled_lines.append(stripped[3:])
                self.line_idx += 1
            elif stripped == "##":
                disabled_lines.append("")
                self.line_idx += 1
            else:
                break
        if not disabled_lines:
            self.line_idx = start_line
            return None
        # Parse the uncommented text as a whole script rather than reaching
        # straight for `_parse_if_block`. That is what accepts BOTH name
        # shapes (areyousievious-8fg.15): the clean one, where the name is a
        # normal comment above the `## ` block and arrives here as `comment`;
        # and the legacy poisoned one, where a previous version wrote it
        # INSIDE, so uncommenting yields `# --- name ---` on its own line and
        # the ordinary comment handling picks it up. Reaching for
        # `_parse_if_block` at line 0 could only ever handle the first, which
        # is why the second baked a `# --- ` in per save.
        #
        # Scripts already carry the poisoned shape and we do not own the file,
        # so normalising on the way IN is what unwinds it: the name reads
        # correctly, and the next save writes the clean shape.
        uncommented = "\n".join(disabled_lines)
        try:
            inner = SieveParser(uncommented, depth=self.depth + 1).parse()
        except (ParseError, IndexError):
            self.line_idx = start_line
            return None

        # Exactly one Rule and nothing else. A `## ` run holding two rules, or
        # a rule plus something unrecognised, is not one disabled Rule and
        # must stay raw rather than be silently narrowed to its first half.
        if len(inner.entries) != 1 or not isinstance(inner.entries[0], Rule):
            self.line_idx = start_line
            return None

        rule = inner.entries[0]
        rule.enabled = False
        # An outer name wins: it is the clean shape, written by this version.
        if comment:
            rule.name = comment
        self._auto_name_rule(rule)
        return rule

    def _parse_if_block(self, comment: str) -> Rule:
        """Parse an if block into a Rule."""
        # Collect lines until matching closing brace
        _lines, start, end = self._collect_block_lines()

        # Every regex below reads the MASKED text: comment bodies replaced by
        # spaces, same length, so offsets are unchanged. Without it the action
        # scan read `# fileinto "Disabled";` and resurrected it as a live
        # action (areyousievious-8fg.10).
        block_text = "\n".join(self.lex.masked_lines[start:end])
        # A nested block is not single-rule shaped. Admitting it dropped
        # the inner condition and left the inner action firing on the OUTER
        # one — `if A { if B { fileinto "X"; } }` came back as
        # `if A { fileinto "X"; }`, so mail matching A alone was filed.
        # One `{` is this block's own; more than one means nesting.
        if sum(self.lex.open_braces[start:end]) > 1:
            raise ParseError("nested block not supported as single rule")

        # NARROWING (areyousievious-8fg.11). A span becomes a Rule only if
        # every construct in it is one we model. Partly-understood used to
        # mean projected anyway, and what fell out was silent: a block whose
        # `allof` held one `header` test and two `date` tests came back
        # carrying the header test alone, and regenerating wrote a script
        # with the hours gone — a rule that filed the boss's mail during
        # office hours now filing it at every hour of the day.
        #
        # Reach is bounded by what the BUILDER can render, not by what a
        # parser could manage. sievelib understands `vacation` perfectly
        # well and a `vacation` block still stays raw, deliberately.
        foreign = {
            name
            for line in self.lex.identifiers[start:end]
            for name in line
            if name not in _MODELLED_IDENTIFIERS
        }
        if foreign:
            raise ParseError(f"not in the builder's vocabulary: {sorted(foreign)}")

        # A vocabulary check is not a grammar check, and this is where that gap
        # showed. `allof(anyof(a, b), c)` uses only modelled words, so nothing
        # above objects — while `_parse_tests` scans the list text with no
        # parenthesis-awareness and returns three conditions, which regenerate
        # as `a AND b AND c`. `(a OR b) AND c` is not that. Raised in review of
        # this PR, and it is the SAME corruption class the bead exists to close,
        # reached through nesting instead of an unmodelled test. A Rule has one
        # flat `match`; a nested list cannot be said in it, so this stays raw.
        if sum(self.lex.open_parens[start:end]) > 1:
            raise ParseError("nested test list has no flat representation")

        # Reject blocks with else/elsif — they are not single-rule shaped.
        # The current AST has no representation for else branches, so admitting
        # them here would silently merge the else body into the if body and
        # corrupt user mail routing on round-trip (Quality C-2). Falling out of
        # _try_parse_rule preserves the whole if/elsif/else chain verbatim as a
        # RawBlock instead.
        if re.search(r"\}\s*(?:else|elsif)\b", block_text):
            raise ParseError("else/elsif not supported as single rule")

        rule = Rule(name=comment)

        # Parse the condition part: if anyof/allof (...) { or if <single test> {
        cond_match = _MATCH_OPERATOR_RE.match(block_text)
        if cond_match:
            rule.match = cond_match.group(1)
            tests_text = cond_match.group(2)
            rule.conditions = self._parse_tests(tests_text)
        else:
            # Single condition: if <test> {
            single_match = re.match(r"if\s+(.*?)\s*\{", block_text, re.DOTALL)
            if single_match:
                # A bare `if <test> {` has no anyof/allof wrapper. Recording it
                # as "" rather than inventing one keeps the round-trip honest:
                # forcing "allof" here made `if anyof (x)` come back as allof,
                # so a user who later added a second condition silently got AND
                # where the script said OR.
                rule.match = ""
                rule.conditions = self._parse_tests(single_match.group(1))
            else:
                raise ParseError("Can't parse condition")

        if not rule.conditions:
            raise ParseError("No conditions parsed")

        # Parse the action part (between { and })
        action_match = re.search(r"\{(.*)\}", block_text, re.DOTALL)
        if action_match:
            rule.actions = self._parse_actions(action_match.group(1))
        else:
            raise ParseError("Can't find action block")

        if not rule.actions:
            raise ParseError("No actions parsed")

        return rule

    def _collect_block_lines(self) -> tuple[list[str], int, int]:
        """Collect the lines of the block starting here, and its line range.

        The depth comes from the lexical map — REAL braces, not every `{`
        character — so a folder called `Weird{Folder` no longer holds the block
        open and swallow the rule after it (areyousievious-8fg.10). Character
        counting is the fallback for text the Lexer refused outright, which is
        what this did for every script before.
        """
        start = self.line_idx
        lines = []
        depth = 0
        started = False

        while self.line_idx < len(self.lines):
            line = self.lines[self.line_idx]
            lines.append(line)
            depth += self.lex.brace_delta[self.line_idx]
            opened = self.lex.open_braces[self.line_idx]
            if opened:
                started = True
            self.line_idx += 1
            if started and depth <= 0:
                break

        return lines, start, self.line_idx

    @staticmethod
    def _unquote(s: str) -> str:
        """Unescape a Sieve quoted string.

        RFC 5228 §2.4.2: an UNDEFINED escape sequence is read as if the
        backslash were not there — `"\\."` is `.`, not `\\.`. Handling only
        `\\"` and `\\\\` meant every other backslash survived parsing and then got
        escaped again on the way out, which changed what the script means.
        Found by the AST oracle (areyousievious-8fg.13), and it is the same
        silent-meaning-change class as the rest of this epic. Three strings in
        the corpus, both kinds:

          `:regex "^test@example\\.org$"` is the regex `^test@example.org$`,
          where the dot matches ANY character. We re-emitted `"\\\\."`, making it
          a literal dot — a different filter.

          `addflag "\\Flagged Big"` is the flag `Flagged Big`. We re-emitted
          `"\\\\Flagged Big"`, i.e. `\\Flagged Big` — a different flag. (Writing
          the IMAP flag `\\Flagged` in Sieve needs `"\\\\Flagged"`; that trap is
          the user's, but turning one into the other is ours.)
        """
        return _ESCAPE_RE.sub(r"\1", s)

    def _parse_tests(self, text: str) -> list[Condition]:
        """Parse condition tests from text.

        Recognises, in any tagged-argument order (RFC 5228 §2.7.1):
            address :contains "from" "something"
            not header :is "subject" "something"
            address :domain :is "from" "example.com"          (Roundcube style)
            header :comparator "i;ascii-casemap" :is "x" "y"

        The address-part and comparator are now PRESERVED on the Condition
        rather than consumed and discarded. Dropping them silently changed
        what a rule matched — `address :domain :is "from" "example.com"`
        regenerated as `address :is "from" "example.com"`, which stops
        matching alice@example.com. Roundcube and SOGo both emit :domain.
        """
        conditions = []
        for m in _TEST_RE.finditer(text):
            mods = (m.group("mods") or "") + (m.group("mods_after") or "")
            part = _ADDRESS_PART_RE.search(mods)
            comp = _COMPARATOR_RE.search(mods)
            conditions.append(
                Condition(
                    header=self._unquote(m.group("header")).lower(),
                    match_type=m.group("match_type"),
                    value=self._unquote(m.group("value")),
                    address_test=(m.group("test_type") == "address"),
                    negate=bool(m.group("negate")),
                    address_part=part.group(1) if part else "",
                    comparator=self._unquote(comp.group(1)) if comp else "",
                )
            )
        return conditions

    def _parse_actions(self, text: str) -> list[Action]:
        """Parse actions from the body of an if block, in source order.

        ONE left-to-right scan, not one pass per action type. The previous
        implementation ran eight independent `finditer`/`search` passes and
        appended in a hardcoded type order, which broke three ways:

        1. **Source order was unrepresentable.** `stop; fileinto "X";` came
           back as `fileinto "X"; stop;` — the stop no longer prevented the
           filing, so a round-trip silently changed where mail went.
        2. **Bare-word passes could see inside quoted strings.** A folder named
           `keep;` matched `\\bkeep\\s*;` and materialised a `keep` action the
           user never wrote. Same for `discard;` and `stop;`.
        3. **Repeats collapsed.** `keep; keep;` came back as one `keep`.

        A single ordered alternation fixes all three: at each position the
        quoted-argument alternatives are tried first, so `fileinto "keep;"`
        consumes the whole string before any bare-word alternative can look
        inside it, and every match is appended where it was found.
        """
        actions = []
        for m in _ACTION_RE.finditer(text):
            for group, action_type in _QUOTED_ACTIONS:
                value = m.group(group)
                if value is not None:
                    actions.append(Action(action_type=action_type, argument=self._unquote(value)))
                    break
            else:
                for bare in _BARE_ACTIONS:
                    if m.group(bare) is not None:
                        actions.append(Action(action_type=bare))
                        break
        return actions

    def _consume_block(self) -> str:
        """Consume lines for current block as raw text.

        The ORIGINAL lines, never the masked ones: a RawBlock is the promise
        that we hand back exactly what we were given.
        """
        lines, _start, _end = self._collect_block_lines()
        return "\n".join(lines)


class ParseError(Exception):
    pass


# ── Generator (SieveScript -> Sieve text) ──


class SieveGenerator:
    """Generate Sieve script text from a SieveScript."""

    def generate(self, script: SieveScript) -> str:
        """The script's bytes: verbatim where nothing changed, canonical where it did.

        Two paths per entry and no third. A span that `span_is_faithful`
        vouches for goes out byte for byte — including the blank lines and the
        `# --- name ---` above it, which is what lets a reordered Rule take its
        name with it. Everything else is rendered in house style.

        The old implementation built a list of `parts` and joined it with
        newlines, which imposed our own blank-line convention on every entry in
        the file. That convention is exactly what we are no longer entitled to
        impose on entries we were not asked to change.
        """
        verbatim = [span_is_faithful(e) for e in script.entries]
        regenerated = not all(verbatim)
        head = script.preamble + self._requires_text(script, regenerated=regenerated)

        if not regenerated and head == script.preamble + script.requires_source:
            # NOTHING CHANGED, so nothing is post-processed — not the blank
            # lines, not the trailing newline count, nothing. Every rule this
            # generator could apply here would be it reformatting a file it was
            # not asked to touch, which is the whole behaviour being removed.
            # This early return is what makes the byte-identical property exact
            # rather than nearly true.
            return (head + "".join(e.source for e in script.entries) + script.tail) or "\n"

        out = head
        for entry, is_verbatim in zip(script.entries, verbatim, strict=True):
            piece = entry.source if is_verbatim else self._canonical_span(entry)
            out = self._join(out, piece, seam=not is_verbatim)

        if verbatim and not verbatim[-1]:
            # The last entry regenerated, so its separation from the tail is
            # ours to settle. The tail itself is still appended as it stands.
            #
            # This is a no-op for every entry the PARSER can produce:
            # `_canonical_span` returns `body.strip("\n") + "\n"`, so `out`
            # already ends in exactly one newline. It is live for one entry the
            # WIRE can produce — `RawBlockDTO.text` defaults to `""`, so
            # `{"kind": "raw"}` is a valid entry whose canonical span is a bare
            # "\n", `_join` strips that to nothing and leaves the seam's blank
            # line dangling at the end of the file. Without this line that save
            # ends "\n\n". Pinned by
            # test_verbatim_reemission.py::test_an_empty_raw_block_last_does_not_leave_a_dangling_blank_line.
            out = out.rstrip("\n") + "\n"
        return (out + script.tail) or "\n"

    @staticmethod
    def _join(out: str, piece: str, seam: bool) -> str:
        """Append `piece`, settling blank lines ONLY at a seam a regeneration made.

        This never reflows the document. A verbatim span's interior — and the
        gap between two verbatim spans — is exactly what the user wrote,
        including two blank lines between rules if that is what they wrote, and
        including the blank lines inside a multi-line `vacation` message. An
        earlier draft of this ran `re.sub(r"\\n{3,}", "\\n\\n", ...)` over the
        whole output, which corrupts both: it is the same shape as the bug
        `.13` fixed, where a blank line was injected into a vacation message
        and changed the text a sender received.

        The only place this generator is entitled to impose a convention is
        where a regenerated span meets its neighbour, because a regenerated
        span has no gap of its own and something has to separate it.
        """
        if not seam:
            return out + piece
        if not out:
            return piece.lstrip("\n")
        return out.rstrip("\n") + "\n\n" + piece.lstrip("\n")

    def _canonical_span(self, entry: Entry) -> str:
        """One regenerated entry's bytes. Separation is `_join`'s problem."""
        if isinstance(entry, Rule):
            body = self.generate_entry(entry)
        else:
            body = f"# {entry.comment}\n{entry.text}" if entry.comment else entry.text
        return body.strip("\n") + "\n"

    def _requires_text(self, script: SieveScript, regenerated: bool) -> str:
        """The `require` statement(s), verbatim when the file was not rewritten.

        Pruning (areyousievious-8fg.15) is a property of REGENERATION. An
        untouched file that over-declares `reject` keeps saying so, because
        rewriting that line would break the byte-identical property for a file
        nobody edited. Once anything regenerates, the computed set governs and
        the extension that no longer has a user is dropped.

        Do NOT additionally gate this on `self._compute_requires(script) ==
        script.requires`: pruning makes those two differ for exactly the
        over-declared script this branch exists to leave alone, so that gate
        would send every such file down the canonical path and defeat itself.
        That the bytes agree with the declared list is `_boundary_error`'s job
        (Task 7), and it holds by construction for a freshly parsed script.
        """
        if script.requires_source and not regenerated:
            return script.requires_source
        computed = self._compute_requires(script)
        if not computed:
            return ""
        req_list = ", ".join(f'"{self._quote(r)}"' for r in computed)
        return f"require [{req_list}];\n"

    def generate_entry(self, rule: Rule) -> str:
        """The exact bytes one Rule contributes to a script.

        Public because the preview endpoint calls it (areyousievious-8fg.17),
        and `generate` calls it too. That sharing is the point: the SPA used to
        carry `previewRule`, a SECOND implementation of this generator, and
        both modules said in a comment that the two "must agree" while nothing
        checked it. Five divergences shipped — dropped `negate`, no quote
        escaping, a disabled rule shown live, the missing `# --- name ---`
        line, and a conditionless Rule previewing as nothing while a save
        wrote `if anyof ( ) {`. There is now one implementation to diverge
        from.
        """
        block = self._generate_rule(rule)
        if not rule.enabled:
            # A disabled Rule is stored commented out.
            block = "\n".join("## " + line if line.strip() else "##" for line in block.split("\n"))
        if not rule.name:
            return block
        # The name is emitted HERE, outside anything that gets commented, and
        # never by `_generate_rule`. It used to live inside the block, so a
        # disabled Rule had its own name `## `-prefixed; on reparse that line
        # found no `if`, fell through to the generic comment handler, and
        # `lstrip("#").strip()` baked the marker in — one more `# --- ` per
        # save, forever (areyousievious-8fg.15). Emitting it out here does not
        # fix that bug so much as make it unrepresentable: there is no longer a
        # path by which `## ` can reach the name.
        return f"# --- {rule.name} ---\n{block}"

    def _compute_requires(self, script: SieveScript) -> list[str]:
        """The extensions this script needs.

        Seeding from `script.requires` made this a FLOOR: it only ever grew.
        Swap a `reject` action for `keep` and save, and `require ["fileinto",
        "reject"]` outlives the action that needed it — the script keeps
        claiming an extension it does not use, and a server that does not offer
        `reject` then refuses a script that no longer needs it
        (areyousievious-8fg.15).

        THE CARVE-OUT, and why this is not simply "derive from content": a
        RawBlock's requirements are unknowable. We did not recognise the block,
        so we cannot say what it needs. Measured — an `envelope` test lands in
        a RawBlock, and deriving purely from Rules drops `require ["envelope"]`
        and leaves a script the server rejects. So pruning happens only when
        EVERY entry is a Rule, i.e. when we understand the whole file. One
        RawBlock and the declared set is preserved whole, which is what the old
        floor did for every script.

        AND THEN WHAT THE FILE'S OWN BYTES ALREADY SAY IS SUBTRACTED, because
        this set becomes a `require` line the generator writes ABOVE entries it
        re-emits verbatim — see `_requires_the_bytes_already_declare`.
        """
        # `bool(script.entries)` first: `all(...)` over an empty sequence is
        # True, so a require-only script counted as fully understood and had
        # every extension pruned — regenerating `require ["fileinto"];` to
        # nothing at all. Raised in review; a script with no entries is not one
        # we understand, it is one with nothing in it to derive from.
        understood = bool(script.entries) and all(
            isinstance(entry, Rule) for entry in script.entries
        )
        requires = set() if understood else set(script.requires)

        for rule in script.rules:
            if not rule.enabled:
                continue
            for action in rule.actions:
                if action.action_type in ("fileinto", "fileinto_copy"):
                    requires.add("fileinto")
                if action.action_type == "fileinto_copy":
                    requires.add("copy")
                if action.action_type in ("addflag",):
                    requires.add("imap4flags")
                if action.action_type == "reject":
                    requires.add("reject")
            for cond in rule.conditions:
                if cond.match_type == "regex":
                    requires.add("regex")
                # RFC 5228 §2.7.3: `i;octet` and `i;ascii-casemap` are built in,
                # anything else must be required. `_generate_test` happily emits
                # the `:comparator` tag, so deriving requires without this
                # pruned the declaration while leaving the tag behind — a
                # script a compliant server refuses, produced by an UNEDITED
                # re-save. Raised in review of this PR.
                if cond.comparator and cond.comparator not in _BUILTIN_COMPARATORS:
                    requires.add(f"comparator-{cond.comparator}")
                # address test is core Sieve, no require needed

        return sorted(requires - _requires_the_bytes_already_declare(script))

    def _generate_rule(self, rule: Rule) -> str:
        lines = []

        # NO name comment here. It is `generate_entry`'s, so that it lands
        # outside the `## ` prefixing a disabled Rule gets. The name is emitted
        # verbatim there — `.upper()` once meant a user's "GitHub
        # notifications" came back as "GITHUB NOTIFICATIONS" after one save,
        # permanently, because the comment is the only place a name is stored.

        # Conditions. A wrapper is emitted when the source had one, or whenever
        # there is more than one condition (where it is required). A single
        # condition parsed from a bare `if <test> {` keeps match="" and is
        # re-emitted bare, so the shape survives the round trip.
        if len(rule.conditions) == 1 and not rule.match:
            lines.append(f"if {self._generate_test(rule.conditions[0])} {{")
        else:
            tests = [f"    {self._generate_test(cond)}" for cond in rule.conditions]
            lines.append(f"if {rule.match or 'anyof'} (")
            lines.append(",\n".join(tests))
            lines.append(") {")

        # Actions
        for action in rule.actions:
            lines.append(f"    {self._generate_action(action)}")

        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def _quote(s: str) -> str:
        """Escape a string for use inside Sieve double quotes."""
        return s.replace("\\", "\\\\").replace('"', '\\"')

    def _generate_test(self, cond: Condition) -> str:
        """Render a test, re-emitting any tagged arguments the parser saw.

        Order follows RFC 5228: ADDRESS-PART, then COMPARATOR, then MATCH-TYPE.
        """
        parts = ["not " if cond.negate else "", "address" if cond.address_test else "header"]
        if cond.address_part:
            parts.append(f" :{cond.address_part}")
        if cond.comparator:
            parts.append(f' :comparator "{self._quote(cond.comparator)}"')
        parts.append(f" :{cond.match_type}")
        parts.append(f' "{self._quote(cond.header)}"')
        parts.append(f' "{self._quote(cond.value)}"')
        return "".join(parts)

    def _generate_action(self, action: Action) -> str:
        arg = self._quote(action.argument)
        if action.action_type == "fileinto":
            return f'fileinto "{arg}";'
        elif action.action_type == "fileinto_copy":
            return f'fileinto :copy "{arg}";'
        elif action.action_type == "redirect":
            return f'redirect "{arg}";'
        elif action.action_type == "keep":
            return "keep;"
        elif action.action_type == "discard":
            return "discard;"
        elif action.action_type == "stop":
            return "stop;"
        elif action.action_type == "addflag":
            return f'addflag "{arg}";'
        elif action.action_type == "reject":
            return f'reject "{arg}";'
        # Unreachable from the API since .18 closed ActionType — routers/scripts.py
        # is the only production caller and Pydantic 422s first. Kept because the
        # generator takes a DATACLASS, not a DTO, so a caller can still hand it an
        # Action it built itself; a visible comment beats a KeyError, and the
        # closed wire is what stops this ever reaching a user's script again.
        return f"# unknown action: {action.action_type}"


# ── JSON serialization ──


def _rule_to_json(r: Rule) -> dict:
    return {
        "kind": "rule",
        "name": r.name,
        "enabled": r.enabled,
        "match": r.match,
        "conditions": [
            {
                "header": c.header,
                "match_type": c.match_type,
                "value": c.value,
                "address_test": c.address_test,
                "negate": c.negate,
                "address_part": c.address_part,
                "comparator": c.comparator,
            }
            for c in r.conditions
        ],
        "actions": [{"type": a.action_type, "argument": a.argument} for a in r.actions],
        "source": r.source,
    }


def script_to_json(script: SieveScript) -> dict:
    """Convert SieveScript to a JSON-serializable dict.

    Pure: the same SieveScript always produces the same dict. Nothing is minted
    here (see docs/adr/0001-identity-is-view-state.md), so tests can assert exact
    payloads.
    """
    return {
        "requires": script.requires,
        "preamble": script.preamble,
        "requires_source": script.requires_source,
        "tail": script.tail,
        "entries": [
            _rule_to_json(e)
            if isinstance(e, Rule)
            else {"kind": "raw", "text": e.text, "comment": e.comment, "source": e.source}
            for e in script.entries
        ],
    }


def _rule_from_json(r: dict) -> Rule:
    conditions = []
    for c in r.get("conditions", []):
        if not isinstance(c, dict) or "header" not in c or "match_type" not in c:
            continue
        conditions.append(
            Condition(
                header=c["header"],
                match_type=c["match_type"],
                value=c.get("value", ""),
                address_test=c.get("address_test", False),
                negate=c.get("negate", False),
                address_part=c.get("address_part", ""),
                comparator=c.get("comparator", ""),
            )
        )
    actions = []
    for a in r.get("actions", []):
        if not isinstance(a, dict) or "type" not in a:
            continue
        actions.append(Action(action_type=a["type"], argument=a.get("argument", "")))
    return Rule(
        name=r.get("name", ""),
        enabled=r.get("enabled", True),
        match=r.get("match", "anyof"),
        conditions=conditions,
        actions=actions,
        source=r.get("source", ""),
    )


def json_to_script(data: dict) -> SieveScript:
    """Convert a JSON dict back to a SieveScript.

    Ordering comes from position in `entries`, so there is no index to validate
    and no way for a caller to submit an order that omits one of its own rules.
    The previous representation could, and silently dropped the omitted rule on
    save.
    """
    script = SieveScript(
        requires=data.get("requires", []),
        preamble=data.get("preamble", ""),
        requires_source=data.get("requires_source", ""),
        tail=data.get("tail", ""),
    )

    for e in data.get("entries", []):
        if not isinstance(e, dict):
            continue
        if e.get("kind") == "raw":
            script.entries.append(
                RawBlock(
                    text=e.get("text", ""),
                    comment=e.get("comment", ""),
                    source=e.get("source", ""),
                )
            )
        elif e.get("kind") == "rule":
            script.entries.append(_rule_from_json(e))

    return script


# ── Convenience ──


def parse_sieve(text: str) -> SieveScript:
    """Parse Sieve text into a SieveScript."""
    return SieveParser(text).parse()


def generate_sieve(script: SieveScript) -> str:
    """Generate Sieve text from a SieveScript."""
    return SieveGenerator().generate(script)


def rule_from_json(data: dict) -> Rule:
    """Build a single Rule from its wire dict.

    The rule-sized counterpart to `json_to_script`, for the preview endpoint —
    which has one Rule and no script to put it in.
    """
    return _rule_from_json(data)


# sievelib's PARSER resets `RequireCommand.loaded_extensions` — a CLASS
# attribute — on every parse, so two concurrent parses race and one sees the
# other's extensions. Measured: 30 spurious rejections in 24,000 parses across
# 16 threads, 0 under this lock. FastAPI runs sync handlers on a threadpool, so
# that race is two HTTP requests apart, and on the pre-flight path each one
# tells a user their perfectly good script is broken.
#
# The LEXER needs no such thing and does not take this (areyousievious-8fg.10);
# only the Parser has the shared state.
_PARSER_LOCK = threading.Lock()


def sieve_is_parseable(text: str) -> str | None:
    """sievelib's complaint about `text`, or None if it parses.

    An INDEPENDENT grammar. Checking our generator's output with our own parser
    would assert only that the two agree with each other, which is the loop
    that let three `previewRule` divergences ship.
    """
    parser = Parser()
    with _PARSER_LOCK:
        if parser.parse(text.encode()):
            return None
        return str(parser.error)


def _without_span(entry: Entry) -> Entry:
    """A copy with `source` cleared, for comparison by value alone."""
    return replace(entry, source="")


def span_is_faithful(entry: Entry) -> bool:
    """True when `entry.source` re-parses to exactly this entry and nothing else.

    This is the whole of the dirty check. The span is the pristine copy the
    entry was parsed from, so comparing against it needs no flag, no identity
    and no cooperation from the client — which matters, because `source`
    crosses the wire and comes back under the client's control.

    Four things are required, and all four are load-bearing:

      - EXACTLY ONE entry, so a span cannot carry a second statement. Append
        `redirect "attacker@example.com";` to an otherwise honest span and this
        is what refuses it.
      - NO requires, so a span cannot smuggle an extension in beside the entry
        it claims to be. A span that is a `require` AND NOTHING ELSE is the one
        exception, handled by `_unharvested_require_is_faithful` — the parser
        makes such a span an entry in its own right, and refusing it there cost
        the byte-identical property (areyousievious-3xk).
      - NO preamble and NO tail, so a span cannot carry loose bytes on either
        side of the entry it claims to be.
      - VALUE EQUALITY ignoring `source` itself, so the bytes mean what the
        entry says they mean.

    It fails CLOSED. Every path that cannot vouch for the span returns False
    and the caller regenerates, which is correct but reformats — the failure
    mode is a cosmetic loss, never a wrong filter.

    THE LEADING/TRAILING ASYMMETRY IS DELIBERATE. A span may carry comment and
    blank lines ABOVE the entry beyond the one absorbed as its name, and may not
    carry so much as a blank line BELOW it. That is not an oversight to be
    tidied up: the leading gap is part of the span on purpose, because that is
    what makes a reordered Rule take its `# --- name ---` — and any comment the
    user wrote above it — along to its new position. Re-parsing a span with a
    leading gap yields one entry and no preamble, precisely because the parser
    puts that gap inside the entry. A TRAILING gap is different in kind: bytes
    after an entry belong to whatever comes next, or to the file's tail, so a
    span claiming them re-parses with a non-empty tail and is refused. Making
    the two sides symmetrical breaks reordering, which is a core requirement.

    The `not entry.source` line below is a REDUNDANT fast path, kept for
    clarity. An empty span parses to zero entries, so `len(...) != 1` already
    refuses it — deleting the line changes no result. It is marked so the next
    reader does not spend time working out which case it uniquely catches.
    """
    if not entry.source:
        return False
    reparsed = parse_sieve(entry.source)
    if reparsed.requires and not reparsed.entries:
        # The span is a `require` statement the file left unharvested. Read in
        # isolation it lands in the requires slot instead of coming back as an
        # entry, so none of the four checks below can be asked of it — see
        # `_unharvested_require_is_faithful`, which asks all four anyway.
        return _unharvested_require_is_faithful(entry)
    if reparsed.requires or reparsed.preamble or reparsed.tail:
        return False
    if len(reparsed.entries) != 1:
        return False
    return _without_span(reparsed.entries[0]) == _without_span(entry)


_REQUIRE_PROBE = "keep;\n"
"""A statement to stand in front of a span, so a `require` inside it parses the
way the file's own parse produced it. `keep;` is core Sieve: one line, its own
terminator, and it needs no extension — so the probe cannot change what the span
is measured to declare."""


def _unharvested_require_is_faithful(entry: Entry) -> bool:
    """True when a span whose `require` re-parses out of reach still IS this entry.

    THE ORDINARY CHECK CANNOT REACH THIS ENTRY, and that is a fact about the
    parser rather than about the span. `SieveParser.parse` harvests a `require`
    into `script.requires` only while `script.entries` is still empty. Once
    anything precedes it — a bracketed license header (RFC 5228 §2.3, and
    perfectly legal there, since a comment is not a command), or a rule written
    above it — the statement stays a RawBlock and its extensions are
    deliberately NOT harvested, so that the bytes carry the declaration exactly
    once.

    Re-parsing such a span ALONE puts the statement first again, so it IS
    harvested after all: zero entries, a non-empty `requires`, and the leading
    blank line sitting in `preamble`. `span_is_faithful`'s "no requires, no
    preamble, exactly one entry" then refuses a span that is an honest copy of
    its own entry. The whole file regenerates, and the canonical `require` line
    lands on top of the one the RawBlock re-emits — two declarations, and an
    unedited save that is no longer byte-identical (areyousievious-3xk).

    So re-parse it IN THE POSITION IT CAME FROM. With a statement in front the
    parser takes the same RawBlock path it took on the file, and the result is
    held to the SAME value equality as any other entry: exactly the probe's
    statement and this one, nothing in the requires slot, nothing loose on
    either side, and a value match ignoring `source`. No weaker rule, and no
    second notion of what a faithful span is.

    NOTHING NEW CAN BE WRITTEN THROUGH HERE, which is why relaxing the
    no-requires rule costs nothing. A RawBlock's `text` is opaque text
    re-emitted verbatim on BOTH paths — `_canonical_span` hands it back
    unchanged — so a span vouched for here writes the same bytes the canonical
    rendering would have written anyway. What changes is only whether they go
    out with their own blank lines or with ours.
    """
    probe = parse_sieve(_REQUIRE_PROBE + entry.source)
    if probe.requires or probe.requires_source or probe.preamble or probe.tail:
        return False
    if len(probe.entries) != 2:
        return False
    if probe.entries[1].source != entry.source:
        # The probe's own statement did not claim exactly its own line, so the
        # split is not the one the rest of this is reasoning about. Fail closed.
        return False
    return _without_span(probe.entries[1]) == _without_span(entry)


def _requires_the_bytes_already_declare(script: SieveScript) -> set[str]:
    """Extensions a RawBlock's own bytes declare, which the head must not repeat.

    `SieveParser.parse` leaves a `require` that follows another entry as a
    RawBlock and does not harvest it, on the stated ground that "left
    unharvested the declaration survives exactly once, in the verbatim bytes
    that already carry it". That sentence was an ASSERTION, not a lock:
    `_requires_text` rendered the computed set regardless and the RawBlock
    re-emitted its own copy below it, so a file with a bracketed license header
    above its `require` came back declaring `fileinto` twice
    (areyousievious-3xk). Subtracting what the bytes say is the lock.

    NO POSITIONAL CARVE-OUT, and the tempting one is empty. It looks unsafe to
    drop the head declaration when the RawBlock carrying it sits BELOW a rule
    that needs the extension — the emitted script would then use `fileinto`
    before declaring it. But RFC 5228 §3.2 requires every `require` to precede
    every other command, so that file is refused for the position of its own
    statement whatever we prepend — sievelib refuses the two-line case outright
    — and the head line rescues nothing there, it only adds the second
    declaration. The shapes that reach this path and are still VALID Sieve are
    the ones whose preceding entry is not a command at all: a bracketed comment,
    and a `## ` disabled Rule, which is comment text the recogniser reads back.
    In both the statement already precedes every live rule.

    Every RawBlock is asked, not only the ones the parser routed here, because
    `text` arrives over the wire and both generation paths write it out
    verbatim — what is emitted is the only thing that can be double-declared.

    A declaration the parser did NOT read stays unread. A `require` inside a
    bracketed comment, or under a `## ` disabled run, parses to no requires here
    for the same reason it did on the way in, so nothing is subtracted on the
    strength of bytes the server will never execute.
    """
    declared: set[str] = set()
    for block in script.raw_blocks:
        declared.update(parse_sieve(block.text).requires)
    return declared


_LONE_CR = re.compile(r"\r(?!\n)")
_EXTENSION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._;/-]*")


def _unwritable_byte_error(script: SieveScript) -> str | None:
    """Whether any text we would write carries a byte that is not ours to write.

    One question — are these bytes ours to write — asked of every field that
    becomes part of the script. The generator escapes a Condition's header,
    value and comparator and an Action's argument into quoted strings, verified,
    so a byte there is a literal and not a statement of its own.

    QUOTING ANSWERS STATEMENT INJECTION AND NOTHING ELSE, and the difference is
    the whole reason those four fields are checked for a NUL below rather than
    trusted to their quotes. Escaping stops a byte from becoming a statement; it
    does not stop the byte from reaching the mail server. A server that
    truncates its input at a NUL does not truncate one value — it truncates the
    WHOLE SCRIPT there, silently dropping every rule after the offending one
    while our UI keeps showing them, because our own parser is happy with a NUL
    between quotes. That is DELETION of a user's filters, which this module
    treats as the worst thing it can do (see `_consume_statement`), and it needs
    no `RawBlock` to reach. RFC 5228 §2.4.2's quoted-string production does not
    admit NUL, so refusing it costs nothing legitimate.

    LF AND CR ARE NOT ASKED OF THOSE FOUR, deliberately, and the reason is NOT
    that quoting escapes them — `_quote` escapes a backslash and a quote and
    nothing else, so a newline in a value goes out RAW between the quotes. It is
    that the string is still open around it: the statement ends at the closing
    quote, so a line ending inside one cannot terminate anything, and a value
    carrying one parses back to the same Condition, a fixed point, verified.
    Those two bytes are refused where they are refused below because THOSE
    fields are not quoted — a comment line, or verbatim span bytes, where a line
    ending is the end of the construct.

    THE RESIDUAL THERE, named rather than left to be found: RFC 5228's
    `quoted-safe` admits CRLF but not a lone CR or LF, so a bare one in a value
    is malformed for a strict server too. It is left to the server because the
    two failures are not the same failure — a server that dislikes a line
    ending REFUSES THE SCRIPT, loudly, and the user sees it; a server that
    truncates at a NUL accepts a script and silently drops the rules after it.
    Only the second is invisible, and invisible is what this guard is for.

    THE FOUR ARE THE FREE TEXT THE WIRE ADMITS, which is why they are the four.
    `api_models` pins `match_type`, `address_part`, the action type and `match`
    to `Literal` vocabularies that hold no NUL to smuggle; `header`, `value` and
    `comparator` are free text there on purpose, and `argument` is a folder name
    or an address. A NUL in the comparator happens to be refused today by
    sievelib's own comparator whitelist, but ONLY as collateral of
    areyousievious-3o4 — that whitelist refuses `i;ascii-numeric` too, which is
    a bug — so the day 3o4 is fixed that accidental cover goes with it. Checking
    the field here is what survives the fix.

    THE SCOPE DIFFERS PER BYTE, and each difference is the line between a guard
    and a lockout:

    A BARE LF, in `Rule.name` or `RawBlock.comment` ONLY. Those two are
    interpolated into a single `# ` line — `f"# {comment}\n{text}"` and
    `f"# --- {name} ---"` — so a newline in them ends the comment and everything
    after it is a live statement. `RawBlock(comment='c\nredirect "a@b.com";')`
    rendered as `# c\nredirect "a@b.com";\nkeep;` and was answered 200. This
    needs no reading of the RFC, unlike the CR below: a bare LF ends a line for
    every parser there is. It must NOT be asked of `text`, `source`, `preamble`,
    `requires_source` or `tail`, all of which are many lines by definition.

    A LONE CR, in every field. We split lines on "\n" alone, so a bare CR is an
    ordinary mid-line character and `# note\rredirect "a@b.com";` is ONE comment
    to our parser, to sievelib, and therefore to the `.13` pre-flight too. RFC
    5228 ends a comment at CRLF and excludes CR from its body, so what a server
    does with the octets after it is undefined and one plausible reading runs
    them. CRLF stays legal because every CR in it is followed by LF.

    A NUL, in everything EXCEPT a `RawBlock`'s own `text` and `source` — the
    quoted Condition and Action fields above included. RFC 5228's
    `octet-not-crlf` excludes %x00, so a NUL is never valid Sieve, and against a
    C-implemented server truncation at it is the classic desync.

    The exemption is meant for the file that ALREADY holds one — a NUL that
    breaks lexing takes the whole file down the `usable == False` path and comes
    back as a single RawBlock carrying the entire text — but WHAT THE CODE
    ACTUALLY KEYS ON is narrower than that sentence and worth stating plainly: a
    NUL anywhere in `RawBlock.text` exempts that entry's whole `source`. Both
    sides of that test are bytes the client supplies, so it is usable on purpose:
    put a NUL in `text` and one in the leading gap rides along. No capability is
    gained, because the NUL in `text` is itself the unrestricted channel —
    `RawBlock.text` grants arbitrary statements by design and by ADR 0002 — so a
    tighter test would buy nothing while risking the lockout it exists to avoid.
    Refusing it would lock a user out of saving their own file over a byte
    already sitting on their server, and re-emitting bytes that are already there
    changes nothing.

    SO THE EXEMPTION REACHES ONLY AS FAR AS THAT REASON DOES: a `source` is
    exempt when the NUL is in the block's own `text`, and not otherwise. Two
    earlier scopings were wider than their own rationale, both for one structural
    reason — bytes an entry was parsed from that land in NO COMPARED FIELD, and
    therefore need only survive `span_is_faithful`, which cannot see them:

      - A RULE'S `source`. An earlier version of this comment claimed the lockout
        case put the NUL in `text` and `source` and nowhere else; that is true
        only of a NUL that BREAKS LEXING.
        `parse_sieve('# note\x00here\n# --- n ---\nif ...')` lexes fine and gives
        a RULE whose `source` carries the NUL, and exempting it there wrote
        `# lead\x00redirect "attacker@example.com";` to the mail server, 200 and
        byte-identical.
      - A RAWBLOCK'S LEADING GAP. The parser keeps only the LAST comment line as
        `comment`; earlier lines, and blank lines, stay in `source` alone. So
        `'# a\x00redirect "atk@e.com";\n# b\nvacation :days 7 "Away";\n'` has
        `comment == 'b'`, a clean `text`, and the NUL in neither — the
        single-comment shape was refused and this one was not.

    Marginal capability over `RawBlock.text` is nil either way, since that field
    already grants arbitrary statements deliberately. The reason to refuse it is
    that these bytes sit in no modelled field at all, so they survive parse →
    display → save invisibly, and an exemption wider than the reason given for it
    is one nobody can check.

    THE RESIDUAL COST, named rather than left to be discovered: a NUL ANYWHERE in
    a Rule's span is now refused — not only in a comment above it, but inside a
    quoted value (`"sp\x00am"`) and in a trailing in-body comment, both of which
    lex, are faithful, and are refused. Same for a RawBlock's leading gap. That is
    the cost already accepted for a lone CR, which is refused in `source`
    unconditionally; accepting it for one byte and not the other was two opposite
    principles applied to one shape.

    A REQUIRE ITEM must look like an extension name, which is a whitelist rather
    than a byte list because nothing else here can be: `_requires_text`
    interpolates each item into `require ["..."];`, and `script.requires` is the
    one client-supplied string the design never thought to check — it is what
    `_boundary_error` checks the head bytes AGAINST, so it was read as the
    trusted reference rather than as input. Unescaped, and with no entries in the
    script at all, `requires=['fileinto"];\nredirect "atk@e.com";\n#']` rendered
    a live `redirect` that sievelib pronounced valid Sieve. That is the original
    Task 7 bug — hostile bytes, no entries, 200 — one field along.

    `[A-Za-z0-9][A-Za-z0-9._;/-]*` matched in FULL is a shape, not a list of
    names, so an extension nobody here has heard of still saves; all 16 declared
    across the corpus fixtures match it, `vacation-seconds` and `imap4flags`
    included. It subsumes the byte checks for this one field, since CR, LF and
    NUL are all outside the class. The interpolation is escaped as well, because
    every other string this generator writes is, and a guard that happens to sit
    upstream is not a reason to emit text unescaped.

    `;` AND `/` ARE IN THE CLASS BECAUSE COLLATION NAMES CARRY THEM, and leaving
    them out was this guard's own turn at being `.13`. RFC 5228 §2.7.3 mandates
    `comparator-<name>` for any collation outside `i;octet` and
    `i;ascii-casemap`, and every RFC 4790 collation name has a `;` in it — so
    `comparator-i;ascii-numeric` was refused, which meant a user with an ordinary
    relational spam-score rule could open their script and never save it again.
    `_compute_requires` WRITES THAT NAME ITSELF, so the pre-flight was rejecting
    our own generator's output. No corpus fixture held a relational test or a
    declared collation, which is exactly why the corpus stayed green: it is
    the oracle only for shapes it contains. Both shapes are in it now —
    `match-relational.sieve` and `modifiers-comparator-declared.sieve`, added by
    areyousievious-gey — so the corpus can fail for this reason today, and the
    second of them does, pinned to areyousievious-3o4. Neither character can
    break out of a quoted string, so this costs nothing — and the escaping at
    `_requires_text` is what would hold if it did.

    NOT CHECKED, DELIBERATELY: \x0b, \x0c, \x85, U+2028 and U+2029 all reach the
    output and all are legal comment octets under RFC 5228, which ends a comment
    at CRLF and at nothing else. Python's `str.splitlines()` breaks on every one
    of them, which is why a fuzz oracle built on it reports them and why this
    one is built on CRLF/LF/CR instead. Refusing them would be superstition.
    """
    one_comment_line: list[str] = []
    written_verbatim: list[str] = [script.preamble, script.requires_source, script.tail]
    no_nul: list[str] = [script.preamble, script.requires_source, script.tail]
    for entry in script.entries:
        written_verbatim.append(entry.source)
        if isinstance(entry, Rule):
            one_comment_line.append(entry.name)
            no_nul.append(entry.source)
            for cond in entry.conditions:
                no_nul.extend((cond.header, cond.value, cond.comparator))
            for action in entry.actions:
                no_nul.append(action.argument)
        else:
            one_comment_line.append(entry.comment)
            written_verbatim.append(entry.text)
            if "\x00" not in entry.text:
                # The NUL is not in the bytes the exemption is for, so whatever
                # else the span holds is not covered by it.
                no_nul.append(entry.source)

    for extension in script.requires:
        # `fullmatch`, not `match`: Python's `$` also matches BEFORE a trailing
        # newline, so `"elsif\n"` satisfied an anchored pattern and rendered
        # `require ["elsif` and `"];` on two lines. Caught by the fuzzer the
        # first time it could see this field at all.
        if not _EXTENSION_NAME.fullmatch(extension):
            return f"not an extension name: {extension!r}"
    for text in one_comment_line:
        if "\n" in text:
            return "a line break in a name or comment would end the comment it sits in"
    for text in (*one_comment_line, *written_verbatim):
        if _LONE_CR.search(text):
            return "a carriage return would end a line for the server but not for us"
    for text in (*one_comment_line, *no_nul):
        if "\x00" in text:
            return "a NUL would truncate the script for the server"
    return None


def _head_error(head: SieveScript, declared: list[str]) -> str | None:
    """Why a parse of the head's bytes is not something we may write out.

    Asked of the preamble alone and of the preamble with the `require` bytes
    appended, because a statement can appear from the JOIN that neither half
    holds on its own. Split out of `_boundary_error`'s loop so the second parse
    is paid for only when the first one found nothing: a rejected save should
    not parse the head twice to report the same refusal.
    """
    if head.entries:
        return "preamble carries a statement"
    undeclared = [r for r in head.requires if r not in declared]
    if undeclared:
        return f"require bytes declare an undeclared extension: {undeclared[0]}"
    return None


def _boundary_error(script: SieveScript) -> str | None:
    """What is wrong with the verbatim bytes that are not an entry's span.

    `span_is_faithful` proves an entry's span by re-parsing it and comparing to
    the entry. The preamble, the `require` bytes and the tail have no entry to
    be compared against, so they are held to a narrower rule instead: the head
    may hold comments, blank lines and `require` statements for extensions the
    wire declares, and NOTHING else; the tail may hold no statement at all.
    Without this, `source` on the wire would be an arbitrary-text-to-the-mail-
    server hole with no guard on either end — and not a theoretical one. Before
    this guard, a PUT carrying `preamble = 'redirect "attacker@example.com";'`
    and no entries at all was answered 200 and written to the user's mail
    server.

    THE PREAMBLE IS CHECKED TWICE, ALONE AND THEN WITH THE `require` BYTES
    JOINED ON, because the generator emits it in both companies. A save that
    regenerates anything drops `requires_source` and writes the preamble against
    a freshly rendered `require` line instead, so checking only the join
    validates bytes that are not the bytes written: a `preamble` of
    `require ["fileinto"` with a `requires_source` of `];` reads as one honest
    statement joined, and on the regenerating path goes out as
    `require ["fileinto"require ["fileinto"];`. Found by attacking this guard
    after writing it. A real server refuses that, so the cost was a confusing
    failure rather than a wrong filter — but a check that does not cover what is
    actually emitted is not a check.

    The join is needed as well as the halves, and is parsed as ONE unit, because
    `requires_source` is not always a single well-formed statement: a file that
    declares its extensions in three goes keeps the comment sitting between them
    in the same span.

    THE REQUIRES CHECK IS SUBSET, NOT EQUALITY, and that difference is the whole
    difference between a guard and a lockout. The property worth having is that
    the verbatim bytes never DECLARE MORE than the wire says — a client must not
    send `requires: ["fileinto"]` and write `require ["fileinto", "vacation"];`.
    The converse costs nothing and is the ordinary case: a script built in the
    UI declares `["fileinto"]` and carries no `requires_source` at all, because
    there were never any bytes to parse and the generator renders that line
    canonically. Demanding equality refuses every such save — it refused nine
    existing tests, `test_saving_rules_stores_generated_sieve` among them,
    before this was corrected. An empty head is therefore always agreement, and
    so is a script whose `require` sits BELOW its first entry: those extensions
    are deliberately not harvested, so the list and the bytes are both empty.

    This is deliberately NOT `.13`'s mistake in a new place. That bead learned
    that a whole-script validator refuses working scripts forever, because
    sievelib does not know `include`, `addheader` or `spamtest` though every
    real server does. Two things keep this clear of it: it runs OUR parser, not
    sievelib's, and it runs over the head and tail ONLY — never over an entry,
    which is where an unknown extension lives.

    THE PREAMBLE ALONE MUST DECLARE NOTHING, checked after the pair above rather
    than inside it. The undeclared-extension bound already held for a `require`
    sitting in the preamble — one naming an extension the wire did not declare is
    refused there, so nothing is smuggled — but one naming an extension the wire
    DID declare satisfied both clauses: it parses into `head.requires` rather
    than `head.entries`, and it declares exactly what it is allowed to. The
    generator then wrote those preamble bytes AND `_requires_text`'s canonical
    line, declaring the same extension twice (areyousievious-5vp). RFC 5228 §3.2
    permits the repetition, so this was untidy output rather than a wrong filter,
    and no path in the SPA produces it — it takes a hand-built request. It is
    refused all the same, because `preamble` is documented (docs/adr/0002,
    AGENTS.md) as immovable NON-`require` bytes, and a field whose stated shape
    nothing enforces stops being a shape. The declaration belongs in
    `requires_source`, which is the term the generator knows how to leave alone.

    The order is deliberate: the undeclared-extension message is the one that
    reports a bound being ATTACKED, so it keeps precedence over this one, which
    reports a field being MISUSED.
    """
    preamble_head = parse_sieve(script.preamble)
    problem = _head_error(preamble_head, script.requires) or _head_error(
        parse_sieve(script.preamble + script.requires_source), script.requires
    )
    if problem:
        return problem
    if preamble_head.requires:
        return "preamble carries a require statement"
    tail = parse_sieve(script.tail)
    if tail.entries or tail.requires:
        return "trailing bytes carry a statement"
    return None


def preflight_error(script: SieveScript) -> str | None:
    """Why the mail server would refuse this script, or None (`.13`).

    ONLY THE RULES are checked, never the RawBlocks, and that scoping is
    load-bearing rather than an optimisation. sievelib's grammar has real gaps
    — `include`, `addheader` and `spamtest` are all "unknown command" to it
    though every real server takes them — so validating the whole script would
    refuse working scripts forever, for a construct we never touched. A
    RawBlock is where such a construct lives, and it is exempt.

    NOTE THAT THIS IS NOT THE SAME LINE AS "what we regenerated". The loop
    below runs over every Rule unconditionally, including one whose span
    `span_is_faithful` vouched for and which a save will therefore re-emit
    verbatim rather than regenerate. `generate_sieve` takes the same verbatim
    path here as it does on the save, so what sievelib sees for such a Rule is
    that original span itself, under the require line it needs — the check is
    over the bytes that will actually go out either way.

    Skipping the RawBlocks is sound for a different reason: their bytes are
    re-emitted byte-identical and the server already accepted them once.

    Each Rule is checked as its own little script, with the requires it needs,
    because sievelib treats a command whose extension was not required as a
    hard parse failure.

    SINCE areyousievious-8fg.14 IT ALSO COVERS THE BOUNDARY BYTES. The
    preamble, the `require` bytes and the tail cross the wire and are written
    to the mail server verbatim, and no entry exists to compare them against —
    so `_boundary_error` checks them first, and `_unwritable_byte_error` checks
    every field that becomes a line of the script for a byte that would end that
    line for the server and not for us. Both ask a different question from the
    one below — is this text ours to write at all, rather than will the server
    compile it — which is why they are separate functions and not more clauses.
    """
    problem = _unwritable_byte_error(script) or _boundary_error(script)
    if problem:
        return problem
    for rule in script.rules:
        problem = sieve_is_parseable(generate_sieve(SieveScript(entries=[rule])))
        if problem:
            return problem
    return None


def generate_rule(rule: Rule) -> str:
    """The house-style Sieve one Rule renders to.

    Goes through the same `SieveGenerator.generate_entry` a regenerating save
    does — one generator, not two. That sharing is the whole point of
    areyousievious-8fg.17: the SPA used to carry `previewRule`, a second
    implementation that had already diverged five ways from this one.

    THIS IS NOT ALWAYS THE BYTES A SAVE WRITES, and since
    areyousievious-8fg.14 it is not meant to be. A save re-emits an UNEDITED
    Rule's original span verbatim and never reaches this function; only an
    edited Rule takes the regenerating path. So what a preview shows is the
    text a Rule would take IF IT WERE EDITED — which is exactly the disclosure
    it is for, since the reformatting is what the user has not committed to
    yet. An untouched Rule keeps its own bytes.

    Note what this does NOT include: the `require [...]` line, which is a
    property of the whole script rather than of any one Rule — nor the trailing
    newline, which `_canonical_span` appends when a save places this text among
    its neighbours. Preview shows a Rule on its own, so it has no neighbours and
    no separator to settle.
    """
    return SieveGenerator().generate_entry(rule)
