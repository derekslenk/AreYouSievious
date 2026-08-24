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
from dataclasses import dataclass, field

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
    exact round-trip fidelity rather than mere stability.
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
    """Bytes before the first `require`, or before the first entry when there
    is none. Immovable: reordering Rules never moves the file's header."""
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
            body = self.text.rstrip("\n")
            return SieveScript(entries=[RawBlock(text=body)] if body.strip() else [])

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

            # Require statement
            if line.startswith("require"):
                # EXTEND, never assign. Assigning meant a second `require`
                # replaced the first and everything it named was gone before
                # the first generation — invisible to both round-trip tests,
                # since by gen1 both sides had already lost it. RFC 5228 §3.2
                # shows multiple statements and Horde/Ingo emits them
                # (areyousievious-8fg.15).
                statement, clean = self._consume_statement()
                if not clean:
                    # Not a `require` we can read. Keep its bytes rather than
                    # guess at them.
                    script.entries.append(RawBlock(text=statement, comment=pending_comment))
                    pending_comment = ""
                    continue
                for extension in self._parse_require(statement):
                    if extension not in script.requires:
                        script.requires.append(extension)
                continue

            # Disabled rule (commented out with ## prefix) — check before comment handler
            if line.startswith("## ") and self.line_idx >= failed_run_end:
                disabled_rule = self._try_parse_disabled_block(pending_comment)
                if disabled_rule:
                    script.entries.append(disabled_rule)
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
                    script.entries.append(rule)
                else:
                    # Couldn't parse - store as raw block
                    raw_text = self._consume_block()
                    script.entries.append(RawBlock(text=raw_text, comment=pending_comment))
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
            script.entries.append(RawBlock(text=raw_text, comment=pending_comment))
            pending_comment = ""

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
        parts = []

        # Require statement
        requires = self._compute_requires(script)
        if requires:
            req_list = ", ".join(f'"{r}"' for r in requires)
            parts.append(f"require [{req_list}];")
            parts.append("")

        # Generate in order — position in `entries` IS the order
        for entry in script.entries:
            if isinstance(entry, Rule):
                parts.append(self.generate_entry(entry))
                parts.append("")
            else:
                if entry.comment:
                    parts.append(f"# {entry.comment}")
                parts.append(entry.text)
                parts.append("")

        return "\n".join(parts).rstrip() + "\n"

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

        return sorted(requires)

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


def preflight_error(script: SieveScript) -> str | None:
    """Why the mail server would refuse this script, or None (`.13`).

    ONLY THE SPANS WE REGENERATED are checked, never the RawBlocks, and that
    scoping is load-bearing rather than an optimisation. sievelib's grammar has
    real gaps — `include`, `addheader` and `spamtest` are all "unknown command"
    to it though every real server takes them — so validating the whole script
    would refuse working scripts forever, for a construct we never touched.

    Checking only what we generated is sound because a RawBlock is re-emitted
    byte-identical and the server already accepted it once.

    Each Rule is checked as its own little script, with the requires it needs,
    because sievelib treats a command whose extension was not required as a
    hard parse failure.
    """
    for rule in script.rules:
        problem = sieve_is_parseable(generate_sieve(SieveScript(entries=[rule])))
        if problem:
            return problem
    return None


def generate_rule(rule: Rule) -> str:
    """The Sieve one Rule contributes to a script, byte for byte.

    Goes through the same `SieveGenerator.generate_entry` a save does, so a
    preview cannot say one thing and a save write another. Note what this does
    NOT include: the `require [...]` line, which is a property of the whole
    script rather than of any one Rule.
    """
    return SieveGenerator().generate_entry(rule)
