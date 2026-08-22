"""
Bidirectional Sieve <-> JSON rule transform.

Parses Sieve scripts into structured JSON rules for UI editing,
and generates valid Sieve scripts from JSON rules.

Design principles:
- Lossless round-trip for supported constructs
- Unsupported/complex blocks preserved as raw Sieve text
- Comments preserved as rule names or raw blocks
"""

import re
from dataclasses import dataclass, field

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


@dataclass
class RawBlock:
    """An Entry the parser doesn't recognise, preserved verbatim."""

    text: str
    comment: str = ""


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

_PARTS = "|".join(ADDRESS_PARTS)

# Tagged arguments on a test. RFC 5228 lets ADDRESS-PART, COMPARATOR and
# MATCH-TYPE appear in any order, so the run of modifiers is captured as one
# blob and picked apart afterwards rather than pinned to a fixed sequence.
_MODIFIER_RUN = rf'(?P<mods>(?:\s+:(?:{_PARTS})|\s+:comparator\s+"(?:[^"\\]|\\.)*")*)'

_TEST_RE = re.compile(
    r"(?P<negate>not\s+)?"
    r"(?P<test_type>address|header)"
    + _MODIFIER_RUN
    + rf"\s+:(?P<match_type>{'|'.join(MATCH_TYPES)})"
    + rf"\s+{_Q('header')}"
    + rf"\s+{_Q('value')}"
)

_ADDRESS_PART_RE = re.compile(rf":({_PARTS})\b")
_COMPARATOR_RE = re.compile(r':comparator\s+"((?:[^"\\]|\\.)*)"')

# The test-list wrappers. `_parse_if_block` records Rule.match as one of these,
# or as "" for a bare `if <test> {` that carried no wrapper at all.
_MATCH_OPERATOR_RE = re.compile(rf"if\s+({'|'.join(MATCH_OPERATORS)})\s*\((.*?)\)\s*\{{", re.DOTALL)


# ── Parser (Sieve text -> SieveScript) ──


class SieveParser:
    """
    Hand-rolled parser because sievelib's AST is hard to work with
    for bidirectional transforms. We parse the common patterns we
    support and preserve everything else as raw blocks.
    """

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.lines = text.split("\n")
        self.line_idx = 0

    def parse(self) -> SieveScript:
        script = SieveScript()
        pending_comment = ""

        while self.line_idx < len(self.lines):
            line = self.lines[self.line_idx].strip()

            # Skip empty lines
            if not line:
                self.line_idx += 1
                continue

            # Require statement
            if line.startswith("require"):
                script.requires = self._parse_require(line)
                self.line_idx += 1
                continue

            # Disabled rule (commented out with ## prefix) — check before comment handler
            if line.startswith("## "):
                disabled_rule = self._try_parse_disabled_block(pending_comment)
                if disabled_rule:
                    script.entries.append(disabled_rule)
                    pending_comment = ""
                    continue
                # Not a disabled rule — fall through to comment handler

            # Comments - accumulate as potential rule name
            if line.startswith("#"):
                comment_text = line.lstrip("#").strip()
                # Skip decorator lines (=== --- etc.)
                if comment_text and not re.match(r"^[=\-\s]+$", comment_text):
                    # Strip surrounding --- markers from comment names
                    clean = re.sub(r"^-+\s*", "", comment_text)
                    clean = re.sub(r"\s*-+$", "", clean)
                    pending_comment = clean.strip() or comment_text
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

            # Anything else is a raw block
            raw_text = self.lines[self.line_idx]
            self.line_idx += 1
            script.entries.append(RawBlock(text=raw_text, comment=pending_comment))
            pending_comment = ""

        return script

    def _parse_require(self, line: str) -> list[str]:
        """Parse: require ["fileinto", "envelope", "regex"];"""
        match = re.findall(r'"([^"]+)"', line)
        return match

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

    def _try_parse_disabled_block(self, comment: str) -> Rule | None:
        """Try to parse a ## commented-out block as a disabled rule."""
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
        # Try to parse the uncommented text as a normal rule
        uncommented = "\n".join(disabled_lines)
        sub_parser = SieveParser(uncommented)
        sub_parser.line_idx = 0
        try:
            rule = sub_parser._parse_if_block(comment)
            rule.enabled = False
            self._auto_name_rule(rule)
            return rule
        except (ParseError, IndexError):
            self.line_idx = start_line
            return None

    def _parse_if_block(self, comment: str) -> Rule:
        """Parse an if block into a Rule."""
        # Collect lines until matching closing brace
        block_lines = self._collect_block_lines()
        block_text = "\n".join(block_lines)

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

    def _collect_block_lines(self) -> list[str]:
        """Collect lines from current if block including nested braces."""
        lines = []
        depth = 0
        started = False

        while self.line_idx < len(self.lines):
            line = self.lines[self.line_idx]
            lines.append(line)
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            self.line_idx += 1
            if started and depth <= 0:
                break

        return lines

    @staticmethod
    def _unquote(s: str) -> str:
        """Unescape a Sieve quoted string (reverse of SieveGenerator._quote)."""
        return s.replace('\\"', '"').replace("\\\\", "\\")

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
            mods = m.group("mods") or ""
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
        """Consume lines for current block as raw text."""
        lines = self._collect_block_lines()
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
        text = self._generate_rule(rule)
        if rule.enabled:
            return text
        # A disabled Rule is stored commented out.
        return "\n".join("## " + line if line.strip() else "##" for line in text.split("\n"))

    def _compute_requires(self, script: SieveScript) -> list[str]:
        """Compute required extensions from rules."""
        requires = set(script.requires)

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
                # address test is core Sieve, no require needed

        return sorted(requires)

    def _generate_rule(self, rule: Rule) -> str:
        lines = []

        # Comment with rule name. Emitted verbatim — `.upper()` here meant a
        # user's "GitHub notifications" came back as "GITHUB NOTIFICATIONS"
        # after a single save, permanently, because the comment is the only
        # place the name is stored.
        if rule.name:
            lines.append(f"# --- {rule.name} ---")

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
    }


def script_to_json(script: SieveScript) -> dict:
    """Convert SieveScript to a JSON-serializable dict.

    Pure: the same SieveScript always produces the same dict. Nothing is minted
    here (see docs/adr/0001-identity-is-view-state.md), so tests can assert exact
    payloads.
    """
    return {
        "requires": script.requires,
        "entries": [
            _rule_to_json(e)
            if isinstance(e, Rule)
            else {"kind": "raw", "text": e.text, "comment": e.comment}
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
    )


def json_to_script(data: dict) -> SieveScript:
    """Convert a JSON dict back to a SieveScript.

    Ordering comes from position in `entries`, so there is no index to validate
    and no way for a caller to submit an order that omits one of its own rules.
    The previous representation could, and silently dropped the omitted rule on
    save.
    """
    script = SieveScript(requires=data.get("requires", []))

    for e in data.get("entries", []):
        if not isinstance(e, dict):
            continue
        if e.get("kind") == "raw":
            script.entries.append(RawBlock(text=e.get("text", ""), comment=e.get("comment", "")))
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


def generate_rule(rule: Rule) -> str:
    """The Sieve one Rule contributes to a script, byte for byte.

    Goes through the same `SieveGenerator.generate_entry` a save does, so a
    preview cannot say one thing and a save write another. Note what this does
    NOT include: the `require [...]` line, which is a property of the whole
    script rather than of any one Rule.
    """
    return SieveGenerator().generate_entry(rule)
