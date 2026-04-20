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
import uuid
from dataclasses import dataclass, field
from typing import Optional


# ── Pre-compiled Regex Patterns ──

# Parser patterns
_REQUIRE_PATTERN = re.compile(r'"([^"]+)"')
_DECORATOR_PATTERN = re.compile(r'^[=\-\s]+$')
_COND_ANYOF_ALLOF_PATTERN = re.compile(r'if\s+(anyof|allof)\s*\((.*?)\)\s*\{', re.DOTALL)
_COND_SINGLE_PATTERN = re.compile(r'if\s+(.*?)\s*\{', re.DOTALL)
_ACTION_BLOCK_PATTERN = re.compile(r'\{(.*)\}', re.DOTALL)

# Test patterns
_TEST_PATTERN = re.compile(
    r'(not\s+)?(address|header)\s+:(contains|is|matches|regex)\s+"([^"]*(?:\\.[^"]*)*)"\s+"([^"]*(?:\\.[^"]*)*)"'
)

# Action patterns (quoted string helper)
_QUOTED_STRING = r'"([^"]*(?:\\.[^"]*)*)"'
_FILEINTO_COPY_PATTERN = re.compile(rf'fileinto\s+:copy\s+{_QUOTED_STRING}')
_FILEINTO_PATTERN = re.compile(rf'fileinto\s+(?!:copy){_QUOTED_STRING}')
_REDIRECT_PATTERN = re.compile(rf'redirect\s+{_QUOTED_STRING}')
_KEEP_PATTERN = re.compile(r'\bkeep\s*;')
_DISCARD_PATTERN = re.compile(r'\bdiscard\s*;')
_STOP_PATTERN = re.compile(r'\bstop\s*;')
_ADDFLAG_PATTERN = re.compile(rf'addflag\s+{_QUOTED_STRING}')
_REJECT_PATTERN = re.compile(rf'reject\s+{_QUOTED_STRING}')


# ── Data Model ──

@dataclass
class Condition:
    header: str           # "from", "to", "subject", "cc", etc.
    match_type: str       # "contains", "is", "matches", "regex"
    value: str
    address_test: bool = False  # True = address test, False = header test
    negate: bool = False


@dataclass
class Action:
    action_type: str      # "fileinto", "redirect", "keep", "discard", "stop", "addflag"
    argument: str = ""    # folder name, address, flag value, etc.


@dataclass
class Rule:
    id: str = ""
    name: str = ""
    enabled: bool = True
    match: str = "anyof"  # "anyof", "allof"
    conditions: list[Condition] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]


@dataclass
class RawBlock:
    """Opaque Sieve text we don't parse into rules."""
    text: str
    comment: str = ""


@dataclass
class SieveScript:
    """Full parsed representation of a Sieve script."""
    requires: list[str] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    raw_blocks: list[RawBlock] = field(default_factory=list)
    # Interleaved order: list of ("rule", index) or ("raw", index)
    order: list[tuple[str, int]] = field(default_factory=list)


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
        self.lines = text.split('\n')
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
            if line.startswith('require'):
                script.requires = self._parse_require(line)
                self.line_idx += 1
                continue

            # Disabled rule (commented out with ## prefix) — check before comment handler
            if line.startswith('## '):
                disabled_rule = self._try_parse_disabled_block(pending_comment)
                if disabled_rule:
                    idx = len(script.rules)
                    script.rules.append(disabled_rule)
                    script.order.append(("rule", idx))
                    pending_comment = ""
                    continue
                # Not a disabled rule — fall through to comment handler

            # Comments - accumulate as potential rule name
            if line.startswith('#'):
                comment_text = line.lstrip('#').strip()
                # Skip decorator lines (=== --- etc.)
                if comment_text and not _DECORATOR_PATTERN.match(comment_text):
                    # Strip surrounding --- markers from comment names
                    clean = re.sub(r'^-+\s*', '', comment_text)
                    clean = re.sub(r'\s*-+$', '', clean)
                    pending_comment = clean.strip() or comment_text
                self.line_idx += 1
                continue

            # If/elsif/else block - try to parse as a rule
            if line.startswith('if ') or line.startswith('if\t'):
                rule = self._try_parse_rule(pending_comment)
                if rule:
                    self._auto_name_rule(rule)
                    idx = len(script.rules)
                    script.rules.append(rule)
                    script.order.append(("rule", idx))
                else:
                    # Couldn't parse - store as raw block
                    raw_text = self._consume_block()
                    idx = len(script.raw_blocks)
                    script.raw_blocks.append(RawBlock(text=raw_text, comment=pending_comment))
                    script.order.append(("raw", idx))
                pending_comment = ""
                continue

            # Anything else is a raw block
            raw_text = self.lines[self.line_idx]
            self.line_idx += 1
            idx = len(script.raw_blocks)
            script.raw_blocks.append(RawBlock(text=raw_text, comment=pending_comment))
            script.order.append(("raw", idx))
            pending_comment = ""

        return script

    def _parse_require(self, line: str) -> list[str]:
        """Parse: require ["fileinto", "envelope", "regex"];"""
        return _REQUIRE_PATTERN.findall(line)

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

    def _try_parse_rule(self, comment: str) -> Optional[Rule]:
        """Try to parse current position as a rule. Returns None if too complex."""
        start_line = self.line_idx
        try:
            rule = self._parse_if_block(comment)
            return rule
        except (ParseError, IndexError):
            # Reset and let caller handle as raw block
            self.line_idx = start_line
            return None

    def _try_parse_disabled_block(self, comment: str) -> Optional[Rule]:
        """Try to parse a ## commented-out block as a disabled rule."""
        start_line = self.line_idx
        # Peek ahead to see if there's an 'if' line in this ## block
        has_if = False
        peek = self.line_idx
        while peek < len(self.lines):
            stripped = self.lines[peek].strip()
            if not stripped.startswith('## ') and stripped != '##':
                break
            content = stripped[3:] if stripped.startswith('## ') else ''
            if content.startswith('if ') or content.startswith('if\t'):
                has_if = True
                break
            peek += 1
        if not has_if:
            return None
        # Collect all ## lines that form this disabled block
        disabled_lines = []
        while self.line_idx < len(self.lines):
            stripped = self.lines[self.line_idx].strip()
            if stripped.startswith('## '):
                disabled_lines.append(stripped[3:])
                self.line_idx += 1
            elif stripped == '##':
                disabled_lines.append('')
                self.line_idx += 1
            else:
                break
        if not disabled_lines:
            self.line_idx = start_line
            return None
        # Try to parse the uncommented text as a normal rule
        uncommented = '\n'.join(disabled_lines)
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
        block_text = '\n'.join(block_lines)

        rule = Rule(name=comment)

        # Parse the condition part: if anyof/allof (...) { or if <single test> {
        cond_match = _COND_ANYOF_ALLOF_PATTERN.match(block_text)
        if cond_match:
            rule.match = cond_match.group(1)
            tests_text = cond_match.group(2)
            rule.conditions = self._parse_tests(tests_text)
        else:
            # Single condition: if <test> {
            single_match = _COND_SINGLE_PATTERN.match(block_text)
            if single_match:
                rule.match = "allof"
                rule.conditions = self._parse_tests(single_match.group(1))
            else:
                raise ParseError("Can't parse condition")

        if not rule.conditions:
            raise ParseError("No conditions parsed")

        # Parse the action part (between { and })
        action_match = _ACTION_BLOCK_PATTERN.search(block_text)
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
            depth += line.count('{') - line.count('}')
            if '{' in line:
                started = True
            self.line_idx += 1
            if started and depth <= 0:
                break

        return lines

    @staticmethod
    def _unquote(s: str) -> str:
        """Unescape a Sieve quoted string (reverse of SieveGenerator._quote)."""
        return s.replace('\\"', '"').replace('\\\\', '\\')

    def _parse_tests(self, text: str) -> list[Condition]:
        """Parse condition tests from text."""
        conditions = []

        for m in _TEST_PATTERN.finditer(text):
            negate, test_type, match_type, header_name, value = m.groups()
            conditions.append(Condition(
                header=self._unquote(header_name).lower(),
                match_type=match_type,
                value=self._unquote(value),
                address_test=(test_type == "address"),
                negate=bool(negate),
            ))

        return conditions

    def _parse_actions(self, text: str) -> list[Action]:
        """Parse actions from the body of an if block."""
        actions = []

        # fileinto :copy "Folder";  (must check before plain fileinto)
        for m in _FILEINTO_COPY_PATTERN.finditer(text):
            actions.append(Action(action_type="fileinto_copy", argument=self._unquote(m.group(1))))

        # fileinto "Folder/Name";  (exclude :copy matches)
        for m in _FILEINTO_PATTERN.finditer(text):
            actions.append(Action(action_type="fileinto", argument=self._unquote(m.group(1))))

        # redirect "address";
        for m in _REDIRECT_PATTERN.finditer(text):
            actions.append(Action(action_type="redirect", argument=self._unquote(m.group(1))))

        # keep;
        if _KEEP_PATTERN.search(text):
            actions.append(Action(action_type="keep"))

        # discard;
        if _DISCARD_PATTERN.search(text):
            actions.append(Action(action_type="discard"))

        # stop;
        if _STOP_PATTERN.search(text):
            actions.append(Action(action_type="stop"))

        # addflag "\\Seen";
        for m in _ADDFLAG_PATTERN.finditer(text):
            actions.append(Action(action_type="addflag", argument=self._unquote(m.group(1))))

        # reject "message";
        for m in _REJECT_PATTERN.finditer(text):
            actions.append(Action(action_type="reject", argument=self._unquote(m.group(1))))

        return actions

    def _consume_block(self) -> str:
        """Consume lines for current block as raw text."""
        lines = self._collect_block_lines()
        return '\n'.join(lines)


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
            req_list = ', '.join(f'"{r}"' for r in requires)
            parts.append(f'require [{req_list}];')
            parts.append('')

        # Generate in order
        for kind, idx in script.order:
            if kind == "rule":
                rule = script.rules[idx]
                rule_text = self._generate_rule(rule)
                if not rule.enabled:
                    rule_text = '\n'.join(
                        '## ' + line if line.strip() else '##'
                        for line in rule_text.split('\n')
                    )
                parts.append(rule_text)
                parts.append('')
            elif kind == "raw":
                raw = script.raw_blocks[idx]
                if raw.comment:
                    parts.append(f'# {raw.comment}')
                parts.append(raw.text)
                parts.append('')

        return '\n'.join(parts).rstrip() + '\n'

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

        # Comment with rule name
        if rule.name:
            lines.append(f'# --- {rule.name.upper()} ---')

        # Conditions
        if len(rule.conditions) == 1:
            cond = rule.conditions[0]
            test_str = self._generate_test(cond)
            lines.append(f'if {test_str} {{')
        else:
            tests = []
            for cond in rule.conditions:
                tests.append(f'    {self._generate_test(cond)}')
            lines.append(f'if {rule.match} (')
            lines.append(',\n'.join(tests))
            lines.append(') {')

        # Actions
        for action in rule.actions:
            lines.append(f'    {self._generate_action(action)}')

        lines.append('}')
        return '\n'.join(lines)

    @staticmethod
    def _quote(s: str) -> str:
        """Escape a string for use inside Sieve double quotes."""
        return s.replace('\\', '\\\\').replace('"', '\\"')

    def _generate_test(self, cond: Condition) -> str:
        test_type = "address" if cond.address_test else "header"
        neg = "not " if cond.negate else ""
        return f'{neg}{test_type} :{cond.match_type} "{self._quote(cond.header)}" "{self._quote(cond.value)}"'

    def _generate_action(self, action: Action) -> str:
        arg = self._quote(action.argument)
        if action.action_type == "fileinto":
            return f'fileinto "{arg}";'
        elif action.action_type == "fileinto_copy":
            return f'fileinto :copy "{arg}";'
        elif action.action_type == "redirect":
            return f'redirect "{arg}";'
        elif action.action_type == "keep":
            return 'keep;'
        elif action.action_type == "discard":
            return 'discard;'
        elif action.action_type == "stop":
            return 'stop;'
        elif action.action_type == "addflag":
            return f'addflag "{arg}";'
        elif action.action_type == "reject":
            return f'reject "{arg}";'
        return f'# unknown action: {action.action_type}'


# ── JSON serialization ──

def script_to_json(script: SieveScript) -> dict:
    """Convert SieveScript to JSON-serializable dict."""
    return {
        "requires": script.requires,
        "rules": [
            {
                "id": r.id,
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
                    }
                    for c in r.conditions
                ],
                "actions": [
                    {"type": a.action_type, "argument": a.argument}
                    for a in r.actions
                ],
            }
            for r in script.rules
        ],
        "raw_blocks": [
            {"text": rb.text, "comment": rb.comment}
            for rb in script.raw_blocks
        ],
        "order": script.order,
    }


def json_to_script(data: dict) -> SieveScript:
    """Convert JSON dict back to SieveScript."""
    script = SieveScript(requires=data.get("requires", []))

    for r in data.get("rules", []):
        conditions = []
        for c in r.get("conditions", []):
            if not isinstance(c, dict) or "header" not in c or "match_type" not in c:
                continue
            conditions.append(Condition(
                header=c["header"],
                match_type=c["match_type"],
                value=c.get("value", ""),
                address_test=c.get("address_test", False),
                negate=c.get("negate", False),
            ))
        actions = []
        for a in r.get("actions", []):
            if not isinstance(a, dict) or "type" not in a:
                continue
            actions.append(Action(
                action_type=a["type"],
                argument=a.get("argument", ""),
            ))
        rule = Rule(
            id=r.get("id", ""),
            name=r.get("name", ""),
            enabled=r.get("enabled", True),
            match=r.get("match", "anyof"),
            conditions=conditions,
            actions=actions,
        )
        script.rules.append(rule)

    for rb in data.get("raw_blocks", []):
        if not isinstance(rb, dict):
            continue
        script.raw_blocks.append(RawBlock(
            text=rb.get("text", ""),
            comment=rb.get("comment", ""),
        ))

    # Validate order entries reference valid indices
    order = []
    for item in data.get("order", []):
        entry = tuple(item) if not isinstance(item, tuple) else item
        if len(entry) == 2:
            kind, idx = entry
            if kind == "rule" and 0 <= idx < len(script.rules):
                order.append(entry)
            elif kind == "raw" and 0 <= idx < len(script.raw_blocks):
                order.append(entry)
    # Fallback: if order is empty but we have rules/raw_blocks, generate default order
    if not order and (script.rules or script.raw_blocks):
        order = [("rule", i) for i in range(len(script.rules))]
        order += [("raw", i) for i in range(len(script.raw_blocks))]
    script.order = order

    return script


# ── Convenience ──

def parse_sieve(text: str) -> SieveScript:
    """Parse Sieve text into a SieveScript."""
    return SieveParser(text).parse()


def generate_sieve(script: SieveScript) -> str:
    """Generate Sieve text from a SieveScript."""
    return SieveGenerator().generate(script)
