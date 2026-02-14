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

            # Comments - accumulate as potential rule name
            if line.startswith('#'):
                comment_text = line.lstrip('#').strip()
                # Skip decorator lines (=== --- etc.)
                if comment_text and not re.match(r'^[=\-\s]+$', comment_text):
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
        match = re.findall(r'"([^"]+)"', line)
        return match

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

    def _parse_if_block(self, comment: str) -> Rule:
        """Parse an if block into a Rule."""
        # Collect lines until matching closing brace
        block_lines = self._collect_block_lines()
        block_text = '\n'.join(block_lines)

        rule = Rule(name=comment)

        # Parse the condition part: if anyof/allof (...) { or if <single test> {
        cond_match = re.match(
            r'if\s+(anyof|allof)\s*\((.*?)\)\s*\{',
            block_text, re.DOTALL
        )
        if cond_match:
            rule.match = cond_match.group(1)
            tests_text = cond_match.group(2)
            rule.conditions = self._parse_tests(tests_text)
        else:
            # Single condition: if <test> {
            single_match = re.match(r'if\s+(.*?)\s*\{', block_text, re.DOTALL)
            if single_match:
                rule.match = "allof"
                rule.conditions = self._parse_tests(single_match.group(1))
            else:
                raise ParseError("Can't parse condition")

        if not rule.conditions:
            raise ParseError("No conditions parsed")

        # Parse the action part (between { and })
        action_match = re.search(r'\{(.*)\}', block_text, re.DOTALL)
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

    def _parse_tests(self, text: str) -> list[Condition]:
        """Parse condition tests from text."""
        conditions = []

        # Match patterns like:
        # address :contains "from" "something"
        # header :contains "subject" "something"
        # header :is "subject" "something"
        # address :is "from" "something"
        # address :matches "to" "something"
        pattern = r'(address|header)\s+:(contains|is|matches|regex)\s+"([^"]+)"\s+"([^"]*)"'

        for m in re.finditer(pattern, text):
            test_type, match_type, header_name, value = m.groups()
            conditions.append(Condition(
                header=header_name.lower(),
                match_type=match_type,
                value=value,
                address_test=(test_type == "address"),
            ))

        return conditions

    def _parse_actions(self, text: str) -> list[Action]:
        """Parse actions from the body of an if block."""
        actions = []

        # fileinto "Folder/Name";
        for m in re.finditer(r'fileinto\s+"([^"]+)"', text):
            actions.append(Action(action_type="fileinto", argument=m.group(1)))

        # fileinto :copy "Folder";
        for m in re.finditer(r'fileinto\s+:copy\s+"([^"]+)"', text):
            actions.append(Action(action_type="fileinto_copy", argument=m.group(1)))

        # redirect "address";
        for m in re.finditer(r'redirect\s+"([^"]+)"', text):
            actions.append(Action(action_type="redirect", argument=m.group(1)))

        # keep;
        if re.search(r'\bkeep\s*;', text):
            actions.append(Action(action_type="keep"))

        # discard;
        if re.search(r'\bdiscard\s*;', text):
            actions.append(Action(action_type="discard"))

        # stop;
        if re.search(r'\bstop\s*;', text):
            actions.append(Action(action_type="stop"))

        # addflag "\\Seen";
        for m in re.finditer(r'addflag\s+"([^"]+)"', text):
            actions.append(Action(action_type="addflag", argument=m.group(1)))

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
                parts.append(self._generate_rule(rule))
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
                if cond.address_test:
                    requires.add("envelope")

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

    def _generate_test(self, cond: Condition) -> str:
        test_type = "address" if cond.address_test else "header"
        neg = "not " if cond.negate else ""
        return f'{neg}{test_type} :{cond.match_type} "{cond.header}" "{cond.value}"'

    def _generate_action(self, action: Action) -> str:
        if action.action_type == "fileinto":
            return f'fileinto "{action.argument}";'
        elif action.action_type == "fileinto_copy":
            return f'fileinto :copy "{action.argument}";'
        elif action.action_type == "redirect":
            return f'redirect "{action.argument}";'
        elif action.action_type == "keep":
            return 'keep;'
        elif action.action_type == "discard":
            return 'discard;'
        elif action.action_type == "stop":
            return 'stop;'
        elif action.action_type == "addflag":
            return f'addflag "{action.argument}";'
        elif action.action_type == "reject":
            return f'reject "{action.argument}";'
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
        rule = Rule(
            id=r.get("id", ""),
            name=r.get("name", ""),
            enabled=r.get("enabled", True),
            match=r.get("match", "anyof"),
            conditions=[
                Condition(
                    header=c["header"],
                    match_type=c["match_type"],
                    value=c["value"],
                    address_test=c.get("address_test", False),
                    negate=c.get("negate", False),
                )
                for c in r.get("conditions", [])
            ],
            actions=[
                Action(action_type=a["type"], argument=a.get("argument", ""))
                for a in r.get("actions", [])
            ],
        )
        script.rules.append(rule)

    for rb in data.get("raw_blocks", []):
        script.raw_blocks.append(RawBlock(text=rb["text"], comment=rb.get("comment", "")))

    script.order = [tuple(x) for x in data.get("order", [])]

    return script


# ── Convenience ──

def parse_sieve(text: str) -> SieveScript:
    """Parse Sieve text into a SieveScript."""
    return SieveParser(text).parse()


def generate_sieve(script: SieveScript) -> str:
    """Generate Sieve text from a SieveScript."""
    return SieveGenerator().generate(script)
