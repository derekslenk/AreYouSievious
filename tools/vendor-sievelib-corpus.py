#!/usr/bin/env python3
"""Re-vendor sievelib's parser corpus into backend/test_scripts/vendor/.

sievelib is already a runtime dependency and is MIT-licensed, so its test
corpus can be copied with attribution (backend/test_scripts/vendor/
LICENSE-sievelib). It is vendored rather than imported at test time because a
benchmark whose contents move when a dependency upgrades measures nothing.

Only the scripts sievelib asserts are VALID (`compilation_ok`) are taken. The
`compilation_ko` half is deliberately malformed Sieve; every one of those would
land in a RawBlock and pin the reach benchmark with noise. `AdditionalCommands`
is skipped too — its script calls `mytest`, a command sievelib's own test suite
registers at run time, so it is not Sieve any server would accept.

Run from the repo root:
    python3 tools/vendor-sievelib-corpus.py

Then re-measure: the per-file pins in RECOGNITION_CENSUS and the
VENDOR_RULES_RECOGNISED total in backend/tests/test_sieve_transform.py are
expected to change whenever the corpus does.
"""

from __future__ import annotations

import ast
import collections
import pathlib
import re
import sys
import textwrap

DEST = pathlib.Path(__file__).resolve().parent.parent / "backend" / "test_scripts" / "vendor"


def _sievelib_tests() -> pathlib.Path:
    import sievelib

    return pathlib.Path(sievelib.__file__).resolve().parent / "tests"


def _module_constants(tree: ast.Module) -> dict[str, str | bytes]:
    """Module-level string constants, so `compilation_ok(some_sieve)` resolves."""
    found: dict[str, str | bytes] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
            continue
        if not isinstance(node.value.value, str | bytes):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                found[target.id] = node.value.value
    return found


def _valid_scripts(source: str) -> list[tuple[str, str]]:
    """Every `compilation_ok(<literal>)` in test_parser.py, as (method, script)."""
    tree = ast.parse(source)
    constants = _module_constants(tree)
    scripts: list[tuple[str, str]] = []

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.cls: str | None = None
            self.fn: str | None = None

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            outer, self.cls = self.cls, node.name
            self.generic_visit(node)
            self.cls = outer

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            outer, self.fn = self.fn, node.name
            self.generic_visit(node)
            self.fn = outer

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name == "compilation_ok" and node.args and self.cls != "AdditionalCommands":
                arg = node.args[0]
                value: str | bytes | None = None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str | bytes):
                    value = arg.value
                elif isinstance(arg, ast.Name):
                    value = constants.get(arg.id)
                if value is not None:
                    text = value.decode("utf-8") if isinstance(value, bytes) else value
                    scripts.append((self.fn or "script", text))
            self.generic_visit(node)

    Visitor().visit(tree)
    return scripts


def main() -> int:
    tests = _sievelib_tests()
    DEST.mkdir(parents=True, exist_ok=True)
    for stale in DEST.glob("*.sieve"):
        stale.unlink()

    # `utf8` is claimed up front: it is written after this loop, so a test method
    # that slugified to the same stem would otherwise be silently overwritten by
    # it. Claiming it here makes that collision come out as `utf8-2` instead.
    seen: collections.Counter[str] = collections.Counter({"utf8": 1})
    for method, text in _valid_scripts((tests / "test_parser.py").read_text()):
        body = textwrap.dedent(text).lstrip("\n")
        if not body.endswith("\n"):
            body += "\n"
        stem = re.sub(r"[^a-z0-9]+", "-", re.sub(r"^test_", "", method).lower()).strip("-")
        seen[stem] += 1
        name = stem if seen[stem] == 1 else f"{stem}-{seen[stem]}"
        (DEST / f"{name}.sieve").write_text(body)

    (DEST / "utf8.sieve").write_text((tests / "files" / "utf8_sieve.txt").read_text())

    print(f"vendored {len(list(DEST.glob('*.sieve')))} scripts into {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
