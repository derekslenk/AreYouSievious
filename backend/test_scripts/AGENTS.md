<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-24 -->

# test_scripts

## Purpose
The Sieve fixture corpus. These are not samples for reading — `tests/test_sieve_transform.py` parametrizes over every `*.sieve` file here and in `vendor/`, and asserts round-trip fidelity plus a pinned recognition census against each one.

## Layout
| Path | Description |
|------|-------------|
| `*.sieve` | Tier A: three scripts captured from real servers, plus twenty hand-written files holding one construct family each |
| `vendor/*.sieve` | Tier B: sievelib's own parser corpus, vendored under MIT. A recogniser-reach benchmark, not a wish list |
| `vendor/LICENSE-sievelib` | Attribution and licence for everything under `vendor/` |

### Tier A — captured
| File | Description |
|------|-------------|
| `grak.sieve` | The largest fixture — a real generated filter set (~5 KB). Exercises `anyof`/`allof`, multi-condition blocks, `redirect` + `keep` in one rule, and `# ---` name comments |
| `sogo.sieve` | Filter set exported from SOGo groupware. Single-condition `allof (...)` wrappers, which is the shape that must NOT collapse to `anyof` on round-trip |
| `roundcube.sieve` | A `/* empty script */` C-style comment and nothing else. The degenerate case: the parser must preserve it as a `RawBlock` rather than emitting an empty file |

### Tier A — hand-written (areyousievious-8fg.3)
One construct family per file, so "what does the parser do with X" has a single file for an answer.

| File | Construct |
|------|-----------|
| `actions-all.sieve` | Every action the generator can emit: `fileinto`, `fileinto :copy`, `redirect`, `addflag`, `reject`, `keep`, `discard`, `stop` |
| `modifiers-address-part.sieve` | `:all`, `:localpart`, `:domain` on an address test |
| `modifiers-comparator.sieve` | `:comparator` on a header test and alongside an address part |
| `modifiers-either-order.sieve` | RFC 5228 §2.7.1 lets tagged arguments appear in any order; both orders must parse and normalise to one |
| `negation.sieve` | `not` on a lone test and on tests inside `allof` |
| `match-regex.sieve` | `:regex`, plain and negated, including a value carrying backslash escapes |
| `escaping.sieve` | `\"` and `\\` inside both a match value and a folder name |
| `layout-variants.sieve` | A whole rule on one line; tabs and run-on spacing |
| `raw-else-chain.sieve` | `if`/`elsif`/`else` — must land wholly in one `RawBlock`, never be merged into a single rule |
| `raw-unparseable-if.sieve` | An `envelope` test and a `size` test wrapping a nested `if` — must land in `RawBlock` without the nested body being half-eaten |
| `disabled-rules.sieve` | A `##`-commented rule, and the name that used to accrete a `# --- ` per save (`.15`) |
| `multiple-requires.sieve` | Repeated `require` statements and a multi-line one — both used to be lost before the first generation (`.15`) |
| `lexical-brace-in-a-string.sieve` | `fileinto "Weird{Folder";` — the brace that used to hold the block open and swallow the rule after it (`.10`) |
| `lexical-nested-if.sieve` | A nested block, which must reach `RawBlock` whole rather than have its inner condition dropped (`.10`) |
| `lexical-commented-action.sieve` | A commented-out action inside a live block, which must stay commented out (`.10`) |
| `modifiers-comparator-declared.sieve` | A collation outside the two RFC 5228 built-ins, so `require ["comparator-i;ascii-numeric"]` is mandatory. Red: **areyousievious-3o4** |
| `match-relational.sieve` | A `:value "gt"` relational test — unmodelled, so a `RawBlock`. Carries `i;ascii-casemap` DELIBERATELY: under `i;ascii-numeric` it lands in `UNREADABLE_BY_THE_ORACLE` for the same reason as the fixture above and the oracle never sees its relational-ness at all |
| `lexical-bracket-comment-scope.sieve` | A `/* */` comment whose scope crosses entries: live rule, commented-out rule, live rule. Documents **areyousievious-hr6**, and green since the parser learned bracketed comments |
| `bracketed-comment-between-rules.sieve` | A `/* ... */` between two live rules and another after the last one — the live rule below a comment used to be fused into the comment's `RawBlock` (`hr6`) |
| `bracketed-comment-at-file-start.sieve` | A `/* ... */` before anything else, which is where the preamble boundary is easiest to get wrong (`hr6`) |

## For AI Agents

### Working In This Directory
- Adding a `.sieve` file here automatically extends the parametrized suite. It must survive `parse -> generate` as a fixed point in both text and AST, AND be added to `RECOGNITION_CENSUS` in `../tests/test_sieve_transform.py` — an uncensused fixture fails on purpose
- Empty files are skipped (the collector filters on `st_size > 0`)
- Every fixture here must be LEXABLE — `tests/test_lexical_map.py::test_every_fixture_is_lexable` says so. The parser falls back to character counting for text sievelib's Lexer refuses, and a fixture on that path is silently exempt from the defects `.10` closes
- When you hit a Sieve construct the parser mishandles, add the smallest fixture that reproduces it, then fix the parser — **do not adjust a fixture to match current behaviour**
- If the fix belongs to a bead you are not working, the fixture still lands truthful: register it in the `corpus_params({...})` call (`tests/conftest.py`) of the tests it fails, with a reason naming the owning bead. Those pins are `xfail(strict=True)`, so the day the fix lands the XPASS fails the suite and the pin has to go. A pin cannot outlive its defect
- **A test that asserts a property over the WHOLE corpus in one assertion takes a named set, never an `xfail`.** `xfail` is per-param, and a test that is not parametrized has one param: the whole corpus. Marking it does not narrow the claim to your fixture — it switches the claim off for all of them, and the next fixture to regress does so in silence. Assert the exact known-failing set instead (`UNREADABLE_BY_THE_ORACLE` in `tests/test_ast_oracle.py`, `RULES_THE_ORACLE_REFUSES` in `tests/test_lexical_map.py`). That still cannot outlive the defect — fixing it empties the set and the mismatch names the entries to delete — and it fails differently, by name, if a different fixture regresses
- These files contain real addresses and folder names from the maintainer's mail. Do not add new fixtures carrying anyone else's PII; `tools/check-no-pii.sh` guards the fetch script but not this directory
- `vendor/` is third-party test data published under MIT and is out of scope for that rule, but it is not synthetic either: a handful of its addresses are the sievelib author's own (`tonio@ngyn.org`) or RFC 5228's examples. Copy it wholesale via the tool, never hand-pick lines out of it

### The fixtures that arrived red
`disabled-rules.sieve` and `multiple-requires.sieve` were added by `.3` reproducing defects
it did not own, and pinned `xfail(strict=True)` naming **areyousievious-8fg.15**. Both are
green now and the pins are gone — which is the mechanism working, not a coincidence: strict
means an unexpected PASS fails the suite, so a pin cannot outlive its defect.

Keep that pattern. A fixture that reproduces a defect belonging to another bead lands
truthful and pinned, never edited until it passes.

`modifiers-comparator-declared.sieve` is the current one, pinned to **areyousievious-3o4**
across five places — three as per-fixture `xfail(strict=True)`, and two as named sets
(`UNREADABLE_BY_THE_ORACLE` in `test_ast_oracle.py` and `RULES_THE_ORACLE_REFUSES` in
`test_lexical_map.py`), each asserting over the whole corpus in a single assertion. One root cause: sievelib's comparator whitelist holds `i;octet` and
`i;ascii-casemap` and nothing else, so it refuses `i;ascii-numeric` — and our pre-flight, our
round-trip validity oracle and our AST oracle all run through sievelib.

**sievelib parses a RELATIONAL test perfectly well.** Given `require ["relational"]`, both
`:value "gt"` and `:count "eq"` are fine; the collation alone defeats it. That is why
`match-relational.sieve` declares `i;ascii-casemap` and is GREEN: written with the numeric
collation it was red for the collation, not for being relational, so it bought a second copy
of the fixture above's coverage and gave the oracle no sight of a relational test at all. The
numeric-collation shape is still covered, at the unit level, by `_RELATIONAL_SPAM_SCORE` in
`tests/test_span_injection_guard.py`. A fixture must be red for its OWN shape or not at all.

`lexical-bracket-comment-scope.sieve` is green and is still evidence: our projection sees
three entries where sievelib sees two rules, because the commented-out rule between them is
one of ours. `/*` and `*/` land in SEPARATE entries, so reordering can move a rule into or
out of the commented region. That is **areyousievious-hr6**, pre-existing on main, and the
fixture is what makes it measurable rather than described.

### Regenerating `vendor/`
`vendor/` is produced mechanically from the installed sievelib, never edited by hand:

    python3 tools/vendor-sievelib-corpus.py

It takes only the scripts sievelib asserts valid (`compilation_ok`), skips the one that calls a command sievelib's test suite registers at run time, and copies `utf8_sieve.txt` as `utf8.sieve`. Re-running it after a sievelib upgrade will move `RECOGNITION_CENSUS` and `VENDOR_RULES_RECOGNISED`; re-measure rather than reverting.

## Dependencies

### Internal
- `../tests/test_sieve_transform.py` — the only consumer
- `../fetch_grak_script.py` — how the captured fixtures were pulled off a live server
- `../../tools/vendor-sievelib-corpus.py` — how `vendor/` is regenerated

### External
- `sievelib` (MIT) — source of the vendored corpus; see `vendor/LICENSE-sievelib`

<!-- MANUAL: -->
