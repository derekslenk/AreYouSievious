<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-22 -->

# test_scripts

## Purpose
The Sieve fixture corpus. These are not samples for reading — `tests/test_sieve_transform.py` parametrizes over every `*.sieve` file here and in `vendor/`, and asserts round-trip fidelity plus a pinned recognition census against each one.

## Layout
| Path | Description |
|------|-------------|
| `*.sieve` | Tier A: three scripts captured from real servers, plus twelve hand-written files holding one construct family each |
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
| `disabled-rules.sieve` | A `##`-commented rule. **Red on arrival** — see below |
| `multiple-requires.sieve` | Repeated `require` statements and a multi-line one. **Red on arrival** — see below |

## For AI Agents

### Working In This Directory
- Adding a `.sieve` file here automatically extends the parametrized suite. It must survive `parse -> generate` as a fixed point in both text and AST, AND be added to `RECOGNITION_CENSUS` in `../tests/test_sieve_transform.py` — an uncensused fixture fails on purpose
- Empty files are skipped (the collector filters on `st_size > 0`)
- When you hit a Sieve construct the parser mishandles, add the smallest fixture that reproduces it, then fix the parser — **do not adjust a fixture to match current behaviour**
- If the fix belongs to a bead you are not working, the fixture still lands truthful: register it in the `_corpus({...})` call of the tests it fails, with a reason naming the owning bead. Those pins are `xfail(strict=True)`, so the day the fix lands the XPASS fails the suite and the pin has to go. A pin cannot outlive its defect
- These files contain real addresses and folder names from the maintainer's mail. Do not add new fixtures carrying anyone else's PII; `tools/check-no-pii.sh` guards the fetch script but not this directory
- `vendor/` is third-party test data published under MIT and is out of scope for that rule, but it is not synthetic either: a handful of its addresses are the sievelib author's own (`tonio@ngyn.org`) or RFC 5228's examples. Copy it wholesale via the tool, never hand-pick lines out of it

### The two red fixtures
Both reproduce defects owned by **areyousievious-8fg.15**, and both are `xfail(strict=True)` today:

- `disabled-rules.sieve` — the name comment is emitted *inside* the block that then gets `## `-prefixed, so each save re-parses the name as `# --- name` and accretes one more marker. Three saves give `## # --- # --- # --- GitHub notifications ---`
- `multiple-requires.sieve` — the parser *assigns* `requires` per `require` line instead of extending, and reads only the first line of a multi-line `require`. `envelope`, `copy` and `reject` are gone after one pass, and the continuation lines come back as raw text emitted *after* the regenerated `require` — Sieve a real server refuses

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
