<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# test_scripts

## Purpose
Real-world Sieve scripts used as round-trip fixtures by the parser test suite. These are not samples for reading — `tests/test_sieve_transform.py` parametrizes over `*.sieve` and asserts fidelity against every one of them.

## Key Files
| File | Description |
|------|-------------|
| `grak.sieve` | The largest fixture — a real generated filter set (~5 KB). Exercises `anyof`/`allof`, multi-condition blocks, `redirect` + `keep` in one rule, and `# ---` name comments |
| `sogo.sieve` | Filter set exported from SOGo groupware. Single-condition `allof (...)` wrappers, which is the shape that must NOT collapse to `anyof` on round-trip |
| `roundcube.sieve` | A `/* empty script */` C-style comment and nothing else. The degenerate case: the parser must preserve it as a `RawBlock` rather than emitting an empty file |

## For AI Agents

### Working In This Directory
- Adding a `.sieve` file here automatically extends the parametrized round-trip suite. It must survive `parse -> generate` as a fixed point in both text and AST, so add a fixture only when you intend the parser to handle it
- Empty files are skipped (the collector filters on `st_size > 0`)
- When you hit a Sieve construct the parser mishandles, add the smallest fixture that reproduces it, then fix the parser — do not adjust a fixture to match current behaviour
- These files contain real addresses and folder names from the maintainer's mail. Do not add new fixtures carrying anyone else's PII; `tools/check-no-pii.sh` guards the fetch script but not this directory

## Dependencies

### Internal
- `../tests/test_sieve_transform.py` — the only consumer
- `../fetch_grak_script.py` — how these were captured from a live server

<!-- MANUAL: -->
