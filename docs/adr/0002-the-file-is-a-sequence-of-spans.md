# 2. The file is a sequence of spans

Date: 2026-08-23

## Status

Accepted. Implements areyousievious-8fg.14.

## Context

We edit filter files we did not write, on servers we do not own. Opening a
SOGo-authored script and changing one Rule rewrote every Rule in the file into
our house style, because generation was the only path.
`backend/test_scripts/sogo.sieve` is that case: 14 Rules, every one of them
reformatted by a save that touched one.

Roundcube was the other name here, and it is the wrong example.
`backend/test_scripts/roundcube.sieve` parses to no Rule at all — a single
whole-file `RawBlock` — so there was never a Rule in it for a save to reformat.
The Known Limitations section of `docs/ARCHITECTURE.md` records that same
split across the corpus.

The obvious fix — mark edited Rules dirty — does not survive contact with the
data model. `Rule` carries no identity (ADR 0001), so a flag has nothing
durable to hang on, can be bypassed by direct mutation, and marks a field
changed-and-changed-back as dirty.

## Decision

Parsing decomposes the file into

    file = preamble + requires_source + Σ entry.source + tail

where every byte belongs to exactly one term. Each entry's span includes the
blank lines and comments immediately above it, so a reordered Rule takes its
`# --- name ---` with it. Content before the first span is an immovable file
preamble.

Generation has two paths per entry and no third: re-emit `source` byte for
byte, or render canonically. Which one is chosen by re-parsing the span and
comparing the result to the entry by value. The span IS the pristine copy, so
dirtiness is a comparison rather than a flag, and the comparison is made
where the bytes are written rather than where they are edited.

`source` crosses the wire. A client could therefore propose any bytes — so
the verbatim path re-parses what it is given and refuses it unless the span
yields exactly one entry, no requires, no preamble and no tail, and that entry
is value-equal to the one submitted. One shape needs its own reading of that
rule: a span that IS a `require` statement and nothing else, which the parser
makes an entry in its own right whenever something already stands above it
(a bracketed comment, a `## ` disabled Rule). Read in isolation such a span
lands in the requires slot rather than coming back as an entry, so it is
re-parsed with a statement in front of it — the position it came from — and
then held to the same four conditions and the same value equality
(areyousievious-3xk). The worst a hostile client can do is
choose alternate formatting of a rule whose meaning it already controls, which
is strictly less than the existing verbatim `RawBlock.text` path already
allows. The guard fails closed: any doubt regenerates.

## Consequences

- Parse and re-save with no edits is byte-identical. The old
  `generate(parse(x))` property could not express this and passed vacuously on
  anything unrecognised.
- Edited Rules still reformat into house style. That is disclosed by
  construction: the preview endpoint shows the text a Rule takes ONCE IT IS
  EDITED. That is not the text every save writes — a Rule left alone is
  re-emitted from its own span and never reaches the generator — and it is the
  more useful thing to show, because the reformatting is precisely what the
  user has not committed to yet.
- `require` pruning (areyousievious-8fg.15) now happens only on a save that
  actually regenerates something. An untouched over-declared `require` line
  survives, because rewriting it would break the byte-identical property for a
  file we were not asked to change.
