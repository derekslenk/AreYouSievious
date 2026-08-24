# 2. The file is a sequence of spans

Date: 2026-08-23

## Status

Accepted. Implements areyousievious-8fg.14.

## Context

We edit filter files we did not write, on servers we do not own. Opening a
Roundcube- or SOGo-authored script and changing one Rule rewrote every Rule
in the file into our house style, because generation was the only path.

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
is value-equal to the one submitted. The worst a hostile client can do is
choose alternate formatting of a rule whose meaning it already controls, which
is strictly less than the existing verbatim `RawBlock.text` path already
allows. The guard fails closed: any doubt regenerates.

## Consequences

- Parse and re-save with no edits is byte-identical. The old
  `generate(parse(x))` property could not express this and passed vacuously on
  anything unrecognised.
- Edited Rules still reformat into house style. That is disclosed by
  construction: the preview endpoint shows the exact text before a save.
- `require` pruning (areyousievious-8fg.15) now happens only on a save that
  actually regenerates something. An untouched over-declared `require` line
  survives, because rewriting it would break the byte-identical property for a
  file we were not asked to change.
