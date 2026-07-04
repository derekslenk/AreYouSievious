#!/usr/bin/env node
// Bundle-size regression gate for bp8 (Vite code-split SPA).
//
// Asserts the SPA's main entry chunk — the JS file referenced directly by
// <script type="module" src="..."> in dist/index.html — stays under
// THRESHOLD_RATIO of the recorded pre-bp8 BASELINE_BYTES.
//
// Pre-bp8 baseline (recorded 2026-06-21, vite 8.0.16, svelte 5.56.3):
//   dist/assets/index-B9t9sqh-.js = 109774 bytes  (single chunk, all routes)
//   gzip: 38.66 kB
//   Build cmd: `npm run build`
//
// Threshold: main entry must drop to < 70% of baseline (≥ 30% reduction).
// Goal: pull non-landing routes (Dashboard, RuleEditor, RawEditor, Privacy)
// and the Svelte vendor runtime out of the initial-paint payload via
// Vite manualChunks + Svelte {#await import()} dynamic imports.
//
// Usage:
//   npm run build && node scripts/check-bundle-size.mjs
// Exit 0 on PASS, 1 on FAIL.

import { readFileSync, statSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FRONTEND_ROOT = resolve(__dirname, '..');
const DIST_DIR = resolve(FRONTEND_ROOT, 'dist');
const INDEX_HTML = resolve(DIST_DIR, 'index.html');

// Pre-bp8 single-bundle baseline. DO NOT update casually; updating this
// number weakens the regression gate.
const BASELINE_BYTES = 109774;
const THRESHOLD_RATIO = 0.7; // main entry must be < 70% of baseline

function die(msg) {
  console.error(`\x1b[31m[bundle-size FAIL]\x1b[0m ${msg}`);
  process.exit(1);
}

function ok(msg) {
  console.log(`\x1b[32m[bundle-size PASS]\x1b[0m ${msg}`);
}

let html;
try {
  html = readFileSync(INDEX_HTML, 'utf8');
} catch (e) {
  die(`cannot read ${INDEX_HTML} — did you run \`npm run build\` first? (${e.code || e.message})`);
}

// Match the entry: <script type="module" ... src="/assets/index-XXXX.js"></script>
// crossorigin attr ordering varies; tolerate it.
const entryMatch = html.match(/<script[^>]*\bsrc=["']\/assets\/([^"']+\.js)["']/);
if (!entryMatch) {
  die(`could not locate <script type="module" src="/assets/...js"> in ${INDEX_HTML}`);
}
const entryName = entryMatch[1];
const entryPath = resolve(DIST_DIR, 'assets', entryName);

let entrySize;
try {
  entrySize = statSync(entryPath).size;
} catch (e) {
  die(`entry chunk referenced by index.html is missing: ${entryPath} (${e.code || e.message})`);
}

const thresholdBytes = Math.floor(BASELINE_BYTES * THRESHOLD_RATIO);
const reductionPct = ((BASELINE_BYTES - entrySize) / BASELINE_BYTES) * 100;

console.log('');
console.log(`  baseline:   ${BASELINE_BYTES.toLocaleString()} bytes  (pre-bp8 single-bundle build)`);
console.log(`  entry now:  ${entrySize.toLocaleString()} bytes  (${entryName})`);
console.log(`  threshold:  ${thresholdBytes.toLocaleString()} bytes  (${THRESHOLD_RATIO * 100}% of baseline)`);
console.log(`  reduction:  ${reductionPct.toFixed(1)}%`);
console.log('');

if (entrySize >= thresholdBytes) {
  die(
    `main entry chunk \`${entryName}\` is ${entrySize.toLocaleString()} bytes ` +
      `(${(100 - THRESHOLD_RATIO * 100).toFixed(0)}%+ reduction required). ` +
      `Got ${reductionPct.toFixed(1)}% reduction; need ≥ ${((1 - THRESHOLD_RATIO) * 100).toFixed(0)}%.`,
  );
}

ok(
  `main entry \`${entryName}\` = ${entrySize.toLocaleString()} bytes ` +
    `(${reductionPct.toFixed(1)}% under baseline, threshold ${(THRESHOLD_RATIO * 100).toFixed(0)}%).`,
);
