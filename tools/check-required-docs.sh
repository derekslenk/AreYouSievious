#!/bin/sh
set -eu
[ -f SECURITY.md ] || { echo "missing SECURITY.md" >&2; exit 1; }
[ -f CHANGELOG.md ] || { echo "missing CHANGELOG.md" >&2; exit 1; }
grep -q "## Reporting" SECURITY.md || { echo "SECURITY.md missing '## Reporting' section" >&2; exit 1; }
grep -q "Keep a Changelog" CHANGELOG.md || { echo "CHANGELOG.md missing 'Keep a Changelog' reference" >&2; exit 1; }
echo "OK"
