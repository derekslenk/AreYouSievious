#!/bin/sh
# Regenerate the frontend's wire types from the backend's OpenAPI schema.
#
# Runs as a pre-commit hook whenever a backend file that can change the schema
# is staged. pre-commit compares the worktree before and after, so if the
# committed artifacts were stale it reports "files were modified by this hook"
# and you re-stage — the same flow as ruff-format.
#
# The point is to move the failure off CI and onto the machine making the
# change. The CI `contract` job is the backstop for anyone who has not run
# `pre-commit install`, since hooks are opt-in per clone.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d frontend/node_modules ]; then
    echo "regen-wire-types: frontend/node_modules is missing — skipping." >&2
    echo "  Run 'cd frontend && npm ci' to enable this hook locally." >&2
    echo "  CI's contract job still verifies the artifacts either way." >&2
    exit 0
fi

# Drop cached bytecode before importing the app. CPython invalidates .pyc files
# on (mtime, size) with ONE-SECOND mtime granularity, so an edit landing in the
# same second as a previous compile is not detected — and a same-size edit
# (`max_length=80` -> `max_length=82`) does not move the size either. Observed
# in practice: the schema regenerated from code that no longer existed on disk.
# The backend is small, so recompiling costs milliseconds and buys certainty.
find backend -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

cd frontend
PYTHONDONTWRITEBYTECODE=1 npm run --silent gen:types
