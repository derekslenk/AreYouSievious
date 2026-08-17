#!/usr/bin/env python3
"""Dump the backend's OpenAPI schema to stdout.

The frontend generates its wire types from this (see frontend/package.json
`gen:types`), so the SPA and the DTOs cannot drift apart silently — which is
exactly what shipped a two-month HTTP 422 on every visual-editor save.

Note this calls `app.openapi()` directly rather than fetching /openapi.json.
The route is gated behind AYS_ENV=dev (app.py), but the method always works,
so codegen needs no server and no environment juggling.

Usage (from the repo root):
    python3 tools/dump-openapi.py > frontend/src/lib/openapi.json
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

# Keep the dump independent of whoever's shell it runs in: the schema must be a
# function of the code alone, or the regeneration guard produces spurious diffs.
os.environ.pop("AYS_ENV", None)

from app import app  # noqa: E402


def main() -> None:
    schema = app.openapi()
    # sort_keys so the committed artifact is stable across Python versions and
    # dict-ordering changes; a diff should mean the API moved, nothing else.
    json.dump(schema, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
