"""
Regression lock for the RawEditor empty-overwrite bug (areyousievious-8fg.20).

RawEditor could PUT an empty string over a real Script: on any non-401 load
failure the editor still rendered an empty textarea with Save enabled, and
SaveRawRequest.content accepted "" — so one click PUTSCRIPTed an empty
Script over the user's real one. The backend half of the fix: content is
required and must be non-empty, so the destructive path is closed even if a
future frontend regression re-opens the window.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from api_models import SaveRawRequest
from pydantic import ValidationError

# ── Model layer ──


def test_empty_content_is_rejected():
    with pytest.raises(ValidationError):
        SaveRawRequest(content="")


def test_omitted_content_is_rejected():
    """`content` must be required. With a default of "" the min_length guard
    would be skipped entirely — pydantic does not validate defaults."""
    with pytest.raises(ValidationError):
        SaveRawRequest()


def test_real_content_still_validates():
    assert SaveRawRequest(content="keep;\n").content == "keep;\n"


# ── Endpoint layer: the wire refuses to destroy a script ──


def test_put_raw_with_empty_content_is_422_and_never_dials(authed_client, sieve_client_passthrough):
    calls = []
    with patch.object(
        sieve_client_passthrough.SieveClient,
        "put_script",
        lambda self, n, c: calls.append((n, c)),
    ):
        with authed_client() as http:
            r = http.put("/api/scripts/primary/raw", json={"content": ""})
    assert r.status_code == 422, r.text
    assert calls == [], "an empty PUT must never reach the ManageSieve sink"


def test_put_raw_with_real_content_still_saves(authed_client, sieve_client_passthrough):
    calls = []
    with patch.object(
        sieve_client_passthrough.SieveClient,
        "put_script",
        lambda self, n, c: calls.append((n, c)),
    ):
        with authed_client() as http:
            r = http.put("/api/scripts/primary/raw", json={"content": "keep;\n"})
    assert r.status_code == 200, r.text
    assert calls == [("primary", "keep;\n")]
