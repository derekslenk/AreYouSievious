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

from unittest.mock import MagicMock

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


def test_put_raw_with_empty_content_never_reaches_the_sink(authed_client):
    """The destructive path is closed at the model, before any write.

    This proves `put_script` is never CALLED. It does not prove nothing is
    dialled: since `.7` the store is a dependency, and FastAPI resolves
    dependencies before it validates the body, so the real adapter opens a
    connection even for a request that 422s. That cost is tracked separately
    — see the `.7` follow-up bead — and is invisible here because this test
    substitutes the store.
    """
    store = MagicMock()
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/primary/raw", json={"content": ""})
    assert r.status_code == 422, r.text
    store.put_script.assert_not_called()


def test_put_raw_with_real_content_still_saves(authed_client):
    store = MagicMock()
    with authed_client(script_store=store) as http:
        r = http.put("/api/scripts/primary/raw", json={"content": "keep;\n"})
    assert r.status_code == 200, r.text
    store.put_script.assert_called_once_with("primary", "keep;\n")
