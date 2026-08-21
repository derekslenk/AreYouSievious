"""
The mail-server seams and the error vocabulary they fail in
(areyousievious-8fg.5).

Two things are pinned here:

  1. The semantic errors are protocol-free and HTTP-free. Adapters translate
     ManageSieve/IMAP failures INTO them; app.py translates them OUT to a
     status code, in exactly one table.
  2. That translation works through the REAL stack — a router with no
     try/except, an app-level handler, one status per semantic failure. This
     is what lets `.6`'s adapters stop discarding errcode/errmsg without
     every router growing its own except block.
"""

from __future__ import annotations

import pytest
from app import _MAIL_ERROR_STATUS, _status_for
from mail_errors import (
    AuthFailed,
    MailServerUnavailable,
    MailStoreError,
    QuotaExceeded,
    ScriptNotFound,
    ScriptRejected,
)
from mail_stores import FolderStore, ScriptStore

from tests.fakes import FakeScriptStore

# The vocabulary, and the status each failure means to a client.
ERROR_STATUS = [
    (ScriptNotFound, 404),
    (ScriptRejected, 400),
    (QuotaExceeded, 507),
    (MailServerUnavailable, 502),
    (AuthFailed, 401),
]

# ── The vocabulary itself ──


@pytest.mark.parametrize("error_type,_status", ERROR_STATUS)
def test_every_error_is_a_mail_store_error(error_type, _status):
    """One base, so a caller that wants "any seam failure" can say so."""
    assert issubclass(error_type, MailStoreError)


@pytest.mark.parametrize("error_type,_status", ERROR_STATUS)
def test_bare_raise_carries_a_safe_default_message(error_type, _status):
    """str(exc) reaches the client, so a bare raise must not produce an empty
    body — and must not require the adapter to invent wording."""
    assert str(error_type()).strip()


def test_script_rejected_carries_its_reason():
    """The one error with a payload: the server said WHY it refused."""
    exc = ScriptRejected("line 3: unknown command 'fileintoo'")
    assert exc.reason == "line 3: unknown command 'fileintoo'"
    assert "fileintoo" in str(exc)


@pytest.mark.parametrize("empty", [None, ""], ids=["none", "empty-string"])
def test_script_rejected_reason_and_message_never_disagree(empty):
    """An empty reason must read as "nothing to relay" BOTH ways.

    Without normalising, ScriptRejected("") gave the safe default from
    str(exc) while .reason stayed "" — two readings of one error saying
    different things. `.6` passes sievelib's errmsg straight in here, which
    is exactly where an empty string comes from.
    """
    exc = ScriptRejected(empty)
    assert exc.reason is None
    assert str(exc) == ScriptRejected.default_detail


@pytest.mark.parametrize("error_type,_status", ERROR_STATUS)
def test_errors_carry_no_http_status(error_type, _status):
    """Protocol-free by construction. A status living on the semantic type is
    what lets two sinks answer differently for the same failure — the mapping
    belongs in app.py's one table."""
    assert not hasattr(error_type, "status_code")


# ── The mapping table ──


@pytest.mark.parametrize("error_type,status", ERROR_STATUS)
def test_status_table_maps_every_error(error_type, status):
    assert _MAIL_ERROR_STATUS[error_type] == status


def test_no_semantic_error_is_left_unmapped():
    """Adding an error type without giving it a status is the bug this
    catches — it would otherwise surface as a silent 502."""
    defined = {
        t
        for t in vars(__import__("mail_errors")).values()
        if isinstance(t, type) and issubclass(t, MailStoreError) and t is not MailStoreError
    }
    assert defined == set(_MAIL_ERROR_STATUS), (
        f"unmapped: {sorted(t.__name__ for t in defined - set(_MAIL_ERROR_STATUS))}"
    )


def test_unclassified_mail_failure_falls_back_to_502():
    """A bare MailStoreError is still a mail-server failure, not a 500."""
    assert _status_for(MailStoreError()) == 502


def test_most_derived_mapping_wins():
    """MRO order, not table order, decides — so a future subclass of a mapped
    error keeps its parent's status until it is given its own."""

    class TransientlyUnavailable(MailServerUnavailable):
        pass

    assert _status_for(TransientlyUnavailable()) == 502


# ── Through the real stack ──


@pytest.mark.parametrize("error_type,status", ERROR_STATUS)
def test_adapter_failure_reaches_the_client_as_its_status(authed_client, error_type, status):
    """A store raises in domain terms; the client sees the right status.

    GET /api/scripts carries no try/except, so this is the app-level handler
    doing the whole job. If a router grows one, the status stops coming from
    the table and this says so.

    The store is SUBSTITUTED, not patched: `.7` made the seam a dependency,
    so a test hands the router a different object rather than reaching into
    SieveClient's internals.

    Note this pins propagation, not the absence of try/except — `auth.py`
    still hand-maps `imaplib.IMAP4.error` to 401 and bare `Exception` to 502.
    Retiring that is `.26`.
    """
    store = FakeScriptStore()
    store.reject_next(error_type("upstream said no"))
    with authed_client(script_store=store) as http:
        r = http.get("/api/scripts")
    assert r.status_code == status, r.text
    assert r.json()["detail"] == "upstream said no"


def test_handler_is_registered_on_the_base_class_only_once():
    """One registration covers the whole vocabulary — Starlette resolves a
    handler by walking the exception's MRO."""
    from app import create_app

    app = create_app()
    registered = set(app.exception_handlers)
    assert MailStoreError in registered
    for error_type, _status in ERROR_STATUS:
        assert error_type not in registered, (
            f"{error_type.__name__} has its own handler; the base-class "
            "registration already covers it"
        )


# ── The seams ──


def _operations(protocol: type) -> set[str]:
    """The operations a seam declares.

    Read from the class body rather than `__protocol_attrs__`, which is a
    CPython internal that only became an attribute in 3.12.
    """
    return {name for name in vars(protocol) if not name.startswith("_")}


def test_script_store_names_the_five_script_operations():
    assert _operations(ScriptStore) == {
        "list_scripts",
        "get_script",
        "put_script",
        "activate_script",
        "delete_script",
    }


def test_folder_store_names_the_two_folder_operations():
    assert _operations(FolderStore) == {"list_folders", "create_folder"}


def test_seams_stay_separate():
    """A single seven-operation MailStore would be a union, not an
    abstraction — no caller wants both halves."""
    assert not _operations(ScriptStore) & _operations(FolderStore)


def test_neither_seam_is_runtime_checkable():
    """isinstance against a Protocol compares method NAMES only. It cannot
    see a return type, and it cannot see whether an operation raises on
    failure or swallows it — which is the entire substance of this contract.
    A green check that proves none of it would license the wrong refactor."""
    assert not getattr(ScriptStore, "_is_runtime_protocol", False)
    assert not getattr(FolderStore, "_is_runtime_protocol", False)


@pytest.mark.parametrize(
    "seam,implementation",
    [
        (ScriptStore, "managesieve_client.SieveClient"),
        (FolderStore, "imap_client.IMAPClient"),
        (ScriptStore, "tests.fakes.FakeScriptStore"),
        (FolderStore, "tests.fakes.FakeFolderStore"),
    ],
    ids=["SieveClient", "IMAPClient", "FakeScriptStore", "FakeFolderStore"],
)
def test_every_implementation_offers_the_whole_seam(seam, implementation):
    """The seam describes what already exists, so `.7` can inject the shipped
    adapter and `.8` can substitute a fake without either changing a router.
    Both live here, because a fake that drifts from the interface makes every
    test using it prove something the real adapter does not do.

    Method presence only, and claiming no more: this module refuses
    `runtime_checkable` precisely because names cannot show whether failure
    raises. That the adapters raise is pinned in test_adapter_failures.py
    (`.6`); that the fakes do is pinned in test_save_path.py (`.8`).
    """
    module_name, _, class_name = implementation.rpartition(".")
    module = __import__(module_name, fromlist=[class_name])
    impl = getattr(module, class_name)
    for op in _operations(seam):
        assert callable(getattr(impl, op, None)), f"{class_name} lacks {op}"
