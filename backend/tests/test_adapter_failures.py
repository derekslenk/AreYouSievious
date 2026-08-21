"""
The adapters stop discarding failures (areyousievious-8fg.6).

Every case below was verified to lose information silently before this
change: sievelib reports failure by RETURNING a falsy value and parking the
reason on its public `errcode` / `errmsg`, and the adapters read neither. The
worst of them answered `200 {ok: true}` to a script the server had refused to
compile.

The reasons were always there. `errcode` carries RFC 5804 response codes and
`errmsg` carries the server's own text — for a bad script, the Sieve
compiler's diagnostic.
"""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import mail_dial
import pytest
from auth import Session
from imap_client import IMAPClient
from mail_errors import (
    AuthFailed,
    FolderRejected,
    MailServerUnavailable,
    MailStoreError,
    QuotaExceeded,
    ScriptNotFound,
    ScriptRejected,
)
from managesieve_client import SieveClient


def _session() -> Session:
    return Session(
        token="t",
        host="mail.example.com",
        host_ip="93.184.216.34",
        port_imap=993,
        port_sieve=4190,
        username="user@example.com",
        password="hunter2",
        created_at=0.0,
        last_used=0.0,
    )


def _as(adapter: SieveClient, sievelib_client) -> SieveClient:
    """Enter the REAL adapter with a stubbed sievelib client underneath.

    Patching `__enter__` rather than the class keeps every translation path
    under test — a full mock of SieveClient would swallow the very code these
    tests exist to exercise.
    """
    adapter._client = sievelib_client
    return adapter


def _sieve(**client_attrs) -> SieveClient:
    """A SieveClient whose sievelib client fails the way the server would."""
    client = SieveClient(_session())
    client._client = MagicMock(**client_attrs)
    return client


# ── The script sink: a falsy return is a failure, and it says why ──


def test_put_script_surfaces_the_compilers_own_diagnostic():
    """The headline defect. sievelib returned False, the adapter dropped it,
    and the route answered 200 {ok: true} for a script the server refused."""
    client = _sieve(
        putscript=MagicMock(return_value=False),
        errcode=b"",
        errmsg=b"line 4: unknown command 'vacation'",
    )
    with pytest.raises(ScriptRejected) as caught:
        client.put_script("filters", "vacation :days 1;")
    assert caught.value.reason == "line 4: unknown command 'vacation'"


@pytest.mark.parametrize(
    "errcode,expected",
    [
        (b"NONEXISTENT", ScriptNotFound),
        (b"QUOTA", QuotaExceeded),
        # RFC 5804 §1.3 refines QUOTA — the leading token is what classifies it
        (b"QUOTA/MAXSCRIPTS", QuotaExceeded),
        (b"QUOTA/MAXSIZE", QuotaExceeded),
        (b"ALREADYEXISTS", ScriptRejected),
        (b"ACTIVE", ScriptRejected),
        (b"TRYLATER", MailServerUnavailable),
    ],
    ids=lambda v: v.decode() if isinstance(v, bytes) else v.__name__,
)
def test_response_code_classifies_the_failure(errcode, expected):
    client = _sieve(putscript=MagicMock(return_value=False), errcode=errcode, errmsg=b"nope")
    with pytest.raises(expected):
        client.put_script("filters", "keep;")


def test_unknown_response_code_does_not_masquerade_as_a_known_one():
    client = _sieve(
        putscript=MagicMock(return_value=False), errcode=b"WHAT-IS-THIS", errmsg=b"nope"
    )
    with pytest.raises(ScriptRejected):
        client.put_script("filters", "keep;")


@pytest.mark.parametrize(
    "op,args",
    [
        ("activate_script", ("filters",)),
        ("delete_script", ("filters",)),
    ],
)
def test_activate_and_delete_report_a_missing_script(op, args):
    client = _sieve(
        setactive=MagicMock(return_value=False),
        deletescript=MagicMock(return_value=False),
        errcode=b"NONEXISTENT",
        errmsg=b"no such script",
    )
    with pytest.raises(ScriptNotFound):
        getattr(client, op)(*args)


def test_get_script_missing_is_not_an_attribute_error():
    """Before: getscript returned None, parse_sieve(None) raised
    AttributeError, and the client saw a 500 for a script that simply is not
    there."""
    client = _sieve(getscript=MagicMock(return_value=None), errcode=b"NONEXISTENT", errmsg=b"")
    with pytest.raises(ScriptNotFound):
        client.get_script("filters")


def test_list_scripts_failure_is_not_a_type_error():
    """Before: listscripts returned None and unpacking it raised
    `TypeError: cannot unpack non-iterable NoneType` — a 500."""
    client = _sieve(listscripts=MagicMock(return_value=None), errcode=b"", errmsg=b"")
    with pytest.raises(MailServerUnavailable):
        client.list_scripts()


def test_a_successful_operation_still_returns_normally():
    client = _sieve(
        putscript=MagicMock(return_value=True),
        listscripts=MagicMock(return_value=("active", ["other"])),
        getscript=MagicMock(return_value="keep;\n"),
    )
    client.put_script("filters", "keep;")
    assert client.get_script("filters") == "keep;\n"
    assert client.list_scripts() == [
        {"name": "active", "active": True},
        {"name": "other", "active": False},
    ]


# ── Reading what sievelib actually hands back ──


def test_a_str_errmsg_is_handled_as_well_as_bytes():
    """sievelib is inconsistent: errmsg is bytes almost everywhere but a str
    in at least one path (managesieve.py:403). Decoding must survive both."""
    client = _sieve(putscript=MagicMock(return_value=False), errcode=b"", errmsg="a str, not bytes")
    with pytest.raises(ScriptRejected) as caught:
        client.put_script("filters", "keep;")
    assert caught.value.reason == "a str, not bytes"


def test_undecodable_errmsg_does_not_crash_the_adapter():
    """A server may send bytes that are not UTF-8. Losing the wording is
    acceptable; raising UnicodeDecodeError from an error path is not."""
    client = _sieve(putscript=MagicMock(return_value=False), errcode=b"", errmsg=b"\xff\xfe bad")
    with pytest.raises(ScriptRejected):
        client.put_script("filters", "keep;")


def test_an_empty_errmsg_yields_the_safe_default():
    """Ties to the .5 normalisation: nothing to relay must read that way from
    both `.reason` and `str(exc)`."""
    client = _sieve(putscript=MagicMock(return_value=False), errcode=b"", errmsg=b"")
    with pytest.raises(ScriptRejected) as caught:
        client.put_script("filters", "keep;")
    assert caught.value.reason is None
    assert str(caught.value) == ScriptRejected.default_detail


# ── The dial: a False from connect is not a connection ──


def _connect_returning(ok: bool, tls: bool):
    """A sievelib Client whose connect() reports `ok`, with TLS up or not."""
    client = MagicMock()
    client.connect.return_value = ok
    client.sock = MagicMock(spec=ssl.SSLSocket) if tls else MagicMock(spec=object)
    return client


def test_refused_credentials_are_an_auth_failure():
    """sievelib returns False rather than raising on a failed SASL, so
    open_sieve used to hand back an UNAUTHENTICATED client while its
    docstring promised 'connected, authenticated, policy-checked'."""
    with (
        patch.object(mail_dial, "assert_host_resolves_to"),
        patch.object(mail_dial, "Client", return_value=_connect_returning(False, tls=True)),
    ):
        with pytest.raises(AuthFailed):
            mail_dial.open_sieve("mail.example.com", "93.184.216.34", 4190, "u", "p")


def test_refused_starttls_is_a_transport_failure_not_an_auth_failure():
    """Telling the user to log in again would be a lie — and would send them
    round a loop that cannot succeed."""
    with (
        patch.object(mail_dial, "assert_host_resolves_to"),
        patch.object(mail_dial, "Client", return_value=_connect_returning(False, tls=False)),
    ):
        with pytest.raises(MailServerUnavailable):
            mail_dial.open_sieve("mail.example.com", "93.184.216.34", 4190, "u", "p")


def test_a_successful_dial_still_returns_the_client():
    stub = _connect_returning(True, tls=True)
    with (
        patch.object(mail_dial, "assert_host_resolves_to"),
        patch.object(mail_dial, "Client", return_value=stub),
    ):
        assert mail_dial.open_sieve("mail.example.com", "93.184.216.34", 4190, "u", "p") is stub


# ── The folder sink ──


def _imap(create_status: str, subscribe_status: str) -> IMAPClient:
    client = IMAPClient(_session())
    conn = MagicMock()
    conn.create.return_value = (create_status, [b""])
    conn.subscribe.return_value = (subscribe_status, [b""])
    client._conn = conn
    return client


def test_create_folder_reports_a_refused_create():
    with pytest.raises(FolderRejected):
        _imap("NO", "OK").create_folder("Archive/2026")


def test_create_folder_reports_a_refused_subscribe():
    """The verified gap: subscribe's status was discarded while create's was
    checked two lines above, so a folder most mail clients will not display
    was reported as {ok: true}."""
    with pytest.raises(FolderRejected):
        _imap("OK", "NO").create_folder("Archive/2026")


def test_create_folder_returns_nothing_on_success():
    """The seam says failure raises, so success has nothing to report."""
    assert _imap("OK", "OK").create_folder("Archive/2026") is None


# ── Through the HTTP stack: the failure now reaches the user ──


def test_saving_an_uncompilable_script_answers_400_with_the_diagnostic(
    authed_client, sieve_client_passthrough
):
    """The bead's headline, end to end.

    Before: the route answered `200 {ok: true}` and the user believed their
    filter was live. Now the Sieve compiler's own words come back with a 400,
    through the adapter, the vocabulary and app.py's table — no try/except
    anywhere in the router.
    """
    client_mock = MagicMock()
    client_mock.putscript.return_value = False
    client_mock.errcode = b""
    client_mock.errmsg = b"line 4: unknown command 'vacation'"

    with patch.object(
        sieve_client_passthrough.SieveClient, "__enter__", lambda self: _as(self, client_mock)
    ):
        with authed_client() as http:
            r = http.put("/api/scripts/filters/raw", json={"content": "vacation :days 1;\n"})

    assert r.status_code == 400, r.text
    assert r.json()["detail"] == "line 4: unknown command 'vacation'"


def test_quota_on_save_answers_507_not_a_generic_error(authed_client, sieve_client_passthrough):
    """A full account is neither the user's syntax error nor a dead server."""
    client_mock = MagicMock()
    client_mock.putscript.return_value = False
    client_mock.errcode = b"QUOTA/MAXSIZE"
    client_mock.errmsg = b"script too large"

    with patch.object(
        sieve_client_passthrough.SieveClient, "__enter__", lambda self: _as(self, client_mock)
    ):
        with authed_client() as http:
            r = http.put("/api/scripts/filters/raw", json={"content": "keep;\n"})

    assert r.status_code == 507, r.text


def test_fetching_a_missing_script_answers_404_not_500(authed_client, sieve_client_passthrough):
    """Before: getscript returned None and parse_sieve(None) raised
    AttributeError, so a script that is merely absent read as a server bug."""
    client_mock = MagicMock()
    client_mock.getscript.return_value = None
    client_mock.errcode = b"NONEXISTENT"
    client_mock.errmsg = b"no such script"

    with patch.object(
        sieve_client_passthrough.SieveClient, "__enter__", lambda self: _as(self, client_mock)
    ):
        with authed_client() as http:
            r = http.get("/api/scripts/ghost/raw")

    assert r.status_code == 404, r.text


# ── What may be repeated back to the client ──


@pytest.mark.parametrize(
    "errcode,relays",
    [
        (b"", True),  # ScriptRejected — the compiler talking
        (b"QUOTA", True),  # QuotaExceeded — actionable
        (b"NONEXISTENT", True),  # ScriptNotFound — about the request
        (b"TRYLATER", False),  # MailServerUnavailable — where a banner leaks
    ],
    ids=["rejected", "quota", "not-found", "unavailable"],
)
def test_only_request_shaped_failures_repeat_the_servers_words(errcode, relays):
    """mail_errors' own rule: never relay a raw upstream banner, which can
    carry software versions and internal hostnames. A failure that is a
    decision about the REQUEST may quote the server; a transport failure
    answers with its safe default however much the server said."""
    banner = "Cyrus timsieved v2.4.17 on mail-int-07.corp.lan"
    client = _sieve(
        putscript=MagicMock(return_value=False), errcode=errcode, errmsg=banner.encode()
    )
    with pytest.raises(MailStoreError) as caught:
        client.put_script("filters", "keep;")
    assert (banner in str(caught.value)) is relays
    if not relays:
        assert str(caught.value) == type(caught.value).default_detail


def test_auth_failure_never_repeats_the_servers_words():
    with (
        patch.object(mail_dial, "assert_host_resolves_to"),
        patch.object(mail_dial, "Client", return_value=_connect_returning(False, tls=True)),
    ):
        with pytest.raises(AuthFailed) as caught:
            mail_dial.open_sieve("mail.example.com", "93.184.216.34", 4190, "u", "p")
    assert str(caught.value) == AuthFailed.default_detail


# ── An unexplained NO is not the caller's fault ──


@pytest.mark.parametrize(
    "op,stub",
    [
        ("activate_script", {"setactive": MagicMock(return_value=False)}),
        ("delete_script", {"deletescript": MagicMock(return_value=False)}),
        ("get_script", {"getscript": MagicMock(return_value=None)}),
    ],
)
def test_a_bare_no_is_not_reported_as_the_callers_mistake(op, stub):
    """No response code means we do not know why. Guessing 4xx would tell the
    user to fix something that may be nothing to do with them."""
    client = _sieve(errcode=b"", errmsg=b"", **stub)
    with pytest.raises(MailServerUnavailable):
        getattr(client, op)("filters")


# ── The sievelib assumption open_sieve depends on ──


def test_sievelib_still_wraps_the_socket_only_after_starttls_succeeds():
    """open_sieve tells a refused STARTTLS from a failed SASL by asking
    whether the socket got wrapped, because sievelib reports both as a bare
    `False`. That inference is read off sievelib's control flow, so it is
    pinned here against the REAL library rather than against our own mock —
    a reordering upstream would otherwise silently invert the two, sending
    users into the re-login loop the discrimination exists to prevent.
    """
    import inspect

    from sievelib.managesieve import Client

    source = inspect.getsource(Client._Client__starttls)
    refused = source.index("return False")
    wrapped = source.index("__enable_ssl")
    assert refused < wrapped, (
        "sievelib now enables SSL before deciding STARTTLS succeeded; "
        "open_sieve's AuthFailed/MailServerUnavailable split is no longer sound"
    )
