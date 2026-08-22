"""
The transport net covers SPEAKING, not just dialling (areyousievious-66i).

`.28` made transport failures semantic where the connection is ESTABLISHED —
the dial, and LOGIN. It did not cover the operations that follow, so a socket
dropping one call later escaped as a raw imaplib/sievelib exception and
FastAPI answered 500: a mail-server outage wearing the costume of our own bug.

All five cases below were verified to escape before this change. A dropped
socket mid-request is not exotic — it is what a server restart, an idle
timeout, and a NAT eviction all look like.

WHERE THE NET GOES is the substance of this bead, and the tempting answer is
wrong. Wrapping the yield in `dependencies.get_script_store` would be one
place instead of seven and would cover operations not yet written — but the
yield hands control to the ROUTE HANDLER, so the net would span the handler's
own code too. `routers/scripts.py:82` reads an uploaded file inside exactly
that span, and a disk error there would have told the user "the mail server
could not be reached". The net belongs where "the transport can fail" is
true, which is the adapter method.

That leaves one real risk: the next operation forgets to wrap. It is closed
structurally rather than by discipline — `test_every_seam_operation_is_netted`
reads the operations off the SEAM, so a method added to `ScriptStore` or
`FolderStore` and left unnetted fails the suite.
"""

from __future__ import annotations

import imaplib
from unittest.mock import MagicMock

import pytest
from auth import Session
from config import Settings
from imap_store import ImapFolderStore
from mail_errors import MailServerUnavailable, MailStoreError, ScriptRejected
from mail_stores import FolderStore, ScriptStore
from managesieve_client import SieveClient
from sievelib.managesieve import Error as SievelibError


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


def _imap(**conn_attrs) -> ImapFolderStore:
    store = ImapFolderStore(_session(), Settings())
    store._conn = MagicMock(**conn_attrs)
    return store


def _sieve(**client_attrs) -> SieveClient:
    store = SieveClient(_session(), Settings())
    store._client = MagicMock(**client_attrs)
    return store


# ── A socket that dies mid-operation is an outage, not a 500 ──

TRANSPORT_FAILURES = [
    pytest.param(imaplib.IMAP4.abort("connection closed"), id="imap-abort"),
    pytest.param(ConnectionResetError(104, "reset by peer"), id="reset"),
    pytest.param(BrokenPipeError(32, "broken pipe"), id="broken-pipe"),
    pytest.param(TimeoutError("timed out"), id="timeout"),
    pytest.param(OSError(101, "network unreachable"), id="oserror"),
]


@pytest.mark.parametrize("failure", TRANSPORT_FAILURES)
def test_a_dropped_socket_during_list_folders_is_an_outage(failure):
    with pytest.raises(MailServerUnavailable):
        _imap(**{"list.side_effect": failure}).list_folders()


@pytest.mark.parametrize("failure", TRANSPORT_FAILURES)
def test_a_dropped_socket_during_create_folder_is_an_outage(failure):
    with pytest.raises(MailServerUnavailable):
        _imap(**{"create.side_effect": failure}).create_folder("Archive")


def test_a_dropped_socket_during_subscribe_is_an_outage():
    """CREATE succeeds and SUBSCRIBE never lands. Verified separately because
    it is the second verb in the method, and the first one succeeding is what
    makes it easy to leave uncovered."""
    store = _imap(
        **{
            "create.return_value": ("OK", [b"created"]),
            "subscribe.side_effect": imaplib.IMAP4.abort("connection closed"),
        }
    )
    with pytest.raises(MailServerUnavailable):
        store.create_folder("Archive")


SIEVE_OPERATIONS = [
    pytest.param("list_scripts", (), "listscripts", id="list_scripts"),
    pytest.param("get_script", ("n",), "getscript", id="get_script"),
    pytest.param("put_script", ("n", "keep;\n"), "putscript", id="put_script"),
    pytest.param("activate_script", ("n",), "setactive", id="activate_script"),
    pytest.param("delete_script", ("n",), "deletescript", id="delete_script"),
]


@pytest.mark.parametrize("method,args,verb", SIEVE_OPERATIONS)
def test_a_dropped_socket_during_a_script_operation_is_an_outage(method, args, verb):
    store = _sieve(**{f"{verb}.side_effect": ConnectionResetError(104, "reset by peer")})
    with pytest.raises(MailServerUnavailable):
        getattr(store, method)(*args)


@pytest.mark.parametrize("method,args,verb", SIEVE_OPERATIONS)
def test_sievelibs_own_error_during_a_script_operation_is_an_outage(method, args, verb):
    """sievelib raises its own Error for a failed socket — not an OSError,
    and just as fatal."""
    store = _sieve(**{f"{verb}.side_effect": SievelibError("connection lost")})
    with pytest.raises(MailServerUnavailable):
        getattr(store, method)(*args)


# ── The net must not swallow what is already semantic ──


def test_a_semantic_failure_passes_through_the_net_untouched():
    """The exemption `.28` built into the net, now load-bearing in a second
    place: a compiler diagnostic must not come back out as "could not be
    reached". Same reason a mistyped password does not."""
    store = _sieve(
        **{
            "putscript.return_value": False,
            "errcode": b"",
            "errmsg": b"line 4: unknown command 'vacation'",
        }
    )
    with pytest.raises(ScriptRejected) as caught:
        store.put_script("n", "vacation :days 1 'x';\n")
    assert "vacation" in str(caught.value)


def test_a_refused_folder_name_is_still_the_callers_mistake():
    store = _imap(**{"create.return_value": ("NO", [b"[CANNOT] invalid name"])})
    with pytest.raises(MailStoreError) as caught:
        store.create_folder("Archive")
    assert not isinstance(caught.value, MailServerUnavailable)


def test_our_own_bugs_are_not_relabelled_as_mail_server_failures():
    """The risk that ruled out wrapping the dependency's yield. The net
    catches transport types only, so a defect in our code must still surface
    as itself rather than as an outage the user cannot act on."""
    store = _sieve(**{"listscripts.side_effect": ZeroDivisionError("our bug")})
    with pytest.raises(ZeroDivisionError):
        store.list_scripts()


# ── The structural lock ──


def _seam_operations(protocol: type) -> set[str]:
    return {name for name in vars(protocol) if not name.startswith("_")}


@pytest.mark.parametrize(
    "adapter,seam",
    [
        pytest.param(ImapFolderStore, FolderStore, id="ImapFolderStore"),
        pytest.param(SieveClient, ScriptStore, id="SieveClient"),
    ],
)
def test_every_seam_operation_is_netted(adapter: type, seam: type) -> None:
    """ARCHITECTURAL LOCK: an operation that speaks is an operation that nets.

    Read off the SEAM, not off the adapter, so the failure mode this bead
    exists to remove cannot come back by someone adding a seventh operation
    and forgetting the decorator. That is not a hypothetical — it is how these
    five got missed when `.28` netted the dial and LOGIN.

    If this fails, decorate the method with `@speaks_to_mail_server`. Do not
    add the name to an exemption list.
    """
    unnetted = {
        name
        for name in _seam_operations(seam)
        if not getattr(getattr(adapter, name), "speaks_to_mail_server", False)
    }
    assert not unnetted, (
        f"{adapter.__name__} speaks to the mail server in {sorted(unnetted)} "
        "without translating what the transport raises. Decorate with "
        "@speaks_to_mail_server."
    )


def test_a_malformed_name_is_still_the_callers_mistake_not_an_outage():
    """`ProtocolNameError` subclasses ValueError, which the net does not
    catch — so a name that would break command framing keeps its own status
    instead of being reported as a server that could not be reached."""
    from protocol_names import ProtocolNameError

    with pytest.raises(ProtocolNameError):
        _sieve().get_script('bad\r\nDELETESCRIPT "primary"')
    with pytest.raises(ProtocolNameError):
        _imap().create_folder("bad\r\nLOGOUT")


# ── Through the real stack, where the status is decided ──


@pytest.mark.parametrize(
    "store_factory,path",
    [
        pytest.param(
            lambda: _imap(**{"list.side_effect": imaplib.IMAP4.abort("closed")}),
            "/api/folders",
            id="GET-folders",
        ),
        pytest.param(
            lambda: _sieve(**{"listscripts.side_effect": ConnectionResetError(104, "reset")}),
            "/api/scripts",
            id="GET-scripts",
        ),
    ],
)
def test_a_dropped_socket_answers_502_not_500(authed_client, store_factory, path):
    """The whole point, in the only terms the user sees. A 500 says our bug
    and offers nothing to do; a 502 says the mail server, and retrying is a
    real next step."""
    store = store_factory()
    kwargs = {"folder_store": store} if path == "/api/folders" else {"script_store": store}
    with authed_client(**kwargs) as http:
        response = http.get(path)
    assert response.status_code == 502
    # The net's own wording, not a stack trace and not a bare "Internal
    # Server Error" — the reply has to name what failed to be worth anything.
    assert "mail server" in response.json()["detail"].lower()
