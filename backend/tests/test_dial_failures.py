"""
Transport failures are semantic, not 500s (areyousievious-8fg.28).

`.6` taught the adapters to stop discarding failures sievelib REPORTED BY
RETURN. It never looked at the failures the transport RAISES, and those went
straight past every handler in `app.py`:

    open_sieve  / ConnectionRefusedError, gaierror, SSLError, TimeoutError
    open_imap   / ConnectionRefusedError, gaierror, SSLError
    IMAP login  / imaplib.IMAP4.error, IMAP4.abort

all verified escaping as HTTP 500. A mail server that is simply down read as
a bug in this app, and a password that had expired since login read as one
too.

Only the login route was protected, by a bare `except Exception -> 502`.
These tests are what made deleting it safe in `.9` — and one of them exists
because deleting it was NOT safe at first: the net covered the dial but not
the conversation, so a socket dying mid-LOGIN still answered 500.

The messages are deliberately OUR words. `MailServerUnavailable` is absent
from `mail_errors.RELAYS_SERVER_TEXT`, so interpolating a transport
exception here would smuggle upstream text past that policy.
"""

from __future__ import annotations

import imaplib
import socket
import ssl
from unittest.mock import MagicMock, patch

import mail_dial
import pytest
from auth import Session
from config import Settings
from imap_client import ImapFolderStore
from mail_errors import AuthFailed, MailServerUnavailable
from managesieve_client import SieveClient

# Every way the transport can fail before we have said anything.
TRANSPORT_FAILURES = [
    ConnectionRefusedError("[Errno 61] Connection refused"),
    socket.gaierror("[Errno 8] nodename nor servname provided"),
    TimeoutError("timed out"),
    ssl.SSLError("[SSL] internal error"),
    ssl.SSLCertVerificationError("certificate verify failed: self signed certificate"),
    OSError("[Errno 51] Network is unreachable"),
]
IDS = [type(e).__name__ for e in TRANSPORT_FAILURES]


def _session() -> Session:
    return Session(
        token="t",
        host="mail.example.com",
        host_ip="93.184.216.34",
        port_imap=993,
        port_sieve=4190,
        username="u",
        password="p",
        created_at=0.0,
        last_used=0.0,
    )


# ── The dial ──


@pytest.mark.parametrize("failure", TRANSPORT_FAILURES, ids=IDS)
def test_open_sieve_reports_a_dead_server_as_unavailable(failure):
    class _Client:
        def __init__(self, *a, **kw):
            self.sock = None

        def connect(self, *a, **kw):
            raise failure

    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "Client", _Client),
    ):
        with pytest.raises(MailServerUnavailable):
            mail_dial.open_sieve("m.example.com", "93.184.216.34", 4190, "u", "p", cfg=Settings())


@pytest.mark.parametrize("failure", TRANSPORT_FAILURES, ids=IDS)
def test_open_imap_reports_a_dead_server_as_unavailable(failure):
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "_PinnedIMAP4_SSL", MagicMock(side_effect=failure)),
    ):
        with pytest.raises(MailServerUnavailable):
            mail_dial.open_imap("m.example.com", "93.184.216.34", 993, cfg=Settings())


def test_a_bad_certificate_says_so_rather_than_blaming_the_network():
    """Distinct causes, distinct words. A failed chain check can mean an
    on-path attacker; reporting it as an ordinary outage buries that."""
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(
            mail_dial,
            "_PinnedIMAP4_SSL",
            MagicMock(side_effect=ssl.SSLCertVerificationError("verify failed")),
        ),
    ):
        with pytest.raises(MailServerUnavailable) as caught:
            mail_dial.open_imap("m.example.com", "93.184.216.34", 993, cfg=Settings())
    assert "certificate" in str(caught.value).lower()


@pytest.mark.parametrize("failure", TRANSPORT_FAILURES, ids=IDS)
def test_the_transports_own_words_are_never_relayed(failure):
    """MailServerUnavailable is not in RELAYS_SERVER_TEXT. Interpolating the
    exception would route around that policy by the back door."""
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "_PinnedIMAP4_SSL", MagicMock(side_effect=failure)),
    ):
        with pytest.raises(MailServerUnavailable) as caught:
            mail_dial.open_imap("m.example.com", "93.184.216.34", 993, cfg=Settings())
    assert str(failure) not in str(caught.value)


def test_a_rebinding_abort_is_not_flattened_into_an_outage():
    """HostValidationError must survive the transport net.

    Raised from INSIDE the wrapped block deliberately. The obvious version of
    this test patches `assert_host_resolves_to`, which runs BEFORE the `with`
    — so it passes whatever the net does and locks nothing. Raising it from
    the dial itself is what actually exercises the exemption, and what would
    fail if the net were ever widened to catch Exception.

    It matters because this is a 400 with an explicit message; reporting a
    rebinding attempt as an ordinary outage is the confusion `routers/auth.py`
    ordered its excepts to avoid.
    """
    from ssrf import HostValidationError

    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(
            mail_dial,
            "_PinnedIMAP4_SSL",
            MagicMock(side_effect=HostValidationError("DNS rebinding detected")),
        ),
    ):
        with pytest.raises(HostValidationError):
            mail_dial.open_imap("m.example.com", "93.184.216.34", 993, cfg=Settings())


def test_an_already_semantic_error_passes_through_the_net_unchanged():
    """The other half of the exemption: a MailStoreError raised inside must
    not be re-wrapped into a generic MailServerUnavailable."""
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "_PinnedIMAP4_SSL", MagicMock(side_effect=AuthFailed())),
    ):
        with pytest.raises(AuthFailed):
            mail_dial.open_imap("m.example.com", "93.184.216.34", 993, cfg=Settings())


@pytest.mark.parametrize(
    "failure,expected_fragment",
    [
        (imaplib.IMAP4.error("BYE server unavailable"), "could not be reached"),
        (imaplib.IMAP4.abort("connection closed"), "was lost"),
    ],
    ids=["error", "abort"],
)
def test_open_imap_handles_imaplibs_own_errors(failure, expected_fragment):
    """imaplib's errors are NOT OSErrors, so the OSError net misses them —
    and `IMAP4_SSL.__init__` reads the server greeting, so a server that
    accepts TCP and TLS and then says BYE arrives exactly here. Both escaped
    as 500 until this was pinned.

    No credentials have been sent at connect time, so neither is an auth
    failure: reporting one would send the user to reset a working password.
    """
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "_PinnedIMAP4_SSL", MagicMock(side_effect=failure)),
    ):
        with pytest.raises(MailServerUnavailable) as caught:
            mail_dial.open_imap("m.example.com", "93.184.216.34", 993, cfg=Settings())
    assert expected_fragment in str(caught.value)


def test_a_broken_ca_store_is_not_blamed_on_the_server():
    """build_tls_context runs outside the net. A missing system CA store
    raises ssl.SSLError too, and calling that 'TLS negotiation with the mail
    server failed' would blame the server for a fault on this machine."""
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(
            mail_dial, "build_tls_context", MagicMock(side_effect=ssl.SSLError("no CA store"))
        ),
    ):
        with pytest.raises(ssl.SSLError):
            mail_dial.open_imap("m.example.com", "93.184.216.34", 993, cfg=Settings())


# ── Saying hello ──


def test_an_expired_password_is_an_auth_failure_not_a_server_error():
    """The most visible of the three: a session that authenticated once and
    no longer does gave HTTP 500 on GET /api/folders."""
    conn = MagicMock()
    conn.login.side_effect = imaplib.IMAP4.error("AUTHENTICATIONFAILED")
    with patch("imap_client.open_imap", return_value=conn):
        with pytest.raises(AuthFailed):
            with ImapFolderStore(_session(), Settings()):
                pass


def test_a_dropped_connection_during_login_is_not_an_auth_failure():
    """IMAP4.abort subclasses IMAP4.error, so order matters: telling the user
    their password is wrong when the socket died sends them to reset a
    working password."""
    conn = MagicMock()
    conn.login.side_effect = imaplib.IMAP4.abort("connection closed")
    with patch("imap_client.open_imap", return_value=conn):
        with pytest.raises(MailServerUnavailable):
            with ImapFolderStore(_session(), Settings()):
                pass


# ── Through the routes ──


def test_folders_reports_a_dead_server_as_502(authed_client):
    with patch(
        "dependencies.ImapFolderStore",
        MagicMock(side_effect=MailServerUnavailable()),
    ):
        with authed_client() as http:
            r = http.get("/api/folders")
    assert r.status_code == 502, r.text


def test_scripts_reports_a_dead_server_as_502(authed_client):
    with patch(
        "dependencies.SieveClient",
        MagicMock(side_effect=MailServerUnavailable()),
    ):
        with authed_client() as http:
            r = http.get("/api/scripts")
    assert r.status_code == 502, r.text


def test_a_real_dial_failure_reaches_the_client_as_502(authed_client):
    """End to end through the actual adapter and dial, not a pre-raised
    error: the transport blows up and the user sees 502, not 500."""
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(
            mail_dial, "_PinnedIMAP4_SSL", MagicMock(side_effect=ConnectionRefusedError("refused"))
        ),
    ):
        with authed_client() as http:
            r = http.get("/api/folders")
    assert r.status_code == 502, r.text


def test_sieve_client_still_constructs_normally():
    """Guard against the net swallowing construction itself."""
    assert SieveClient(_session(), Settings()).cfg == Settings()


# ── The login route draws the same distinction ──


@pytest.mark.parametrize(
    "failure,status",
    [
        (imaplib.IMAP4.abort("connection closed"), 502),
        (imaplib.IMAP4.error("AUTHENTICATIONFAILED"), 401),
    ],
    ids=["dropped-socket", "bad-password"],
)
def test_login_tells_a_dropped_socket_from_a_bad_password(make_app, failure, status):
    """`login` calls imaplib directly rather than through ImapFolderStore, so the
    adapter's abort/error split does not cover it. Without its own, a network
    blip during login answered 401 "Authentication failed" — identical to a
    genuinely wrong password, sending the user to reset a working credential.

    `.9` retired the ladder: the router now calls `verify_credentials`, which
    speaks IMAP in one place and reports in the shared vocabulary. The
    distinction is asserted through the route either way.
    """
    from fastapi.testclient import TestClient

    conn = MagicMock()
    conn.login.side_effect = failure
    with (
        patch("routers.auth.validate_host", return_value="93.184.216.34"),
        # The dial lives in the adapter now: the router no longer imports
        # imaplib or open_imap, which is the point of `.9`.
        patch("imap_client.open_imap", return_value=conn),
    ):
        with TestClient(make_app()) as http:
            r = http.post(
                "/api/auth/login",
                json={"host": "mail.example.com", "username": "u", "password": "p"},
            )
    assert r.status_code == status, r.text


@pytest.mark.parametrize("failure", TRANSPORT_FAILURES, ids=IDS)
def test_a_socket_that_dies_mid_login_is_not_our_bug(failure):
    """The conversation needs the same net the connection gets.

    imaplib does not wrap OSError, so a socket reset while we are talking
    raises straight through the adapter. `.9` retired login's bare
    `except Exception -> 502`, which had been quietly covering this — without
    extending the net, a mail server that dropped mid-LOGIN answered 500 and
    blamed this app. Both call sites of `_login` are covered: the login route
    and the store's `__enter__`.
    """
    conn = MagicMock()
    conn.login.side_effect = failure
    with patch("imap_client.open_imap", return_value=conn):
        with pytest.raises(MailServerUnavailable):
            with ImapFolderStore(_session(), Settings()):
                pass


def test_sievelibs_own_error_is_translated_too():
    """sievelib raises its own Error — not an OSError — when the socket fails
    or the capability banner is unreadable. Covered here because the
    OSError-kin cases above cannot reach that branch."""
    from sievelib.managesieve import Error as SievelibError

    class _Client:
        def __init__(self, *a, **kw):
            self.sock = None

        def connect(self, *a, **kw):
            raise SievelibError("Connection to server failed: [Errno 61] refused")

    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "Client", _Client),
    ):
        with pytest.raises(MailServerUnavailable) as caught:
            mail_dial.open_sieve("m.example.com", "93.184.216.34", 4190, "u", "p", cfg=Settings())
    assert "Errno 61" not in str(caught.value), "sievelib's text must not be relayed"
