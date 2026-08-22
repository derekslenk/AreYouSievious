"""
One module owns dialling the user's mail server.

Connection policy — re-validate DNS, dial the IP pinned at login, keep TLS SNI
and certificate verification on the original hostname, apply timeouts — used to
be re-derived at each call site, in each library's idiom. That is a locality
failure with teeth: a caller that does not go through `ImapFolderStore` silently
gets none of the policy.

It cost us a real gap. areyousievious-vzs closed the third-resolution TOCTOU
for `ImapFolderStore` (via `_PinnedIMAP4_SSL`) and for `SieveClient` (via sievelib's
`srvhostname`), but the login handler built its own `imaplib.IMAP4_SSL(host, …)`
and was left re-resolving the hostname — on the very first connection the app
makes, with the user's credentials in hand. The fix was applied twice and
missed the third site, because nothing made the policy unskippable.

Now there is one way to obtain a connection, and it applies the policy. A new
caller cannot forget, because there is nothing to forget.
"""

from __future__ import annotations

import imaplib
import logging
import socket
import ssl
import threading
from contextlib import contextmanager
from functools import lru_cache, wraps

from config import Settings
from mail_errors import AuthFailed, MailServerUnavailable, MailStoreError
from sievelib.managesieve import Client
from sievelib.managesieve import Error as SievelibError
from ssrf import HostValidationError, assert_host_resolves_to

_log = logging.getLogger("ays.dial")


# ── Transport failures ──
#
# The transport raises; `.6` only taught the adapters about failures sievelib
# REPORTED BY RETURN. Everything below escaped every handler in app.py, so a
# mail server that was merely down read as a bug in this app.
#
# The wording is ours, never the exception's. `MailServerUnavailable` is
# absent from `mail_errors.RELAYS_SERVER_TEXT`, so interpolating a transport
# error here would route upstream text past that policy by the back door.
# Most-specific first: SSLCertVerificationError subclasses SSLError, and all
# of these subclass OSError.
_TRANSPORT_CAUSES: tuple[tuple[type[BaseException], str], ...] = (
    (ssl.SSLCertVerificationError, "The mail server's TLS certificate could not be verified."),
    (ssl.SSLError, "TLS negotiation with the mail server failed."),
    (socket.gaierror, "The mail server's hostname could not be resolved."),
    (ConnectionRefusedError, "The mail server refused the connection."),
    (TimeoutError, "The mail server did not respond in time."),
)
_TRANSPORT_DEFAULT = "The mail server could not be reached."


@contextmanager
def transport_failures_are_semantic():
    """Translate whatever the transport raises into the mail vocabulary.

    Public because speaking is as exposed as dialling: `imaplib` does not wrap
    OSError, so a socket that dies mid-LOGIN raises straight through the
    adapter. The conversation needs the same net the connection gets.

    Deliberately lets `MailStoreError` and `HostValidationError` through
    untouched: the first is already semantic, and the second is a 400 whose
    explicit message must survive — reporting a rebinding attempt as an
    ordinary outage is the exact confusion `routers/auth.py`'s ladder ordered
    its excepts to avoid.
    """
    try:
        yield
    except (MailStoreError, HostValidationError):
        # Load-bearing, not defensive. `imap_store._login` raises AuthFailed
        # from INSIDE this net — the protocol's own errors have to be read
        # before the net sees them, because an IMAP4.error means "would not
        # talk to us" at the dial and "refused these credentials" during
        # LOGIN. Without this exemption a mistyped password would come back
        # out as "the mail server could not be reached".
        #
        # HostValidationError is here for its own reason: it is a 400 whose
        # explicit message must survive, and reporting a rebinding attempt as
        # an ordinary outage is the confusion `routers/auth.py` ordered its
        # excepts to avoid.
        raise
    except OSError as exc:
        for cause, message in _TRANSPORT_CAUSES:
            if isinstance(exc, cause):
                raise MailServerUnavailable(message) from exc
        raise MailServerUnavailable(_TRANSPORT_DEFAULT) from exc
    except imaplib.IMAP4.abort as exc:
        # MUST precede IMAP4.error, which it subclasses.
        raise MailServerUnavailable("The connection to the mail server was lost.") from exc
    except imaplib.IMAP4.error as exc:
        # Not an OSError — `IMAP4_SSL.__init__` reads the server greeting, so a
        # server that accepts TCP and TLS and then says BYE arrives here. No
        # credentials have been sent at this point, so this is the server
        # refusing to talk, not a rejected password.
        raise MailServerUnavailable(_TRANSPORT_DEFAULT) from exc
    except SievelibError as exc:
        # sievelib raises its own Error for a failed socket or an unreadable
        # capability banner; not an OSError, and just as fatal.
        raise MailServerUnavailable(_TRANSPORT_DEFAULT) from exc


def speaks_to_mail_server(method):
    """Mark an adapter operation as speaking, and net what the transport raises.

    `.28` netted the DIAL and LOGIN and stopped there, so a socket dropping
    one call later escaped as a raw imaplib/sievelib exception and FastAPI
    answered 500 — an upstream outage wearing the costume of our own bug.

    The net goes HERE, on the method, rather than around the yield in
    `dependencies.get_script_store`. That would be one place instead of seven
    and would cover operations not yet written, but the yield hands control to
    the route handler, so the net would span the handler's own code too —
    and `routers/scripts.py` reads an uploaded file inside exactly that span,
    where a disk error would come back as "the mail server could not be
    reached". The net belongs where "the transport can fail" is true.

    The marker is what closes the gap that argument opens. Nothing here stops
    the next operation from forgetting to decorate, so
    `tests/test_transport_net_covers_operations.py` reads the operations off
    the SEAM and fails when one is unnetted — the same by-construction shape
    the import allowlist uses, rather than a promise to remember.
    """

    @wraps(method)
    def netted(*args, **kwargs):
        with transport_failures_are_semantic():
            return method(*args, **kwargs)

    netted.speaks_to_mail_server = True
    return netted


# ── TLS ──

# A running process serves one app and therefore one configuration; the extra
# room is for test suites, which build many. Bounded rather than unbounded so
# a caller constructing Settings in a loop cannot grow this without limit.
_TLS_CONTEXT_CACHE = 8


@lru_cache(maxsize=_TLS_CONTEXT_CACHE)
def build_tls_context(cfg: Settings) -> ssl.SSLContext:
    """Build the TLS context used for every outbound connection.

    Defaults: verify the server certificate chain against the system root store
    and check the hostname (CWE-295, CWE-297). Without this, the stdlib default
    accepts ANY certificate, including a self-signed cert from an on-path MITM,
    and the client then sends the user's plaintext password.

    Opt-out: `AYS_IMAP_INSECURE=1` falls back to an unverified context for
    self-signed test setups. Emits a warning so the operator cannot miss it.

    Cached ON THE CONFIGURATION, so building the system CA store does not
    repeat per connection. This is not the argument-less cache it replaced:
    that one held whatever vintage of the environment it was first called
    with, and clearing `config.settings`'s cache did not invalidate it — two
    caches, two vintages, no relationship between them. Keying on `cfg` makes
    a different configuration a different entry by construction. `create_app`
    builds one eagerly so a broken CA store still fails at startup rather
    than on a user's first login.
    """
    if cfg.imap_insecure:
        _log.warning(
            "AYS_IMAP_INSECURE is set — outbound TLS is NOT verified. "
            "Use only for self-signed test setups."
        )
        return ssl._create_unverified_context()
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# ── IMAP ──


class _PinnedIMAP4_SSL(imaplib.IMAP4_SSL):
    """IMAP4_SSL that dials a pre-validated IP but presents the original
    hostname for TLS SNI and certificate validation.

    Stock `imaplib.IMAP4_SSL` uses `self.host` for both
    `socket.create_connection` and `wrap_socket(server_hostname=…)`, so the OS
    performs a further DNS resolution AFTER the rebinding guard has run —
    a TOCTOU window a rebinding attacker can drive to a private destination
    (CWE-367 + CWE-918).

    Splitting the two roles closes it: dial the IP `validate_host` pinned,
    keep certificate CN/SAN matching tied to the hostname the user typed.
    """

    def __init__(
        self,
        host: str,
        host_ip: str,
        port: int,
        ssl_context: ssl.SSLContext,
        timeout: float,
    ):
        self._pinned_ip = host_ip
        super().__init__(host, port, ssl_context=ssl_context, timeout=timeout)

    def _create_socket(self, timeout):
        sock = socket.create_connection((self._pinned_ip, self.port), timeout)
        return self.ssl_context.wrap_socket(sock, server_hostname=self.host)


def open_imap(host: str, host_ip: str, port: int, *, cfg: Settings, timeout: float | None = None):
    """Return a connected, policy-checked IMAP connection.

    Re-resolves `host` and aborts if it no longer answers with `host_ip`, then
    dials the pinned address. The caller still performs LOGIN — this owns
    getting to the right machine safely, not what you say once you are there.

    `cfg` arrives from the caller rather than being read out of the process
    global. Reading the global is what made four of nine Settings fields inert
    when passed to `create_app`: the app honoured them and the dial did not.
    """
    assert_host_resolves_to(host, host_ip)
    # Built OUTSIDE the net: a broken system CA store raises ssl.SSLError too,
    # and calling that "TLS negotiation with the mail server failed" would
    # blame the server for a fault on this machine.
    tls = build_tls_context(cfg)
    with transport_failures_are_semantic():
        return _PinnedIMAP4_SSL(
            host,
            host_ip,
            port,
            ssl_context=tls,
            timeout=cfg.imap_timeout if timeout is None else timeout,
        )


# ── ManageSieve ──

# sievelib's `Client.connect` calls `socket.create_connection` with no timeout
# and offers no seam to override it, so the connect timeout can only be set
# through the PROCESS-GLOBAL `socket.setdefaulttimeout`. That is not
# thread-safe, and this app runs its sync handlers in a threadpool
# deliberately (`import_script` is sync precisely so uploads run concurrently).
#
# Two threads interleaving the save/restore corrupts the global permanently:
#   A: previous=None, set 10.0
#   B: previous=10.0 (!), set 10.0
#   A: restore None
#   B: restore 10.0   ← every socket created afterwards now inherits it
#
# Reproduced before this lock existed. Serialising the connect window is the
# available fix; it is brief, and the alternative is a process-wide timeout
# leak that also silently reshapes unrelated IMAP connections.
_CONNECT_TIMEOUT_LOCK = threading.Lock()


def open_sieve(
    host: str, host_ip: str, port: int, username: str, password: str, *, cfg: Settings
) -> Client:
    """Return a connected, authenticated, policy-checked ManageSieve client.

    Unlike `open_imap` this performs the login too, because sievelib fuses
    connect and authenticate into one call.
    """
    assert_host_resolves_to(host, host_ip)

    with _CONNECT_TIMEOUT_LOCK:
        previous_default = socket.getdefaulttimeout()
        socket.setdefaulttimeout(cfg.sieve_connect_timeout)
        try:
            # srvaddr is the pinned IP; srvhostname keeps TLS SNI and cert
            # verification on the name the user typed. sievelib supports the
            # split natively, so no monkey-patch is needed.
            client = Client(host_ip, port, srvhostname=host)
            with transport_failures_are_semantic():
                connected = client.connect(username, password, starttls=True)
        finally:
            socket.setdefaulttimeout(previous_default)

    if not connected:
        # sievelib returns False rather than raising for BOTH a refused
        # STARTTLS and a failed SASL, and this used to be discarded — so the
        # function handed back an unauthenticated client while promising a
        # "connected, authenticated, policy-checked" one, and the failure
        # surfaced later as something unrelated.
        #
        # The two causes need different answers, and the socket tells them
        # apart: sievelib wraps it in TLS only once STARTTLS has succeeded, so
        # a bare socket here means the transport was refused. Calling that an
        # auth failure would send the user round a re-login loop that cannot
        # succeed.
        if isinstance(client.sock, ssl.SSLSocket):
            raise AuthFailed()
        if client.sock is None:
            # Unreachable with sievelib as installed: connect() assigns the
            # socket before any path that can return False, and a socket that
            # never opened arrives as sievelib's own Error, already mapped
            # above. Kept as a forward guard — if a future sievelib returns
            # False before wrapping, the branch below would claim STARTTLS was
            # refused for a server that was never reached.
            raise MailServerUnavailable(_TRANSPORT_DEFAULT)
        raise MailServerUnavailable("The mail server refused to start TLS.")

    if client.sock is not None:
        client.sock.settimeout(cfg.sieve_io_timeout)
    return client
