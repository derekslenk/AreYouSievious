"""
One module owns dialling the user's mail server.

Connection policy — re-validate DNS, dial the IP pinned at login, keep TLS SNI
and certificate verification on the original hostname, apply timeouts — used to
be re-derived at each call site, in each library's idiom. That is a locality
failure with teeth: a caller that does not go through `IMAPClient` silently
gets none of the policy.

It cost us a real gap. areyousievious-vzs closed the third-resolution TOCTOU
for `IMAPClient` (via `_PinnedIMAP4_SSL`) and for `SieveClient` (via sievelib's
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
import os
import socket
import ssl
import threading

from sievelib.managesieve import Client
from ssrf import assert_host_resolves_to

_log = logging.getLogger("ays.dial")


# ── Timeouts ──


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(0.1, float(raw))
    except ValueError:
        return default


IMAP_TIMEOUT = _env_float("AYS_IMAP_TIMEOUT", 10.0)
SIEVE_CONNECT_TIMEOUT = _env_float("AYS_SIEVE_CONNECT_TIMEOUT", 10.0)
SIEVE_IO_TIMEOUT = _env_float("AYS_SIEVE_IO_TIMEOUT", 30.0)


# ── TLS ──


def _build_tls_context() -> ssl.SSLContext:
    """Build the TLS context used for every outbound connection.

    Defaults: verify the server certificate chain against the system root store
    and check the hostname (CWE-295, CWE-297). Without this, the stdlib default
    accepts ANY certificate, including a self-signed cert from an on-path MITM,
    and the client then sends the user's plaintext password.

    Opt-out: `AYS_IMAP_INSECURE=1` falls back to an unverified context for
    self-signed test setups. Emits a warning so the operator cannot miss it.
    """
    if os.environ.get("AYS_IMAP_INSECURE", "").lower() in ("1", "true", "yes"):
        _log.warning(
            "AYS_IMAP_INSECURE is set — outbound TLS is NOT verified. "
            "Use only for self-signed test setups."
        )
        return ssl._create_unverified_context()
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# Built once at import so a missing system CA store fails fast at startup
# rather than on a user's first login.
TLS_CONTEXT = _build_tls_context()


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


def open_imap(host: str, host_ip: str, port: int, *, timeout: float | None = None):
    """Return a connected, policy-checked IMAP connection.

    Re-resolves `host` and aborts if it no longer answers with `host_ip`, then
    dials the pinned address. The caller still performs LOGIN — this owns
    getting to the right machine safely, not what you say once you are there.
    """
    assert_host_resolves_to(host, host_ip)
    return _PinnedIMAP4_SSL(
        host,
        host_ip,
        port,
        ssl_context=TLS_CONTEXT,
        timeout=IMAP_TIMEOUT if timeout is None else timeout,
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


def open_sieve(host: str, host_ip: str, port: int, username: str, password: str) -> Client:
    """Return a connected, authenticated, policy-checked ManageSieve client.

    Unlike `open_imap` this performs the login too, because sievelib fuses
    connect and authenticate into one call.
    """
    assert_host_resolves_to(host, host_ip)

    with _CONNECT_TIMEOUT_LOCK:
        previous_default = socket.getdefaulttimeout()
        socket.setdefaulttimeout(SIEVE_CONNECT_TIMEOUT)
        try:
            # srvaddr is the pinned IP; srvhostname keeps TLS SNI and cert
            # verification on the name the user typed. sievelib supports the
            # split natively, so no monkey-patch is needed.
            client = Client(host_ip, port, srvhostname=host)
            client.connect(username, password, starttls=True)
        finally:
            socket.setdefaulttimeout(previous_default)

    if client.sock is not None:
        client.sock.settimeout(SIEVE_IO_TIMEOUT)
    return client
