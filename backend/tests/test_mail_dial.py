"""
Tests for the module that owns dialling the user's mail server.

Connection policy used to be re-derived at each call site. That is what let
areyousievious-vzs fix the third-resolution TOCTOU twice — once as an imaplib
subclass for IMAPClient, once via sievelib's srvhostname for SieveClient — and
still leave the login handler building a stock `imaplib.IMAP4_SSL(host, …)`
that re-resolved the hostname after the rebinding guard had run.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_mail_dial.py -v
"""

from __future__ import annotations

import ast
import socket
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import mail_dial
import pytest
import ssrf
from config import Settings
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parent.parent


def _addrinfo(*ips: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


# ── The policy is applied, whoever calls ──


def test_open_imap_dials_the_pinned_ip_and_keeps_sni_on_the_hostname():
    """The whole point of the split: connect to the vetted address, but let
    TLS verify the certificate against the name the user typed."""
    instance = mail_dial._PinnedIMAP4_SSL.__new__(mail_dial._PinnedIMAP4_SSL)
    instance._pinned_ip = "93.184.216.34"
    instance.host = "mail.example.com"
    instance.port = 993
    ctx = MagicMock()
    instance.ssl_context = ctx

    with patch.object(mail_dial.socket, "create_connection") as mock_conn:
        instance._create_socket(10)

    assert mock_conn.call_args.args[0] == ("93.184.216.34", 993)
    assert ctx.wrap_socket.call_args.kwargs["server_hostname"] == "mail.example.com"


def test_open_imap_revalidates_dns_before_touching_the_network():
    """A rebinding must abort before a socket exists, not after."""
    with patch.object(ssrf.socket, "getaddrinfo", return_value=_addrinfo("10.0.0.5")):
        with patch.object(mail_dial, "_PinnedIMAP4_SSL") as mock_pinned:
            with pytest.raises(ssrf.HostValidationError, match="rebinding"):
                mail_dial.open_imap("example.com", "93.184.216.34", 993, cfg=Settings())
            mock_pinned.assert_not_called()


def test_open_sieve_revalidates_dns_before_touching_the_network():
    with patch.object(ssrf.socket, "getaddrinfo", return_value=_addrinfo("10.0.0.5")):
        with patch.object(mail_dial, "Client") as mock_client:
            with pytest.raises(ssrf.HostValidationError, match="rebinding"):
                mail_dial.open_sieve("example.com", "93.184.216.34", 4190, "u", "p", cfg=Settings())
            mock_client.assert_not_called()


def test_open_sieve_splits_dial_from_sni():
    with patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None):
        with patch.object(mail_dial, "Client") as mock_client:
            mock_client.return_value = MagicMock(sock=MagicMock())
            mail_dial.open_sieve(
                "sieve.example.com", "93.184.216.34", 4190, "u", "p", cfg=Settings()
            )

    assert mock_client.call_args.args[0] == "93.184.216.34"
    assert mock_client.call_args.kwargs["srvhostname"] == "sieve.example.com"


# ── The process-global timeout is no longer corruptible ──


def test_concurrent_sieve_connects_do_not_leak_the_process_default_timeout():
    """REGRESSION: sievelib offers no seam for a connect timeout, so it can
    only be set through the PROCESS-GLOBAL socket.setdefaulttimeout. Two
    threads interleaving save/restore used to strand the value permanently:

        A: previous=None, set 10.0
        B: previous=10.0 (!), set 10.0
        A: restore None
        B: restore 10.0   <- every socket in the process inherits it

    Reproduced before the lock existed. Every socket created afterwards —
    including unrelated IMAP connections — silently got a 10s timeout.
    """
    baseline = socket.getdefaulttimeout()
    errors: list[BaseException] = []

    def fake_client(*_a, **_kw):
        # Widen the window each thread spends with the global mutated. Without
        # the lock the save/restore interleaves and the value is stranded.
        time.sleep(0.02)
        return MagicMock(sock=MagicMock())

    def run():
        try:
            mail_dial.open_sieve("h.example.com", "93.184.216.34", 4190, "u", "p", cfg=Settings())
        except BaseException as exc:
            # Collected rather than raised: an exception in a worker thread
            # would otherwise vanish and the assertion below would pass on a
            # test that never actually connected.
            errors.append(exc)

    # Patch OUTSIDE the threads: patch.object is not thread-safe, and one
    # thread exiting the context would restore the real Client underneath the
    # others still running.
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "Client", side_effect=fake_client),
    ):
        threads = [threading.Thread(target=run) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

    assert not errors, f"connect raised: {errors}"
    assert socket.getdefaulttimeout() == baseline, (
        f"process default timeout leaked: {socket.getdefaulttimeout()!r} "
        f"(expected {baseline!r}) — the connect-window lock is missing or broken"
    )


def test_sieve_connect_restores_the_default_even_when_connect_raises():
    baseline = socket.getdefaulttimeout()
    with patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None):
        with patch.object(mail_dial, "Client", side_effect=RuntimeError("upstream down")):
            with pytest.raises(RuntimeError):
                mail_dial.open_sieve(
                    "h.example.com", "93.184.216.34", 4190, "u", "p", cfg=Settings()
                )
    assert socket.getdefaulttimeout() == baseline


# ── Nobody can bypass the module ──

_ALLOWED_TO_DIAL = {"mail_dial.py"}
_RAW_DIAL_CALLS = {"IMAP4_SSL", "Client", "create_connection"}


def _dialling_calls(path: Path) -> set[str]:
    """Names called in `path` that open a connection to the mail server."""
    tree = ast.parse(path.read_text())
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (
            func.attr
            if isinstance(func, ast.Attribute)
            else func.id
            if isinstance(func, ast.Name)
            else None
        )
        if name in _RAW_DIAL_CALLS:
            found.add(name)
    return found


@pytest.mark.parametrize(
    "path",
    sorted(
        p
        for p in BACKEND.rglob("*.py")
        if "tests" not in p.parts
        and "__pycache__" not in p.parts
        and p.name not in _ALLOWED_TO_DIAL
        and p.name != "fetch_grak_script.py"
    ),
    ids=lambda p: str(p.relative_to(BACKEND)),
)
def test_no_module_outside_mail_dial_opens_its_own_connection(path: Path) -> None:
    """ARCHITECTURAL LOCK: only mail_dial may dial the mail server.

    This is the property the whole module exists for. The login handler
    building its own `imaplib.IMAP4_SSL` is exactly how the rebinding fix was
    applied twice and still missed a caller — connection policy that lives in
    a class only protects callers who remember to use that class.

    If this fails, do not add the guard to the new call site. Route it through
    `mail_dial.open_imap` / `open_sieve` so the next caller cannot forget
    either.
    """
    offenders = _dialling_calls(path)
    assert not offenders, (
        f"{path.relative_to(BACKEND)} opens its own connection ({sorted(offenders)}). "
        f"Use mail_dial.open_imap / open_sieve instead."
    )


# ── The login path, specifically ──


@pytest.fixture(autouse=True)
def _reset_login_limiter():
    """login() is rate-limited 5/5min per IP; these tests share one client IP."""
    from routers import auth as auth_mod

    auth_mod._login_limiter._attempts.clear()
    yield
    auth_mod._login_limiter._attempts.clear()


def test_login_goes_through_the_pinned_dial(make_app):
    """REGRESSION (the candidate-04 gap): login used to build a stock
    imaplib.IMAP4_SSL(host, …), which re-resolves the hostname AFTER the
    rebinding guard ran — a live TOCTOU on the first connection the app makes,
    while IMAPClient and SieveClient were both already pinned."""
    with (
        patch.object(ssrf.socket, "getaddrinfo", return_value=_addrinfo("93.184.216.34")),
        patch.object(mail_dial, "_PinnedIMAP4_SSL") as mock_pinned,
    ):
        mock_pinned.return_value = MagicMock()
        with TestClient(make_app()) as client:
            r = client.post(
                "/api/auth/login",
                json={"host": "mail.example.com", "username": "u", "password": "p"},
            )

    assert r.status_code == 200, r.text
    mock_pinned.assert_called_once()
    assert mock_pinned.call_args.args[:3] == ("mail.example.com", "93.184.216.34", 993)


def test_login_aborts_on_rebinding_without_connecting(make_app):
    """DNS flips to a private address between validation and connect."""
    answers = iter([_addrinfo("93.184.216.34"), _addrinfo("10.0.0.5")])
    with (
        patch.object(ssrf.socket, "getaddrinfo", side_effect=lambda *a, **kw: next(answers)),
        patch.object(mail_dial, "_PinnedIMAP4_SSL") as mock_pinned,
    ):
        with TestClient(make_app()) as client:
            r = client.post(
                "/api/auth/login",
                json={"host": "attacker.example", "username": "u", "password": "p"},
            )

    assert r.status_code == 400, r.text
    mock_pinned.assert_not_called()
