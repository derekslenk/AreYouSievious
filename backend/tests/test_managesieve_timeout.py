"""
Regression tests for the ManageSieve socket timeouts (areyousievious-pfo,
Sec H-2 / Perf H1).

`sievelib.managesieve.Client.connect` calls `socket.create_connection`
without an explicit timeout, so a blackhole upstream pins the threadpool
worker for the OS default (~2 minutes). The wrapper sets the connect
timeout via `socket.setdefaulttimeout` (process-default trick) for the
window during which the socket is created, then sets the long-lived I/O
timeout via `sock.settimeout` on the live socket.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_managesieve_timeout.py -v
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import managesieve_client
from auth import Session


def _session() -> Session:
    return Session(
        token="t",
        host="sieve.example.com",
        host_ip="93.184.216.34",
        port_imap=993,
        port_sieve=4190,
        username="u",
        password="p",
        created_at=0.0,
        last_used=0.0,
    )


# ── Module-level defaults + env overrides ──


def test_default_connect_timeout_is_10s():
    """Bead spec default — 10s connect timeout."""
    assert managesieve_client.CONNECT_TIMEOUT == 10.0


def test_default_io_timeout_is_30s():
    """Bead spec default — 30s I/O timeout."""
    assert managesieve_client.IO_TIMEOUT == 30.0


def test_env_overrides_apply(monkeypatch):
    monkeypatch.setenv("AYS_SIEVE_CONNECT_TIMEOUT", "3")
    monkeypatch.setenv("AYS_SIEVE_IO_TIMEOUT", "7.5")
    try:
        importlib.reload(managesieve_client)
        assert managesieve_client.CONNECT_TIMEOUT == 3.0
        assert managesieve_client.IO_TIMEOUT == 7.5
    finally:
        monkeypatch.delenv("AYS_SIEVE_CONNECT_TIMEOUT", raising=False)
        monkeypatch.delenv("AYS_SIEVE_IO_TIMEOUT", raising=False)
        importlib.reload(managesieve_client)


def test_invalid_env_value_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("AYS_SIEVE_CONNECT_TIMEOUT", "not-a-float")
    try:
        importlib.reload(managesieve_client)
        assert managesieve_client.CONNECT_TIMEOUT == 10.0
    finally:
        monkeypatch.delenv("AYS_SIEVE_CONNECT_TIMEOUT", raising=False)
        importlib.reload(managesieve_client)


def test_zero_or_negative_env_value_clamped_to_minimum(monkeypatch):
    """A literal `0` would mean 'block forever' on sockets — the wrapper
    floors at 0.1s so the operator can't accidentally re-enable indefinite
    hangs by typing the wrong number."""
    monkeypatch.setenv("AYS_SIEVE_CONNECT_TIMEOUT", "0")
    try:
        importlib.reload(managesieve_client)
        assert managesieve_client.CONNECT_TIMEOUT >= 0.1
    finally:
        monkeypatch.delenv("AYS_SIEVE_CONNECT_TIMEOUT", raising=False)
        importlib.reload(managesieve_client)


# ── __enter__ wires the timeouts ──


def _stub_ssrf(monkeypatch):
    """Disable the rebinding guard for these timeout-focused tests —
    DNS-rebinding is covered by test_ssrf_rebinding.py."""
    monkeypatch.setattr(managesieve_client, "assert_host_resolves_to", lambda *a, **kw: None)


def test_enter_sets_connect_timeout_before_client_then_restores(monkeypatch):
    """The first `setdefaulttimeout` call MUST be CONNECT_TIMEOUT (so the
    socket inside sievelib's `create_connection` inherits it), the last
    call MUST restore the previous default."""
    _stub_ssrf(monkeypatch)

    set_calls: list[float | None] = []
    monkeypatch.setattr(
        managesieve_client.socket,
        "getdefaulttimeout",
        lambda: None,
    )

    def _record(t):
        set_calls.append(t)

    monkeypatch.setattr(managesieve_client.socket, "setdefaulttimeout", _record)

    mock_client = MagicMock()
    mock_client.sock = MagicMock()
    with patch.object(managesieve_client, "Client", return_value=mock_client):
        with managesieve_client.SieveClient(_session()):
            pass

    assert set_calls[0] == managesieve_client.CONNECT_TIMEOUT, (
        f"first setdefaulttimeout was {set_calls[0]}, expected "
        f"{managesieve_client.CONNECT_TIMEOUT} (was sievelib called before the timeout was set?)"
    )
    assert set_calls[-1] is None, (
        f"last setdefaulttimeout was {set_calls[-1]}, expected None (missing finally-block restore)"
    )


def test_enter_sets_io_timeout_on_live_socket(monkeypatch):
    """After connect succeeds, `sock.settimeout(IO_TIMEOUT)` MUST be called
    so reads/writes can't block indefinitely on a slow server."""
    _stub_ssrf(monkeypatch)

    mock_client = MagicMock()
    mock_client.sock = MagicMock()
    with patch.object(managesieve_client, "Client", return_value=mock_client):
        with managesieve_client.SieveClient(_session()):
            pass

    mock_client.sock.settimeout.assert_called_with(managesieve_client.IO_TIMEOUT)


def test_enter_restores_default_timeout_even_when_connect_raises(monkeypatch):
    """The previous default MUST be restored on the exception path so a
    failed connect doesn't poison the process-global timeout for the next
    request."""
    _stub_ssrf(monkeypatch)

    set_calls: list[float | None] = []
    monkeypatch.setattr(
        managesieve_client.socket,
        "getdefaulttimeout",
        lambda: None,
    )
    monkeypatch.setattr(
        managesieve_client.socket,
        "setdefaulttimeout",
        set_calls.append,
    )

    raising_client = MagicMock()
    raising_client.connect.side_effect = RuntimeError("upstream down")
    with patch.object(managesieve_client, "Client", return_value=raising_client):
        with pytest.raises(RuntimeError):
            with managesieve_client.SieveClient(_session()):
                pass

    assert set_calls[0] == managesieve_client.CONNECT_TIMEOUT
    assert set_calls[-1] is None, (
        "Default timeout NOT restored after connect failure — process-global state is now poisoned."
    )
