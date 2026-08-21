"""
ManageSieve socket timeouts (areyousievious-pfo, Sec H-2 / Perf H1).

`sievelib.managesieve.Client.connect` calls `socket.create_connection` with no
timeout, so a blackhole upstream pins a threadpool worker for the OS default
(~2 minutes). The connect timeout is applied through the process-global
`socket.setdefaulttimeout` under a lock (see mail_dial), and the long-lived I/O
timeout is set on the live socket.

These tests used to reload the module six times, because the timeouts were
module constants computed at import. They are Settings fields now, so the
parsing and the wiring can be checked separately — and the wiring test states
the values it expects instead of arranging for the environment to produce them.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_managesieve_timeout.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import mail_dial
import pytest
from config import Settings

# ── Parsing: env -> Settings ──


def test_defaults_match_the_bead_spec(monkeypatch):
    monkeypatch.delenv("AYS_SIEVE_CONNECT_TIMEOUT", raising=False)
    monkeypatch.delenv("AYS_SIEVE_IO_TIMEOUT", raising=False)
    cfg = Settings.from_env()
    assert cfg.sieve_connect_timeout == 10.0
    assert cfg.sieve_io_timeout == 30.0


def test_env_overrides_apply(monkeypatch):
    monkeypatch.setenv("AYS_SIEVE_CONNECT_TIMEOUT", "3")
    monkeypatch.setenv("AYS_SIEVE_IO_TIMEOUT", "7.5")
    cfg = Settings.from_env()
    assert cfg.sieve_connect_timeout == 3.0
    assert cfg.sieve_io_timeout == 7.5


def test_unparseable_value_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("AYS_SIEVE_CONNECT_TIMEOUT", "not-a-float")
    assert Settings.from_env().sieve_connect_timeout == 10.0


@pytest.mark.parametrize("value", ["0", "-5", "0.0"])
def test_zero_or_negative_is_clamped(monkeypatch, value):
    """A literal 0 means "block forever" on a socket, so the floor stops an
    operator re-enabling indefinite hangs by typing the wrong number."""
    monkeypatch.setenv("AYS_SIEVE_CONNECT_TIMEOUT", value)
    assert Settings.from_env().sieve_connect_timeout >= 0.1


# ── Wiring: Settings -> sockets ──


# The timeouts under test, handed to open_sieve directly.
#
# This used to patch `mail_dial.settings` because the dial read a process
# global. Since areyousievious-8fg.7 the configuration is an argument, so a
# test states what it wants and passes it — there is no global left to stub,
# which is the same reason four Settings fields stopped being inert.
SIEVE_TIMEOUTS = Settings(sieve_connect_timeout=3.0, sieve_io_timeout=7.5)


def test_connect_timeout_is_set_before_the_client_then_restored():
    """The first setdefaulttimeout MUST be the connect timeout, so the socket
    created inside sievelib inherits it; the last MUST restore the previous
    value."""
    calls: list[float | None] = []
    mock_client = MagicMock(sock=MagicMock())

    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial.socket, "getdefaulttimeout", lambda: None),
        patch.object(mail_dial.socket, "setdefaulttimeout", calls.append),
        patch.object(mail_dial, "Client", return_value=mock_client),
    ):
        mail_dial.open_sieve("h.example.com", "93.184.216.34", 4190, "u", "p", cfg=SIEVE_TIMEOUTS)

    assert calls[0] == 3.0, f"first setdefaulttimeout was {calls[0]}, expected the connect timeout"
    assert calls[-1] is None, "the previous default was not restored"


def test_io_timeout_is_set_on_the_live_socket():
    mock_client = MagicMock(sock=MagicMock())
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "Client", return_value=mock_client),
    ):
        mail_dial.open_sieve("h.example.com", "93.184.216.34", 4190, "u", "p", cfg=SIEVE_TIMEOUTS)

    mock_client.sock.settimeout.assert_called_with(7.5)


def test_default_is_restored_even_when_connect_raises():
    """A failed connect must not poison the process-global timeout for the next
    request."""
    calls: list[float | None] = []
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial.socket, "getdefaulttimeout", lambda: None),
        patch.object(mail_dial.socket, "setdefaulttimeout", calls.append),
        patch.object(mail_dial, "Client", side_effect=RuntimeError("upstream down")),
    ):
        with pytest.raises(RuntimeError):
            mail_dial.open_sieve(
                "h.example.com", "93.184.216.34", 4190, "u", "p", cfg=SIEVE_TIMEOUTS
            )

    assert calls[0] == 3.0
    assert calls[-1] is None, "default NOT restored after a failed connect"
