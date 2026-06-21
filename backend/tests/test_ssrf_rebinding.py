"""
Regression tests for the SSRF / DNS-rebinding guard (areyousievious-8ca,
Sec H-1).

`validate_host` rejects private/loopback/link-local/multicast/IPv4-mapped-v6
answers at login time and returns the IP it pinned. `assert_host_resolves_to`
is the per-connect defence: re-resolves and raises HostValidationError if
the hostname now answers with a different IP, closing the TOCTOU window
that DNS rebinding relies on.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_ssrf_rebinding.py -v
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import imap_client
import ssrf
from auth import Session


def _addrinfo(*ips: str):
    """Build a getaddrinfo-shaped result that resolves to the given IPs."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


def _session(host: str = "example.com", host_ip: str = "93.184.216.34") -> Session:
    return Session(
        token="t",
        host=host,
        host_ip=host_ip,
        port_imap=993,
        port_sieve=4190,
        username="u",
        password="p",
        created_at=0.0,
        last_used=0.0,
    )


# ── validate_host ──


def test_validate_host_returns_first_public_ip():
    with patch.object(ssrf.socket, "getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        assert ssrf.validate_host("example.com") == "93.184.216.34"


@pytest.mark.parametrize(
    "blocked_ip,reason",
    [
        ("10.0.0.5", "private"),
        ("192.168.1.1", "private"),
        ("172.16.5.4", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.169.254", "link-local (AWS metadata)"),
        ("0.0.0.0", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("::1", "ipv6 loopback"),
        ("fe80::1", "ipv6 link-local"),
    ],
    ids=lambda v: v if (isinstance(v, str) and "." in v) or ":" in v else str(v),
)
def test_validate_host_rejects_blocked_ranges(blocked_ip, reason):
    with patch.object(ssrf.socket, "getaddrinfo", return_value=_addrinfo(blocked_ip)):
        with pytest.raises(ssrf.HostValidationError):
            ssrf.validate_host("attacker.example")


def test_validate_host_rejects_ipv4_mapped_ipv6_loopback():
    """A `::ffff:127.0.0.1` answer must NOT slip past by virtue of being a
    v6 address — `ipv4_mapped` collapses it to the v4 view where
    is_loopback works correctly."""
    with patch.object(ssrf.socket, "getaddrinfo", return_value=_addrinfo("::ffff:127.0.0.1")):
        with pytest.raises(ssrf.HostValidationError):
            ssrf.validate_host("sneaky.example")


def test_validate_host_rejects_when_any_answer_is_blocked():
    """If `getaddrinfo` returns BOTH a public and a private IP (DNS round-
    robin abuse), the whole hostname must be rejected — we don't get to
    pick a 'safe' one because the next resolution could return the private
    answer first."""
    with patch.object(
        ssrf.socket,
        "getaddrinfo",
        return_value=_addrinfo("93.184.216.34", "10.0.0.5"),
    ):
        with pytest.raises(ssrf.HostValidationError):
            ssrf.validate_host("mixed.example")


def test_validate_host_rejects_unresolvable():
    with patch.object(ssrf.socket, "getaddrinfo", side_effect=socket.gaierror):
        with pytest.raises(ssrf.HostValidationError):
            ssrf.validate_host("nope.invalid")


# ── assert_host_resolves_to ──


def test_assert_passes_when_expected_ip_in_answer():
    with patch.object(ssrf.socket, "getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        ssrf.assert_host_resolves_to("example.com", "93.184.216.34")


def test_assert_passes_when_expected_ip_in_multi_answer():
    with patch.object(
        ssrf.socket,
        "getaddrinfo",
        return_value=_addrinfo("198.51.100.1", "93.184.216.34"),
    ):
        ssrf.assert_host_resolves_to("example.com", "93.184.216.34")


def test_assert_raises_when_expected_ip_absent():
    """The H-1 rebinding signature: validation pinned a public IP, but the
    hostname now answers with a different (private) IP only."""
    with patch.object(ssrf.socket, "getaddrinfo", return_value=_addrinfo("10.0.0.5")):
        with pytest.raises(ssrf.HostValidationError, match="rebinding"):
            ssrf.assert_host_resolves_to("example.com", "93.184.216.34")


# ── End-to-end: full attack scenario ──


def test_full_rebinding_attack_blocked(monkeypatch):
    """Sec H-1 attack flow: validate sees public IP, then DNS flips to
    private for the very next resolution. The assert MUST fail closed."""
    answers = iter([_addrinfo("93.184.216.34"), _addrinfo("10.0.0.5")])
    monkeypatch.setattr(
        ssrf.socket,
        "getaddrinfo",
        lambda *_a, **_kw: next(answers),
    )

    pinned = ssrf.validate_host("attacker.example")
    assert pinned == "93.184.216.34"
    with pytest.raises(ssrf.HostValidationError, match="rebinding"):
        ssrf.assert_host_resolves_to("attacker.example", pinned)


def test_imap_client_aborts_on_rebinding_before_touching_network():
    """IMAPClient.__enter__ MUST re-validate BEFORE constructing IMAP4_SSL
    so a rebinding never reaches the socket layer.

    If a future refactor moves assert_host_resolves_to after the
    IMAP4_SSL call, the mock would be called and this assertion goes red.
    """
    session = _session()
    with patch.object(ssrf.socket, "getaddrinfo", return_value=_addrinfo("10.0.0.5")):
        with patch.object(imap_client.imaplib, "IMAP4_SSL") as mock_ssl:
            with pytest.raises(ssrf.HostValidationError, match="rebinding"):
                with imap_client.IMAPClient(session):
                    pass
            mock_ssl.assert_not_called()
