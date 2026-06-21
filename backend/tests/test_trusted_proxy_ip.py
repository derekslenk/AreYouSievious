"""
Regression tests for the trusted-proxy rate-limit IP detection
(areyousievious-jt2, Sec H-7).

Without these checks, the login rate limiter reads `X-Real-IP` /
`X-Forwarded-For` from every request and a direct client can spoof those
headers to rotate fake source IPs, defeating the 5-attempts-per-5-min
throttle. Only requests whose immediate peer is itself in an
`AYS_TRUSTED_PROXIES` CIDR may set those headers.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_trusted_proxy_ip.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import app as app_mod


def _fake_request(client_host: str | None, headers: dict[str, str] | None = None):
    """Minimal Request stub exposing the attributes _get_client_ip touches."""
    req = MagicMock()
    req.client = MagicMock(host=client_host) if client_host else None
    req.headers = headers or {}
    return req


@pytest.fixture(autouse=True)
def _clear_trusted_env(monkeypatch):
    monkeypatch.delenv("AYS_TRUSTED_PROXIES", raising=False)


# ── Untrusted (direct) peer — proxy headers MUST be ignored ──


def test_direct_peer_ignores_x_real_ip():
    req = _fake_request("198.51.100.7", {"x-real-ip": "8.8.8.8"})
    assert app_mod._get_client_ip(req) == "198.51.100.7"


def test_direct_peer_ignores_x_forwarded_for():
    req = _fake_request("198.51.100.7", {"x-forwarded-for": "1.1.1.1, 2.2.2.2"})
    assert app_mod._get_client_ip(req) == "198.51.100.7"


def test_no_client_returns_unknown():
    req = _fake_request(None, {"x-real-ip": "8.8.8.8"})
    assert app_mod._get_client_ip(req) == "unknown"


# ── Trusted peer — proxy headers honored ──


def test_trusted_peer_honors_x_real_ip(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "127.0.0.0/8")
    req = _fake_request("127.0.0.1", {"x-real-ip": "8.8.8.8"})
    assert app_mod._get_client_ip(req) == "8.8.8.8"


def test_trusted_peer_xff_uses_rightmost_untrusted_hop(monkeypatch):
    """Canonical reverse-proxy parse: walk X-Forwarded-For right-to-left,
    skipping known proxy hops, until the first untrusted entry — that's
    the real client."""
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "127.0.0.0/8,10.0.0.0/8")
    req = _fake_request("127.0.0.1", {"x-forwarded-for": "8.8.8.8, 10.1.1.1"})
    assert app_mod._get_client_ip(req) == "8.8.8.8"


def test_trusted_peer_xff_falls_back_to_leftmost_when_all_hops_trusted(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "127.0.0.0/8,10.0.0.0/8")
    req = _fake_request("127.0.0.1", {"x-forwarded-for": "10.1.1.1, 10.2.2.2"})
    assert app_mod._get_client_ip(req) == "10.1.1.1"


def test_trusted_peer_xff_takes_precedence_over_x_real_ip(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "127.0.0.0/8")
    req = _fake_request(
        "127.0.0.1",
        {"x-forwarded-for": "8.8.8.8", "x-real-ip": "9.9.9.9"},
    )
    assert app_mod._get_client_ip(req) == "8.8.8.8"


def test_trusted_peer_without_headers_uses_direct_ip(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "127.0.0.0/8")
    req = _fake_request("127.0.0.1")
    assert app_mod._get_client_ip(req) == "127.0.0.1"


# ── Robust parsing ──


def test_invalid_cidrs_are_silently_skipped(monkeypatch):
    """Operator typo should not take the app down. We honor the valid CIDR
    portion and skip garbage."""
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "garbage,not-a-cidr,127.0.0.0/8")
    req = _fake_request("127.0.0.1", {"x-real-ip": "8.8.8.8"})
    assert app_mod._get_client_ip(req) == "8.8.8.8"


def test_all_invalid_cidrs_means_no_trust(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "not,a,cidr")
    req = _fake_request("127.0.0.1", {"x-real-ip": "8.8.8.8"})
    assert app_mod._get_client_ip(req) == "127.0.0.1"


def test_ipv6_trusted_proxy_honored(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "::1/128")
    req = _fake_request("::1", {"x-real-ip": "8.8.8.8"})
    assert app_mod._get_client_ip(req) == "8.8.8.8"


def test_whitespace_in_csv_tolerated(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", " 127.0.0.0/8 , 10.0.0.0/8 ")
    req = _fake_request("10.5.5.5", {"x-real-ip": "8.8.8.8"})
    assert app_mod._get_client_ip(req) == "8.8.8.8"
