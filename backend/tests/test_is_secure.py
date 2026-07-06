"""
Regression tests for the trusted-proxy gate on X-Forwarded-Proto
(areyousievious-av5, F-2, CWE-290 + CWE-346).

Without the gate, `_is_secure()` reads `X-Forwarded-Proto` from ANY client.
An attacker over HTTP can send `X-Forwarded-Proto: https` to force cookies
with `Secure=True`. When the browser later tries to send those cookies over
HTTP, it refuses -- session silently breaks after login. On-path attacker
over HTTP can send `X-Forwarded-Proto: http` to force non-Secure cookies
that leak on future HTTP redirects.

Mirrors the trusted-proxy gate pattern from `_get_client_ip` (introduced by
areyousievious-jt2, extended by areyousievious-1vp).

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_is_secure.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from routers import auth as app_mod


def _fake_request(client_host: str | None, headers: dict[str, str] | None = None):
    """Minimal Request stub exposing only the attributes _is_secure touches."""
    req = MagicMock()
    req.client = MagicMock(host=client_host) if client_host else None
    req.headers = headers or {}
    return req


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("AYS_TRUSTED_PROXIES", raising=False)
    monkeypatch.delenv("AYS_SECURE_COOKIES", raising=False)


# ── Direct (untrusted) peer — X-Forwarded-Proto MUST be ignored ──


def test_direct_peer_ignores_x_forwarded_proto_https():
    """F-2 primary attack: attacker over HTTP sends `X-Forwarded-Proto: https`.
    Guard denies (direct peer isn't a trusted proxy), cookies stay not-Secure,
    session doesn't break on subsequent HTTP requests."""
    req = _fake_request("198.51.100.7", {"x-forwarded-proto": "https"})
    assert app_mod._is_secure(req) is False


def test_direct_peer_ignores_x_forwarded_proto_http():
    """Reverse variant: attacker forces non-Secure over HTTPS by sending
    `X-Forwarded-Proto: http`. Guard denies -- header is not authoritative
    from an untrusted peer."""
    req = _fake_request("198.51.100.7", {"x-forwarded-proto": "http"})
    assert app_mod._is_secure(req) is False


def test_direct_peer_without_headers_is_not_secure():
    req = _fake_request("198.51.100.7")
    assert app_mod._is_secure(req) is False


def test_no_client_returns_not_secure():
    req = _fake_request(None, {"x-forwarded-proto": "https"})
    assert app_mod._is_secure(req) is False


# ── Trusted peer — X-Forwarded-Proto is honored ──


def test_trusted_peer_honors_x_forwarded_proto_https(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "127.0.0.0/8")
    req = _fake_request("127.0.0.1", {"x-forwarded-proto": "https"})
    assert app_mod._is_secure(req) is True


def test_trusted_peer_x_forwarded_proto_http_not_secure(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "127.0.0.0/8")
    req = _fake_request("127.0.0.1", {"x-forwarded-proto": "http"})
    assert app_mod._is_secure(req) is False


def test_trusted_peer_without_proto_not_secure(monkeypatch):
    """Trusted peer but no X-Forwarded-Proto header -- default is not-Secure.
    Prevents silent-Secure regressions when a misconfigured proxy stops
    forwarding the header."""
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "127.0.0.0/8")
    req = _fake_request("127.0.0.1")
    assert app_mod._is_secure(req) is False


def test_trusted_peer_ipv6(monkeypatch):
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "::1/128")
    req = _fake_request("::1", {"x-forwarded-proto": "https"})
    assert app_mod._is_secure(req) is True


# ── AYS_SECURE_COOKIES env override always wins ──


@pytest.mark.parametrize("val", ["1", "true", "yes", "TRUE", "Yes"])
def test_env_override_forces_secure_even_from_direct_peer(monkeypatch, val):
    """Explicit operator opt-in via env -- forces Secure regardless of headers
    or peer. This is the deploy escape hatch for HTTPS reverse-proxy setups
    that don't set X-Forwarded-Proto."""
    monkeypatch.setenv("AYS_SECURE_COOKIES", val)
    req = _fake_request("198.51.100.7", {"x-forwarded-proto": "http"})
    assert app_mod._is_secure(req) is True


def test_env_override_forces_secure_without_headers(monkeypatch):
    monkeypatch.setenv("AYS_SECURE_COOKIES", "true")
    req = _fake_request("127.0.0.1")
    assert app_mod._is_secure(req) is True


# ── F-2 regression locks ──


def test_ays_av5_attacker_cannot_spoof_secure_without_trusted_proxies_env(monkeypatch):
    """F-2 regression: no AYS_TRUSTED_PROXIES set. An attacker sending
    `X-Forwarded-Proto: https` from the public internet cannot influence
    the Secure-cookie decision, regardless of whether they claim to be
    a proxy IP."""
    # Explicitly ensure no trusted CIDRs are configured
    req = _fake_request(
        "203.0.113.42",
        {"x-forwarded-proto": "https"},
    )
    assert app_mod._is_secure(req) is False


def test_ays_av5_attacker_at_untrusted_peer_ignored(monkeypatch):
    """F-2 regression: AYS_TRUSTED_PROXIES set to 10.0.0.0/8, request from
    8.8.8.8 (untrusted). X-Forwarded-Proto must be ignored -- attacker
    outside the trusted CIDR cannot force Secure."""
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "10.0.0.0/8")
    req = _fake_request("8.8.8.8", {"x-forwarded-proto": "https"})
    assert app_mod._is_secure(req) is False


def test_ays_av5_env_wins_over_untrusted_peer_denial(monkeypatch):
    """Env override precedence: even with AYS_TRUSTED_PROXIES set and the
    request coming from an untrusted peer, AYS_SECURE_COOKIES=true wins.
    Confirms the two mechanisms are orthogonal and env is the ultimate
    escape hatch."""
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "10.0.0.0/8")
    monkeypatch.setenv("AYS_SECURE_COOKIES", "true")
    req = _fake_request("8.8.8.8", {"x-forwarded-proto": "http"})
    assert app_mod._is_secure(req) is True
