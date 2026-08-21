"""
Trusted-proxy gate on X-Forwarded-Proto (areyousievious-av5, F-2,
CWE-290 + CWE-346).

Without the gate, `_is_secure` reads `X-Forwarded-Proto` from ANY client. An
attacker over HTTP sends `X-Forwarded-Proto: https` to force `Secure=True`
cookies; the browser then refuses to send them over HTTP and the session
silently breaks after login. The reverse variant forces non-Secure cookies
that leak on a later HTTP redirect.

These tests used to juggle two environment variables through monkeypatch with
an autouse `delenv` fixture. `_is_secure` now takes a Settings, so both knobs
are ordinary arguments.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_is_secure.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock

from config import Settings, _parse_networks
from routers.auth import _is_secure


def _request(client_host: str | None, headers: dict[str, str] | None = None):
    req = MagicMock()
    req.client = MagicMock(host=client_host) if client_host else None
    req.headers = headers or {}
    return req


def _cfg(*cidrs: str, secure_cookies: bool = False) -> Settings:
    return Settings(
        trusted_proxies=_parse_networks(",".join(cidrs)),
        secure_cookies=secure_cookies,
    )


NO_PROXIES = Settings()


# ── Direct (untrusted) peer — X-Forwarded-Proto MUST be ignored ──


def test_direct_peer_ignores_forwarded_proto_https():
    """F-2 primary attack: an attacker over HTTP claims https, which would
    force Secure cookies and break their own session — or someone else's."""
    assert _is_secure(_request("198.51.100.7", {"x-forwarded-proto": "https"}), NO_PROXIES) is False


def test_direct_peer_ignores_forwarded_proto_http():
    """Reverse variant: force non-Secure cookies while actually on HTTPS."""
    assert _is_secure(_request("198.51.100.7", {"x-forwarded-proto": "http"}), NO_PROXIES) is False


def test_direct_peer_without_headers_is_not_secure():
    assert _is_secure(_request("198.51.100.7"), NO_PROXIES) is False


def test_no_client_is_not_secure():
    assert _is_secure(_request(None, {"x-forwarded-proto": "https"}), NO_PROXIES) is False


def test_peer_outside_the_trusted_set_is_ignored():
    """Trusted CIDRs configured, but the request did not arrive through one."""
    assert (
        _is_secure(_request("8.8.8.8", {"x-forwarded-proto": "https"}), _cfg("10.0.0.0/8")) is False
    )


# ── Trusted peer — the header is authoritative ──


def test_trusted_peer_honors_forwarded_proto_https():
    assert (
        _is_secure(_request("127.0.0.1", {"x-forwarded-proto": "https"}), _cfg("127.0.0.0/8"))
        is True
    )


def test_trusted_peer_forwarded_proto_http_is_not_secure():
    assert (
        _is_secure(_request("127.0.0.1", {"x-forwarded-proto": "http"}), _cfg("127.0.0.0/8"))
        is False
    )


def test_trusted_peer_without_the_header_is_not_secure():
    """Defaults closed, so a proxy that stops forwarding the header degrades to
    non-Secure rather than silently claiming Secure."""
    assert _is_secure(_request("127.0.0.1"), _cfg("127.0.0.0/8")) is False


def test_trusted_peer_ipv6():
    assert _is_secure(_request("::1", {"x-forwarded-proto": "https"}), _cfg("::1/128")) is True


# ── The explicit operator override wins ──


def test_secure_cookies_setting_forces_secure_from_any_peer():
    """The deploy escape hatch for an HTTPS reverse proxy that does not set
    X-Forwarded-Proto. Orthogonal to the trusted-peer gate."""
    req = _request("198.51.100.7", {"x-forwarded-proto": "http"})
    assert _is_secure(req, _cfg(secure_cookies=True)) is True


def test_secure_cookies_setting_wins_over_an_untrusted_peer_denial():
    req = _request("8.8.8.8", {"x-forwarded-proto": "http"})
    assert _is_secure(req, _cfg("10.0.0.0/8", secure_cookies=True)) is True
