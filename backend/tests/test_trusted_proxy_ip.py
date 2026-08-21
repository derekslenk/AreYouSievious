"""
Trusted-proxy rate-limit IP detection (areyousievious-jt2, Sec H-7).

Without the gate, the login rate limiter reads `X-Real-IP` / `X-Forwarded-For`
from every request, and a direct client can spoof them to rotate fake source
IPs and defeat the 5-per-5-minutes throttle. Those headers are honoured only
when the immediate peer is itself in a trusted CIDR.

Every test here used to `monkeypatch.setenv("AYS_TRUSTED_PROXIES", …)` and rely
on an autouse `delenv` fixture, because `_get_client_ip` read the environment
and re-parsed the CIDRs on each call. It now takes a Settings, so the trusted
set is just an argument — no environment, no fixture, no cross-test leakage.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_trusted_proxy_ip.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock

from config import Settings, _parse_networks
from routers.auth import _get_client_ip


def _request(client_host: str | None, headers: dict[str, str] | None = None):
    """Minimal Request stub exposing only what _get_client_ip touches."""
    req = MagicMock()
    req.client = MagicMock(host=client_host) if client_host else None
    req.headers = headers or {}
    return req


def _cfg(*cidrs: str) -> Settings:
    return Settings(trusted_proxies=_parse_networks(",".join(cidrs)))


NO_PROXIES = Settings()


# ── Untrusted (direct) peer — proxy headers MUST be ignored ──


def test_direct_peer_ignores_x_real_ip():
    req = _request("198.51.100.7", {"x-real-ip": "8.8.8.8"})
    assert _get_client_ip(req, NO_PROXIES) == "198.51.100.7"


def test_direct_peer_ignores_x_forwarded_for():
    req = _request("198.51.100.7", {"x-forwarded-for": "1.1.1.1, 2.2.2.2"})
    assert _get_client_ip(req, NO_PROXIES) == "198.51.100.7"


def test_peer_outside_the_trusted_set_is_ignored():
    """Trusted CIDRs configured, but this request did not come through one."""
    req = _request("8.8.8.8", {"x-real-ip": "1.1.1.1"})
    assert _get_client_ip(req, _cfg("10.0.0.0/8")) == "8.8.8.8"


def test_no_client_returns_unknown():
    req = _request(None, {"x-real-ip": "8.8.8.8"})
    assert _get_client_ip(req, NO_PROXIES) == "unknown"


# ── Trusted peer — proxy headers honoured ──


def test_trusted_peer_honors_x_real_ip():
    req = _request("127.0.0.1", {"x-real-ip": "8.8.8.8"})
    assert _get_client_ip(req, _cfg("127.0.0.0/8")) == "8.8.8.8"


def test_trusted_peer_xff_uses_rightmost_untrusted_hop():
    """Canonical reverse-proxy parse: walk right-to-left, skipping known proxy
    hops, until the first untrusted entry — that is the real client."""
    req = _request("127.0.0.1", {"x-forwarded-for": "8.8.8.8, 10.1.1.1"})
    assert _get_client_ip(req, _cfg("127.0.0.0/8", "10.0.0.0/8")) == "8.8.8.8"


def test_trusted_peer_falls_back_to_direct_ip_when_all_xff_hops_trusted():
    """No real client to extract, so fall back to the direct peer rather than
    picking an arbitrary trusted-proxy address (areyousievious-1vp)."""
    req = _request("127.0.0.1", {"x-forwarded-for": "10.1.1.1, 10.2.2.2"})
    assert _get_client_ip(req, _cfg("127.0.0.0/8", "10.0.0.0/8")) == "127.0.0.1"


def test_x_real_ip_takes_precedence_over_xff():
    """F-10: X-Real-IP is authoritative (the proxy sets it from $remote_addr,
    unspoofable by the client), whereas XFF is only authoritative when the
    proxy sanitises it. Prefer X-Real-IP when both are present."""
    req = _request("127.0.0.1", {"x-forwarded-for": "8.8.8.8", "x-real-ip": "9.9.9.9"})
    assert _get_client_ip(req, _cfg("127.0.0.0/8")) == "9.9.9.9"


def test_rate_limit_key_is_not_movable_by_a_client_supplied_xff():
    """F-10 regression lock: an attacker rotating XFF values through a trusted
    proxy that sets X-Real-IP must keep landing in the same rate-limit bucket
    (CWE-300 + CWE-307)."""
    cfg = _cfg("127.0.0.0/8")
    attacker = "203.0.113.42"
    for spoofed in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "attacker.tld"):
        req = _request("127.0.0.1", {"x-forwarded-for": spoofed, "x-real-ip": attacker})
        assert _get_client_ip(req, cfg) == attacker, f"XFF={spoofed!r} moved the key"


def test_trusted_peer_without_headers_uses_direct_ip():
    req = _request("127.0.0.1")
    assert _get_client_ip(req, _cfg("127.0.0.0/8")) == "127.0.0.1"


def test_ipv6_trusted_proxy_honored():
    req = _request("::1", {"x-real-ip": "8.8.8.8"})
    assert _get_client_ip(req, _cfg("::1/128")) == "8.8.8.8"
