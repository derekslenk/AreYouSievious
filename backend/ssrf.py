"""
SSRF + DNS-rebinding guards for outbound IMAP / ManageSieve.

`_validate_host` resolves the hostname once and validates the answer
against the private/loopback/link-local deny-list. `_assert_host_resolves_to`
is the per-connect defence: each client `__enter__` re-resolves and aborts
if the hostname now answers with a different IP, which closes the DNS-
rebinding TOCTOU window that existed between validate-time and connect-time
(Sec H-1 / areyousievious-8ca).
"""

from __future__ import annotations

import ipaddress
import socket


class HostValidationError(Exception):
    """Raised on rejected hosts — caller decides the HTTP response."""


def _resolve(host: str) -> list[str]:
    """Return every IP `host` resolves to (v4 + v6) as plain strings.

    `socket.getaddrinfo` may include IPv4-mapped IPv6 (`::ffff:10.0.0.1`)
    which `ipaddress.ip_address.is_private` correctly classifies, so we
    leave the addresses as the kernel returns them.
    """
    try:
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise HostValidationError(f"Cannot resolve hostname: {host}") from e
    return [sockaddr[0] for _, _, _, _, sockaddr in results]


def _is_blocked(ip_str: str) -> bool:
    """True if the IP is private / loopback / reserved / link-local / multicast.

    Covers IPv4-mapped IPv6 (`::ffff:127.0.0.1`) via the `ipv4_mapped`
    attribute — without that check, a `127.0.0.1` lurking inside a v6
    address slips past.
    """
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_host(host: str) -> str:
    """Resolve `host`, reject if ANY answer points at a private destination,
    return the first non-blocked IP for the caller to pin.

    The caller MUST then use `assert_host_resolves_to(host, ip)` at each
    subsequent connect to detect a DNS-rebinding flip after validation.
    """
    ips = _resolve(host)
    if not ips:
        raise HostValidationError(f"Cannot resolve hostname: {host}")
    for ip in ips:
        if _is_blocked(ip):
            raise HostValidationError("Connection to private/internal addresses is not allowed")
    return ips[0]


def assert_host_resolves_to(host: str, expected_ip: str) -> None:
    """Re-resolve `host`; raise if the answer set no longer includes the IP
    we validated at login time.

    This is the rebinding guard: an attacker who flips the authoritative
    DNS answer between login-validation and a later connect MUST end up
    with an answer set that excludes `expected_ip` (the IP we
    originally vetted). When that happens we abort instead of dialing
    the now-private destination.
    """
    current = _resolve(host)
    if expected_ip in current:
        return
    raise HostValidationError(
        f"DNS for {host} no longer resolves to the validated IP — rebinding attempt blocked"
    )
