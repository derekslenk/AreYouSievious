"""
Every environment variable this app reads, in one place.

Configuration used to be pulled from `os.environ` at whatever moment each
module happened to run: some at import (`app.py`'s docs gating, CORS origins,
`mail_dial`'s timeouts), some on every request (`AYS_TRUSTED_PROXIES` was
re-read and its CIDRs re-parsed per login), and `AYS_IMAP_INSECURE` at both —
read at call time but frozen at import time, two lifetimes for one switch.

With nothing to pass configuration across, the only way to vary it was
`importlib.reload`, used 13 times in the test suite — several purely to undo
global state in a `finally` block. `AYS_MAX_BODY_BYTES` ended up with no test
of its actual wiring at all, because reaching it meant reloading the app.

So: read the environment once, at the edge, into a frozen value. Two adapters
already existed for that seam — the real environment, and a Settings a test
constructs directly.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from functools import lru_cache

DEFAULT_MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB
DEFAULT_CORS_ORIGINS = "https://areyousievious.com"

_TRUTHY = ("1", "true", "yes")


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        # Floored so a literal 0 cannot mean "block forever" on a socket.
        return max(0.1, float(raw))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _parse_networks(raw: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse a CSV of CIDRs. Invalid entries are skipped — an operator typo
    should not take the app down — but an all-garbage value yields an empty
    tuple, which means proxy headers are never trusted."""
    nets = []
    for cidr in (c.strip() for c in raw.split(",") if c.strip()):
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return tuple(nets)


@dataclass(frozen=True)
class Settings:
    """Immutable configuration for one running app.

    Frozen because configuration that changes under a running request is how
    `AYS_IMAP_INSECURE` came to have two different lifetimes.
    """

    # ── HTTP surface ──
    env: str = "prod"
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    cors_origins: tuple[str, ...] = (DEFAULT_CORS_ORIGINS,)

    # ── Request provenance (Sec H-7) ──
    # Parsed once here rather than per request, which is what `_get_client_ip`
    # and `_is_secure` each used to do on every call.
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(
        default_factory=tuple
    )
    secure_cookies: bool = False

    # ── Outbound transport ──
    imap_insecure: bool = False
    imap_timeout: float = 10.0
    sieve_connect_timeout: float = 10.0
    sieve_io_timeout: float = 30.0

    @property
    def is_dev(self) -> bool:
        """Only an exact `dev` enables /docs, /redoc, /openapi.json. Anything
        else — including a typo like `develop` — is treated as production, so
        a mistake fails closed."""
        return self.env.strip().lower() == "dev"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            env=os.environ.get("AYS_ENV", "prod"),
            max_body_bytes=_env_int("AYS_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES),
            cors_origins=tuple(
                o.strip()
                for o in os.environ.get("AYS_CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",")
                if o.strip()
            ),
            trusted_proxies=_parse_networks(os.environ.get("AYS_TRUSTED_PROXIES", "")),
            secure_cookies=_env_bool("AYS_SECURE_COOKIES"),
            imap_insecure=_env_bool("AYS_IMAP_INSECURE"),
            imap_timeout=_env_float("AYS_IMAP_TIMEOUT", 10.0),
            sieve_connect_timeout=_env_float("AYS_SIEVE_CONNECT_TIMEOUT", 10.0),
            sieve_io_timeout=_env_float("AYS_SIEVE_IO_TIMEOUT", 30.0),
        )


@lru_cache(maxsize=1)
def settings() -> Settings:
    """The process-wide Settings, read from the environment once.

    Callers with no request context (the outbound clients) use this. Anything
    inside a request should prefer `request.app.state.settings`, so a test can
    build an app with different configuration instead of mutating os.environ.

    Tests that must change the environment call `settings.cache_clear()`.
    """
    return Settings.from_env()
