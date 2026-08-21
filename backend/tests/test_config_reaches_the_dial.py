"""
Configuration passed to create_app reaches the connection (areyousievious-8fg.7).

The probe this locks, run before the fix:

    create_app(Settings(imap_insecure=True, imap_timeout=1.0))
      app.state.settings.imap_timeout = 1.0
      mail_dial will actually use     = 10.0
      app says imap_insecure          = True
      mail_dial TLS built from        = False

Four of nine Settings fields were inert when passed to create_app: the app
honoured them and the dial did not, because `mail_dial` read the process-wide
`settings()` singleton instead of the configuration its caller was built with.
A dependency receives the request, so it reads `request.app.state.settings`
and passes that down — which is what closes the split.
"""

from __future__ import annotations

import ssl
from unittest.mock import patch

import mail_dial
import pytest
from app import create_app
from config import Settings

# The fields that were inert, with values no default would produce.
CONFIG = Settings(
    imap_insecure=True,
    imap_timeout=1.0,
    sieve_connect_timeout=2.0,
    sieve_io_timeout=3.0,
)


def _capture_imap_dial(cfg: Settings) -> dict:
    """Dial through open_imap and report what the connection was built with."""
    seen: dict = {}

    class _Capture:
        def __init__(self, host, host_ip, port, ssl_context, timeout):
            seen["timeout"] = timeout
            seen["ssl_context"] = ssl_context

    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "_PinnedIMAP4_SSL", _Capture),
    ):
        mail_dial.open_imap("mail.example.com", "93.184.216.34", 993, cfg=cfg)
    return seen


def test_imap_timeout_reaches_the_connection():
    assert _capture_imap_dial(CONFIG)["timeout"] == CONFIG.imap_timeout


def test_imap_insecure_reaches_the_tls_context():
    """The one with teeth: an app told to skip verification that silently
    verified anyway would be the safe direction, but the reverse — an app told
    to verify while the dial used a stale unverified context — is a silent
    downgrade to a MITM-able connection."""
    assert _capture_imap_dial(CONFIG)["ssl_context"].verify_mode == ssl.CERT_NONE
    assert _capture_imap_dial(Settings())["ssl_context"].verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("field", ["sieve_connect_timeout", "sieve_io_timeout"])
def test_sieve_timeouts_reach_the_dial(field):
    """Asserted through the socket calls open_sieve makes, since sievelib's
    Client is what carries them."""
    seen: dict = {}

    class _Client:
        def __init__(self, *a, **kw):
            self.sock = type("S", (), {"settimeout": lambda _s, v: seen.__setitem__("io", v)})()

        def connect(self, *a, **kw):
            seen["connect_default"] = __import__("socket").getdefaulttimeout()
            return True

    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "Client", _Client),
    ):
        mail_dial.open_sieve("mail.example.com", "93.184.216.34", 4190, "u", "p", cfg=CONFIG)

    got = {"sieve_connect_timeout": seen["connect_default"], "sieve_io_timeout": seen["io"]}
    assert got[field] == getattr(CONFIG, field)


def test_the_app_and_the_dial_cannot_hold_different_vintages():
    """Two caches with no relationship was the mechanism: `config.settings`
    and `mail_dial.tls_context` each memoised argument-lessly, so clearing one
    did not invalidate the other. Keyed on the frozen Settings, the app's
    configuration and the dial's context are the same object by construction.
    """
    app = create_app(CONFIG)
    assert app.state.settings is CONFIG
    assert _capture_imap_dial(app.state.settings)["ssl_context"] is mail_dial.build_tls_context(
        CONFIG
    )
