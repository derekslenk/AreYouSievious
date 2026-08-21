"""
Outbound TLS verification (Phase-CP1, Sec C-1 / CWE-295 / CVSS 9.1).

Without an explicit context, `imaplib.IMAP4_SSL` falls back to
`ssl._create_stdlib_context()`, which accepts ANY certificate — including a
self-signed one from an on-path MITM — and the client then sends the user's
plaintext password. Credential theft, silently.

These tests used to set AYS_IMAP_INSECURE and reload the module, because the
context was a module constant computed from the environment; one of them even
documented having to recover from pollution left by an earlier test. The
builder now takes a Settings.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_imap_tls.py -v
"""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import mail_dial
from auth import Session
from config import Settings


def test_default_context_verifies_chain_and_hostname():
    ctx = mail_dial.build_tls_context(Settings())
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_default_context_requires_tls_1_2_or_better():
    assert mail_dial.build_tls_context(Settings()).minimum_version >= ssl.TLSVersion.TLSv1_2


def test_insecure_setting_disables_verification_and_warns(caplog):
    with caplog.at_level("WARNING", logger="ays.dial"):
        ctx = mail_dial.build_tls_context(Settings(imap_insecure=True))
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False
    assert any("AYS_IMAP_INSECURE" in r.message for r in caplog.records), (
        "an operator turning off verification must see a warning"
    )


def test_insecure_env_var_reaches_settings(monkeypatch):
    """The env var is still the operator-facing switch; Settings is where it
    gets read, exactly once."""
    for value in ("1", "true", "yes", "TRUE", "Yes"):
        monkeypatch.setenv("AYS_IMAP_INSECURE", value)
        assert Settings.from_env().imap_insecure is True
    monkeypatch.setenv("AYS_IMAP_INSECURE", "0")
    assert Settings.from_env().imap_insecure is False
    monkeypatch.delenv("AYS_IMAP_INSECURE")
    assert Settings.from_env().imap_insecure is False


def test_tls_context_is_cached_per_configuration():
    """One context per configuration, not one per dial and not one per process.

    The argument-less cache this replaced held whatever vintage of the
    environment it was first built with, and clearing `config.settings`'s
    cache did not invalidate it. Keying on the frozen Settings makes a
    different configuration a different entry by construction — so two apps
    with different TLS policy cannot share a context (areyousievious-8fg.7).
    """
    default = Settings()
    assert mail_dial.build_tls_context(default) is mail_dial.build_tls_context(default)
    assert mail_dial.build_tls_context(default) is mail_dial.build_tls_context(Settings())
    assert mail_dial.build_tls_context(Settings(imap_insecure=True)) is not (
        mail_dial.build_tls_context(default)
    )


def test_open_imap_passes_the_verified_context():
    """The connection MUST be opened with our context, not the stdlib default."""
    session = Session(
        token="t",
        host="imap.example.com",
        host_ip="93.184.216.34",
        port_imap=993,
        port_sieve=4190,
        username="user@example.com",
        password="hunter2",
        created_at=0.0,
        last_used=0.0,
    )
    with (
        patch.object(mail_dial, "assert_host_resolves_to", lambda *a, **kw: None),
        patch.object(mail_dial, "_PinnedIMAP4_SSL") as mock_pinned,
    ):
        mock_pinned.return_value = MagicMock()
        mail_dial.open_imap(session.host, session.host_ip, session.port_imap, cfg=Settings())

    ctx = mock_pinned.call_args.kwargs["ssl_context"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
