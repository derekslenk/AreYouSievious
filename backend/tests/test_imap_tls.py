"""
Regression tests locking in the outbound IMAP TLS verification fix
(Phase-CP1, Sec C-1 / CWE-295 / CVSS 9.1).

Without `ssl.create_default_context()` the stdlib `imaplib.IMAP4_SSL`
falls back to `ssl._create_stdlib_context()` which accepts ANY certificate,
including a self-signed cert from an on-path MITM. The next line of the
client sends the user's plaintext password — credential theft is silent.

These tests assert:
  1. Default context has cert + hostname verification on.
  2. `AYS_IMAP_INSECURE=1` produces an unverified context AND logs a warning.
  3. `IMAPClient.__enter__` passes the module-level `TLS_CONTEXT` to
     `imaplib.IMAP4_SSL` (catches a future refactor that drops `ssl_context=`).

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_imap_tls.py -v
"""

from __future__ import annotations

import importlib
import ssl
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import imap_client  # noqa: E402
from auth import Session  # noqa: E402


# ── _build_tls_context() ──


def test_default_context_verifies_chain_and_hostname(monkeypatch):
    """Default: verify_mode == CERT_REQUIRED AND check_hostname is True."""
    monkeypatch.delenv("AYS_IMAP_INSECURE", raising=False)
    ctx = imap_client._build_tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_insecure_env_var_disables_verification_and_warns(monkeypatch, caplog):
    """AYS_IMAP_INSECURE=1: unverified context + warning."""
    monkeypatch.setenv("AYS_IMAP_INSECURE", "1")
    with caplog.at_level("WARNING", logger="ays.imap"):
        ctx = imap_client._build_tls_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False
    assert any("AYS_IMAP_INSECURE" in r.message for r in caplog.records), (
        "Operator must see a warning when verification is off"
    )


@pytest.mark.parametrize("val", ["1", "true", "yes", "TRUE", "Yes"])
def test_insecure_env_var_accepts_truthy_values(monkeypatch, val):
    monkeypatch.setenv("AYS_IMAP_INSECURE", val)
    ctx = imap_client._build_tls_context()
    assert ctx.verify_mode == ssl.CERT_NONE


# ── IMAPClient.__enter__ passes the verified context to IMAP4_SSL ──


def test_imap_client_enter_passes_ssl_context_kwarg():
    """The connection MUST be opened with our ssl_context, not the stdlib default."""
    session = Session(
        token="t",
        host="imap.example.com",
        port_imap=993,
        port_sieve=4190,
        username="user@example.com",
        password="hunter2",
        created_at=0.0,
        last_used=0.0,
    )
    with patch.object(imap_client.imaplib, "IMAP4_SSL") as mock_ssl:
        mock_conn = MagicMock()
        mock_ssl.return_value = mock_conn
        with imap_client.IMAPClient(session):
            pass

    mock_ssl.assert_called_once()
    kwargs = mock_ssl.call_args.kwargs
    assert "ssl_context" in kwargs, "ssl_context kwarg missing — stdlib default would silently accept any cert"
    ctx = kwargs["ssl_context"]
    assert isinstance(ctx, ssl.SSLContext)
    # The context that ships with the module must verify by default.
    # (We re-build it here to catch a test pollution where TLS_CONTEXT was
    # constructed under AYS_IMAP_INSECURE=1 from an earlier test.)
    if not ctx.check_hostname:
        # Module was loaded with INSECURE — re-import without it to confirm
        # the production default verifies.
        import os
        os.environ.pop("AYS_IMAP_INSECURE", None)
        importlib.reload(imap_client)
        ctx = imap_client.TLS_CONTEXT
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
