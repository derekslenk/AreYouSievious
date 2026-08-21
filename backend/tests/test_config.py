"""
Settings — the one place the environment is read.

Parsing lived scattered across the modules that consumed it, so these cases
were previously tested (where they were tested at all) through whichever
consumer happened to own them: CIDR parsing through `_get_client_ip`, timeout
clamping through a module reload. They belong here.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_config.py -v
"""

from __future__ import annotations

import dataclasses
import ipaddress

import pytest
from config import DEFAULT_CORS_ORIGINS, Settings, _parse_networks, settings

# ── Defaults are the production posture ──


def test_defaults_are_safe():
    cfg = Settings()
    assert cfg.is_dev is False, "docs must be closed by default"
    assert cfg.trusted_proxies == (), "proxy headers must not be trusted by default"
    assert cfg.secure_cookies is False
    assert cfg.imap_insecure is False, "TLS verification must be on by default"
    assert cfg.max_body_bytes == 1 * 1024 * 1024
    assert cfg.cors_origins == (DEFAULT_CORS_ORIGINS,)


def test_settings_are_frozen():
    """Configuration that changes under a running request is how
    AYS_IMAP_INSECURE ended up with two different lifetimes."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        Settings().env = "dev"  # type: ignore[misc]


# ── is_dev fails closed ──


@pytest.mark.parametrize("value", ["dev", "DEV", " dev ", "Dev"])
def test_is_dev_accepts_dev_in_any_case(value):
    assert Settings(env=value).is_dev is True


@pytest.mark.parametrize("value", ["", "prod", "production", "develop", "development", "staging"])
def test_is_dev_rejects_everything_else(value):
    """A near-miss like `develop` must NOT open the docs."""
    assert Settings(env=value).is_dev is False


# ── CIDR parsing ──


def test_parse_networks_accepts_ipv4_and_ipv6():
    nets = _parse_networks("127.0.0.0/8, ::1/128")
    assert ipaddress.ip_address("127.0.0.1") in nets[0]
    assert ipaddress.ip_address("::1") in nets[1]


def test_parse_networks_tolerates_whitespace():
    assert len(_parse_networks(" 127.0.0.0/8 , 10.0.0.0/8 ")) == 2


def test_parse_networks_skips_invalid_entries():
    """An operator typo should not take the app down; the valid part is kept."""
    nets = _parse_networks("garbage,not-a-cidr,127.0.0.0/8")
    assert len(nets) == 1
    assert ipaddress.ip_address("127.0.0.1") in nets[0]


def test_parse_networks_all_invalid_means_no_trust():
    """Fails closed: nothing parsed means proxy headers are never honoured."""
    assert _parse_networks("not,a,cidr") == ()


def test_parse_networks_empty_string():
    assert _parse_networks("") == ()


# ── from_env ──


def test_from_env_reads_every_knob(monkeypatch):
    monkeypatch.setenv("AYS_ENV", "dev")
    monkeypatch.setenv("AYS_MAX_BODY_BYTES", "2048")
    monkeypatch.setenv("AYS_CORS_ORIGINS", "https://a.test, https://b.test")
    monkeypatch.setenv("AYS_TRUSTED_PROXIES", "10.0.0.0/8")
    monkeypatch.setenv("AYS_SECURE_COOKIES", "yes")
    monkeypatch.setenv("AYS_IMAP_INSECURE", "1")
    monkeypatch.setenv("AYS_IMAP_TIMEOUT", "5")
    monkeypatch.setenv("AYS_SIEVE_CONNECT_TIMEOUT", "6")
    monkeypatch.setenv("AYS_SIEVE_IO_TIMEOUT", "7")

    cfg = Settings.from_env()
    assert cfg.is_dev is True
    assert cfg.max_body_bytes == 2048
    assert cfg.cors_origins == ("https://a.test", "https://b.test")
    assert len(cfg.trusted_proxies) == 1
    assert cfg.secure_cookies is True
    assert cfg.imap_insecure is True
    assert (cfg.imap_timeout, cfg.sieve_connect_timeout, cfg.sieve_io_timeout) == (5.0, 6.0, 7.0)


@pytest.mark.parametrize("value", ["0", "no", "false", "", "off", "2"])
def test_bool_knobs_only_accept_known_truthy_values(monkeypatch, value):
    """Anything unrecognised means off, so a typo cannot silently disable TLS
    verification."""
    monkeypatch.setenv("AYS_IMAP_INSECURE", value)
    assert Settings.from_env().imap_insecure is False


def test_from_env_ignores_empty_cors_entries(monkeypatch):
    monkeypatch.setenv("AYS_CORS_ORIGINS", "https://a.test,,  ,https://b.test")
    assert Settings.from_env().cors_origins == ("https://a.test", "https://b.test")


# ── The process-wide accessor ──


def test_settings_accessor_is_cached():
    assert settings() is settings()


def test_settings_accessor_can_be_reset(monkeypatch):
    """The seam that replaced `importlib.reload` for tests that must change the
    environment."""
    settings.cache_clear()
    monkeypatch.setenv("AYS_ENV", "dev")
    try:
        assert settings().is_dev is True
    finally:
        monkeypatch.delenv("AYS_ENV", raising=False)
        settings.cache_clear()
    assert settings().is_dev is False
