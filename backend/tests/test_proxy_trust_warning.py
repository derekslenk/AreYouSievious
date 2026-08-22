"""
The startup warning for an unset AYS_TRUSTED_PROXIES (Coolify deploy).

`_get_client_ip` falls back to the direct peer when no proxy is trusted, which
is correct and deliberate — trusting `X-Forwarded-For` from anyone is the F-2
hole (CWE-290/348). But behind a reverse proxy the direct peer is the PROXY,
for every request, so the login limiter's 5-attempts-per-5-minutes bucket is
shared by every user of the instance. Five failed logins lock out everybody.

Nothing about that is visible: the app starts, serves, and throttles. It only
shows up as "nobody can log in" some minutes after a stranger typed a password
wrong. So the app says so at startup instead.

The DEFAULT IS NOT CHANGED. Defaulting to "trust the private ranges" would
make a proxied deploy work with no configuration and hand anything on the same
network the ability to spoof past the throttle — reversing the fix that put
this gate here.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_proxy_trust_warning.py -v
"""

from __future__ import annotations

import ipaddress
import logging

import pytest
from app import create_app
from config import Settings


def test_an_empty_trusted_proxy_list_warns_at_startup(caplog) -> None:
    """The whole point: a deploy behind a proxy with no configuration gets
    told, in the log Coolify shows, what it is about to do."""
    with caplog.at_level(logging.WARNING):
        create_app(Settings())

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1, f"expected exactly one warning, got {warnings}"
    message = warnings[0].getMessage()
    assert "AYS_TRUSTED_PROXIES" in message, "name the variable to set"
    assert "rate limit" in message.lower(), "name the consequence, not just the setting"


def test_a_configured_trusted_proxy_list_is_silent(caplog) -> None:
    """A warning that fires when the thing is configured correctly is a
    warning people learn to scroll past."""
    with caplog.at_level(logging.WARNING):
        create_app(Settings(trusted_proxies=(ipaddress.ip_network("10.0.0.0/8"),)))

    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


@pytest.mark.parametrize("env", ["prod", "dev", ""])
def test_the_warning_does_not_depend_on_env(caplog, env: str) -> None:
    """`AYS_ENV=dev` gates the docs, not this. A dev deploy behind a proxy
    has exactly the same shared-bucket problem."""
    with caplog.at_level(logging.WARNING):
        create_app(Settings(env=env))
    assert [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_it_is_a_log_record_and_not_a_print(capsys, caplog) -> None:
    """`print` is what the static-dir warning in `main()` uses, and it goes to
    stdout unstructured. This one has to survive whatever the platform does
    with its logs, so it is a WARNING on a named logger — which is also why
    the rest of the suite can build a thousand apps without it becoming noise
    anyone has to filter.
    """
    with caplog.at_level(logging.WARNING):
        create_app(Settings())

    assert "AYS_TRUSTED_PROXIES" not in capsys.readouterr().out
    (record,) = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert record.name.startswith("app"), f"unexpected logger {record.name!r}"
