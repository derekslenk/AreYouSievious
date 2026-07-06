"""Sieve script-name validation (areyousievious-2j9 / F-P0 / CWE-77 + CWE-93).

Separate module so ScriptNameError has a stable class identity across
managesieve_client and app reloads in the test suite — mirrors the
HostValidationError pattern in ssrf.py.

Mirrors the IMAP folder-name defense at imap_client.py (from -sv3): same
protocol-framing threat class (line-oriented ManageSieve, RFC 5804), same
forbidden character set (CR, LF, NUL, double-quote, backslash), and the
same reject-before-the-sink shape.
"""

from __future__ import annotations

import re


class ScriptNameError(ValueError):
    """Raised when a Sieve script name would break ManageSieve command framing.

    sievelib's upstream Client.__prepare_args wraps script-name bytes as
    b'"' + name + b'"' with ZERO escaping, so a name containing CR, LF, NUL,
    double-quote, or backslash lets the server interpret the suffix as a
    separate command (CWE-77 / CWE-93). We reject these BEFORE any sievelib
    call so the malformed frame never reaches the wire.

    Subclasses ValueError so existing except-ValueError handlers still catch
    it, while the specific class lets app.py map it to HTTP 400 without
    shadowing unrelated ValueError semantics.
    """


_FORBIDDEN_SIEVE_NAME_CHARS = re.compile(r'[\r\n\x00"\\]')

_MAX_SIEVE_NAME_LEN = 128


def validate_script_name(name: str) -> None:
    """Reject Sieve script names that would break ManageSieve framing.

    Raises ScriptNameError; callers propagate it out of the SieveClient
    method, and the router-layer FastAPI exception handler in app.py maps
    it to HTTP 400.
    """
    if not name:
        raise ScriptNameError("Script name is required")
    if _FORBIDDEN_SIEVE_NAME_CHARS.search(name):
        raise ScriptNameError("Script name contains forbidden characters")
    if len(name) > _MAX_SIEVE_NAME_LEN:
        raise ScriptNameError(f"Script name too long (max {_MAX_SIEVE_NAME_LEN} bytes)")
