"""
Names that are safe to embed in a line-oriented protocol frame.

ManageSieve (RFC 5804) and IMAP (RFC 3501) share a hazard: a name is written
into the command as a bare quoted string with no escaping, so a name
containing CR, LF, NUL, a double-quote, or a backslash lets the server read
the suffix as a separate command (CWE-77 / CWE-93).

That is one rule, and it used to live in two places. The Sieve half shipped in
areyousievious-2j9, the IMAP half in areyousievious-sv3 — two commits, two
byte-identical regexes, two exception types, two ways of turning the rejection
into an HTTP 400, and two test matrices whose own comment asked humans to
"keep them aligned". A rule that asks to be kept in sync by hand is a module
waiting to be written.

Callers raise `ProtocolNameError`; `app.py` maps it to HTTP 400 in one place.
"""

from __future__ import annotations

import re


class ProtocolNameError(ValueError):
    """Raised when a name would break protocol command framing.

    Subclasses `ValueError` so existing `except ValueError` handlers still
    catch it, while the specific class lets `app.py` map it to HTTP 400
    without swallowing unrelated `ValueError` semantics.
    """


# CR, LF, NUL, double-quote, backslash. Shared by every protocol sink — if a
# new framing character is discovered, it is fixed here once.
_FORBIDDEN_CHARS = re.compile(r'[\r\n\x00"\\]')

# RFC 5804 §1.6 recommends 128 bytes for a Sieve script name. Enforced as the
# ceiling so an oversized name cannot waste ManageSieve socket time.
MAX_SCRIPT_NAME_BYTES = 128


def _validate(name: str, *, label: str, max_bytes: int | None) -> None:
    if not name:
        raise ProtocolNameError(f"{label} is required")
    if _FORBIDDEN_CHARS.search(name):
        raise ProtocolNameError(f"{label} contains forbidden characters")
    if max_bytes is not None and len(name) > max_bytes:
        raise ProtocolNameError(f"{label} too long (max {max_bytes} bytes)")


def validate_script_name(name: str) -> None:
    """Reject Sieve script names that would break ManageSieve framing.

    sievelib's `Client.__prepare_args` wraps script-name bytes as
    `b'"' + name + b'"'` with ZERO escaping, so this must run before any
    sievelib call — the malformed frame must never reach the wire.
    """
    _validate(name, label="Script name", max_bytes=MAX_SCRIPT_NAME_BYTES)


def validate_folder_name(name: str) -> None:
    """Reject IMAP folder names that would break IMAP framing.

    No length ceiling here: IMAP sets none, and the API surface is already
    capped by `CreateFolderRequest.name` (max_length=200). Adding a second,
    different limit would be the same duplication this module exists to end.
    """
    _validate(name, label="Folder name", max_bytes=None)
