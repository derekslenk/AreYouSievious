"""
The vocabulary the mail-server seams fail in.

Protocol-free in both directions, deliberately. Nothing here knows a
ManageSieve response code or an IMAP tagged response — adapters translate
their protocol's failures INTO these types. Nothing here knows an HTTP status
either — `app.py` translates these types OUT, in one table.

That second half is the point. When the status lives on the exception, every
new sink has to decide what it means to a client, and the decision drifts;
`folders.py` used to carry its own `except ValueError -> 400` for exactly the
reason `protocol_names.py` was written to remove. One vocabulary, one table.

`str(exc)` reaches the client as the response body, so an adapter must put
only user-safe text in these — never a raw upstream banner, which can carry
software versions and internal hostnames. Each type has a safe default for
the case where there is nothing worth relaying.

Which types may carry server text is not the adapter's judgement call:
`RELAYS_SERVER_TEXT` below names them. They are the failures that are a
decision ABOUT THE REQUEST — a compiler diagnostic, a quota, a refused
folder — where the server is telling the user something they can act on. A
failure to connect or authenticate says nothing actionable and is exactly
where a banner would leak, so those keep their defaults.
"""

from __future__ import annotations


class MailStoreError(Exception):
    """Base for every semantic failure a ScriptStore or FolderStore may raise.

    A caller that wants "any seam failure" catches this; `app.py` registers
    ONE handler against it and lets Starlette's MRO walk do the rest.
    """

    default_detail = "The mail server could not complete the request."

    def __init__(self, detail: str | None = None):
        super().__init__(detail or self.default_detail)
        # Normalised, so `.reason` and `str(exc)` can never disagree: an empty
        # detail means the server gave us nothing worth relaying, and both
        # readings should say exactly that.
        self.reason = detail or None


class ScriptNotFound(MailStoreError):
    """No script by that name exists on the server."""

    default_detail = "No such script."


class ScriptRejected(MailStoreError):
    """The server refused what was asked of this script.

    Usually its CONTENT — a well-framed script the Sieve compiler would not
    accept, where `reason` carries the compiler's own diagnostic. Also covers
    the server refusing the OPERATION on grounds the caller can act on: RFC
    5804 `ALREADYEXISTS`, or `ACTIVE` for deleting the script in use.

    Distinct from a name rejection, which never reaches the wire —
    `ProtocolNameError` covers that before any protocol call is made.
    """

    default_detail = "The mail server rejected the script."


class QuotaExceeded(MailStoreError):
    """The account is out of space for scripts."""

    default_detail = "The mail account is out of script storage space."


class MailServerUnavailable(MailStoreError):
    """The server could not be reached, or failed in a way we cannot classify.

    Also the fallback for an unmapped failure: a mail server that did not
    answer is an upstream problem, so it must not surface as a 500 that reads
    like our own bug.
    """

    default_detail = "The mail server is unavailable."


class AuthFailed(MailStoreError):
    """The stored session credentials were refused by the mail server.

    Distinct from having no session at all, which never gets this far —
    `get_session` rejects that. This is a session that authenticated once and
    no longer does, so the client is told to authenticate again.
    """

    default_detail = "The mail server rejected the stored credentials."


class FolderRejected(MailStoreError):
    """The server refused to create or subscribe the folder.

    The folder counterpart to `ScriptRejected`, and separate for the same
    reason the two seams are separate: a caller handling folder failures has
    no interest in script ones.

    Added with the adapters (`.6`) because the FolderStore seam says failure
    raises, and there was no folder-shaped error to raise. The status it maps
    to is the 400 `routers/folders.py` already returned by hand; what changed
    is that a refused SUBSCRIBE now reaches it at all, and that the server's
    own words come with it.
    """

    default_detail = "The mail server refused the folder."


# The errors whose message may be the server's own words. Everything absent
# from this set answers with its default_detail, however much the server said.
def server_text(value) -> str | None:
    """Whatever the server said, as text safe to hand onward — or None.

    Adapters receive this in whatever type their library favours: sievelib's
    `errmsg` is bytes almost everywhere but a str in at least one path, and
    imaplib hands back a list of bytes. A server may also send bytes that are
    not UTF-8; losing the wording is acceptable, raising UnicodeDecodeError
    out of an error path is not.
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).strip() or None if value is not None else None


RELAYS_SERVER_TEXT: frozenset[type[MailStoreError]] = frozenset(
    {ScriptNotFound, ScriptRejected, QuotaExceeded, FolderRejected}
)


def relayed(error: type[MailStoreError], reason: str | None) -> MailStoreError:
    """Build `error`, carrying `reason` only if that type may relay it.

    One place, so no adapter has to remember the rule — and adding an error
    type means deciding, once, whether the server's text is safe to repeat.
    """
    return error(reason if error in RELAYS_SERVER_TEXT else None)
