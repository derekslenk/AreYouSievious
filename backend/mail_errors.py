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


class ScriptNotFound(MailStoreError):
    """No script by that name exists on the server."""

    default_detail = "No such script."


class ScriptRejected(MailStoreError):
    """The server refused the script's CONTENT.

    Distinct from a name rejection, which never reaches the wire —
    `ProtocolNameError` covers that before any protocol call is made. This is
    the server having parsed a well-framed script and said no, so the reason
    it gave is worth relaying to the user who wrote it.
    """

    default_detail = "The mail server rejected the script."

    def __init__(self, reason: str | None = None):
        super().__init__(reason)
        self.reason = reason


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
