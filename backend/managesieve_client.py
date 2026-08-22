"""
ManageSieve client wrapper — the ScriptStore adapter.

Dialling policy — rebinding re-check, pinned connect, SNI split, timeouts —
lives in `mail_dial`. This module owns the script operations, and the job of
turning sievelib's failure convention into the `mail_errors` vocabulary.

That convention is the reason this file has a translation layer at all:
sievelib reports failure by RETURNING a falsy value, never by raising, and
parks the explanation on two public attributes it expects you to read.
Ignoring the return therefore loses the failure AND the reason — `put_script`
used to discard a `False` and answer `200 {ok: true}` for a script the server
had refused to compile, with the compiler's own diagnostic sitting unread in
`errmsg`.
"""

from typing import NoReturn

from auth import Session
from config import Settings
from mail_dial import open_sieve, speaks_to_mail_server
from mail_errors import (
    MailServerUnavailable,
    MailStoreError,
    QuotaExceeded,
    ScriptNotFound,
    ScriptRejected,
    relayed,
    server_text,
)
from protocol_names import validate_script_name

# RFC 5804 §1.3 response codes, as sievelib hands them over: parens stripped,
# bytes, and `b""` when the server sent no code at all. Matched on the leading
# token because the spec refines some of them with a slash — QUOTA arrives as
# QUOTA, QUOTA/MAXSCRIPTS or QUOTA/MAXSIZE and all three mean the same thing
# to a caller.
_RESPONSE_CODE_ERRORS = {
    "NONEXISTENT": ScriptNotFound,
    "ALREADYEXISTS": ScriptRejected,
    "ACTIVE": ScriptRejected,
    "QUOTA": QuotaExceeded,
    "TRYLATER": MailServerUnavailable,
}


def _fail(client, when_no_response_code: type[MailStoreError]) -> NoReturn:
    """Raise the failure sievelib just reported by return value.

    `when_no_response_code` is what the operation means when the server sent
    no code at all: for a script upload that is a rejection, because the text
    is the compiler talking; everywhere else it is an unavailable server,
    because an unexplained NO is not evidence the caller did anything wrong.

    Whether the server's words travel with the error is `relayed`'s decision,
    not this function's — see mail_errors.RELAYS_SERVER_TEXT.
    """
    code = (server_text(client.errcode) or "").upper()
    error = _RESPONSE_CODE_ERRORS.get(code.split("/", 1)[0], when_no_response_code)
    raise relayed(error, server_text(client.errmsg))


class SieveClient:
    """Wraps a sievelib ManageSieve client with session credentials."""

    def __init__(self, session: Session, cfg: Settings):
        self.session = session
        self.cfg = cfg
        self._client = None

    def __enter__(self):
        self._client = open_sieve(
            self.session.host,
            self.session.host_ip,
            self.session.port_sieve,
            self.session.username,
            self.session.password,
            cfg=self.cfg,
        )
        return self

    def __exit__(self, *args):
        if self._client:
            try:
                self._client.logout()
            except Exception:
                pass

    @speaks_to_mail_server
    def list_scripts(self) -> list[dict]:
        """Return list of {name, active} dicts."""
        listed = self._client.listscripts()
        if listed is None:
            # Unpacking None raised `TypeError: cannot unpack non-iterable
            # NoneType` — a 500 for what is usually a dropped connection.
            _fail(self._client, MailServerUnavailable)
        active, inactive = listed
        scripts = []
        if active:
            scripts.append({"name": active, "active": True})
        for name in inactive:
            scripts.append({"name": name, "active": False})
        return scripts

    @speaks_to_mail_server
    def get_script(self, name: str) -> str:
        """Get script content by name."""
        validate_script_name(name)
        result = self._client.getscript(name)
        if result is None:
            # Returning None sent parse_sieve(None) into an AttributeError —
            # a 500 for a script that simply is not there.
            _fail(self._client, MailServerUnavailable)
        if isinstance(result, tuple):
            return result[-1]
        return result

    @speaks_to_mail_server
    def put_script(self, name: str, content: str) -> None:
        """Upload/update a script. Raises ScriptRejected with the server's
        own compiler diagnostic when the script will not compile."""
        validate_script_name(name)
        if not self._client.putscript(name, content):
            _fail(self._client, ScriptRejected)

    @speaks_to_mail_server
    def activate_script(self, name: str) -> None:
        """Set a script as active."""
        validate_script_name(name)
        if not self._client.setactive(name):
            _fail(self._client, MailServerUnavailable)

    @speaks_to_mail_server
    def delete_script(self, name: str) -> None:
        """Delete a script."""
        validate_script_name(name)
        if not self._client.deletescript(name):
            _fail(self._client, MailServerUnavailable)
