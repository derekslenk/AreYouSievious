"""
The FolderStore adapter: IMAP folder operations.

Dialling policy — rebinding re-check, pinned connect, TLS context, timeouts —
lives in `mail_dial`. This module owns what to say once connected.

Reading a LIST response is `imapclient`'s job, not ours. Three names are used
from it and nothing else — `response_parser.parse_response` for the grammar,
`imap_utf7` for the encoding, and `ProtocolError`, which is how the grammar
reports a line it cannot read (it does NOT subclass ValueError, so catching
`parse_response` needs the name). imaplib stays the transport, so `mail_dial`
takes a zero-line diff. See `_folder_from_list_row`.
"""

import imaplib

from auth import Session
from config import Settings
from imapclient import imap_utf7
from imapclient.exceptions import ProtocolError
from imapclient.response_parser import parse_response
from mail_dial import open_imap, speaks_to_mail_server, transport_failures_are_semantic
from mail_errors import (
    AuthFailed,
    FolderRejected,
    MailServerUnavailable,
    MailStoreError,
    relayed,
    server_text,
)
from protocol_names import validate_folder_name


def _decode_name(atom) -> str:
    """A mailbox name or delimiter as text a caller can put in a `fileinto`.

    Bytes are the ordinary case and carry modified UTF-7 — IMAP's own
    encoding, which is NOT stdlib utf-7 (the stdlib emits `+AOk-` where IMAP
    requires `&AOk-`; CPython declined to ship the codec, bpo-22598). A bare
    numeric atom is typed as an int by the grammar, because a mailbox name is
    an astring and `2024` is legal unquoted.

    The fallback is load-bearing. A compliant server writes a literal `&` as
    `&-`, and `imap_utf7.decode` raises UnicodeDecodeError on a lone one — so
    an ordinary `Q&A` on a sloppy server threw straight out of `list_folders`,
    a 500 for a folder that exists. That is the same failure this bead exists
    to remove, so it is answered the way `mail_errors.server_text` already
    answers it: losing fidelity is acceptable, raising out is not. Refusing
    the whole listing over one odd name would be worse than the mojibake the
    regex produced. `AT&T` and `R&D` hit this too — ordinary names, not
    exotica.

    What it does NOT cover, because the codec does not fail there: a raw
    8-bit byte is read as latin-1 rather than rejected (`caf\xe9` -> `café`),
    a TRAILING lone `&` decodes to `+` (`Tom&` -> `Tom+`), and malformed
    mUTF-7 partially decodes instead of failing (`&AOk*-` -> `é*-`). All
    three are wrong names arriving with no exception to catch — imapclient's
    reading of an already-malformed encoding, and the price of adopting a
    grammar rather than writing one.
    """
    if isinstance(atom, bytes):
        try:
            return imap_utf7.decode(atom)
        except UnicodeDecodeError:
            return atom.decode("utf-8", "replace")
    return str(atom)


def _encode_name(name: str) -> bytes:
    """A mailbox name as the bytes IMAP wants on the wire.

    The outbound mirror of `_decode_name`, and it lives beside it on purpose:
    `.12` taught this module to READ modified UTF-7 and left writing it
    undone, so the UI began spelling `Été` correctly for the first time while
    `create_folder("Été")` raised UnicodeEncodeError — imaplib encodes command
    arguments itself with `bytes(arg, self._encoding)`, and `_encoding` is
    ascii unless `enable("UTF8=ACCEPT")` has run, which we never call.

    Bytes rather than str because that is what stops imaplib re-encoding:
    `_command` converts only `str` arguments and passes bytes through
    untouched. Handing it a str of mUTF-7 would work by accident for ASCII
    and be wrong the moment it was not.

    Not `enable("UTF8=ACCEPT")`, deliberately: that needs a capability check
    and changes the encoding of everything on the connection, to solve what
    one codec call at the boundary already solves.
    """
    return imap_utf7.encode(name)


def _decode_flag(atom) -> str:
    """One LIST flag, which is an ATOM and never modified UTF-7.

    Separate from `_decode_name` because running flags through the codec is
    wrong in principle and was fatal in practice: `&` is a legal ATOM-CHAR, so
    a server offering `\\$Junk&x` raised UnicodeDecodeError and took the
    entire folder listing down with it.
    """
    return atom.decode("ascii", "replace") if isinstance(atom, bytes) else str(atom)


def _folder_from_list_row(row) -> dict | None:
    """One `{name, delimiter, flags}` from one untagged LIST row, or None.

    `row` is exactly what imaplib hands back: bytes for an ordinary line, or a
    `(line_ending_in_{n}, literal)` tuple when the server sent the name as a
    literal — which `re.match` answered with a TypeError, a 500 for a folder
    listing. Passing the item through untouched is what makes both work, since
    the lexer takes the tuple as one logical line.

    None means the row held nothing at all: imaplib reports "no untagged LIST
    responses" as `[None]`, which is an empty account rather than a failure.
    An UNREADABLE row is the opposite and raises, because silently skipping it
    is precisely how the NIL-delimiter namespace went missing without a trace.

    Anything past the third field is discarded: RFC 5258 LIST-EXTENDED appends
    extended data after the name, and no caller of ours wants it.
    """
    try:
        parsed = parse_response([row])
    except (ProtocolError, ValueError, TypeError) as exc:
        # TypeError belongs here on the strength of this bead's own history:
        # it is what the old regex did to a literal tuple, and what the first
        # shape guard did to an int in the flags field. Both were rows nobody
        # expected, which is the only kind that gets through. imaplib hands
        # back bytes or a (bytes, bytes) tuple and nothing else, so this
        # catches nothing reachable today — it makes the docstring's promise
        # below hold for any shape rather than for the ones we thought of.
        raise MailServerUnavailable() from exc
    if not parsed:
        return None
    if len(parsed) < 3:
        raise MailServerUnavailable()
    flags, delimiter, name = parsed[:3]
    # ARITY is not SHAPE, and checking only the first let the grammar's own
    # typing rules walk through a row already declared readable. A bare
    # numeric atom becomes an int, so `2024 "." "n"` made `for f in flags`
    # raise TypeError — the same `TypeError -> 500` this bead exists to
    # remove, one field over. NIL becomes None, so a nameless row yielded
    # `str(None)`: a folder called `None`, offered by FolderPicker and filed
    # into by a Rule that matches nothing. A wrong name is worse than a
    # missing one.
    if not isinstance(flags, tuple) or name is None:
        raise MailServerUnavailable()
    return {
        "name": _decode_name(name),
        # NIL, and therefore None, for a server with a flat namespace. The
        # regex required a quoted character here and so matched nothing at
        # all, and a row that matched nothing was skipped by the loop.
        "delimiter": _decode_name(delimiter) if delimiter is not None else None,
        "flags": [_decode_flag(f) for f in flags or ()],
    }


# RFC 5530 response codes worth telling apart when the server refuses LIST.
# The CODE is not a banner — it is a fixed token from the spec — so reading it
# leaks nothing, and neither error relays the text that follows it.
_LIST_REFUSALS: dict[str, type[MailStoreError]] = {"AUTHENTICATIONFAILED": AuthFailed}


def _refusal(detail) -> MailStoreError:
    """What a `NO` to LIST means, in the mail vocabulary.

    `AUTHENTICATIONFAILED` is the case this bead names: credentials that
    worked once and no longer do. Answering `MailServerUnavailable` told that
    user the server was down and sent them somewhere that cannot help, which
    is the same class of misdirection as reporting an empty account.

    Anything else stays `MailServerUnavailable`: no response code means
    nothing the caller can act on, and blaming their credentials for it would
    be a guess.
    """
    text = server_text(detail) or ""
    # No RFC 5530 code is refined with a slash, so this is a plain lookup —
    # unlike ManageSieve's, where QUOTA/MAXSCRIPTS forces a split.
    code = text[1 : text.index("]")].upper() if text.startswith("[") and "]" in text else ""
    return relayed(_LIST_REFUSALS.get(code, MailServerUnavailable), text)


def _login(conn, username: str, password: str, *, rejected: str | None = None) -> None:
    """Say LOGIN, and report the two ways it fails in the mail vocabulary.

    One place, because two callers need it: the store's `__enter__` and the
    credential check the login route performs before any session exists.
    """
    # Nesting matters. The protocol's own errors are handled INSIDE the
    # transport net, because the net reads an IMAP4.error as "the server would
    # not talk to us" — true at the dial, where no credentials have been sent,
    # and wrong here, where it means exactly the opposite: the server talked
    # and refused these. Outside-in, a mistyped password answered 502 "could
    # not be reached".
    #
    # The net still wraps this, because imaplib does not wrap OSError: a reset
    # socket raises straight through. It passes our AuthFailed out untouched
    # via its MailStoreError exemption.
    with transport_failures_are_semantic():
        try:
            conn.login(username, password)
        except imaplib.IMAP4.abort as exc:
            # MUST precede IMAP4.error, which it subclasses. A dropped socket
            # is not a rejected password, and telling the user to reset a
            # working one sends them somewhere that cannot help.
            raise MailServerUnavailable("The connection to the mail server was lost.") from exc
        except imaplib.IMAP4.error as exc:
            raise AuthFailed(rejected) from exc


def verify_credentials(
    host: str, host_ip: str, port: int, username: str, password: str, *, cfg: Settings
) -> None:
    """Prove these credentials open a mailbox, then hang up.

    What the login route needs and a FolderStore cannot give it: there is no
    session yet, so there is nothing to build a store around. Speaking IMAP
    lives here rather than in the router, which is what lets `routers/auth.py`
    stop importing imaplib and stop deciding what a protocol error means.
    """
    conn = open_imap(host, host_ip, port, cfg=cfg)
    try:
        _login(conn, username, password, rejected="Authentication failed")
    finally:
        try:
            conn.logout()
        except Exception:
            # Already said what we came to say; a failed goodbye is not the
            # caller's problem and must not mask the reason we are leaving.
            pass


class ImapFolderStore:
    """The FolderStore adapter.

    Named for the seam rather than the protocol, and so is the MODULE: this
    class was `IMAPClient` in `imap_client.py`, and the file now imports the
    `imapclient` package. Two spellings of the same word, one of them a
    third-party client this module deliberately does not use, is a mistake
    waiting to be made. `managesieve_client.py` keeps its name — it has no
    such collision, and renaming it would be churn without a reason.
    """

    def __init__(self, session: Session, cfg: Settings):
        self.session = session
        self.cfg = cfg
        self._conn = None

    def __enter__(self):
        self._conn = open_imap(
            self.session.host,
            self.session.host_ip,
            self.session.port_imap,
            cfg=self.cfg,
        )
        try:
            _login(self._conn, self.session.username, self.session.password)
        except Exception:
            # `__exit__` only runs if `__enter__` RETURNED, so a failed login
            # would leave this socket open — one leaked connection per
            # request, which stale credentials plus a polling client turns
            # into a steady drip.
            self._close()
            raise
        return self

    def __exit__(self, *args):
        self._close()

    def _close(self):
        """Hang up, and never let the goodbye mask why we are leaving."""
        if self._conn:
            try:
                self._conn.logout()
            except Exception:
                pass

    @speaks_to_mail_server
    def list_folders(self) -> list[dict]:
        """Every folder on the account, as {name, delimiter, flags} dicts.

        A refused LIST raises. It used to `return folders` — the empty list
        built two lines above — so a server that would not answer was
        indistinguishable from an account with no folders, and the user was
        invited to create folders they already had. Which failure it raises is
        `_refusal`'s decision, and neither of the two relays the server's
        banner (see mail_errors.RELAYS_SERVER_TEXT).
        """
        status, data = self._conn.list()
        if status != "OK":
            raise _refusal(data)

        folders = [f for f in (_folder_from_list_row(row) for row in data) if f is not None]
        folders.sort(key=lambda f: f["name"].lower())
        return folders

    @speaks_to_mail_server
    def create_folder(self, name: str) -> None:
        """Create a new IMAP folder, and subscribe it.

        Returns nothing: failure raises, per the FolderStore seam. The bool
        this replaced made the router ask "did that work?" and answer 400 for
        every cause alike, so an unreachable server and a refused name were
        indistinguishable.

        Both statuses are checked. Subscribing was previously fire-and-forget
        while create's status was checked two lines above, so a refused
        subscribe still reported success — for a folder most mail clients
        will not display, which is indistinguishable from the folder never
        having been created.

        The framing guard lives in `protocol_names`, shared with the
        ManageSieve script-name sink — same hazard, same rule, one place.
        """
        # Order is load-bearing. `validate_folder_name` guards command framing
        # — CR, LF, NUL, quote — and it must inspect the name the CALLER gave,
        # not an encoded form of it. mUTF-7 happens to leave those characters
        # alone, but a guard that depends on that is checking a value it does
        # not own.
        validate_folder_name(name)
        quoted = b'"' + _encode_name(name) + b'"'
        status, detail = self._conn.create(quoted)
        if status != "OK":
            raise relayed(FolderRejected, server_text(detail))
        # Both verbs, or the folder is created under one spelling and
        # subscribed under another.
        status, detail = self._conn.subscribe(quoted)
        if status != "OK":
            raise relayed(FolderRejected, server_text(detail))
