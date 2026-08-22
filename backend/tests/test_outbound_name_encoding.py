r"""Names go out encoded, not just come in decoded (areyousievious-rc9).

`.12` adopted imapclient's modified-UTF-7 codec so folder names DECODE
correctly on the way in. A user with an existing `Été` folder saw it spelled
properly in FolderPicker for the first time. Nothing encoded on the way OUT,
and that asymmetry is the bug: the UI now displays non-ASCII folder names it
cannot create, and round-tripping one fails.

`imaplib` encodes command arguments itself — `_command` does
`bytes(arg, self._encoding)`, and `_encoding` is **'ascii'** unless
`enable('UTF8=ACCEPT')` has run, which we never call. So `create_folder("Été")`
raised UnicodeEncodeError: a ValueError, which the transport net deliberately
does not catch, so it reached the client as a 500.

REPRODUCED END-TO-END on a real socket before the fix — a MagicMock conn
cannot show this, because the thing that fails is what imaplib does with what
we hand it. A mock accepts the name the real library refuses, which is why
this bead's tests use `imap_server` and not a mock.

ManageSieve is NOT affected and is verified so rather than assumed: sievelib
encodes script names with UTF-8 (`getscript`/`deletescript` call
`name.encode("utf-8")`, and `__prepare_args` does the same), which is what RFC
5804 requires. Only the IMAP sinks needed this.
"""

from __future__ import annotations

import pytest
from auth import Session
from config import Settings
from imap_store import ImapFolderStore
from imapclient import imap_utf7
from protocol_names import ProtocolNameError


def _session() -> Session:
    return Session(
        token="t",
        host="mail.example.com",
        host_ip="127.0.0.1",
        port_imap=0,
        port_sieve=4190,
        username="user@example.com",
        password="hunter2",
        created_at=0.0,
        last_used=0.0,
    )


def _store_over(conn) -> ImapFolderStore:
    store = ImapFolderStore(_session(), Settings())
    store._conn = conn
    return store


# Names whose wire form differs from the caller's spelling.
ENCODED = [
    pytest.param("Été", b"&AMk-t&AOk-", id="accented"),
    pytest.param("Ärchiv", b"&AMQ-rchiv", id="umlaut"),
    pytest.param("収納", b"&U859DQ-", id="cjk"),
    pytest.param("Ω", b"&A6k-", id="greek"),
    # `&` is ASCII and is the ONE character mUTF-7 must escape, which makes
    # these the names most likely to disagree between the two directions —
    # `.12` documented that `imap_utf7.decode` REFUSES a lone `&` and falls
    # back to a lossy read (`AT&T`, `R&D`, `Q&A` all raise UnicodeDecodeError
    # there). Escaping on the way out is what keeps that fallback off our own
    # output: a name we wrote is always decodable.
    pytest.param("Q&A", b"Q&-A", id="ampersand"),
    pytest.param("AT&T", b"AT&-T", id="ampersand-mid"),
    pytest.param("&", b"&-", id="ampersand-alone"),
    pytest.param("R&D & Ops", b"R&-D &- Ops", id="ampersand-several"),
    pytest.param("Été & Q&A", b"&AMk-t&AOk- &- Q&-A", id="ampersand-and-accents"),
]


@pytest.mark.parametrize("name,encoded", ENCODED)
def test_a_non_ascii_folder_can_be_created(imap_server, name, encoded):
    """The bug, in the terms the user meets it: this raised
    UnicodeEncodeError and answered 500 for a perfectly ordinary name."""
    conn, sent = imap_server()
    _store_over(conn).create_folder(name)
    created = [line for line in sent if b"CREATE" in line.upper()]
    assert created, f"no CREATE reached the server: {sent!r}"
    assert encoded in created[0]


@pytest.mark.parametrize("name,encoded", ENCODED)
def test_the_subscribe_leg_is_encoded_too(imap_server, name, encoded):
    """Both verbs or neither. SUBSCRIBE takes the same name and would have
    failed the same way — and it runs second, so CREATE succeeding first is
    what makes it easy to leave behind."""
    conn, sent = imap_server()
    _store_over(conn).create_folder(name)
    subscribed = [line for line in sent if b"SUBSCRIBE" in line.upper()]
    assert subscribed, f"no SUBSCRIBE reached the server: {sent!r}"
    assert encoded in subscribed[0]


def test_an_ascii_name_goes_out_unchanged():
    """The common case must not gain a wrapper that changes what a working
    server already sees — ALMOST all of ASCII passes through untouched."""
    assert imap_utf7.encode("Archive") == b"Archive"
    assert imap_utf7.encode("Archive/2026") == b"Archive/2026"


@pytest.mark.parametrize("name,encoded", ENCODED)
def test_a_created_name_round_trips_through_the_listing(imap_server, name, encoded):
    """The asymmetry, closed. What `create_folder` puts on the wire is what
    `list_folders` reads back — the same spelling the user typed, not the
    mojibake `.12` removed and not a name the server never received."""

    def answer_list(conn, stream, tag, line):
        if b"LIST" not in line.upper():
            return None
        stream.write(b'* LIST (\\HasNoChildren) "." "' + encoded + b'"\r\n')
        stream.write(tag + b" OK done\r\n")
        stream.flush()
        return True

    conn, _sent = imap_server(handle=answer_list)
    store = _store_over(conn)
    store.create_folder(name)
    assert [f["name"] for f in store.list_folders()] == [name]


# ── The guard still runs first ──


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("bad\r\nLOGOUT", id="CRLF-then-command"),
        pytest.param('bad" DELETE "other', id="quote-break"),
        pytest.param("bad\x00LOGOUT", id="NUL"),
    ],
)
def test_framing_is_still_rejected_before_anything_is_encoded(imap_server, name):
    """ORDER MATTERS, and this is the trap the bead named.

    `validate_folder_name` guards command framing — CR, LF, NUL, quote. If
    encoding happened first, the guard would inspect different bytes than the
    ones that reach the wire: mUTF-7 leaves those characters untouched, but
    relying on that means the guard is checking a value it does not own.
    Nothing may reach the server.
    """
    conn, sent = imap_server()
    before = len(sent)
    with pytest.raises(ProtocolNameError):
        _store_over(conn).create_folder(name)
    assert len(sent) == before, f"a rejected name still reached the wire: {sent[before:]!r}"


def test_the_server_fixture_leaves_the_session_usable_after_a_handled_command(imap_server):
    """The fixture's own contract, pinned because it was wrong once.

    A handler that wrote its own reply and returned None got a SECOND tagged
    OK appended by the loop. imaplib reads that as `unexpected tagged
    response` and aborts the NEXT command — a corrupted session surfacing as
    a `MailServerUnavailable` several lines from its cause. It was harmless
    only because the one handler in the suite answered the last command.
    """

    def answer_list(conn, stream, tag, line):
        if b"LIST" not in line.upper():
            return None
        stream.write(b'* LIST (\\HasNoChildren) "." "Inbox"\r\n')
        stream.write(tag + b" OK done\r\n")
        stream.flush()
        return True

    conn, _sent = imap_server(handle=answer_list)
    store = _store_over(conn)
    assert [f["name"] for f in store.list_folders()] == ["Inbox"]
    # The command AFTER the handled one is where the duplicate OK landed.
    store.create_folder("Archive")
