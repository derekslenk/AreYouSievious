r"""
The LIST parser (areyousievious-8fg.12).

`list_folders` was the only non-trivial implementation across both client
modules with ZERO coverage — nothing anywhere called it. What it ran was a
regex over the raw untagged line:

    r'\(([^)]*)\)\s+"([^"]+)"\s+"?([^"]*)"?'

Every row below was verified against that regex before this change. It does
not merely fail to parse the hard cases; it fails SILENTLY, in the two ways
that matter to a caller:

  * DROPS a row whose delimiter is NIL — `"([^"]+)"` cannot match `NIL`, so a
    shared namespace simply is not offered.
  * TRUNCATES a name at the first escaped quote — `Weird "Quoted" Name`
    arrives as `Weird \`, and FolderPicker offers that. The user's Action
    becomes `fileinto "Weird \"`, a Rule filing into a folder that does not
    exist. A wrong name is worse than a missing one.

The fix is ADOPTION, not implementation: `imapclient.response_parser` is the
IMAP grammar, and `imapclient.imap_utf7` is the modified-UTF-7 codec CPython
declined to ship (bpo-22598). imaplib stays the transport.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from auth import Session
from config import Settings
from imap_store import ImapFolderStore
from mail_errors import AuthFailed, MailServerUnavailable, MailStoreError


def _session() -> Session:
    return Session(
        token="t",
        host="mail.example.com",
        host_ip="93.184.216.34",
        port_imap=993,
        port_sieve=4190,
        username="user@example.com",
        password="hunter2",
        created_at=0.0,
        last_used=0.0,
    )


def _store(rows, status: str = "OK") -> ImapFolderStore:
    """A real ImapFolderStore over a connection that answers LIST with `rows`.

    The adapter is the real one — the parser under test lives in it — and only
    imaplib beneath it is replaced. `rows` are exactly what imaplib hands back:
    bytes for an ordinary line, and a (line_with_{n}_marker, literal) tuple
    when the server sent a literal.
    """
    store = ImapFolderStore(_session(), Settings())
    store._conn = MagicMock(**{"list.return_value": (status, rows)})
    return store


def _one(row) -> dict:
    """The single folder parsed out of a single LIST row."""
    folders = _store([row]).list_folders()
    assert len(folders) == 1, f"row was dropped or split: {folders!r}"
    return folders[0]


# ── Every row the regex got wrong ──


def test_a_plain_row_still_parses():
    """The case the regex did handle. It must keep working."""
    assert _one(rb'(\HasNoChildren) "." "INBOX"') == {
        "name": "INBOX",
        "delimiter": ".",
        "flags": ["\\HasNoChildren"],
    }


def test_a_nil_delimiter_row_is_not_dropped():
    """RFC 3501: a flat namespace reports NIL, not a quoted character.

    The regex required `"([^"]+)"` and so matched nothing, and a row that
    matches nothing is skipped by the loop — the folder vanished with no
    error anywhere.
    """
    assert _one(rb'(\Noselect) NIL "Shared"') == {
        "name": "Shared",
        "delimiter": None,
        "flags": ["\\Noselect"],
    }


def test_an_escaped_quote_does_not_truncate_the_name():
    """The corruption that reaches Sieve. `Weird \\"Quoted\\" Name` came back
    as `Weird \\` — a name FolderPicker offers and no server will file into."""
    assert _one(rb'(\HasNoChildren) "." "Weird \"Quoted\" Name"')["name"] == 'Weird "Quoted" Name'


def test_an_escaped_backslash_is_unescaped_exactly_once():
    """On the wire `back\\\\slash` is the four characters b-a-c-k-\\-s...; the
    regex handed the doubled backslash straight through."""
    assert _one(rb'(\HasNoChildren) "." "back\\slash"')["name"] == "back\\slash"


def test_a_modified_utf7_name_is_decoded():
    """IMAP's own encoding, which is NOT stdlib utf-7: the stdlib emits
    `+AOk-` where IMAP requires `&AOk-`. The regex passed the mojibake to the
    user."""
    assert _one(rb'(\HasNoChildren) "." "&AOk-t&AOk-"')["name"] == "été"


def test_a_literal_name_does_not_raise():
    """A server may send the name as a literal, which imaplib hands back as a
    (line, literal) TUPLE. `re.match` on a tuple raised TypeError — a 500 for
    a folder listing."""
    assert _one((rb'(\HasNoChildren) "." {9}', b"Sent Mail"))["name"] == "Sent Mail"


# ── The shape of the result ──


def test_flags_are_split_and_an_empty_flag_list_is_empty():
    assert _one(rb'(\HasNoChildren \Marked) "/" "Work"')["flags"] == [
        "\\HasNoChildren",
        "\\Marked",
    ]
    assert _one(rb'() "/" "Work"')["flags"] == []


def test_folders_sort_case_insensitively_by_name():
    """The order FolderPicker shows, and what `tests/fakes.py` mirrors."""
    rows = [
        rb'(\HasNoChildren) "." "zebra"',
        rb'(\HasNoChildren) "." "Apple"',
        rb'(\HasNoChildren) "." "banana"',
    ]
    assert [f["name"] for f in _store(rows).list_folders()] == ["Apple", "banana", "zebra"]


def test_a_list_extended_row_keeps_its_first_three_fields():
    """RFC 5258 appends extended data after the name. Servers that advertise
    LIST-EXTENDED send it unasked in some configurations."""
    row = rb'(\HasNoChildren) "." "Archive" ("CHILDINFO" ("SUBSCRIBED"))'
    assert _one(row) == {"name": "Archive", "delimiter": ".", "flags": ["\\HasNoChildren"]}


def test_an_unquoted_name_is_still_text():
    """A mailbox name is an astring, so `2024` is legal unquoted — and the
    grammar types a bare numeric atom as an int, which must not reach a
    caller expecting `name` to be a string."""
    assert _one(rb'(\HasNoChildren) "." 2024')["name"] == "2024"


def test_an_account_with_no_folders_is_empty_not_an_error():
    """imaplib reports "no untagged LIST responses" as `[None]`."""
    assert _store([None]).list_folders() == []


# ── Failure is raised, never rendered as "you have no folders" ──


def test_a_refused_list_raises_instead_of_reporting_an_empty_account():
    """`status != "OK"` used to `return folders` — an empty one. A server
    that refused the command was indistinguishable from an account with no
    folders, so the user was told to create folders they already had."""
    with pytest.raises(MailStoreError):
        _store([b"Server refused the command."], status="NO").list_folders()


def test_a_refused_list_does_not_repeat_the_servers_banner():
    """MailServerUnavailable is absent from RELAYS_SERVER_TEXT: a failure to
    reach or be served by the mail server says nothing the user can act on,
    and is exactly where a version banner would leak."""
    store = _store([b"NO [ALERT] dovecot 2.3.19 internal error at /srv/mail"], status="NO")
    with pytest.raises(MailServerUnavailable) as caught:
        store.list_folders()
    assert "dovecot" not in str(caught.value)


def test_an_unparseable_row_raises_rather_than_disappearing():
    """The failure mode this bead exists to remove. A row the grammar cannot
    read is a fact about the server, not a folder that does not exist —
    dropping it is how the NIL row went missing without a trace."""
    with pytest.raises(MailServerUnavailable):
        _store([rb'(\HasNoChildren) "." "unterminated']).list_folders()


def test_a_truncated_row_raises_rather_than_yielding_a_partial_folder():
    with pytest.raises(MailServerUnavailable):
        _store([rb"(\HasNoChildren)"]).list_folders()


# ── Through the route, where the response model gets a say ──


def test_a_nil_delimiter_folder_survives_the_response_model(authed_client):
    r"""Parsing the row is only half of it.

    `FolderListItem.delimiter` was a required `str`, so the moment the parser
    stopped dropping NIL rows the route would have answered a
    ResponseValidationError — a 500 — for exactly the folders this bead
    rescued. The real adapter is under the route here for that reason: a fake
    store hands back whatever shape the test wrote, and would prove nothing.
    """
    store = _store(
        [
            rb'(\Noselect) NIL "Shared"',
            rb'(\HasNoChildren) "." "&AOk-t&AOk-"',
        ]
    )
    with authed_client(folder_store=store) as http:
        response = http.get("/api/folders")
    assert response.status_code == 200
    assert response.json() == [
        {"name": "Shared", "delimiter": None, "flags": ["\\Noselect"]},
        {"name": "été", "delimiter": ".", "flags": ["\\HasNoChildren"]},
    ]


def test_a_refused_list_answers_502_rather_than_an_empty_listing(authed_client):
    """The user-visible half of the `status != "OK"` fix: not "you have no
    folders", but "the mail server is unavailable"."""
    store = _store([b"Server refused the command."], status="NO")
    with authed_client(folder_store=store) as http:
        response = http.get("/api/folders")
    assert response.status_code == 502
    assert response.json() != []


# ── A name the codec cannot read must not become a 500 ──
#
# Found in review of this bead's own first commit. `imap_utf7.decode` raises
# UnicodeDecodeError on a lone `&`, and the decode ran OUTSIDE the try that
# guards parsing — so it escaped `list_folders` uncaught. That is the same
# failure class as the literal-tuple TypeError this bead exists to remove,
# one field over: the regex produced mojibake here, the first fix produced a
# 500.


def test_a_raw_ampersand_in_a_name_does_not_crash_the_listing():
    r"""A compliant server encodes `&` as `&-`; some do not, and `Q&A` is an
    ordinary folder name. `mail_errors.server_text` already sets this
    codebase's precedent for undecodable server bytes — losing the wording is
    acceptable, raising UnicodeDecodeError out is not — and the folder is
    real, so refusing the whole listing over it would be worse than the
    mojibake it replaced."""
    assert _one(rb'(\HasNoChildren) "." "Q&A"')["name"] == "Q&A"


def test_a_flag_is_never_run_through_the_mutf7_codec():
    r"""Flags are atoms, and `&` is a legal ATOM-CHAR. They are never
    mUTF-7-encoded, so decoding them is wrong in principle — and fatal in
    practice, because `$Junk&x` raised UnicodeDecodeError and took the whole
    folder listing with it."""
    assert _one(rb'(\HasNoChildren \$Junk&x) "." "INBOX"')["flags"] == [
        "\\HasNoChildren",
        "\\$Junk&x",
    ]


def test_a_mutf7_name_still_decodes_alongside_an_undecodable_one():
    """The fallback must not cost the encoding it was added to protect."""
    rows = [rb'(\HasNoChildren) "." "&AOk-t&AOk-"', rb'(\HasNoChildren) "." "Q&A"']
    assert [f["name"] for f in _store(rows).list_folders()] == ["Q&A", "été"]


# ── The named case in the bead: AUTHENTICATIONFAILED ──


def test_authenticationfailed_on_list_is_an_auth_failure_not_an_outage():
    """The symptom the bead names by name. `MailServerUnavailable` told a
    user with stale credentials that the server was down, which sends them
    somewhere that cannot help. The RFC 5530 response CODE is not a banner —
    and `AuthFailed` relays no text either, so reading it leaks nothing."""
    store = _store([b"[AUTHENTICATIONFAILED] Authentication failed."], status="NO")
    with pytest.raises(AuthFailed):
        store.list_folders()


def test_an_unexplained_no_is_still_an_unavailable_server():
    """No response code means nothing the caller can act on, and blaming
    their credentials for it would be a guess."""
    with pytest.raises(MailServerUnavailable):
        _store([b"Internal error"], status="NO").list_folders()


def test_an_auth_failure_on_list_does_not_repeat_the_servers_banner():
    store = _store([b"[AUTHENTICATIONFAILED] dovecot 2.3.19 said no"], status="NO")
    with pytest.raises(AuthFailed) as caught:
        store.list_folders()
    assert "dovecot" not in str(caught.value)


def test_a_correctly_escaped_ampersand_beats_the_fallback():
    r"""The boundary the fallback must not cannibalise.

    RFC 3501 spells a literal `&` as `&-`, and that decodes without ever
    reaching the fallback. Only a server that omitted the escape gets the
    lossy path — so the fallback answers a case the codec has already
    definitively failed, rather than competing with it.

    `Q&AOk-A` is deliberately absent: it decodes to `QéA`, which is CORRECT.
    A server meaning the literal text must send `Q&-AOk-A`. That ambiguity
    belongs to the protocol and no parser can resolve it.
    """
    assert _one(rb'(\HasNoChildren) "." "Q&-A"')["name"] == "Q&A"


# ── Row SHAPE, not just row arity ──
#
# Found in verification of this bead's own fix. `len(parsed) < 3` checked how
# many fields arrived and nothing about what they were, so the grammar's own
# typing rules — a bare numeric atom becomes an int, NIL becomes None — walked
# straight through a guard that had already declared the row readable.


def test_a_row_whose_flags_are_not_a_list_raises_rather_than_500ing():
    """`2024 "." "n"` types the first field as an int, and `for f in flags`
    then raised TypeError — the spec's own `literal (tuple) -> TypeError ->
    500` row surviving one field over, in the code written to remove it."""
    with pytest.raises(MailServerUnavailable):
        _store([rb'2024 "." "n"']).list_folders()


def test_a_nil_name_raises_rather_than_offering_a_folder_called_none():
    """NIL where the name belongs produced `str(None)` — a folder literally
    named `None`, offered by FolderPicker, filed into by a Rule, and matching
    nothing on the server. A wrong name is worse than a missing one, which is
    the whole reason this bead exists."""
    with pytest.raises(MailServerUnavailable):
        _store([rb'(\HasNoChildren) "." NIL']).list_folders()
    with pytest.raises(MailServerUnavailable):
        _store([rb"NIL NIL NIL"]).list_folders()


# ── The user-visible half of the AUTHENTICATIONFAILED fix ──


def test_authenticationfailed_on_list_answers_401_not_502(authed_client):
    """The unit test above pins the exception; this pins what the user gets.
    The finding was never about the type — it was that stale credentials read
    as "the mail server is unavailable", sending someone to check a server
    that is fine instead of re-authenticating."""
    store = _store([b"[AUTHENTICATIONFAILED] Authentication failed."], status="NO")
    with authed_client(folder_store=store) as http:
        response = http.get("/api/folders")
    assert response.status_code == 401
