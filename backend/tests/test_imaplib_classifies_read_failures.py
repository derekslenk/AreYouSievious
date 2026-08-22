r"""What imaplib CALLS a broken read (areyousievious-66i).

This file exists because a test in `test_transport_net_covers_operations.py`
claimed something it could not deliver. It hand-built
`imaplib.IMAP4.abort("socket error: EOF")`, fed it to a MagicMock and said
that a future imaplib demoting that abort to an `error` would show up there.
It would not: imaplib never ran, so imaplib's classification was never
observed. Verified — wrapping `_get_line` to re-raise abort as error left
that test green while a real socket escaped as a 500.

The claim matters because it is the JUSTIFICATION for
`transport_failures_are_semantic(protocol_error_is_refusal=False)`. Letting
`IMAP4.error` through during an operation is safe only while every genuine
read failure is an `abort`. If that stops being true, a real outage becomes
a 500 and the user is told to file a bug about a server that went away.

So this drives a REAL `imaplib.IMAP4` over a REAL socket and asserts what it
raises. No mail server, no TLS, no network: a loopback listener on an
ephemeral port that speaks just enough IMAP to reach LIST and then misbehaves.
"""

from __future__ import annotations

import imaplib
import socket
import threading

import pytest

# Every read must land or fail fast; nothing here may hang CI.
_TIMEOUT = 5.0


def _serve(misbehave) -> int:
    """A loopback IMAP listener that greets, accepts LOGIN, then misbehaves.

    Returns the ephemeral port. The thread is a daemon and the socket closes
    with the connection, so a case that leaves the client stuck still cannot
    outlive the test run.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(_TIMEOUT)
    port = listener.getsockname()[1]

    def run() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            listener.close()
            return
        conn.settimeout(_TIMEOUT)
        stream = conn.makefile("rwb")
        stream.write(b"* OK [CAPABILITY IMAP4REV1 AUTH=PLAIN] ready\r\n")
        stream.flush()
        try:
            while True:
                line = stream.readline()
                if not line:
                    break
                tag = line.split(b" ", 1)[0]
                upper = line.upper()
                if b"LIST" in upper:
                    misbehave(conn, stream, tag)
                    break
                if b"CAPABILITY" in upper:
                    stream.write(b"* CAPABILITY IMAP4REV1\r\n" + tag + b" OK done\r\n")
                elif b"LOGIN" in upper:
                    stream.write(tag + b" OK LOGIN done\r\n")
                else:
                    stream.write(tag + b" OK done\r\n")
                stream.flush()
        except OSError:
            pass
        finally:
            for closeable in (conn, listener):
                try:
                    closeable.close()
                except OSError:
                    pass

    threading.Thread(target=run, daemon=True).start()
    return port


def _vanish(conn, stream, tag):
    """The server goes away mid-command — `_get_line` reads EOF."""
    conn.close()


def _unterminated(conn, stream, tag):
    """A line with no CRLF, then silence."""
    stream.write(b"* LIST (\\HasNoChildren) ")
    stream.flush()
    conn.close()


def _unparseable(conn, stream, tag):
    stream.write(b"NOT-A-VALID-RESPONSE-LINE\r\n")
    stream.flush()
    conn.close()


def _wrong_tag(conn, stream, tag):
    stream.write(b"ZZZZ1 OK done\r\n")
    stream.flush()
    conn.close()


def _bad(conn, stream, tag):
    """A BAD tagged response — the server rejecting OUR command."""
    stream.write(tag + b" BAD Invalid arguments\r\n")
    stream.flush()


def _overlong(conn, stream, tag):
    """One response line past imaplib's `_MAXLINE`."""
    stream.write(b'* LIST (\\HasNoChildren) "." "' + b"A" * (imaplib._MAXLINE + 50) + b'"\r\n')
    stream.flush()


def _list_against(misbehave):
    """Run a real LIST against a server that misbehaves, return what raised."""
    port = _serve(misbehave)
    conn = imaplib.IMAP4("127.0.0.1", port, timeout=_TIMEOUT)
    try:
        conn.login("user", "pass")
        conn.list()
    except BaseException as exc:  # the exception IS the result being measured
        return exc
    finally:
        try:
            conn.shutdown()
        except Exception:
            pass
    return None


# ── The load-bearing claim: a broken read is an ABORT ──


@pytest.mark.parametrize(
    "misbehave",
    [
        pytest.param(_vanish, id="server-vanishes"),
        pytest.param(_unterminated, id="unterminated-line"),
        pytest.param(_unparseable, id="unparseable-response"),
        pytest.param(_wrong_tag, id="unexpected-tag"),
    ],
)
def test_a_broken_read_is_an_abort_not_an_error(misbehave):
    """`IMAP4.abort`, which the operation-time net still catches.

    THIS is the test the previous one only claimed to be. imaplib really runs,
    so a future release demoting any of these to `IMAP4.error` fails here —
    which is the moment `protocol_error_is_refusal=False` stops being safe.
    """
    raised = _list_against(misbehave)
    assert isinstance(raised, imaplib.IMAP4.abort), f"got {type(raised).__name__}: {raised}"


def test_a_bad_response_is_an_error_not_an_abort():
    """The other half. A BAD tagged response is the server refusing a command
    of ours, and it must stay distinguishable from a broken read — that
    distinction is the whole basis for letting `error` escape."""
    raised = _list_against(_bad)
    assert isinstance(raised, imaplib.IMAP4.error)
    assert not isinstance(raised, imaplib.IMAP4.abort)


def test_an_overlong_line_is_the_one_documented_exception():
    """Pinned as a KNOWN and accepted cost, not as desired behaviour.

    A single response line past `_MAXLINE` is a misbehaving server, but
    imaplib reports it as `error`, so it escapes the operation-time net and
    reaches the client as a 500. Re-widening the net would restore the
    BAD-response laundering the flag exists to remove, so this is accepted
    and written down. If imaplib ever promotes it to `abort`, this test fails
    and the note in `mail_dial.transport_failures_are_semantic` comes out.
    """
    raised = _list_against(_overlong)
    assert isinstance(raised, imaplib.IMAP4.error)
    assert not isinstance(raised, imaplib.IMAP4.abort)
    assert "1000000" in str(raised)
