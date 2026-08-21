"""
In-memory stand-ins for the two mail-server seams (areyousievious-8fg.8).

A test that wants to know what the ROUTE does when the server says no should
not have to own a mail server, or a mock's worth of protocol detail. These
hold `{name: content}` and which name is active, and let a test arm the exact
failure it wants to see handled:

    store.reject_next(ScriptRejected("line 4: unknown command 'vacation'"))

which is what makes the false-success test readable: WHEN THE SERVER REJECTS,
THE ROUTE MUST NOT ANSWER OK.

Every operation runs the same `protocol_names` guard the real adapter runs,
before anything else. A fake that skipped it would answer 200 to a name the
real sink rejects before it reaches the wire — the precise shape of a passing
test that means nothing.

`validate=True` additionally runs SIEVELIB's parser over anything PUT.
Deliberately sievelib and deliberately NOT our own parser: validating our
generator's output with our own parser asserts only that the two agree with
each other, which is the exact loop that let three `previewRule` divergences
ship. sievelib is a third-party grammar and therefore an independent oracle.

Opt-in rather than always-on because that grammar has real gaps — `include`,
`addheader` and `spamtest` are all rejected as "unknown command" (verified),
though a real server accepts them. A mandatory validator would refuse scripts
that work.
"""

from __future__ import annotations

from mail_errors import FolderRejected, MailStoreError, ScriptNotFound, ScriptRejected
from protocol_names import validate_folder_name, validate_script_name
from sievelib.parser import Parser


def sieve_errors(content: str) -> str | None:
    """sievelib's complaint about `content`, or None if it parses.

    The independent oracle. Its verdict is advisory for anything using an
    extension it lacks, which is why callers opt in.
    """
    parser = Parser()
    if parser.parse(content):
        return None
    return str(parser.error)


class _Programmable:
    """Shared arming: one queued failure, raised by the next operation."""

    def __init__(self) -> None:
        self._armed: MailStoreError | None = None

    def reject_next(self, error: MailStoreError) -> None:
        """Arm the next operation to fail with `error`, once."""
        self._armed = error

    def _fail_if_armed(self) -> None:
        if self._armed is not None:
            error, self._armed = self._armed, None
            raise error


class FakeScriptStore(_Programmable):
    """An in-memory ScriptStore.

    Holds what a real server holds — script text by name, and which one is
    active — so a test can assert on the STATE a request left behind rather
    than on which methods were called.
    """

    def __init__(
        self,
        scripts: dict[str, str] | None = None,
        active: str | None = None,
        *,
        validate: bool = False,
    ) -> None:
        super().__init__()
        self.scripts: dict[str, str] = dict(scripts or {})
        self.active = active
        self.validate = validate

    def list_scripts(self) -> list[dict]:
        self._fail_if_armed()
        # Active first, as the adapter reports it: sievelib's listscripts
        # returns the active name separately from the rest.
        names = sorted(self.scripts, key=lambda n: n != self.active)
        return [{"name": n, "active": n == self.active} for n in names]

    def get_script(self, name: str) -> str:
        validate_script_name(name)
        self._fail_if_armed()
        if name not in self.scripts:
            raise ScriptNotFound()
        return self.scripts[name]

    def put_script(self, name: str, content: str) -> None:
        validate_script_name(name)
        self._fail_if_armed()
        if self.validate:
            complaint = sieve_errors(content)
            if complaint is not None:
                # What a real server does with a script it cannot compile:
                # refuse it, and say why.
                raise ScriptRejected(complaint)
        self.scripts[name] = content

    def activate_script(self, name: str) -> None:
        validate_script_name(name)
        self._fail_if_armed()
        if name not in self.scripts:
            raise ScriptNotFound()
        self.active = name

    def delete_script(self, name: str) -> None:
        validate_script_name(name)
        self._fail_if_armed()
        if name not in self.scripts:
            raise ScriptNotFound()
        if name == self.active:
            # RFC 5804 ACTIVE: a server refuses to delete the script in use.
            # A fake that allowed it would let a test prove behaviour no real
            # server permits.
            raise ScriptRejected("Cannot delete the active script.")
        del self.scripts[name]


class FakeFolderStore(_Programmable):
    """An in-memory FolderStore."""

    def __init__(self, folders: list[str] | None = None) -> None:
        super().__init__()
        self.folders: list[str] = list(folders or [])

    def list_folders(self) -> list[dict]:
        self._fail_if_armed()
        return [{"name": n, "delimiter": "/", "flags": []} for n in self.folders]

    def create_folder(self, name: str) -> None:
        validate_folder_name(name)
        self._fail_if_armed()
        if name in self.folders:
            raise FolderRejected("Folder already exists.")
        self.folders.append(name)
