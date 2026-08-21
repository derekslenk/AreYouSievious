"""
The two mail-server seams.

ScriptStore and FolderStore stay SEPARATE interfaces. A single
seven-operation MailStore would be a union rather than an abstraction: no
caller wants both halves, and `routers/scripts.py` and `routers/folders.py`
already split exactly along this line. What the two share is the `mail_dial`
connection policy and the `mail_errors` vocabulary — not a method table.

Structural (`Protocol`, not ABC) on purpose, and deliberately NOT
`runtime_checkable`: an isinstance check against a Protocol compares method
NAMES only. It cannot see a return type, and it cannot see whether failure
raises or is swallowed — which is the whole substance of this contract. A
check blind to the only thing that matters is worse than no check. The shipped `SieveClient` and
`ImapFolderStore` satisfy these by having the right methods, with no base class to
inherit and no registration step, and so does an in-memory fake (`.8`). The
seam describes what already exists; it does not ask the adapters to be
rebuilt around it.

EVERY operation reports failure by RAISING from `mail_errors` — never by
returning a falsy value, and never by returning `None` and letting the caller
trip over it later. The shipped adapters were brought onto this contract in
`.6`: `SieveClient` translates sievelib's falsy returns plus its `errcode` /
`errmsg`, and `ImapFolderStore.create_folder` raises instead of handing back a
bool for `routers/folders.py` to interpret.
"""

from __future__ import annotations

from typing import Protocol


class ScriptStore(Protocol):
    """Read and write Sieve scripts for one authenticated session.

    Raises (any operation): MailServerUnavailable, AuthFailed.
    """

    def list_scripts(self) -> list[dict]:
        """Every script on the account, with its active flag."""
        ...

    def get_script(self, name: str) -> str:
        """The script's raw Sieve text. Raises ScriptNotFound."""
        ...

    def put_script(self, name: str, content: str) -> None:
        """Create or replace a script. Raises ScriptRejected, QuotaExceeded."""
        ...

    def activate_script(self, name: str) -> None:
        """Make this the one active script. Raises ScriptNotFound."""
        ...

    def delete_script(self, name: str) -> None:
        """Remove a script. Raises ScriptNotFound."""
        ...


class FolderStore(Protocol):
    """Read and create IMAP folders for one authenticated session.

    Raises (any operation): MailServerUnavailable, AuthFailed.
    """

    def list_folders(self) -> list[dict]:
        """Every folder on the account."""
        ...

    def create_folder(self, name: str) -> None:
        """Create and subscribe a folder.

        Returns nothing: failure raises `FolderRejected`. The bool this
        replaced made the router ask "did that work?" and answer 400 for
        every cause alike — an unreachable server and a rejected name looked
        identical. Subscription failure counts: a folder the user cannot see
        is not a folder they got.
        """
        ...
