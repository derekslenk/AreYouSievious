"""
The two mail-server seams.

ScriptStore and FolderStore stay SEPARATE interfaces. A single
seven-operation MailStore would be a union rather than an abstraction: no
caller wants both halves, and `routers/scripts.py` and `routers/folders.py`
already split exactly along this line. What the two share is the `mail_dial`
connection policy and the `mail_errors` vocabulary — not a method table.

Structural (`Protocol`, not ABC) on purpose, and deliberately NOT
`runtime_checkable`: an isinstance check against a Protocol compares method
NAMES only, so `IMAPClient` would pass today despite `create_folder` still
returning `bool` where this seam says it raises. A check that cannot see the
one mismatch that matters is worse than no check. The shipped `SieveClient` and
`IMAPClient` satisfy these by having the right methods, with no base class to
inherit and no registration step, and so does an in-memory fake (`.8`). The
seam describes what already exists; it does not ask the adapters to be
rebuilt around it.

EVERY operation reports failure by RAISING from `mail_errors` — never by
returning a falsy value. `IMAPClient.create_folder` currently returns `bool`
and `routers/folders.py` turns a `False` into a 400 by hand, which is the
last place a router still decides what a protocol failure means. Bringing the
adapters onto this contract is `.6`; this module states the contract they are
brought onto.
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

        Returns nothing: failure raises. The bool this replaces made the
        router ask "did that work?" and answer 400 for every cause alike —
        an unreachable server and a rejected name looked identical.
        """
        ...
