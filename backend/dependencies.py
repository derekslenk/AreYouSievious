"""
Shared FastAPI dependencies (areyousievious-u40, reworked in -8fg.7).

Routers RECEIVE their collaborators here rather than reaching out for them.
That is the whole point of the rework: `get_session` used to be a plain
function called inside each handler, and the stores were constructed inline
as `with SieveClient(session) as client:`, so a test could only substitute
them by patching the class. Now every one of them is a `Depends`, and a test
substitutes with

    app.dependency_overrides[get_script_store] = lambda: FakeScriptStore()

which is also what lets the fakes in `.8` exist at all.

The second half of the rework rides on the same move. A dependency receives
the request, so it can read `request.app.state.settings` — the configuration
THIS app was built with — and pass it down into `mail_dial`. Before, the dial
read the process-global `settings()` singleton, so four of nine Settings
fields were inert when passed to `create_app`: the app honoured them and the
connection did not.
"""

from __future__ import annotations

from collections.abc import Iterator

from auth import Session, sessions
from config import Settings
from fastapi import Depends, HTTPException, Request
from imap_client import IMAPClient
from mail_stores import FolderStore, ScriptStore
from managesieve_client import SieveClient

SESSION_COOKIE = "ays_session"


def get_settings(request: Request) -> Settings:
    """The configuration this app was built with.

    `request.app.state.settings`, never the module-level singleton — an app
    built by `create_app(Settings(...))` must be the one that answers.
    """
    return request.app.state.settings


def get_session(request: Request) -> Session:
    """Extract and validate session from cookie or Authorization header."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "Not authenticated")
    session = sessions.get(token)
    if not session:
        raise HTTPException(401, "Session expired")
    return session


def get_optional_session(request: Request) -> Session | None:
    """The session if there is a valid one, None otherwise.

    For the single endpoint that REPORTS on authentication rather than
    requiring it: `/api/auth/status` answers `{"authenticated": false}`, so it
    needs the absence of a session as a value rather than as a 401. Without
    this it had to call `get_session` inside the handler and catch the
    HTTPException — the reach-out shape this module exists to remove.
    """
    try:
        return get_session(request)
    except HTTPException:
        return None


def get_script_store(
    session: Session = Depends(get_session),
    cfg: Settings = Depends(get_settings),
) -> Iterator[ScriptStore]:
    """An open ScriptStore for this request, closed when it ends.

    Yields rather than returns so FastAPI runs the adapter's teardown after
    the response — the same guarantee the `with` block in each handler used
    to give, minus the handler having to know about it.
    """
    with SieveClient(session, cfg) as store:
        yield store


def get_folder_store(
    session: Session = Depends(get_session),
    cfg: Settings = Depends(get_settings),
) -> Iterator[FolderStore]:
    """An open FolderStore for this request, closed when it ends."""
    with IMAPClient(session, cfg) as store:
        yield store
