"""
Shared FastAPI dependencies (areyousievious-u40).

Houses the per-request session lookup so every router can depend on
it without importing from another router. Pulled out of app.py during
the router split — behavior is byte-identical to the original
inline helper.
"""

from __future__ import annotations

from auth import Session, sessions
from fastapi import HTTPException, Request

SESSION_COOKIE = "ays_session"


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
