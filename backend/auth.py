"""
Session-based auth with in-memory credential storage.
No credentials are persisted to disk.
"""

import secrets
import time
from dataclasses import dataclass
from typing import Optional


SESSION_TIMEOUT = 1800  # 30 minutes


@dataclass
class Session:
    token: str
    host: str
    port_imap: int
    port_sieve: int
    username: str
    password: str
    created_at: float
    last_used: float


class SessionManager:
    def __init__(self, timeout: int = SESSION_TIMEOUT):
        self._sessions: dict[str, Session] = {}
        self._timeout = timeout

    def create(self, host: str, username: str, password: str,
               port_imap: int = 993, port_sieve: int = 4190) -> str:
        """Create a new session, return token."""
        token = secrets.token_urlsafe(32)
        now = time.time()
        self._sessions[token] = Session(
            token=token,
            host=host,
            port_imap=port_imap,
            port_sieve=port_sieve,
            username=username,
            password=password,
            created_at=now,
            last_used=now,
        )
        self._cleanup()
        return token

    def get(self, token: str) -> Optional[Session]:
        """Get session by token, or None if expired/missing."""
        session = self._sessions.get(token)
        if not session:
            return None
        if time.time() - session.last_used > self._timeout:
            del self._sessions[token]
            return None
        session.last_used = time.time()
        return session

    def destroy(self, token: str):
        """Destroy a session."""
        self._sessions.pop(token, None)

    def _cleanup(self):
        """Remove expired sessions."""
        now = time.time()
        expired = [
            k for k, v in self._sessions.items()
            if now - v.last_used > self._timeout
        ]
        for k in expired:
            del self._sessions[k]


sessions = SessionManager()
