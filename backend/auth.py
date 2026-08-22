"""
Session-based auth with in-memory credential storage.
No credentials are persisted to disk.

The store holds a PLAINTEXT PASSWORD for the life of each session, which is
what makes the three properties below security properties rather than
housekeeping: how long one lives, when a dead one is actually dropped, and
whether concurrent requests can corrupt the dict holding them.

There is deliberately NO module-level instance. One dict shared by every app
in the process is what `create_app` threads `Settings` through `app.state` to
avoid, and the session store is the one thing that had escaped it — which is
why the suite needed teardown to stop a session outliving its test. The store
is built in `create_app` and reached through `dependencies.get_sessions`.
"""

import secrets
import threading
import time
from dataclasses import dataclass

# Idle time before a session is dropped. The `ays_session` cookie carries the
# same value as its `max_age`, but that is a hint to the browser; this is the
# one the server enforces.
SESSION_IDLE_TIMEOUT = 1800  # 30 minutes

# Absolute cap, counted from login and NOT refreshed by use. Without it the
# timeout was idle-only, so a client polling `/api/auth/status` kept a
# plaintext password resident for as long as it cared to poll. Eight hours is
# a working day: long enough that nobody is re-authenticating over lunch,
# short enough that a forgotten tab does not hold credentials overnight.
SESSION_MAX_LIFETIME = 8 * 3600

# How often the store may sweep expired sessions. The sweep is O(n), so
# running it per request would make a busy session pay for every dead one;
# running it only on login — which is what happened before — means a
# single-user deployment never sweeps at all, because nobody else ever logs
# in.
SESSION_SWEEP_INTERVAL = 60


@dataclass
class Session:
    token: str
    host: str
    host_ip: str
    port_imap: int
    port_sieve: int
    username: str
    password: str
    created_at: float
    last_used: float


class SessionManager:
    """Tokens to credentials, for one app.

    Every mutation holds `_lock`. Sync handlers run in a threadpool by design,
    and without it eight concurrent logins raised on the first attempt — two
    distinct ways, both landing AFTER the IMAP login had succeeded, so the
    user authenticated correctly and got a 500 with no session:

        RuntimeError: dictionary changed size during iteration
        KeyError: <token>

    The first is a sweep iterating while another thread inserts; the second is
    two sweeps computing overlapping expired lists and both deleting. Removal
    also goes through `pop`, so each method is safe read on its own rather
    than only in company.
    """

    def __init__(
        self,
        idle_timeout: float = SESSION_IDLE_TIMEOUT,
        max_lifetime: float = SESSION_MAX_LIFETIME,
        sweep_interval: float = SESSION_SWEEP_INTERVAL,
    ):
        self._sessions: dict[str, Session] = {}
        self._idle_timeout = idle_timeout
        self._max_lifetime = max_lifetime
        self._sweep_interval = sweep_interval
        self._lock = threading.Lock()
        self._last_sweep = 0.0
        # Counts sweeps rather than timing them, so a test can assert the rate
        # limit holds without sleeping through it.
        self._sweeps = 0

    def create(
        self,
        host: str,
        host_ip: str,
        username: str,
        password: str,
        port_imap: int = 993,
        port_sieve: int = 4190,
    ) -> str:
        """Create a new session, return token.

        `host_ip` is the address `host` resolved to at login time. The
        outbound clients re-resolve at every connect and abort if the answer
        no longer includes this IP — the DNS-rebinding guard.
        """
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sessions[token] = Session(
                token=token,
                host=host,
                host_ip=host_ip,
                port_imap=port_imap,
                port_sieve=port_sieve,
                username=username,
                password=password,
                created_at=now,
                last_used=now,
            )
            self._sweep(now)
        return token

    def get(self, token: str) -> Session | None:
        """The live session for `token`, or None if it is missing or over.

        A session that is over is REMOVED, not merely hidden: reporting None
        while keeping the password in the dict would be the same defect
        wearing a different face.
        """
        now = time.time()
        with self._lock:
            self._sweep(now)
            session = self._sessions.get(token)
            if session is None:
                return None
            if self._is_over(session, now):
                self._sessions.pop(token, None)
                return None
            session.last_used = now
            return session

    def destroy(self, token: str) -> None:
        """Drop a session. Unknown tokens are not an error — a double logout
        is a race, not a mistake."""
        with self._lock:
            self._sessions.pop(token, None)

    def count(self) -> int:
        """How many sessions are held, expired ones included."""
        with self._lock:
            return len(self._sessions)

    def _is_over(self, session: Session, now: float) -> bool:
        """Idle too long, OR alive too long.

        The second half is what `created_at` is for. It was written and never
        read, so use refreshed the clock without limit.
        """
        return (
            now - session.last_used > self._idle_timeout
            or now - session.created_at > self._max_lifetime
        )

    def _sweep(self, now: float) -> None:
        """Drop everything expired. CALLER MUST HOLD `_lock`.

        Rate-limited by `_sweep_interval`: it walks the whole store, so a
        per-request sweep would make a busy session pay for every dead one.
        """
        if now - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now
        self._sweeps += 1
        for token in [t for t, s in self._sessions.items() if self._is_over(s, now)]:
            self._sessions.pop(token, None)
