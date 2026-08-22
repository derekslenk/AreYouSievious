"""
The session store: ownership, lifetime, and concurrency (areyousievious-8fg.23).

`create_app` threads a `Settings` through `app.state` precisely so nothing
mutates globals — and the session store never got that treatment. It was one
module-level dict shared by EVERY app in the process, which is why the suite
grew fixtures that hand-roll a session and destroy it in teardown: a leaked
one outlived its test for the whole run.

Three properties the old interface did not state, each verified before this
change:

  1. EVICTION FIRED ONLY ON LOGIN. `_cleanup` had exactly one caller —
     `create`. On a single-user deployment nobody else ever logs in, so the
     sweep never ran and expired sessions sat in memory holding plaintext
     passwords.

  2. NO ABSOLUTE LIFETIME. `created_at` was written and never read (grepped:
     the definition, the assignment, and test fixtures). `get` refreshed
     `last_used` on every request, so the timeout was idle-only and a client
     polling `/api/auth/status` kept a password resident indefinitely. The
     cookie's `max_age` is a browser hint the server did not enforce.

  3. NOT THREAD-SAFE. Sync handlers run in a threadpool by design, and there
     was no lock across four mutation sites. Reproduced on the first attempt
     with 8 threads and a switch interval of 1e-9 — TWO distinct failures,
     not the one the bead predicted:

         RuntimeError: dictionary changed size during iteration
         KeyError: <token>

     The first is `_cleanup` iterating while another thread inserts. The
     second is two sweeps computing overlapping expired lists and both
     deleting. Both land AFTER the IMAP login succeeded, so the user
     authenticates correctly and receives a 500 with no session.
"""

from __future__ import annotations

import sys
import threading
import time
from unittest.mock import patch

from auth import SessionManager
from config import Settings
from fastapi.testclient import TestClient

CREDS = {"host": "mail.example.com", "host_ip": "93.184.216.34", "username": "u", "password": "p"}


def _store(**kwargs) -> SessionManager:
    return SessionManager(**kwargs)


# ── 3. Concurrency ──


def test_concurrent_creates_do_not_raise():
    """The reproduction, as a lock.

    Every session expires immediately and the store is pre-loaded, so each
    `create` sweeps a full dict while seven other threads insert into it.
    Without a lock this raised within one attempt.
    """
    # sweep_interval=0 so EVERY create sweeps, which is what the old code did
    # unconditionally. With the default interval the sweep runs once and the
    # race never reoccurs — a version of this test that omitted it passed
    # with the lock removed, pinning the outcome and not the mechanism.
    store = _store(idle_timeout=0, sweep_interval=0)
    for _ in range(300):
        store.create(**CREDS)
    errors: list[str] = []

    def hammer() -> None:
        try:
            for _ in range(60):
                store.create(**CREDS)
        except Exception as exc:  # the exception IS the result being measured
            errors.append(f"{type(exc).__name__}: {exc}")

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-9)
    try:
        threads = [threading.Thread(target=hammer) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        sys.setswitchinterval(previous)
    assert not errors, errors[:3]


def test_concurrent_get_and_destroy_of_one_token_do_not_raise():
    """Mixed reads and removals under threads. A smoke test, said plainly.

    It does NOT reproduce a historical failure, and an earlier version of this
    docstring claimed it did. I instrumented the original manager to find
    where each exception was actually raised, and BOTH came from `_cleanup` —
    the RuntimeError from its list comprehension, the KeyError from its `del`.
    Nothing came from `get`. The `get`/`get` window between finding an expired
    session and removing it is real but too narrow to drive reliably, which is
    why removal goes through `pop` (see the test below) rather than resting on
    a race being lost.

    `test_concurrent_creates_do_not_raise` is the one that reproduces.
    """
    # Built so the sessions SURVIVE creation, then expired all at once. With
    # `idle_timeout=0` from the start the sweep removed them as they were
    # made, so `get` returned early and never reached the removal this test
    # is about — the setup destroyed the state under test.
    store = _store(idle_timeout=1000, sweep_interval=3600)
    tokens = [store.create(**CREDS) for _ in range(200)]
    store._idle_timeout = 0
    errors: list[str] = []

    def churn(fn) -> None:
        try:
            for token in tokens:
                fn(token)
        except Exception as exc:  # the exception IS the result being measured
            errors.append(f"{type(exc).__name__}: {exc}")

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-9)
    try:
        threads = [
            threading.Thread(target=churn, args=(store.get if i % 2 else store.destroy,))
            for i in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        sys.setswitchinterval(previous)
    assert not errors, errors[:3]


# ── 2. Absolute lifetime ──


def test_removing_a_session_twice_is_not_an_error():
    """Idempotent removal, pinned directly rather than through a race.

    The original `get` used `del self._sessions[token]`, so two callers that
    both saw the same expired session raced to raise KeyError on the second
    delete. `pop` closes that by construction, and this asserts the property
    instead of trying to lose the race on purpose.
    """
    store = _store(idle_timeout=1000)
    token = store.create(**CREDS)
    store.destroy(token)
    store.destroy(token)
    assert store.get(token) is None
    # -1, not 0: `now - last_used > 0` is FALSE when both land in the same
    # clock tick, so a 0 timeout made this pass alone and fail inside the
    # suite. A negative bound is over for any elapsed time at all.
    store._idle_timeout = -1
    other = store.create(**CREDS)
    assert store.get(other) is None
    assert store.get(other) is None


def test_a_session_dies_at_its_absolute_lifetime_however_busy():
    """`created_at` now means something. Constant use refreshes `last_used`
    and must NOT buy more time: a client polling `/api/auth/status` kept a
    plaintext password resident for as long as it cared to poll."""
    store = _store(idle_timeout=1000, max_lifetime=0.5)
    token = store.create(**CREDS)
    for _ in range(4):
        time.sleep(0.05)
        assert store.get(token) is not None, "constant use must not end it early"
    time.sleep(0.4)
    assert store.get(token) is None, "absolute lifetime did not fire"


def test_an_idle_session_still_dies_of_idleness():
    """The half that already worked, kept honest."""
    store = _store(idle_timeout=0.1, max_lifetime=1000)
    token = store.create(**CREDS)
    assert store.get(token) is not None
    time.sleep(0.15)
    assert store.get(token) is None


def test_an_expired_session_is_dropped_not_merely_hidden():
    """Returning None while keeping the password in the dict would be the
    same defect wearing a different face."""
    store = _store(idle_timeout=0.05)
    token = store.create(**CREDS)
    time.sleep(0.1)
    assert store.get(token) is None
    assert token not in store._sessions


# ── 1. Eviction without a login ──


def test_expired_sessions_are_swept_without_anyone_logging_in():
    """`_cleanup` ran only from `create`. On a single-user deployment nobody
    else ever logs in, so nothing was ever swept — the store only grew."""
    store = _store(idle_timeout=0.05, sweep_interval=0)
    for _ in range(10):
        store.create(**CREDS)
    live = store.create(**CREDS)
    time.sleep(0.1)
    fresh = store.create(**CREDS)  # not the sweeper under test; just a live token
    store.get(fresh)  # a plain request is enough to trigger the sweep
    assert store.count() == 1, f"expected only the fresh session, got {store.count()}"
    assert store.get(live) is None


def test_the_sweep_does_not_run_on_every_request():
    """It is O(n) over the store. A per-request sweep would make a busy
    session pay for every dead one, so it is rate-limited."""
    store = _store(idle_timeout=1000, sweep_interval=3600)
    token = store.create(**CREDS)
    sweeps_before = store._sweeps
    for _ in range(50):
        store.get(token)
    assert store._sweeps == sweeps_before


# ── Ownership ──


def test_two_stores_do_not_share_sessions():
    """The property `app.state` exists to give. One dict shared by every app
    in the process is why the suite needed teardown to stop a session
    outliving its test."""
    first, second = _store(), _store()
    token = first.create(**CREDS)
    assert first.get(token) is not None
    assert second.get(token) is None


def test_count_reports_what_is_held():
    store = _store()
    assert store.count() == 0
    token = store.create(**CREDS)
    assert store.count() == 1
    store.destroy(token)
    assert store.count() == 0


def test_destroying_an_unknown_token_is_not_an_error():
    _store().destroy("never-existed")


# ── The cookie and the store agree ──


def test_the_session_cookie_expires_with_the_store_not_a_literal(make_app):
    """`max_age` was 1800 written twice, beside a store timeout of 1800.

    The cookie is a hint the browser may honour and the store is what
    enforces expiry, so two numbers meaning the same thing drift: a cookie
    outliving its session logs the user out mid-action, and one dying early
    throws away a session the server still holds. Asserted on the real
    Set-Cookie header, not by reading the source.
    """
    app = make_app(Settings(session_idle_timeout=120))
    with (
        patch("routers.auth.validate_host", return_value="93.184.216.34"),
        patch("routers.auth.verify_credentials", return_value=None),
    ):
        with TestClient(app) as http:
            response = http.post(
                "/api/auth/login",
                json={"host": "mail.example.com", "username": "u", "password": "p"},
            )
    assert response.status_code == 200, response.text
    set_cookies = response.headers.get_list("set-cookie")
    assert set_cookies, "login set no cookies"
    for header in set_cookies:
        assert "Max-Age=120" in header, header
