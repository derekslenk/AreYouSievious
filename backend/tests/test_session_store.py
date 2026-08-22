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

import re
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
    """`destroy` must tolerate a token that is already gone.

    A double logout is a race, not a mistake, which is why `destroy` alone
    keeps `pop(..., None)` — the other removals use `del`, because the lock
    guarantees the key is there. Mutating this one to `del` fails three
    tests.

    An earlier version of this test also claimed to prove that two sweeps
    over the same expired token cannot fight. It proved nothing: instrumented
    through that block, the key was present at BOTH deletes, so `del` never
    raised, and `del`->`pop` in the sweep left the whole suite green. The
    claim was written from reasoning about the old code and never checked
    against the new.
    """
    store = _store(idle_timeout=1000, sweep_interval=3600)
    token = store.create(**CREDS)
    store.destroy(token)
    store.destroy(token)
    assert store.get(token) is None
    assert store.count() == 0


def test_a_session_dies_at_its_absolute_lifetime_however_busy():
    """`created_at` now means something. Constant use refreshes `last_used`
    and must NOT buy more time: a client polling `/api/auth/status` kept a
    plaintext password resident for as long as it cared to poll.

    Driven by a patched clock rather than by sleeping. The wall-clock version
    left ~0.3s of slack, which is the first thing to go on a starved CI box —
    and this file already had to stop sleeping once for that reason.
    """
    clock = {"now": 1000.0}
    with patch("auth.time.time", lambda: clock["now"]):
        store = _store(idle_timeout=1000, max_lifetime=100, sweep_interval=99999)
        token = store.create(**CREDS)
        for _ in range(9):
            clock["now"] += 10
            assert store.get(token) is not None, "constant use must not end it early"
        clock["now"] += 20  # now 110s past creation
        assert store.get(token) is None, "absolute lifetime did not fire"


def test_use_refreshes_the_idle_clock():
    """The half of `get` that keeps a working session alive.

    Nothing pinned it: deleting `session.last_used = now` left all 693 tests
    green, and that mutation logs every user out a fixed time after LOGIN
    however hard they are working.

    Each step advances the clock to just INSIDE the idle window, so only the
    refresh carries the session across the next one. Without it the second
    step is already 18s idle against a 10s limit and this fails.
    """
    clock = {"now": 1000.0}
    with patch("auth.time.time", lambda: clock["now"]):
        store = _store(idle_timeout=10, max_lifetime=99999, sweep_interval=99999)
        token = store.create(**CREDS)
        for _ in range(6):
            clock["now"] += 9
            assert store.get(token) is not None, "steady use must keep it alive"
        clock["now"] += 11
        assert store.get(token) is None


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
    # A long interval first, so `create` does NOT sweep — otherwise the
    # creates below do the work and this asserts sweep-on-login, which is the
    # exact old behaviour. An earlier version of this test did precisely
    # that: `count()` was already 1 before any `get`, and deleting the sweep
    # from `get` left the whole suite green.
    store = _store(idle_timeout=100, sweep_interval=3600)
    doomed = [store.create(**CREDS) for _ in range(10)]
    live = store.create(**CREDS)

    # Age the doomed ones by rewriting their clocks rather than sleeping.
    # Sleeping to expire some sessions but not another needs the two windows
    # to stay apart on a loaded CI box; this needs nothing.
    past = time.time() - 1000
    for token in doomed:
        store._sessions[token].last_used = past
        store._sessions[token].created_at = past
    assert store.count() == 11, "setup failed: nothing should have been swept yet"

    store._sweep_interval = 0
    store.get(live)  # ONE ordinary request, by the one user there is

    assert store.count() == 1, f"the sweep did not run on get: {store.count()} left"
    assert all(store.get(token) is None for token in doomed)


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


def test_a_sub_second_timeout_still_yields_a_usable_cookie(make_app):
    """`int(0.1)` is 0, and a browser reads `Max-Age=0` as delete-this-now.

    So a sub-second idle timeout answered 200 OK with a cookie the browser
    threw away immediately and the session never stuck — a login that
    succeeds and does nothing. `_env_float` floors at 0.1, so this is
    reachable from `AYS_SESSION_IDLE_TIMEOUT=0`.
    """
    app = make_app(Settings(session_idle_timeout=0.1))
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
    for header in response.headers.get_list("set-cookie"):
        value = re.search(r"Max-Age=(\d+)", header)
        assert value, header
        # Parsed, not matched as a substring: `"Max-Age=1" in header` is also
        # true of `Max-Age=100` and `Max-Age=1800`, so a mutation to
        # `max(100, ...)` slipped straight through it.
        assert int(value.group(1)) == 1, header


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


# ── The two limits on when credentials are actually freed ──


def test_an_expired_session_can_outlive_its_deadline_by_one_sweep_interval():
    """Documented behaviour, pinned so the README cannot drift from it.

    The sweep is rate-limited, so a busy store does NOT free an expired
    session on the next request — the first wording of that README row said
    it did, and five `get`s inside one interval left the password resident.
    What IS guaranteed is that the session is never handed out, which the
    assertion below states directly.
    """
    store = _store(idle_timeout=100, sweep_interval=60)
    dead, live = store.create(**CREDS), store.create(**CREDS)
    past = time.time() - 1000
    store._sessions[dead].last_used = past
    store._sessions[dead].created_at = past

    for _ in range(5):
        store.get(live)
    assert dead in store._sessions, "rate limit gone: the README row now understates"
    # The property that does hold, and the one that matters to a caller.
    assert store.get(dead) is None


def test_a_session_nobody_returns_to_is_never_swept():
    """The gap the follow-up bead covers, stated as a test rather than only
    as prose. A user who logs in and closes the tab calls neither `create`
    nor `get` again, so nothing sweeps and the credential stays resident."""
    store = _store(idle_timeout=100, sweep_interval=0)
    token = store.create(**CREDS)
    past = time.time() - 1000
    store._sessions[token].last_used = past
    store._sessions[token].created_at = past

    time.sleep(0.05)  # time passing is not, by itself, a sweep
    assert store.count() == 1
    assert store._sessions[token].password == CREDS["password"], "the credential is what lingers"
    # And the moment anything touches the store, it goes.
    store.create(**CREDS)
    assert token not in store._sessions
