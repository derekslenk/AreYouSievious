"""
Integration regression test for the import_script event-loop blocker
(Phase-CP1 follow-up to areyousievious-dfj, Test T-4).

If POST /api/scripts/import is reverted to `async def` with the synchronous
`SieveClient.put_script` inside, every concurrent upload serializes on the
event loop and every async endpoint stalls behind them. With the sync
handler (FastAPI dispatches it to the threadpool), N concurrent slow
uploads finish in ~one SLOW_SECONDS, and `/api/auth/status` (an async
handler) returns in milliseconds throughout.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_import_event_loop.py -v
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import app as app_mod
from auth import sessions

SLOW_SECONDS = 1.0
N_CONCURRENT = 5


def _slow_sieve_client(_session):
    """Drop-in replacement for SieveClient whose put_script sleeps SLOW_SECONDS.

    Used as `patch.object(app_mod, "SieveClient", side_effect=...)` so the
    test never opens a real ManageSieve connection — only the threadpool /
    event-loop interaction matters here.
    """
    cm = MagicMock()
    client = MagicMock()
    client.put_script = lambda name, content: time.sleep(SLOW_SECONDS)
    cm.__enter__.return_value = client
    cm.__exit__.return_value = False
    return cm


@pytest.mark.asyncio
async def test_import_script_does_not_block_event_loop():
    """A slow upload MUST NOT serialize other requests on the event loop.

    Revert `import_script` to `async def` with sync `client.put_script` inside
    and this test goes red:
      - total wall clock for N uploads jumps from ~1 * SLOW_SECONDS
        (sync handler in threadpool) to N * SLOW_SECONDS (async handler
        blocking the loop on each sync put_script call).
      - The async /api/auth/status calls fired during the uploads can't
        be scheduled and their latency explodes past SLOW_SECONDS.
    """
    token = sessions.create(
        host="imap.example.com",
        username="user@example.com",
        password="hunter2",
    )
    cookies = {app_mod.SESSION_COOKIE: token}

    with patch.object(app_mod, "SieveClient", side_effect=_slow_sieve_client):
        transport = httpx.ASGITransport(app=app_mod.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            cookies=cookies,
        ) as client:

            async def do_import(idx: int) -> httpx.Response:
                return await client.post(
                    "/api/scripts/import",
                    data={"name": f"rule_{idx}"},
                    files={"file": (f"rule_{idx}.sieve", b"# rule\n", "application/sieve")},
                )

            async def do_status() -> tuple[httpx.Response, float]:
                t0 = time.monotonic()
                r = await client.get("/api/auth/status")
                return r, time.monotonic() - t0

            start = time.monotonic()
            results = await asyncio.gather(
                *(do_import(i) for i in range(N_CONCURRENT)),
                *(do_status() for _ in range(N_CONCURRENT)),
            )
            elapsed = time.monotonic() - start

    upload_responses = results[:N_CONCURRENT]
    status_pairs = results[N_CONCURRENT:]

    # Every request must have succeeded — otherwise we'd be measuring error
    # paths, not threadpool concurrency.
    for r in upload_responses:
        assert r.status_code == 200, f"upload failed: {r.status_code} {r.text}"
    for r, _ in status_pairs:
        assert r.status_code == 200

    # Anyio's default threadpool is ≥40 workers, so all N uploads run truly
    # concurrently. Total wall clock should be ~SLOW_SECONDS, NOT N * SLOW.
    # Threshold = N/2 * SLOW gives a generous margin and still fails red
    # if the handler is reverted to async (which makes elapsed ~= N * SLOW).
    threshold = SLOW_SECONDS * (N_CONCURRENT / 2)
    assert elapsed < threshold, (
        f"Concurrent uploads took {elapsed:.2f}s, threshold {threshold:.2f}s — "
        f"likely event-loop blocked (was import_script reverted to async def?)"
    )

    # /api/auth/status is a pure-async handler with no I/O — the only thing
    # that can slow it is a blocked event loop. Cap it at SLOW_SECONDS/2.
    max_status_latency = max(latency for _, latency in status_pairs)
    assert max_status_latency < SLOW_SECONDS / 2, (
        f"/api/auth/status max latency {max_status_latency:.2f}s exceeded "
        f"{SLOW_SECONDS / 2:.2f}s — event loop is blocked."
    )
