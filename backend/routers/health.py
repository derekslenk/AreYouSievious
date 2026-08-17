"""
Liveness endpoint.

This module previously declared an APIRouter that app.py never included — it
was unreachable code. The Dockerfile HEALTHCHECK compensated by probing
`/api/auth/status`, which runs session lookup and returns 200 whether or not
the process is healthy, so it was a weak liveness signal that also exercised
auth on every probe.

`/healthz` is unauthenticated by design: it reports only that the process is
up and serving, and deliberately exposes nothing about configuration, the
mail server, or any session. Structured audit logging remains open work
(bd:areyousievious-ilm).
"""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    status: str = "ok"


@router.get("/healthz", response_model=HealthResponse)
def healthz() -> dict[str, str]:
    """Liveness probe. No auth, no dependencies, no I/O."""
    return {"status": "ok"}
