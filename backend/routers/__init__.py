"""
FastAPI router package (areyousievious-u40).

Each module here owns one URL area (auth, scripts, folders, static,
health). app.py composes them via `app.include_router(...)`. Do NOT
cross-import between routers; if two routers need the same helper,
it belongs in backend/dependencies.py.
"""
