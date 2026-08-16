"""ASGI/Starlette adapter for the shared SSO gate (FastAPI apps).

A non-Flask app cannot ask Flask to decode the shared cookie, so this reproduces
Flask's `SecureCookieSessionInterface` signing exactly — itsdangerous with
Flask's own salt, serializer and key derivation — which keeps it byte-compatible
across Flask versions.

    from thedallasan_gate import GateMiddleware, load_secret

    app.add_middleware(GateMiddleware, secret_key=load_secret(),
                       exempt_paths={"/api/health", "/quick-log"})

Requires the `asgi` extra: `pip install thedallasan-gate[asgi]`.
"""
from __future__ import annotations

import hashlib
from typing import Callable

from flask.json.tag import TaggedJSONSerializer
from itsdangerous import URLSafeTimedSerializer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from .core import (DEFAULT_API_PREFIXES, DEFAULT_EXEMPT_PATHS, DEFAULT_GATE_URL,
                   DEFAULT_MAX_AGE, GatePolicy, decide, load_epoch)


def flask_session_serializer(secret_key: str) -> URLSafeTimedSerializer:
    """Reproduce Flask's session signing serializer byte for byte."""
    return URLSafeTimedSerializer(
        secret_key,
        salt="cookie-session",
        serializer=TaggedJSONSerializer(),
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
    )


class GateMiddleware(BaseHTTPMiddleware):
    """Require the shared SSO cookie on every request.

    `extra_allow` is an optional predicate for a bypass this app alone needs —
    health uses it to let the status page read /api/diagnostics with a shared
    header token. It is consulted only after the cookie check fails, so it can
    widen access but never narrow it, and an exception inside it is treated as
    "not allowed" rather than propagating.
    """

    def __init__(self, app, secret_key: str, *,
                 gate_url: str = DEFAULT_GATE_URL,
                 exempt_paths: set[str] | frozenset[str] | None = None,
                 api_prefixes: tuple[str, ...] = DEFAULT_API_PREFIXES,
                 max_age: int = DEFAULT_MAX_AGE,
                 extra_allow: Callable[[Request], bool] | None = None,
                 session_epoch_path: str | None = None):
        super().__init__(app)
        if not secret_key:
            # Defence in depth: callers get the secret from load_secret(), which
            # already raises. This makes it impossible to construct a middleware
            # that silently permits everything even by passing "" directly.
            raise ValueError("GateMiddleware requires a non-empty secret_key")
        if session_epoch_path is not None:
            load_epoch(session_epoch_path)          # fail at construction, not mid-request
        self._serializer = flask_session_serializer(secret_key)
        self._max_age = max_age
        self._extra_allow = extra_allow
        self._session_epoch_path = session_epoch_path
        self._policy = GatePolicy(
            gate_url=gate_url,
            exempt_paths=frozenset(exempt_paths) if exempt_paths is not None
            else DEFAULT_EXEMPT_PATHS,
            api_prefixes=tuple(api_prefixes),
        )

    def _logged_in(self, request: Request) -> bool:
        cookie = request.cookies.get("session")
        if not cookie:
            return False
        try:
            data = self._serializer.loads(cookie, max_age=self._max_age)
        except Exception:                          # noqa: BLE001 — any failure is a no
            return False
        if not (isinstance(data, dict) and data.get("logged_in")):
            return False
        # See flask_gate.py's install_flask_gate — same feature, same reasoning.
        # Read fresh every request so a revoke takes effect without a restart.
        if self._session_epoch_path is not None:
            return data.get("session_epoch") == load_epoch(self._session_epoch_path)
        return True

    def _allowed_by_extra(self, request: Request) -> bool:
        if self._extra_allow is None:
            return False
        try:
            return bool(self._extra_allow(request))
        except Exception:                          # noqa: BLE001 — a broken hook denies
            return False

    async def dispatch(self, request: Request, call_next):
        d = decide(self._policy, request.url.path, self._logged_in(request))
        if d.allowed or self._allowed_by_extra(request):
            return await call_next(request)
        if d.action == "json401":
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return RedirectResponse(d.location, status_code=302)
