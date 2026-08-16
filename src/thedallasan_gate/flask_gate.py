"""Flask adapter for the shared SSO gate.

Flask decodes the shared cookie natively once it holds the same secret_key, so
this adapter is thin: configure the app, then install one before_request that
asks core.decide() what to do.

    from thedallasan_gate import install_flask_gate

    app = Flask(__name__)
    install_flask_gate(app)          # raises if FLASK_SECRET_KEY is unset
"""
from __future__ import annotations

from datetime import timedelta

from flask import jsonify, redirect, request, session

from .core import (COOKIE_CONFIG, DEFAULT_API_PREFIXES, DEFAULT_EXEMPT_PATHS,
                   DEFAULT_GATE_URL, DEFAULT_MAX_AGE, GatePolicy, decide,
                   load_epoch, load_secret)


def install_flask_gate(
    app,
    *,
    gate_url: str | None = None,
    exempt_paths: set[str] | frozenset[str] | None = None,
    exempt_endpoints: set[str] | frozenset[str] | None = None,
    api_prefixes: tuple[str, ...] = DEFAULT_API_PREFIXES,
    secret_var: str = "FLASK_SECRET_KEY",
    env: dict[str, str] | None = None,
    session_epoch_path: str | None = None,
) -> GatePolicy:
    """Configure `app` for the shared SSO cookie and gate every request.

    Raises GateConfigError when the secret is missing — the app must not start.
    Callers pass only what differs from the house default; anything they do not
    pass they cannot get subtly wrong.

    `exempt_paths` REPLACES the default set rather than extending it, so an app
    that needs an extra open path must restate /api/health and see the full list
    of what it is opening. Silently unioning would let an app open a path without
    that showing up at the call site.

    `session_epoch_path` opts this app into central session revocation (#27):
    a cookie is only honoured when it carries the current epoch token from that
    file, so bumping the file (scripts/revoke_sessions.py) instantly logs every
    session out on its next request, on every app that passed this. None (the
    default) leaves this app's behaviour byte-for-byte unchanged — revocation
    is per-app opt-in, not a flag day for the whole fleet. Passed, but the file
    does not exist yet: raises now, at install time, rather than degrading the
    feature into a no-op on the first request that needs it.
    """
    secret = load_secret(env, secret_var)
    if session_epoch_path is not None:
        load_epoch(session_epoch_path)              # fail at startup, not mid-request

    app.secret_key = secret
    app.config.update(COOKIE_CONFIG)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=DEFAULT_MAX_AGE)

    policy = GatePolicy(
        gate_url=gate_url or DEFAULT_GATE_URL,
        exempt_paths=frozenset(exempt_paths) if exempt_paths is not None
        else DEFAULT_EXEMPT_PATHS,
        exempt_endpoints=frozenset(exempt_endpoints or ()),
        api_prefixes=tuple(api_prefixes),
    )

    @app.before_request
    def _thedallasan_gate():                       # noqa: ANN202 — Flask hook
        logged_in = bool(session.get("logged_in"))
        # Re-read on every request, deliberately not cached at install time —
        # see load_epoch(). A stale in-process copy would mean a revoke takes
        # effect only after the app restarts, which is not what "revoke" means.
        if logged_in and session_epoch_path is not None:
            logged_in = session.get("session_epoch") == load_epoch(session_epoch_path)
        d = decide(policy, request.path, logged_in, request.endpoint)
        if d.allowed:
            return None
        if d.action == "json401":
            return jsonify({"error": "unauthorized"}), 401
        return redirect(d.location, code=302)

    app.extensions.setdefault("thedallasan_gate", policy)
    return policy
