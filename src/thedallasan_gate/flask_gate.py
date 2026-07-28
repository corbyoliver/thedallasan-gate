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
                   load_secret)


def install_flask_gate(
    app,
    *,
    gate_url: str | None = None,
    exempt_paths: set[str] | frozenset[str] | None = None,
    exempt_endpoints: set[str] | frozenset[str] | None = None,
    api_prefixes: tuple[str, ...] = DEFAULT_API_PREFIXES,
    secret_var: str = "FLASK_SECRET_KEY",
    env: dict[str, str] | None = None,
) -> GatePolicy:
    """Configure `app` for the shared SSO cookie and gate every request.

    Raises GateConfigError when the secret is missing — the app must not start.
    Callers pass only what differs from the house default; anything they do not
    pass they cannot get subtly wrong.

    `exempt_paths` REPLACES the default set rather than extending it, so an app
    that needs an extra open path must restate /api/health and see the full list
    of what it is opening. Silently unioning would let an app open a path without
    that showing up at the call site.
    """
    secret = load_secret(env, secret_var)
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
        d = decide(policy, request.path, bool(session.get("logged_in")),
                   request.endpoint)
        if d.allowed:
            return None
        if d.action == "json401":
            return jsonify({"error": "unauthorized"}), 401
        return redirect(d.location, code=302)

    app.extensions.setdefault("thedallasan_gate", policy)
    return policy
