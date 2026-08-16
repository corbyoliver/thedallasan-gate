"""The shared thedallasan.shop SSO gate.

One implementation of the cookie check that every app on the box relies on.

It exists because there were five. Three of them treated a missing
FLASK_SECRET_KEY as "run without authentication" rather than as a fatal
misconfiguration, and each of those three carried a comment describing the
convention correctly in the line directly above the bug. Copy-paste moves the
prose and loses the behaviour, so the behaviour lives here now and the apps
import it.

    # Flask
    from thedallasan_gate import install_flask_gate
    install_flask_gate(app)

    # FastAPI / Starlette
    from thedallasan_gate import GateMiddleware, load_secret
    app.add_middleware(GateMiddleware, secret_key=load_secret())

Both raise rather than degrade when the secret is missing.
"""
from .core import (COOKIE_CONFIG, DEFAULT_API_PREFIXES, DEFAULT_EPOCH_PATH,
                   DEFAULT_EXEMPT_PATHS, DEFAULT_GATE_URL, DEFAULT_MAX_AGE,
                   Decision, GateConfigError, GatePolicy, decide, load_epoch,
                   load_secret)

__version__ = "1.1.0"

__all__ = [
    "COOKIE_CONFIG", "DEFAULT_API_PREFIXES", "DEFAULT_EPOCH_PATH",
    "DEFAULT_EXEMPT_PATHS", "DEFAULT_GATE_URL", "DEFAULT_MAX_AGE", "Decision",
    "GateConfigError", "GatePolicy", "decide", "load_epoch", "load_secret",
    "install_flask_gate", "GateMiddleware", "flask_session_serializer",
]


def __getattr__(name):
    """Adapters are imported lazily so a Flask-only app never needs Starlette
    installed, and vice versa."""
    if name == "install_flask_gate":
        from .flask_gate import install_flask_gate
        return install_flask_gate
    if name in ("GateMiddleware", "flask_session_serializer"):
        from . import asgi_gate
        return getattr(asgi_gate, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
