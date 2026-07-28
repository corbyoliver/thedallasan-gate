"""Framework-agnostic policy for the shared thedallasan.shop SSO gate.

The login at thedallasan.shop sets a Flask session cookie scoped to
`.thedallasan.shop`, signed with a shared FLASK_SECRET_KEY and carrying
`logged_in: true`. Every other app on the box trusts that cookie.

Nothing here touches Flask or Starlette. The adapters supply two facts — the
request path, and whether the session says logged-in — and this module decides
what happens. Keeping the decision in one place is the entire point: five apps
each reimplemented it and three got the same detail wrong.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_GATE_URL = "https://thedallasan.shop/"

# Paths every app must leave open. /api/health is polled by UptimeRobot, which
# carries no session and needs a real status code rather than a redirect.
DEFAULT_EXEMPT_PATHS: frozenset[str] = frozenset({"/api/health", "/favicon.svg"})

# An unauthenticated request under one of these gets a JSON 401 instead of a
# redirect: a fetch() following a 302 to an HTML login page produces a confusing
# parse error rather than a usable failure.
DEFAULT_API_PREFIXES: tuple[str, ...] = ("/api/",)

# The canonical shared-cookie settings. They must agree across every app or the
# cookie stops round-tripping; having them written out five times is how they
# drift.
COOKIE_CONFIG: dict[str, object] = {
    "SESSION_COOKIE_DOMAIN": ".thedallasan.shop",
    "SESSION_COOKIE_SAMESITE": "Lax",
    "SESSION_COOKIE_SECURE": True,
    "SESSION_COOKIE_HTTPONLY": True,
}

# Server-side lifetime for an accepted session, in seconds. Flask signs its
# cookies with a timestamp, so rejecting older ones caps how long a captured
# cookie stays replayable. 31 days matches Flask's own default.
DEFAULT_MAX_AGE = 31 * 24 * 3600


class GateConfigError(RuntimeError):
    """The gate cannot be configured, so the app must not start.

    Raised rather than returning a disabled gate. An unset secret used to mean
    "no gate", which turned a missing environment variable into silently serving
    everything publicly — the app started clean, /api/health still answered 200,
    and the uptime monitor stayed green. A crash loop is visible; that was not.
    """


def load_secret(env: dict[str, str] | None = None, var: str = "FLASK_SECRET_KEY") -> str:
    """The shared SSO secret, or raise. There is no third outcome by design."""
    env = os.environ if env is None else env
    secret = (env.get(var) or "").strip()
    if not secret:
        raise GateConfigError(
            f"{var} env var is required — set it in .env. It is the shared "
            f"thedallasan.shop SSO secret; without it this app cannot "
            f"authenticate anyone and would serve every route publicly."
        )
    return secret


@dataclass(frozen=True)
class GatePolicy:
    """What this app leaves open, and where it sends people who are turned away."""

    gate_url: str = DEFAULT_GATE_URL
    exempt_paths: frozenset[str] = DEFAULT_EXEMPT_PATHS
    api_prefixes: tuple[str, ...] = DEFAULT_API_PREFIXES
    # Endpoint *names* rather than paths — Flask-only, for apps that exempt by
    # view function (bill-tracker's login/logout/static).
    exempt_endpoints: frozenset[str] = frozenset()
    extra_exempt: tuple = field(default=())

    def is_exempt(self, path: str, endpoint: str | None = None) -> bool:
        if path in self.exempt_paths:
            return True
        if endpoint is not None and endpoint in self.exempt_endpoints:
            return True
        return False

    def wants_json(self, path: str) -> bool:
        return path.startswith(self.api_prefixes)


@dataclass(frozen=True)
class Decision:
    """allow | json401 | redirect."""

    action: str
    location: str | None = None

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


ALLOW = Decision("allow")


def decide(policy: GatePolicy, path: str, logged_in: bool,
           endpoint: str | None = None) -> Decision:
    """The whole gate, in one function, for every framework.

    Note the order: exemptions are checked before the session, so a health probe
    answers even when nobody is logged in; and `logged_in` is only ever consulted
    as a positive — there is no branch that treats an error, an unset secret, or
    an undecodable cookie as permission.
    """
    if policy.is_exempt(path, endpoint) or logged_in:
        return ALLOW
    if policy.wants_json(path):
        return Decision("json401")
    return Decision("redirect", policy.gate_url)
