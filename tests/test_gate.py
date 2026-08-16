"""Tests for the shared SSO gate.

Five apps depend on this one implementation, so a bug here breaks all of them at
once — the trade for having only one place to get it right. These pin the
behaviours whose absence caused the original incidents, not just the happy path.
"""
from __future__ import annotations

import pytest
from flask import Flask, jsonify

from thedallasan_gate import (DEFAULT_EXEMPT_PATHS, GateConfigError, GatePolicy,
                              decide, install_flask_gate, load_secret)

SECRET = "test-shared-secret"
# The shared cookie is Secure and scoped to .thedallasan.shop, so every test
# that involves a session must speak to a host it would actually be sent to.
BASE = "https://app.thedallasan.shop/"


# ── The secret is mandatory (the original bug) ───────────────────────────────
def test_load_secret_raises_when_unset():
    with pytest.raises(GateConfigError) as exc:
        load_secret({})
    assert "FLASK_SECRET_KEY" in str(exc.value)


def test_load_secret_raises_on_whitespace_only():
    """A key of spaces is absence wearing a disguise."""
    with pytest.raises(GateConfigError):
        load_secret({"FLASK_SECRET_KEY": "   "})


def test_install_flask_gate_refuses_to_configure_without_a_secret():
    app = Flask(__name__)
    with pytest.raises(GateConfigError):
        install_flask_gate(app, env={})


def test_there_is_no_way_to_ask_for_a_disabled_gate():
    """The API deliberately offers no 'enabled=False'. If this ever gains one,
    the class of bug this package exists to remove is back."""
    import inspect
    sig = inspect.signature(install_flask_gate)
    for banned in ("enabled", "disable", "optional", "require_auth"):
        assert banned not in sig.parameters


# ── Core policy ──────────────────────────────────────────────────────────────
def test_exempt_path_allowed_without_a_session():
    p = GatePolicy()
    assert decide(p, "/api/health", logged_in=False).allowed


def test_api_path_gets_json_401_not_a_redirect():
    """A fetch() following a 302 to an HTML page fails confusingly."""
    assert decide(GatePolicy(), "/api/things", logged_in=False).action == "json401"


def test_page_path_redirects_to_the_gate():
    d = decide(GatePolicy(gate_url="https://example.test/"), "/", logged_in=False)
    assert d.action == "redirect" and d.location == "https://example.test/"


def test_logged_in_passes_everything():
    assert decide(GatePolicy(), "/anything/at/all", logged_in=True).allowed


def test_endpoint_exemption_matches_by_view_name():
    p = GatePolicy(exempt_endpoints=frozenset({"login"}))
    assert decide(p, "/whatever", logged_in=False, endpoint="login").allowed
    assert not decide(p, "/whatever", logged_in=False, endpoint="other").allowed


def test_health_probe_is_open_by_default():
    """UptimeRobot carries no session and needs a real status code."""
    assert "/api/health" in DEFAULT_EXEMPT_PATHS


# ── Flask adapter, end to end ────────────────────────────────────────────────
def _app(**kw):
    app = Flask(__name__)
    install_flask_gate(app, env={"FLASK_SECRET_KEY": SECRET}, **kw)

    @app.route("/")
    def index():
        return "secret page"

    @app.route("/api/health")
    def health():
        # Exempt by default, so it answers even when the gate refuses. It reports
        # whether a session cookie arrived, which the cookie tests below assert on
        # first — otherwise a cookie the client declines to send makes a rejection
        # test pass vacuously.
        from flask import request
        return jsonify(status="ok", cookie_seen=bool(request.cookies.get("session")))

    @app.route("/api/things")
    def things():
        return jsonify(things=[])

    return app


def test_anonymous_page_is_redirected():
    c = _app().test_client()
    r = c.get("/")
    assert r.status_code == 302 and "thedallasan.shop" in r.headers["Location"]


def test_anonymous_api_gets_401_json():
    r = _app().test_client().get("/api/things")
    assert r.status_code == 401 and r.get_json() == {"error": "unauthorized"}


def test_health_probe_reachable_anonymously():
    assert _app().test_client().get("/api/health").status_code == 200


def test_authenticated_session_passes():
    # Requests must go to an https .thedallasan.shop host: the shared config marks
    # the cookie Secure and scopes it to that domain, so a plain http://localhost
    # client would simply never send it — and the test would "pass" for the wrong
    # reason if we relaxed the config instead.
    c = _app().test_client()
    with c.session_transaction() as s:
        s["logged_in"] = True
    r = c.get("/", base_url=BASE)
    assert r.status_code == 200 and b"secret page" in r.data


def test_a_session_without_logged_in_is_not_enough():
    """Presence of a valid cookie is not authorisation; the claim must be true."""
    c = _app().test_client()
    with c.session_transaction() as s:
        s["something_else"] = True
    assert c.get("/", base_url=BASE).status_code == 302


def test_logged_in_false_is_refused():
    c = _app().test_client()
    with c.session_transaction() as s:
        s["logged_in"] = False
    assert c.get("/", base_url=BASE).status_code == 302


def test_cookie_config_is_applied():
    app = _app()
    assert app.config["SESSION_COOKIE_DOMAIN"] == ".thedallasan.shop"
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True


def test_exempt_paths_replace_rather_than_extend():
    """Restating the full set is the point — an app that opens a path should see
    everything it is opening at the call site."""
    app = _app(exempt_paths={"/open"})
    c = app.test_client()
    assert c.get("/open").status_code in (200, 404)      # reached routing, not gated
    # /api/health is under the /api/ prefix, so losing its exemption makes it a
    # JSON 401 rather than a redirect.
    assert c.get("/api/health").status_code == 401       # no longer exempt


def test_custom_api_prefix_gets_401():
    c = _app(api_prefixes=("/api/", "/plaid/")).test_client()
    assert c.get("/plaid/webhook").status_code == 401


# ── A forged or foreign cookie must not authenticate ─────────────────────────
# The cookie must be set on the EXACT host. Werkzeug's test client does not send
# a cookie registered against ".thedallasan.shop" to app.thedallasan.shop, and the
# rejection test below happily passed that way — refusing a credential that was
# never presented. Hence the /probe assertion in each: prove it arrived first.
COOKIE_HOST = "app.thedallasan.shop"


def _client_with_cookie(app, value):
    c = app.test_client()
    c.set_cookie("session", value, domain=COOKIE_HOST)
    assert c.get("/api/health", base_url=BASE).get_json()["cookie_seen"], \
        "the cookie never reached the server — this test would pass vacuously"
    return c


def test_cookie_signed_with_a_different_secret_is_rejected():
    """The shared secret is what makes the cookie trustworthy. A well-formed
    session claiming logged_in, signed with any other key, must not pass — else
    the gate is decoration."""
    from thedallasan_gate import flask_session_serializer
    forged = flask_session_serializer("a-different-secret").dumps({"logged_in": True})
    c = _client_with_cookie(_app(), forged)
    assert c.get("/", base_url=BASE).status_code == 302


def test_cookie_signed_with_the_shared_secret_is_accepted():
    """The mirror of the above — proves the rejection is about the signature and
    not about the minting path being broken."""
    from thedallasan_gate import flask_session_serializer
    good = flask_session_serializer(SECRET).dumps({"logged_in": True})
    c = _client_with_cookie(_app(), good)
    assert c.get("/", base_url=BASE).status_code == 200


def test_expired_cookie_is_rejected_by_the_asgi_adapter():
    """Flask signs with a timestamp; the ASGI adapter caps replay via max_age.
    A cookie older than the cap must be refused even though its signature is
    perfectly valid."""
    from thedallasan_gate import flask_session_serializer
    from thedallasan_gate.asgi_gate import GateMiddleware

    ser = flask_session_serializer(SECRET)
    token = ser.dumps({"logged_in": True})

    class _Req:
        def __init__(self, cookies):
            self.cookies = cookies

    mw = GateMiddleware.__new__(GateMiddleware)
    mw._serializer = ser
    mw._session_epoch_path = None
    # A freshly-minted token is 0 seconds old, and itsdangerous expires on
    # `age > max_age` — so max_age=0 does NOT expire it. A negative cap does.
    mw._max_age = -1
    assert mw._logged_in(_Req({"session": token})) is False

    mw._max_age = 3600
    assert mw._logged_in(_Req({"session": token})) is True


def test_asgi_adapter_refuses_an_empty_secret():
    from thedallasan_gate.asgi_gate import GateMiddleware
    with pytest.raises(ValueError):
        GateMiddleware(lambda *a: None, secret_key="")
