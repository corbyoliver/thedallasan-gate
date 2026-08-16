"""Tests for session-epoch revocation (#27).

The point of this feature is a kill switch: bumping one file logs every
session out, everywhere, without touching FLASK_SECRET_KEY. These pin the two
things that would quietly defeat that:
  - a missing epoch file must fail LOUD when an app opts in, never fail open
    (load_epoch mirrors load_secret on purpose — see core.py);
  - the value must be read fresh every request, not cached at install time,
    or a bump would not take effect until every app restarted.
And the one thing that must NOT change: an app that never opts in
(session_epoch_path=None, the default) behaves exactly as before v1.1.0.
"""
from __future__ import annotations

import pytest
from flask import Flask

from thedallasan_gate import GateConfigError, install_flask_gate, load_epoch
from thedallasan_gate.core import DEFAULT_EPOCH_PATH

SECRET = "test-shared-secret"
BASE = "https://app.thedallasan.shop/"


# ── load_epoch: mirrors load_secret's "raise, never degrade" contract ────────
def test_load_epoch_raises_when_file_is_missing(tmp_path):
    with pytest.raises(GateConfigError) as exc:
        load_epoch(tmp_path / "does-not-exist")
    assert "does not exist" in str(exc.value)


def test_load_epoch_raises_when_file_is_empty(tmp_path):
    p = tmp_path / "epoch"
    p.write_text("")
    with pytest.raises(GateConfigError):
        load_epoch(p)


def test_load_epoch_strips_whitespace(tmp_path):
    p = tmp_path / "epoch"
    p.write_text("abc123\n")
    assert load_epoch(p) == "abc123"


def test_default_epoch_path_is_shared_srv_location():
    """A relative or per-app path would defeat the whole point — every app must
    agree on where to look."""
    assert DEFAULT_EPOCH_PATH == "/srv/.session-epoch"


# ── install_flask_gate: opt-in, and fails at startup not mid-request ─────────
def test_epoch_path_missing_raises_at_install_time(tmp_path):
    app = Flask(__name__)
    with pytest.raises(GateConfigError):
        install_flask_gate(app, env={"FLASK_SECRET_KEY": SECRET},
                           session_epoch_path=str(tmp_path / "nope"))


def test_default_behaviour_is_unchanged_when_epoch_path_is_not_passed():
    """Backward compatibility for the five apps already on v1.0.0: upgrading
    the package without passing session_epoch_path must not change behaviour."""
    app = Flask(__name__)
    install_flask_gate(app, env={"FLASK_SECRET_KEY": SECRET})  # must not raise
    c = app.test_client()
    with c.session_transaction() as s:
        s["logged_in"] = True

    @app.route("/")
    def index():
        return "ok"

    assert c.get("/", base_url=BASE).status_code == 200


# ── End-to-end: matching, mismatched, and pre-existing cookies ───────────────
def _epoch_app(epoch_path, **kw):
    app = Flask(__name__)
    install_flask_gate(app, env={"FLASK_SECRET_KEY": SECRET},
                       session_epoch_path=str(epoch_path), **kw)

    @app.route("/")
    def index():
        return "secret page"

    return app


def test_session_with_current_epoch_passes(tmp_path):
    epoch = tmp_path / "epoch"
    epoch.write_text("v1")
    c = _epoch_app(epoch).test_client()
    with c.session_transaction() as s:
        s["logged_in"] = True
        s["session_epoch"] = "v1"
    assert c.get("/", base_url=BASE).status_code == 200


def test_session_with_stale_epoch_is_rejected(tmp_path):
    """The revoke itself: bumping the file must reject a cookie minted under
    the old value, on the very next request, no restart."""
    epoch = tmp_path / "epoch"
    epoch.write_text("v1")
    app = _epoch_app(epoch)
    c = app.test_client()
    with c.session_transaction() as s:
        s["logged_in"] = True
        s["session_epoch"] = "v1"
    assert c.get("/", base_url=BASE).status_code == 200   # valid before the bump

    epoch.write_text("v2")                                 # the revoke
    assert c.get("/", base_url=BASE).status_code == 302   # same process, same cookie, now refused


def test_cookie_minted_before_the_feature_existed_is_rejected(tmp_path):
    """A cookie with logged_in=True but no session_epoch claim at all — exactly
    what every outstanding session looks like the moment an app first turns
    this on. Must be treated as logged out, not grandfathered in forever."""
    epoch = tmp_path / "epoch"
    epoch.write_text("v1")
    c = _epoch_app(epoch).test_client()
    with c.session_transaction() as s:
        s["logged_in"] = True                              # no session_epoch key
    assert c.get("/", base_url=BASE).status_code == 302


# ── ASGI adapter: same behaviour, same reasoning ──────────────────────────────
def test_asgi_adapter_epoch_path_missing_raises_at_construction(tmp_path):
    from thedallasan_gate.asgi_gate import GateMiddleware
    with pytest.raises(GateConfigError):
        GateMiddleware(lambda *a: None, secret_key=SECRET,
                       session_epoch_path=str(tmp_path / "nope"))


def test_asgi_adapter_rejects_stale_epoch(tmp_path):
    from thedallasan_gate import flask_session_serializer
    from thedallasan_gate.asgi_gate import GateMiddleware

    epoch = tmp_path / "epoch"
    epoch.write_text("v1")
    ser = flask_session_serializer(SECRET)
    current = ser.dumps({"logged_in": True, "session_epoch": "v1"})

    class _Req:
        def __init__(self, cookies):
            self.cookies = cookies

    mw = GateMiddleware(lambda *a: None, secret_key=SECRET,
                        session_epoch_path=str(epoch))
    assert mw._logged_in(_Req({"session": current})) is True

    epoch.write_text("v2")
    assert mw._logged_in(_Req({"session": current})) is False
