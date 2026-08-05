# thedallasan-gate

One implementation of the shared `.thedallasan.shop` SSO gate, imported by every
app on the server instead of being reimplemented in each.

## Why

The login at thedallasan.shop sets a Flask session cookie scoped to
`.thedallasan.shop`, signed with a shared `FLASK_SECRET_KEY` and carrying
`logged_in: true`. Every other app trusts that cookie.

There were **five** copies of that check. Three of them — `health`, `house-wiki`,
`dallasan-status` — treated a missing `FLASK_SECRET_KEY` as *"run without
authentication"* rather than as a fatal misconfiguration:

```python
GATE_ENABLED = bool(_SHARED_SECRET)        # house-wiki, before
...
if not GATE_ENABLED:
    return None                            # every route now public
```

Nothing surfaced it. The app started clean, `/api/health` still returned 200, and
the uptime monitor stayed green. Each of those three carried a comment describing
the convention **correctly, in the line directly above the bug**. Copy-paste moves
the prose and loses the behaviour, so the behaviour lives here now.

## Use

```python
# Flask
from thedallasan_gate import install_flask_gate

app = Flask(__name__)
install_flask_gate(app)                    # raises if FLASK_SECRET_KEY is unset
```

```python
# FastAPI / Starlette   (pip install thedallasan-gate[asgi])
from thedallasan_gate import GateMiddleware, load_secret

app.add_middleware(GateMiddleware, secret_key=load_secret(),
                   exempt_paths={"/api/health", "/quick-log"})
```

Both **raise** when the secret is missing. There is no `enabled=False`, and a test
asserts there never is — that parameter is the bug this package exists to remove.

### Options

| Argument | Default | Notes |
| --- | --- | --- |
| `gate_url` | `https://thedallasan.shop/` | Where refused page requests are sent. |
| `exempt_paths` | `{"/api/health", "/favicon.svg"}` | **Replaces** the default, does not extend it. |
| `exempt_endpoints` | `()` | Flask only — exempt by view name. |
| `api_prefixes` | `("/api/",)` | Paths under these get a JSON 401 instead of a redirect. |
| `max_age` | 31 days | ASGI only — caps how long a captured cookie stays replayable. |
| `extra_allow` | `None` | ASGI only — a predicate for an app-specific bypass. |

`exempt_paths` replaces rather than extends deliberately: an app opening a path
should see the full list of what it is opening, at the call site. Silently
unioning would let a path be opened without that being visible where it happens.

## Install

Pin by tag, as a real dependency line:

```
thedallasan-gate @ git+https://github.com/corbyoliver/thedallasan-gate@v1.0.0
```

For development: `pip install -e .`

> This package was private until 2026-08-05, installed from a wheel copied onto
> the server by hand and recorded in each consumer's `requirements.txt` as a
> **comment**. A comment cannot fail, so pip never knew about a hard dependency:
> CI could not install the package, and five repos sat red for a week reporting a
> failure unrelated to anything anyone pushed. Making it fetchable is what fixed
> that. Nothing here is secret — the gate reads `FLASK_SECRET_KEY` from the
> environment, and that is what the security rests on.

## The trade

Five apps now share one implementation, so a bug here breaks all five at once.
That is the cost of having only one place to get it right. Two things pay for it:
the test suite in `tests/`, which pins the behaviours whose absence caused the
original incidents, and a nightly conformance job on the server, which verifies
every app's **live** gate by making an unauthenticated request — so a regression
shows up against the running system rather than only in review.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

One trap worth knowing: Werkzeug's test client will **not** send a cookie
registered against `.thedallasan.shop` to `app.thedallasan.shop`. A forged-cookie
rejection test passed that way while refusing a credential that was never
presented. `_client_with_cookie` now asserts the cookie actually arrived before
asserting it was refused.
