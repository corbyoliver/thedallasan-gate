# thedallasan-gate

The shared SSO gate, imported by every app on the box. **A bug here breaks five
apps at once** — that is the accepted cost of having one place to get it right.
Treat changes here as production changes to all of them.

## The invariant

There must be no way to obtain a disabled gate. Absence of configuration must
never be a mode switch — that is the exact bug (`GATE_ENABLED = bool(secret)`)
this package was created to delete from three apps. `load_secret()` raises,
`install_flask_gate()` raises, `GateMiddleware` rejects an empty key, and
`test_there_is_no_way_to_ask_for_a_disabled_gate` fails the build if anyone adds
an `enabled` / `disable` / `optional` parameter. Do not "helpfully" add one for
local dev — set a dummy key in the environment instead.

## The same invariant applies to session-epoch revocation (#27, added v1.1.0)

`session_epoch_path` is opt-in (`None` by default, unchanged behaviour), but
once an app opts in, a missing or unreadable epoch file must raise
(`GateConfigError` via `load_epoch()`) — never silently skip the check. That
would be the exact `GATE_ENABLED = bool(secret)` bug arriving through a second
config knob. Read `load_epoch()` fresh on every request, never cache it at
install time — a revoke has to take effect without an app restart, or the
"kill switch" framing in the README is a lie for however long the stale copy
lingers.

## Testing gotchas

- Werkzeug's test client does **not** send a cookie registered against
  `.thedallasan.shop` to `app.thedallasan.shop`. Set cookies on the exact host,
  and assert the cookie arrived (`/api/health` reports `cookie_seen`) before
  asserting it was refused — otherwise a rejection test passes while refusing a
  credential that was never presented.
- Session tests must use `base_url=BASE` (an https `.thedallasan.shop` host). The
  shared config marks the cookie Secure and domain-scoped, so a plain
  `http://localhost` client silently never sends it. Relaxing the config to make
  tests easier would be testing something production never runs.
- A freshly-minted token is 0 seconds old and itsdangerous expires on
  `age > max_age`, so `max_age=0` does **not** expire it. Use a negative cap.

## Filing work

File bugs and enhancements as GitHub issues (`gh issue create`), not TODO files.
