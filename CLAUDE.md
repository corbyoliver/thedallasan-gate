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

`session_epoch_path` is opt-in (a caller passes `None` to decline), but once
an app opts in, a missing or unreadable epoch file must raise
(`GateConfigError` via `load_epoch()`) — never silently skip the check. That
would be the exact `GATE_ENABLED = bool(secret)` bug arriving through a second
config knob. Read `load_epoch()` fresh on every request, never cache it at
install time — a revoke has to take effect without an app restart, or the
"kill switch" framing in the README is a lie for however long the stale copy
lingers.

**⚠️ AS OF v2.0.0 (#5), `session_epoch_path` HAS NO DEFAULT — the invariant
above used to have a hole one level up.** Five `v1.1.0` rollout branches
across the consumer repos were reviewed on 2026-08-18; the two that passed CI
did so because forgetting the kwarg silently kept it at `None` — a caller
could not tell "opted out on purpose" from "the person writing this branch
never thought about it" from the diff, from CI, or from the running app. That
is `GATE_ENABLED = bool(secret)` again, just one config knob further out than
the first fix reached. Omitting `session_epoch_path` is now a `TypeError` at
the call site: `install_flask_gate`/`GateMiddleware.__init__` require it,
with no default, and `test_session_epoch_path_has_no_default` +
`test_omitting_session_epoch_path_is_a_typeerror_not_a_silent_default` in
`tests/test_gate.py` fail the build if a default is ever reintroduced — the
epoch-specific sibling of `test_there_is_no_way_to_ask_for_a_disabled_gate`.
**Do not give it a default of any kind, including `DEFAULT_EPOCH_PATH`** —
that would auto-enroll every future caller into revocation without them
deciding to, which is the opposite mistake in the same family: a decision
made by a default is still a decision nobody visibly made.

Every consumer still pinned at `@v1.0.0`/`@v1.1.0` in its `requirements.txt`
is unaffected by this until someone deliberately bumps that pin — see
README's Install section. Bumping a pin means adding the kwarg at that app's
call site in the same commit; it will not build without it.

## `revoke_sessions.py` writes the epoch file world-readable (0o644), not root-only

It used to write `0o600` on the assumption every consuming app runs as root
— wrong (`dotfiles/ssh/ACCESS.md` has the corrected list; 5 of 11 app
services on the box run as `deploy`), and it caused a real ~40min lockout
(#3, 2026-08-16): `home-site` runs as `deploy`, couldn't read a root-only
file it needs on every login, and 500'd. The epoch value isn't a secret —
forging a session cookie still needs `FLASK_SECRET_KEY` — so
world-readable/root-writable is the *correct* model here, not a relaxation.
Don't revert this without re-verifying every consuming app's `User=`.

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

## Finishing work: Claude merges

**Claude merges finished branches into `main`.** Do not end a task by handing
Corbett a branch to merge. This is a standing preference (confirmed
2026-08-23) and it applies to **every** repo in `~/Sessions`, not only this one.

The flow is: branch → implement → **verify** → merge to `main` → push → delete
the branch, local and remote. Do **not** open a PR unless explicitly asked.

Merging is part of the **end-of-session routine**, not an optional extra. If a
session ends with work sitting on an unmerged branch, that session is not
finished.

Two conditions on "finished", both load-bearing:

- **Merge only genuinely verified work.** Whatever this repo's gate is — tests,
  CI, a preflight, a deploy check — it passes *before* the merge.
- **Re-run that check on `main` after the merge and before the push.**
  Verifying the branch is not the same as verifying the merge result.

Merge stacked branches oldest-first. A `--ff-only` merge is a useful tell: it
succeeds only when the history is linear, so nothing is being silently
rewritten.

Note that an issue closed by a commit trailer (`Closes #12`) only actually
closes when that commit reaches the **default** branch — so an unmerged branch
quietly leaves its issues open too.
