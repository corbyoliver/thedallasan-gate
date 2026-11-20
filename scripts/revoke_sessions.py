#!/usr/bin/env python3
"""Bump the shared session-revocation epoch — logs every session out, everywhere.

Run this on the box, as root. The file is written world-readable (0o644) —
apps don't all run as the same user (home-site runs as `deploy`, not root; see
hetzner-vps notes), and every opted-in app needs to read this on every
request. The value itself isn't a secret (forging a cookie also needs
FLASK_SECRET_KEY), so world-readable, root-writable is the right split:

    python3 revoke_sessions.py                    # bootstrap or bump the default path
    python3 revoke_sessions.py /srv/.session-epoch # explicit path

First run bootstraps the file — every app that opts into session_epoch_path
checking will start honouring it from its very next request, no restart
needed, per app in load_epoch()'s docstring. This also means the first run
after any app adopts the feature logs out every existing session on that app,
including a currently-logged-in Corbett — expected, not a bug: an old cookie
was minted before revocation existed and carries no epoch to match.
"""
import os
import pathlib
import secrets
import sys

DEFAULT_PATH = "/srv/.session-epoch"


def main() -> int:
    path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH)
    existed = path.exists()
    # Atomic: write a sibling file, set its mode, then rename over the target.
    # write_text() truncates first, and every opted-in app reads this file on
    # every request, so a request in that window read an empty epoch.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(secrets.token_hex(16))
    tmp.chmod(0o644)
    os.replace(tmp, path)
    verb = "Bumped" if existed else "Bootstrapped"
    print(f"{verb} {path} — every session cookie minted before this moment, "
          f"on every app that checks this file, is now invalid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
