#!/usr/bin/env python3
"""Bump the shared session-revocation epoch — logs every session out, everywhere.

Run this on the box, as root (the file needs to be root-readable by every app,
which all run as root — see hetzner-vps notes):

    python3 revoke_sessions.py                    # bootstrap or bump the default path
    python3 revoke_sessions.py /srv/.session-epoch # explicit path

First run bootstraps the file — every app that opts into session_epoch_path
checking will start honouring it from its very next request, no restart
needed, per app in load_epoch()'s docstring. This also means the first run
after any app adopts the feature logs out every existing session on that app,
including a currently-logged-in Corbett — expected, not a bug: an old cookie
was minted before revocation existed and carries no epoch to match.
"""
import pathlib
import secrets
import sys

DEFAULT_PATH = "/srv/.session-epoch"


def main() -> int:
    path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH)
    existed = path.exists()
    path.write_text(secrets.token_hex(16))
    path.chmod(0o600)
    verb = "Bumped" if existed else "Bootstrapped"
    print(f"{verb} {path} — every session cookie minted before this moment, "
          f"on every app that checks this file, is now invalid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
