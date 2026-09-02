"""Dovecot's checkpassword bridge into Lightr.

Replaces the Lua-over-HTTP passdb, which could not work: ``dovecot.http``
arrived in Dovecot 2.4 and Debian 12 and Ubuntu 22.04 both ship 2.3,
with **zero** HTTP symbols in their Lua modules. Every login failed with
``attempt to index a nil value (field 'http')``.

``checkpassword`` is the portable answer. Dovecot runs an external
program, hands it the credentials, and reads the verdict from the exit
code. It has worked the same way for twenty years and needs nothing
compiled in.

The protocol, because it is unforgiving:

* credentials arrive on **file descriptor 3**, NUL-separated, as
  ``user\\0password\\0``
* on success the script ``exec``s the program named in ``argv[1]``,
  having put the answer in the environment as ``USER`` and ``userdb_*``
* **exit 1** means these credentials are wrong
* **exit 111** means the check could not be made

That last distinction is the whole reason this file is careful. It is
the same one carried by ``AuthFailure``/``TEMPORARY_FAILURES`` and by
the 503 the internal endpoint returns: a provider that is *down* must
not be reported as a password that is *wrong*, or every user on the
server is told to change a password that was fine.

Two constraints on the generated script:

* **stdlib only.** Dovecot execs it as the ``dovecot`` user, outside any
  virtualenv, with almost no environment. ``urllib`` is always there;
  ``httpx`` is not.
* **an absolute interpreter.** Nothing may depend on ``PATH`` or on a
  venv being activated.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

#: Where the script is installed. Beside Dovecot's own configuration,
#: because that is what it belongs to.
SCRIPT_PATH = Path("/etc/dovecot/lightr-checkpassword")

#: Exit codes Dovecot understands.
EXIT_AUTH_FAILED = 1
EXIT_INTERNAL = 111


def interpreter() -> str:
    """An absolute path to a Python that will exist at auth time.

    Not ``sys.executable`` when that is inside a virtualenv: the venv
    may be readable only by another user, and Dovecot runs this as
    ``dovecot``. A system interpreter is the safe default, and the venv
    one is used only when there is no system Python at all.
    """
    for candidate in ("/usr/bin/python3", "/usr/local/bin/python3"):
        if Path(candidate).exists():
            return candidate
    found = shutil.which("python3")
    return found or sys.executable


def script(api_base_url: str, internal_key: str, *, timeout: float = 5.0) -> str:
    """The checkpassword program, as text.

    Generated rather than shipped as a file so the URL and the shared
    secret are baked in: the script runs with no config of its own and
    no way to find one.
    """
    return f'''#!{interpreter()}
"""Dovecot checkpassword client for Lightr. Generated -- do not edit.

Regenerate with: lightr dovecot install
"""

import json
import os
import sys
import urllib.error
import urllib.request

API = "{api_base_url}"
KEY = "{internal_key}"
TIMEOUT = {timeout}

AUTH_FAILED = {EXIT_AUTH_FAILED}
INTERNAL = {EXIT_INTERNAL}


def read_credentials():
    """Dovecot writes user\\0password\\0 to fd 3."""
    try:
        with os.fdopen(3, "rb") as source:
            raw = source.read()
    except OSError as exc:
        sys.stderr.write("lightr: cannot read fd 3: %s\\n" % exc)
        sys.exit(INTERNAL)

    parts = raw.split(b"\\0")
    if len(parts) < 2:
        sys.stderr.write("lightr: malformed credentials on fd 3\\n")
        sys.exit(INTERNAL)
    return parts[0].decode("utf-8", "replace"), parts[1].decode("utf-8", "replace")


def ask(username, password):
    """Ask Lightr. Returns the parsed body, or exits."""
    body = json.dumps({{"username": username, "password": password}}).encode()
    request = urllib.request.Request(
        API + "/internal/auth/verify",
        data=body,
        headers={{
            "Content-Type": "application/json",
            "X-Lightr-Internal-Key": KEY,
        }},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read() or b"{{}}")
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            # The only answer that means "these credentials are wrong".
            sys.exit(AUTH_FAILED)
        # 403 is a misconfigured shared secret, 503 is a provider that
        # could not answer. Neither is the user's fault, and reporting
        # either as a wrong password would have everyone resetting one
        # that works.
        sys.stderr.write("lightr: auth endpoint returned %s\\n" % exc.code)
        sys.exit(INTERNAL)
    except Exception as exc:
        sys.stderr.write("lightr: cannot reach %s: %s\\n" % (API, exc))
        sys.exit(INTERNAL)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("lightr: no program to exec; check the passdb args\\n")
        sys.exit(INTERNAL)

    username, password = read_credentials()
    if not username or not password:
        sys.exit(AUTH_FAILED)

    payload = ask(username, password)
    if str(payload.get("status", "")) != "ok":
        sys.exit(AUTH_FAILED)

    # Dovecot reads the answer out of the environment of the program
    # this execs.
    os.environ["USER"] = str(payload.get("user") or username)
    home = payload.get("home")
    if home:
        os.environ["HOME"] = str(home)
        os.environ["userdb_home"] = str(home)

    try:
        os.execv(sys.argv[1], sys.argv[1:])
    except OSError as exc:
        sys.stderr.write("lightr: cannot exec %s: %s\\n" % (sys.argv[1], exc))
        sys.exit(INTERNAL)


if __name__ == "__main__":
    main()
'''


__all__ = ["EXIT_AUTH_FAILED", "EXIT_INTERNAL", "SCRIPT_PATH", "interpreter", "script"]
