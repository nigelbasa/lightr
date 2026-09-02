"""The checkpassword bridge, run as Dovecot runs it.

These tests execute the generated script as a subprocess with real file
descriptors, because that is the only way this seam has ever been
proven. The Lua passdb it replaces passed every unit test and could not
work at all on the target platform -- so here the script is run, not
inspected.

The exit code is the whole contract:

* 0 (via exec) -- these credentials are good
* 1           -- these credentials are wrong
* 111         -- the check could not be made

The last two must not be confused. Told a password is wrong, users
change it, and a directory outage becomes a week of support.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from lightr.config import Config
from lightr.dovecot import checkpassword

#: Running the script needs fd inheritance and /bin/true. The userdb
#: half of this file is pure text generation and runs anywhere.
posix_only = pytest.mark.skipif(
    os.name == "nt", reason="checkpassword needs POSIX fd inheritance"
)


class FakeLightr:
    """Stands in for /internal/auth/verify."""

    def __init__(self, status: int = 200, body: dict | None = None) -> None:
        self.status = status
        self.body = body if body is not None else {"status": "ok", "user": "ops@acme.test"}
        self.seen: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                outer.seen.append(json.loads(self.rfile.read(length) or b"{}"))
                payload = json.dumps(outer.body).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: object) -> None:
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_port}"

    def __enter__(self) -> FakeLightr:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


def write_script(tmp_path: Path, url: str) -> Path:
    path = tmp_path / "lightr-checkpassword"
    path.write_text(checkpassword.script(url, "internal-key"), encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def fd3_script(tmp_path: Path):
    """The script, but with fd 3 wired up the way Dovecot wires it."""

    def build(server: FakeLightr) -> Path:
        return write_script(tmp_path, server.url)

    return build


@posix_only
class TestTheContract:
    def test_good_credentials_exec_the_next_program(self, fd3_script) -> None:
        with FakeLightr() as server:
            code = _run_with_fd3(fd3_script(server), "ops@acme.test", "right")
        assert code == 0

    def test_wrong_credentials_exit_1(self, fd3_script) -> None:
        with FakeLightr(status=401, body={"status": "fail"}) as server:
            code = _run_with_fd3(fd3_script(server), "ops@acme.test", "wrong")
        assert code == checkpassword.EXIT_AUTH_FAILED

    def test_a_provider_that_could_not_answer_exits_111(self, fd3_script) -> None:
        """503 is Lightr saying "I could not tell" -- an LDAP outage,
        say. Reporting that as exit 1 tells every user their password
        is wrong."""
        with FakeLightr(status=503, body={"status": "fail"}) as server:
            code = _run_with_fd3(fd3_script(server), "ops@acme.test", "right")
        assert code == checkpassword.EXIT_INTERNAL

    def test_a_bad_shared_secret_exits_111_not_1(self, fd3_script) -> None:
        """403 means Lightr and Dovecot disagree about the internal
        key. That is our misconfiguration, not the user's password."""
        with FakeLightr(status=403, body={"status": "fail"}) as server:
            code = _run_with_fd3(fd3_script(server), "ops@acme.test", "right")
        assert code == checkpassword.EXIT_INTERNAL

    def test_an_unreachable_lightr_exits_111(self, tmp_path: Path) -> None:
        script = write_script(tmp_path, "http://127.0.0.1:1")
        assert _run_with_fd3(script, "ops@acme.test", "right") == (
            checkpassword.EXIT_INTERNAL
        )

    def test_empty_credentials_are_a_refusal(self, fd3_script) -> None:
        with FakeLightr() as server:
            code = _run_with_fd3(fd3_script(server), "ops@acme.test", "")
        assert code == checkpassword.EXIT_AUTH_FAILED


@posix_only
class TestWhatItSends:
    def test_the_credentials_reach_lightr(self, fd3_script) -> None:
        with FakeLightr() as server:
            _run_with_fd3(fd3_script(server), "ops@acme.test", "hunter2")
            assert server.seen == [
                {"username": "ops@acme.test", "password": "hunter2"}
            ]

    def test_a_password_with_a_nul_free_oddity_survives(self, fd3_script) -> None:
        """Quotes and backslashes go through JSON, not string-building."""
        with FakeLightr() as server:
            _run_with_fd3(fd3_script(server), 'o"ps@acme.test', 'a"b\\c')
            assert server.seen[0]["password"] == 'a"b\\c'


class TestTheScriptItself:
    def test_it_uses_an_absolute_interpreter(self) -> None:
        """Dovecot execs it with almost no environment and no venv, so
        a bare `python3` in the shebang would not resolve."""
        text = checkpassword.script("http://127.0.0.1:8080", "k")
        shebang = text.splitlines()[0]

        assert shebang.startswith("#!")
        assert Path(shebang[2:]).is_absolute()

    def test_it_imports_only_the_standard_library(self) -> None:
        """It runs outside the virtualenv, as the dovecot user."""
        text = checkpassword.script("http://127.0.0.1:8080", "k")
        imported = {
            line.split()[1].split(".")[0]
            for line in text.splitlines()
            if line.startswith("import ")
        }

        assert imported <= {"json", "os", "sys", "urllib"}
        assert "httpx" not in text
        assert "lightr" not in text.split('"""')[2]

    def test_it_carries_the_internal_key(self) -> None:
        text = checkpassword.script("http://127.0.0.1:8080", "the-secret")
        assert "the-secret" in text


def _run_with_fd3(script: Path, username: str, password: str) -> int:
    """Run the script with credentials on **fd 3**, as Dovecot does.

    `pass_fds` is not enough on its own: it keeps the descriptor at
    whatever number it already had, so the script found nothing on fd 3
    and exited 111 -- which made the "internal error" tests pass for
    entirely the wrong reason. A shell redirection puts it on 3.
    """
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(f"{username}\0{password}\0".encode())
        credentials = handle.name

    try:
        process = subprocess.run(
            [
                "/bin/sh",
                "-c",
                'exec 3<"$1"; shift; exec "$@"',
                "sh",
                credentials,
                sys.executable,
                str(script),
                "/bin/true",
            ],
            capture_output=True,
            timeout=20,
        )
        if process.returncode not in (
            0,
            checkpassword.EXIT_AUTH_FAILED,
            checkpassword.EXIT_INTERNAL,
        ):
            raise AssertionError(
                f"unexpected exit {process.returncode}: "
                f"{process.stderr.decode(errors='replace')}"
            )
        return process.returncode
    finally:
        Path(credentials).unlink()


class TestUserdbConf:
    """The SQL userdb, which LMTP depends on."""

    def test_sqlite_gets_the_sqlite_driver(self, cfg: Config) -> None:
        from lightr.dovecot import userdb

        conf = userdb.userdb_conf(cfg)

        assert "driver = sqlite" in conf
        assert cfg.database.path is not None
        assert cfg.database.path.as_posix() in conf

    def test_postgres_gets_libpq_keywords_not_a_url(self, cfg: Config) -> None:
        """Dovecot's pgsql driver does not take a URL. Handing it one
        fails at delivery time, not at configuration time."""
        from lightr.config import DatabaseDriver
        from lightr.dovecot import userdb

        cfg.database.driver = DatabaseDriver.POSTGRES
        cfg.database.dsn = "postgresql://lightr:pw@127.0.0.1:5432/lightr"

        conf = userdb.userdb_conf(cfg)

        assert "driver = pgsql" in conf
        assert "host=127.0.0.1" in conf
        assert "dbname=lightr" in conf
        assert "user=lightr" in conf
        assert "postgresql://" not in conf

    def test_postgres_without_a_dsn_says_so(self, cfg: Config) -> None:
        from lightr.config import DatabaseDriver
        from lightr.dovecot import userdb

        cfg.database.driver = DatabaseDriver.POSTGRES
        cfg.database.dsn = ""

        with pytest.raises(userdb.UserdbError, match=r"database\.dsn"):
            userdb.userdb_conf(cfg)

    def test_quota_is_omitted_when_there_is_none(self, cfg: Config) -> None:
        """A rule of zero would enforce a limit of zero."""
        from lightr.dovecot import userdb

        conf = userdb.userdb_conf(cfg)

        assert "quota_bytes > 0" in conf
        assert "ELSE NULL" in conf

    def test_it_can_answer_without_a_passdb_lookup(self, cfg: Config) -> None:
        """LMTP delivers to an address nobody authenticated as."""
        from lightr.dovecot import userdb

        conf = userdb.userdb_conf(cfg)

        assert "user_query" in conf
        assert "prefetch" not in conf

    def test_the_missing_driver_package_is_nameable(self, cfg: Config) -> None:
        """A missing driver fails with "Unknown database driver" and
        nothing pointing at the fix."""
        from lightr.dovecot import userdb

        assert userdb.package_name(cfg) == "dovecot-sqlite"
