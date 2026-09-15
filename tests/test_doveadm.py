"""The doveadm client.

doveadm is how Lightr acts on Dovecot. The properties worth testing
are the ones that would be dangerous to get wrong: arguments never
reach a shell, credentials never reach the process table, and every
call is bounded.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
from typing import Any

import pytest

from lightr.dovecot.doveadm import (
    Doveadm,
    DoveadmError,
    DoveadmUnavailableError,
    Quota,
    _as_rows,
    _int,
)


class FakeDoveadm(Doveadm):
    """Records invocations instead of running anything."""

    def __init__(self, *, output: str = "", fail: bool = False) -> None:
        super().__init__()
        self.output = output
        self.fail = fail
        self.calls: list[tuple[tuple[str, ...], bytes | None]] = []
        # version() asks dovecot itself rather than going through run(),
        # so without this a test host with Dovecot installed would run it.
        self.version_commands = [(sys.executable, "-c", "print('2.3.16 (7e2e900c1a)')")]

    @property
    def available(self) -> bool:
        return True

    async def run(
        self, *args: str, stdin: bytes | None = None, timeout: float | None = None
    ) -> str:
        self.calls.append((args, stdin))
        if self.fail:
            raise DoveadmError(" ".join(args), 75, "temporary failure")
        return self.output


class TestProcessSafety:
    def test_arguments_never_reach_a_shell(self) -> None:
        """A mailbox called 'x; rm -rf /' must stay a mailbox name."""
        source = inspect.getsource(Doveadm.run)
        assert "create_subprocess_exec" in source
        assert "create_subprocess_shell" not in source
        assert "shell=True" not in source

    def test_every_call_is_bounded(self) -> None:
        """doveadm can block on a broken index; an unbounded call on
        the delivery path would hang the engine rather than fail it."""
        assert "wait_for" in inspect.getsource(Doveadm.run)

    async def test_a_missing_binary_says_how_to_fix_it(self) -> None:
        client = Doveadm(binary="definitely-not-a-real-binary")
        with pytest.raises(DoveadmUnavailableError, match="dovecot-core"):
            await client.run("reload")

    async def test_a_failure_carries_the_exit_code(self) -> None:
        client = FakeDoveadm(fail=True)
        with pytest.raises(DoveadmError) as excinfo:
            await client.reload()
        assert excinfo.value.code == 75


class TestCredentialHandling:
    async def test_the_password_goes_via_stdin_not_argv(self) -> None:
        """doveadm accepts -p, but that puts the password in the
        process table for every user on the host."""
        client = FakeDoveadm(output="{CRYPT}$2y$05$abc")

        await client.pw("correct-horse-battery")

        args, stdin = client.calls[0]
        assert "correct-horse-battery" not in " ".join(args)
        assert stdin is not None
        assert b"correct-horse-battery" in stdin

    async def test_the_hash_is_returned_stripped(self) -> None:
        client = FakeDoveadm(output="  {CRYPT}$2y$05$abc  \n")
        assert await client.pw("x") == "{CRYPT}$2y$05$abc"

    async def test_the_scheme_is_passed(self) -> None:
        client = FakeDoveadm(output="hash")
        await client.pw("x", scheme="SHA512-CRYPT")
        assert "SHA512-CRYPT" in client.calls[0][0]


class TestSieve:
    async def test_the_script_goes_via_stdin(self) -> None:
        """A Sieve script is multi-line and can be large."""
        client = FakeDoveadm()
        await client.sieve_put("ops@acme.test", "lightr", "# script\nkeep;\n")

        args, stdin = client.calls[0]
        assert args[:2] == ("sieve", "put")
        assert stdin == b"# script\nkeep;\n"

    async def test_install_uploads_before_activating(self) -> None:
        """If activation fails, the mailbox keeps what was working
        rather than ending up with no active script."""
        client = FakeDoveadm()
        await client.install_sieve("ops@acme.test", "keep;")

        assert [c[0][:2] for c in client.calls] == [
            ("sieve", "put"),
            ("sieve", "activate"),
        ]

    async def test_list_parses_the_active_flag(self) -> None:
        client = FakeDoveadm(
            output=json.dumps([
                {"script": "lightr", "active": "yes"},
                {"script": "old", "active": "no"},
            ])
        )
        scripts = await client.sieve_list("ops@acme.test")
        assert [(s.name, s.active) for s in scripts] == [("lightr", True), ("old", False)]

    async def test_the_user_is_passed_as_an_argument(self) -> None:
        client = FakeDoveadm()
        await client.sieve_put("ops@acme.test", "lightr", "keep;")
        assert "-u" in client.calls[0][0]
        assert "ops@acme.test" in client.calls[0][0]


class TestQuota:
    async def test_storage_is_converted_from_kilobytes(self) -> None:
        """doveadm reports storage in KiB."""
        client = FakeDoveadm(
            output=json.dumps([
                {"type": "STORAGE", "value": "1024", "limit": "2048"},
                {"type": "MESSAGE", "value": "42", "limit": "1000"},
            ])
        )
        usage = await client.quota_get("ops@acme.test")

        assert usage.used_bytes == 1024 * 1024
        assert usage.limit_bytes == 2048 * 1024
        assert usage.used_messages == 42

    async def test_no_limit_reads_as_none(self) -> None:
        client = FakeDoveadm(
            output=json.dumps([{"type": "STORAGE", "value": "10", "limit": "-"}])
        )
        usage = await client.quota_get("ops@acme.test")
        assert usage.limit_bytes is None
        assert usage.percent is None
        assert not usage.over

    def test_percent_and_over(self) -> None:
        assert Quota(500, 1000, 0, None).percent == 50.0
        assert Quota(1000, 1000, 0, None).over
        assert not Quota(999, 1000, 0, None).over

    def test_unlimited_is_never_over(self) -> None:
        assert not Quota(10**12, None, 0, None).over


class TestOutputParsing:
    def test_a_bare_dict_becomes_one_row(self) -> None:
        assert _as_rows({"a": 1}) == [{"a": 1}]

    def test_nested_lists_are_flattened(self) -> None:
        """Some doveadm versions wrap rows one level deeper."""
        assert _as_rows([[{"a": 1}, {"b": 2}]]) == [{"a": 1}, {"b": 2}]

    def test_junk_yields_nothing(self) -> None:
        assert _as_rows("not json") == []
        assert _as_rows(None) == []

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("42", 42), (" 7 ", 7), ("-", 0), ("", 0), (None, 0), ("abc", 0)],
    )
    def test_integers_tolerate_doveadm_placeholders(
        self, raw: Any, expected: int
    ) -> None:
        assert _int(raw) == expected

    async def test_empty_output_is_an_empty_result(self) -> None:
        client = FakeDoveadm(output="")
        assert await client.run_json("who") == []

    async def test_unparseable_output_is_reported(self) -> None:
        client = FakeDoveadm(output="not json at all")
        with pytest.raises(DoveadmError, match="could not parse"):
            await client.run_json("who")


class TestRealSubprocess:
    """One end-to-end check that the plumbing actually runs a process."""

    @pytest.mark.skipif(
        sys.platform == "win32", reason="uses a POSIX-style echo binary"
    )
    async def test_it_runs_and_captures_output(self) -> None:  # pragma: no cover
        client = Doveadm(binary="echo")
        assert (await client.run("hello")).strip() == "hello"

    async def test_a_timeout_kills_the_process(self) -> None:
        """An unbounded doveadm on the delivery path would hang the
        engine rather than fail it."""
        client = Doveadm(binary=sys.executable, timeout=0.5)
        with pytest.raises(DoveadmError, match="timed out"):
            await client.run("-c", "import time; time.sleep(30)")


class TestMailboxes:
    async def test_create_passes_every_folder(self) -> None:
        client = FakeDoveadm()
        await client.mailbox_create("ops@acme.test", "Sent", "Drafts")
        assert client.calls[0][0][-2:] == ("Sent", "Drafts")

    async def test_create_with_no_folders_does_nothing(self) -> None:
        client = FakeDoveadm()
        await client.mailbox_create("ops@acme.test")
        assert client.calls == []

    async def test_list_extracts_names(self) -> None:
        client = FakeDoveadm(
            output=json.dumps([{"mailbox": "INBOX"}, {"mailbox": "Sent"}])
        )
        assert await client.mailbox_list("ops@acme.test") == ["INBOX", "Sent"]


class TestVersion:
    """`doveadm --version` does not exist on Dovecot 2.3: `lightr dovecot
    status` reported "doveadm: invalid option -- '-'" on Ubuntu 22.04."""

    def _client(self, *scripts: str) -> Doveadm:
        client = Doveadm(binary="definitely-not-a-real-binary")
        client.version_commands = [(sys.executable, "-c", s) for s in scripts]
        return client

    def test_doveadm_is_not_asked(self) -> None:
        assert all(argv[0] != "doveadm" for argv in Doveadm().version_commands)
        assert Doveadm().version_commands[0] == ("dovecot", "--version")

    async def test_dovecot_version_output_is_returned(self) -> None:
        client = self._client("print('2.3.16 (7e2e900c1a)')")
        assert await client.version() == "2.3.16 (7e2e900c1a)"

    async def test_it_works_without_doveadm_installed(self) -> None:
        client = self._client("print('2.3.16 (7e2e900c1a)')")
        assert not client.available
        assert await client.version() == "2.3.16 (7e2e900c1a)"

    async def test_falls_back_to_doveconfs_header(self) -> None:
        """dovecot is in /usr/sbin, not always on the service user's PATH."""
        client = Doveadm()
        client.version_commands = [
            ("definitely-not-a-real-dovecot", "--version"),
            (
                sys.executable, "-c",
                "print('# 2.3.16 (7e2e900c1a): /etc/dovecot/dovecot.conf'); "
                "print('protocols = imap lmtp')",
            ),
        ]
        assert await client.version() == "2.3.16 (7e2e900c1a)"

    async def test_a_failing_command_falls_through(self) -> None:
        client = self._client(
            "import sys; sys.stderr.write(\"invalid option -- '-'\"); sys.exit(89)",
            "print('2.3.21 (47349e2482)')",
        )
        assert await client.version() == "2.3.21 (47349e2482)"

    async def test_nothing_working_is_a_doveadm_error_saying_why(self) -> None:
        client = self._client("import sys; sys.exit(1)", "print('not a version')")
        client.version_commands.insert(0, ("definitely-not-a-real-dovecot",))
        with pytest.raises(DoveadmError) as excinfo:
            await client.version()
        message = str(excinfo.value)
        assert "definitely-not-a-real-dovecot not found" in message


class TestConcurrency:
    async def test_calls_do_not_block_the_event_loop(self) -> None:
        """Every call is awaited, so a slow doveadm delays only its
        own caller."""
        client = FakeDoveadm(output="{}")
        results = await asyncio.gather(*(client.reload() for _ in range(5)))
        assert len(results) == 5
        assert len(client.calls) == 5
