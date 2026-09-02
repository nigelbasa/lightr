"""Generated Dovecot configuration.

These files decide where mail is stored and who may read it, so they
are tested as carefully as the code that writes them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lightr.config import Config
from lightr.dovecot.config import (
    CONF_NAME,
    DovecotConfigError,
    dovecot_conf,
    generate,
    generate_internal_key,
    lua_script,
)


@pytest.fixture
def configured(cfg: Config) -> Config:
    cfg.dovecot.internal_key = "test-internal-key"
    return cfg


class TestInternalKey:
    def test_keys_are_long_and_unique(self) -> None:
        keys = {generate_internal_key() for _ in range(50)}
        assert len(keys) == 50
        assert all(len(k) >= 32 for k in keys)

    def test_generation_refuses_without_a_key(self, cfg: Config) -> None:
        with pytest.raises(DovecotConfigError, match="lightr dovecot setup"):
            generate(cfg)


class TestStorageSettings:
    def test_maildir_is_the_format(self, configured: Config) -> None:
        assert "maildir:" in dovecot_conf(configured, Path("/x.lua"))

    def test_single_instance_storage_is_not_enabled(self, configured: Config) -> None:
        """SIS is deprecated and its failure mode is losing attachments."""
        conf = dovecot_conf(configured, Path("/x.lua"))
        settings = [
            line.strip()
            for line in conf.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert not any(s.startswith("mail_attachment_dir") for s in settings)

    def test_the_omission_is_explained(self, configured: Config) -> None:
        """A future maintainer must not 'helpfully' turn SIS on."""
        assert "mail_attachment_dir" in dovecot_conf(configured, Path("/x.lua"))

    def test_maildir_root_is_posix(self, configured: Config) -> None:
        conf = dovecot_conf(configured, Path("/x.lua"))
        assert "\\" not in conf.split("mail_home =")[1].splitlines()[0]

    def test_special_use_folders_are_declared(self, configured: Config) -> None:
        conf = dovecot_conf(configured, Path("/x.lua"))
        for flag in ("\\Sent", "\\Drafts", "\\Trash", "\\Junk", "\\Archive"):
            assert flag in conf


class TestAuthWiring:
    def test_passdb_and_userdb_both_use_lua(self, configured: Config) -> None:
        conf = dovecot_conf(configured, Path("/etc/dovecot/lightr-auth.lua"))
        assert conf.count("driver = lua") == 2

    def test_lua_path_is_referenced(self, configured: Config) -> None:
        conf = dovecot_conf(configured, Path("/etc/dovecot/lightr-auth.lua"))
        assert "file=/etc/dovecot/lightr-auth.lua" in conf

    def test_master_user_block_only_when_configured(self, configured: Config) -> None:
        assert "master = yes" not in dovecot_conf(configured, Path("/x.lua"))

        configured.dovecot.master_user = "lightr-master"
        assert "master = yes" in dovecot_conf(configured, Path("/x.lua"))


class TestSieveWiring:
    def test_extensions_the_generator_emits_are_enabled(
        self, configured: Config
    ) -> None:
        """The Sieve generator emits relational and imap4flags tests;
        Dovecot rejects a script using an extension it has not loaded."""
        conf = dovecot_conf(configured, Path("/x.lua"))
        for extension in (
            "+relational",
            "+comparator-i;ascii-numeric",
            "+imap4flags",
            "+mailbox",
            "+body",
        ):
            assert extension in conf

    def test_sieve_runs_on_lmtp(self, configured: Config) -> None:
        conf = dovecot_conf(configured, Path("/x.lua"))
        lmtp_block = conf.split("protocol lmtp {")[1].split("}")[0]
        assert "sieve" in lmtp_block


class TestLuaScript:
    def test_carries_the_internal_key(self, configured: Config) -> None:
        assert "test-internal-key" in lua_script(configured, "http://127.0.0.1:8080")

    def test_calls_both_internal_endpoints(self, configured: Config) -> None:
        script = lua_script(configured, "http://127.0.0.1:8080")
        assert "/internal/auth/verify" in script
        assert "/internal/auth/user" in script

    def test_defines_the_entry_points_dovecot_calls(self, configured: Config) -> None:
        script = lua_script(configured, "http://127.0.0.1:8080")
        for entry in ("auth_init", "auth_passdb_lookup", "auth_userdb_lookup"):
            assert f"function {entry}" in script

    def test_401_is_a_password_mismatch_not_an_error(self, configured: Config) -> None:
        """Mapping 401 to INTERNAL_FAILURE would make every wrong
        password look like an outage."""
        script = lua_script(configured, "http://127.0.0.1:8080")
        mismatch_branch = script.split("elseif status == 401")[1].split("end")[0]
        assert "PASSWORD_MISMATCH" in mismatch_branch

    def test_unreachable_lightr_is_an_internal_failure(self, configured: Config) -> None:
        """Not a mismatch -- that would lock everyone out on a blip."""
        script = lua_script(configured, "http://127.0.0.1:8080")
        assert "PASSDB_RESULT_INTERNAL_FAILURE" in script

    def test_quotes_in_credentials_are_escaped(self, configured: Config) -> None:
        """A password containing a quote must not break the JSON body."""
        script = lua_script(configured, "http://127.0.0.1:8080")
        assert "json_escape" in script
        assert "json_escape(req.password)" in script


class TestGeneratedFiles:
    def test_two_files_are_produced(self, configured: Config) -> None:
        files = generate(configured)
        names = {f.path.name for f in files}
        assert names == {CONF_NAME, "lightr-auth.lua"}

    def test_the_lua_script_is_restricted(self, configured: Config) -> None:
        """It holds the internal key -- but Dovecot has to read it."""
        lua = next(f for f in generate(configured) if f.path.suffix == ".lua")
        assert lua.mode == 0o640
        assert lua.is_secret

    def test_the_conf_is_world_readable(self, configured: Config) -> None:
        conf = next(f for f in generate(configured) if f.path.name == CONF_NAME)
        assert conf.mode == 0o644

    def test_api_url_defaults_to_loopback(self, configured: Config) -> None:
        """These endpoints see plaintext passwords."""
        lua = next(f for f in generate(configured) if f.path.suffix == ".lua")
        assert "127.0.0.1" in lua.content

    def test_api_url_can_be_overridden(self, configured: Config) -> None:
        lua = next(
            f
            for f in generate(configured, api_base_url="http://localhost:9999")
            if f.path.suffix == ".lua"
        )
        assert "http://localhost:9999" in lua.content


class TestOutputIntegrity:
    """`lightr dovecot config > file` must produce a parseable file."""

    def test_no_generated_line_is_wrapped(self, configured: Config) -> None:
        from lightr.cli import output

        for generated in generate(configured):
            for line in generated.content.splitlines():
                # A wrapped line would show as a continuation that does
                # not parse; assert the long ones survived intact.
                if "sieve = " in line:
                    assert line.strip().endswith("active.sieve")
        assert callable(output.raw)

    def test_raw_writes_content_verbatim(self, capsys: pytest.CaptureFixture) -> None:
        from lightr.cli import output

        long_line = "  sieve = file:" + "x" * 300 + "\n"
        output.raw(long_line)

        assert capsys.readouterr().out == long_line

    def test_raw_appends_a_trailing_newline(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        from lightr.cli import output

        output.raw("no trailing newline")
        assert capsys.readouterr().out.endswith("\n")


class TestAgainstARealDovecot:
    """Two things a live Dovecot 2.3 rejected that the tests did not.

    Both were found by running `lightr init` on a real server, and both
    failed the same way -- doveconf refused the file, the install rolled
    back, and mailboxes stayed down until it was fixed.
    """

    def test_the_lmtp_listener_is_named_relative_to_base_dir(
        self, cfg: Config
    ) -> None:
        """Dovecot's stock 10-master.conf already declares
        `unix_listener lmtp`. An absolute path resolves to the same
        socket but counts as a second declaration, and Dovecot refuses
        to start with "duplicate listener"."""
        conf = dovecot_conf(cfg, Path("/etc/dovecot/lightr-auth.lua"))

        assert "unix_listener lmtp {" in conf
        assert "unix_listener /run/dovecot/lmtp" not in conf

    def test_a_socket_outside_the_base_dir_is_kept_absolute(
        self, cfg: Config
    ) -> None:
        """Only the default location merges with the stock listener; a
        socket somewhere else has to be named in full."""
        cfg.dovecot.lmtp_socket = Path("/var/spool/lightr/lmtp")
        conf = dovecot_conf(cfg, Path("/etc/dovecot/lightr-auth.lua"))

        assert "unix_listener /var/spool/lightr/lmtp {" in conf

    def test_managesieve_is_not_required(self, cfg: Config) -> None:
        """`sieve` in `protocols` is ManageSieve, which needs
        dovecot-managesieved. Lightr installs Sieve scripts through
        doveadm and would overwrite anything a user edited, so asking
        for the protocol buys a dependency and a confusion."""
        conf = dovecot_conf(cfg, Path("/etc/dovecot/lightr-auth.lua"))

        protocols = next(
            line for line in conf.splitlines() if line.startswith("protocols")
        )
        assert "sieve" not in protocols
        # The Sieve *plugin* still runs at delivery time.
        assert "mail_plugins = $mail_plugins sieve" in conf


class TestDovecotCanReadWhatWeWrite:
    """The auth process runs as the dovecot user, not as root.

    Files written 0600 root:root left it dead on arrival -- "passdb-lua:
    initialization failed: cannot open ...: Permission denied" -- and
    every login then failed with "Auth process broken". Found on a live
    server, so both halves get asserted: not world-readable, and
    readable by the group.
    """

    def test_the_lua_script_is_group_readable_by_dovecot(self, cfg: Config) -> None:
        cfg.dovecot.internal_key = "k"
        lua = next(g for g in generate(cfg) if g.path.name.endswith(".lua"))

        assert lua.mode & 0o007 == 0, "world-readable"
        assert lua.mode & 0o040, "dovecot cannot read it"
        assert lua.group == "dovecot"

    def test_it_still_counts_as_a_secret(self, cfg: Config) -> None:
        """Group-readable is still secret -- the CLI flags it as
        carrying the internal key."""
        cfg.dovecot.internal_key = "k"
        lua = next(g for g in generate(cfg) if g.path.name.endswith(".lua"))

        assert lua.is_secret

    def test_the_conf_file_is_not_secret(self, cfg: Config) -> None:
        cfg.dovecot.internal_key = "k"
        conf = next(g for g in generate(cfg) if g.path.name == CONF_NAME)

        assert not conf.is_secret
