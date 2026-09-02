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
        assert "maildir:" in dovecot_conf(configured)

    def test_single_instance_storage_is_not_enabled(self, configured: Config) -> None:
        """SIS is deprecated and its failure mode is losing attachments."""
        conf = dovecot_conf(configured)
        settings = [
            line.strip()
            for line in conf.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert not any(s.startswith("mail_attachment_dir") for s in settings)

    def test_the_omission_is_explained(self, configured: Config) -> None:
        """A future maintainer must not 'helpfully' turn SIS on."""
        assert "mail_attachment_dir" in dovecot_conf(configured)

    def test_maildir_root_is_posix(self, configured: Config) -> None:
        conf = dovecot_conf(configured)
        assert "\\" not in conf.split("mail_home =")[1].splitlines()[0]

    def test_special_use_folders_are_declared(self, configured: Config) -> None:
        conf = dovecot_conf(configured)
        for flag in ("\\Sent", "\\Drafts", "\\Trash", "\\Junk", "\\Archive"):
            assert flag in conf


class TestAuthWiring:
    def test_passdb_is_checkpassword(self, configured: Config) -> None:
        """Not Lua: `dovecot.http` does not exist before Dovecot 2.4,
        and Debian 12 and Ubuntu 22.04 both ship 2.3."""
        conf = dovecot_conf(configured)
        assert "driver = checkpassword" in conf
        assert "driver = lua" not in conf

    def test_userdb_is_sql(self, configured: Config) -> None:
        """LMTP looks a user up without authenticating as them, so
        `prefetch` cannot serve it."""
        conf = dovecot_conf(configured)
        assert "driver = sql" in conf

    def test_master_user_block_only_when_configured(self, configured: Config) -> None:
        assert "master = yes" not in dovecot_conf(configured)

        configured.dovecot.master_user = "lightr-master"
        assert "master = yes" in dovecot_conf(configured)


class TestSieveWiring:
    def test_extensions_the_generator_emits_are_enabled(
        self, configured: Config
    ) -> None:
        """The Sieve generator emits relational and imap4flags tests;
        Dovecot rejects a script using an extension it has not loaded."""
        conf = dovecot_conf(configured)
        for extension in (
            "+relational",
            "+comparator-i;ascii-numeric",
            "+imap4flags",
            "+mailbox",
            "+body",
        ):
            assert extension in conf

    def test_sieve_runs_on_lmtp(self, configured: Config) -> None:
        conf = dovecot_conf(configured)
        lmtp_block = conf.split("protocol lmtp {")[1].split("}")[0]
        assert "sieve" in lmtp_block


class TestGeneratedFiles:
    def test_the_expected_files_are_produced(self, configured: Config) -> None:
        files = generate(configured)
        names = {f.path.name for f in files}
        assert names == {
            CONF_NAME, "lightr-checkpassword", "lightr-userdb.conf.ext"
        }

    def test_the_checkpassword_script_is_executable_and_restricted(
        self, configured: Config
    ) -> None:
        """It holds the internal key, and the auth process runs it."""
        script = next(
            f for f in generate(configured) if f.path.name.endswith("checkpassword")
        )
        assert script.mode == 0o750
        assert script.group == "dovecot"
        assert script.is_secret

    def test_the_userdb_conf_is_restricted(self, configured: Config) -> None:
        """It holds the database password."""
        conf = next(f for f in generate(configured) if f.path.suffix == ".ext")
        assert conf.mode == 0o640
        assert conf.group == "dovecot"

    def test_the_conf_is_world_readable(self, configured: Config) -> None:
        conf = next(f for f in generate(configured) if f.path.name == CONF_NAME)
        assert conf.mode == 0o644

    def test_api_url_defaults_to_loopback(self, configured: Config) -> None:
        """These endpoints see plaintext passwords."""
        script = next(
            f for f in generate(configured) if f.path.name.endswith("checkpassword")
        )
        assert "127.0.0.1" in script.content

    def test_api_url_can_be_overridden(self, configured: Config) -> None:
        script = next(
            f
            for f in generate(configured, api_base_url="http://localhost:9999")
            if f.path.name.endswith("checkpassword")
        )
        assert "http://localhost:9999" in script.content


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
        conf = dovecot_conf(cfg)

        assert "unix_listener lmtp {" in conf
        assert "unix_listener /run/dovecot/lmtp" not in conf

    def test_a_socket_outside_the_base_dir_is_kept_absolute(
        self, cfg: Config
    ) -> None:
        """Only the default location merges with the stock listener; a
        socket somewhere else has to be named in full."""
        cfg.dovecot.lmtp_socket = Path("/var/spool/lightr/lmtp")
        conf = dovecot_conf(cfg)

        assert "unix_listener /var/spool/lightr/lmtp {" in conf

    def test_managesieve_is_not_required(self, cfg: Config) -> None:
        """`sieve` in `protocols` is ManageSieve, which needs
        dovecot-managesieved. Lightr installs Sieve scripts through
        doveadm and would overwrite anything a user edited, so asking
        for the protocol buys a dependency and a confusion."""
        conf = dovecot_conf(cfg)

        protocols = next(
            line for line in conf.splitlines() if line.startswith("protocols")
        )
        assert "sieve" not in protocols
        # The Sieve *plugin* still runs at delivery time.
        assert "mail_plugins = $mail_plugins sieve" in conf


class TestTheMasterUserActuallyWorks:
    """Declaring the master passdb is not enough.

    Dovecot only splits "user*master" when the separator is set. Left
    empty -- its default -- it looks the whole string up as one
    username, the lookup fails, and the master user is silently inert.
    Every mailbox read and the whole /v1/mailbox API go through it, so
    on a live server this meant "Dovecot refused the master-user
    login" on every single command.
    """

    def test_the_separator_is_declared(self, configured: Config) -> None:
        configured.dovecot.master_user = "lightr-master"
        configured.dovecot.master_password = "generated"

        conf = dovecot_conf(configured)

        assert "auth_master_user_separator = *" in conf

    def test_it_matches_the_form_lightr_logs_in_with(
        self, configured: Config
    ) -> None:
        """The client side builds `<account>*<master>`; the server side
        has to agree about the `*`."""
        from lightr.cli.imap_client import master_login

        configured.dovecot.master_user = "lightr-master"
        configured.dovecot.master_password = "generated"
        conf = dovecot_conf(configured)

        login = master_login("ops@acme.test", "lightr-master")
        separator = next(
            line.split("=", 1)[1].strip()
            for line in conf.splitlines()
            if line.startswith("auth_master_user_separator")
        )

        assert separator in login
        assert login.split(separator) == ["ops@acme.test", "lightr-master"]

    def test_no_separator_without_a_master_user(self, cfg: Config) -> None:
        """Nothing to split when there is no master user configured."""
        cfg.dovecot.internal_key = "k"
        conf = dovecot_conf(cfg)

        assert "auth_master_user_separator" not in conf


