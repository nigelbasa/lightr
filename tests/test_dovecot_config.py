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
        with pytest.raises(DovecotConfigError, match="lightr setup"):
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


class TestWhatMailClientsNeed:
    def test_quota_is_reported_over_imap(self, configured: Config) -> None:
        """Without imap_quota, clients cannot show how full a mailbox
        is -- the quota plugin enforces it silently."""
        conf = dovecot_conf(configured)
        block = conf.split("protocol imap {", 1)[1].split("}", 1)[0]
        assert "imap_quota" in block

    def test_trash_and_junk_empty_themselves(self, configured: Config) -> None:
        conf = dovecot_conf(configured)
        for folder in ("Trash", "Junk"):
            block = conf.split(f"mailbox {folder} {{", 1)[1].split("}", 1)[0]
            assert "autoexpunge = 30d" in block, folder

    def test_sent_and_archive_are_never_expunged(self, configured: Config) -> None:
        conf = dovecot_conf(configured)
        for folder in ("Sent", "Drafts", "Archive"):
            block = conf.split(f"mailbox {folder} {{", 1)[1].split("}", 1)[0]
            assert "autoexpunge" not in block, folder

    def test_the_list_index_is_on(self, configured: Config) -> None:
        assert "mailbox_list_index = yes" in dovecot_conf(configured)


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
            CONF_NAME, "lightr-checkpassword", "lightr-userdb.conf.ext", "spam.sieve"
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



class TestDriftIsReportedNotCorrected:
    """`serve` used to rewrite Dovecot's configuration on every start.

    That means the mail engine holds write access to /etc/dovecot for
    the life of the process -- or, with ProtectSystem=strict, warns on
    every start instead. Configuration happens at install time now, and
    a running service only says when it has drifted.
    """

    def test_an_unconfigured_dovecot_is_not_reported_as_current(
        self, cfg: Config, tmp_path: Path
    ) -> None:
        """Without an internal key the files cannot even be generated.
        Answering "no drift" there is the reassuring answer rather than
        the true one."""
        from lightr.dovecot.manage import DovecotManager

        stale = DovecotManager(cfg, conf_dir=tmp_path).drift()

        assert stale

    def test_files_that_are_absent_count_as_drift(
        self, configured: Config, tmp_path: Path
    ) -> None:
        from lightr.dovecot.manage import DovecotManager

        stale = DovecotManager(configured, conf_dir=tmp_path).drift()

        assert "lightr-userdb.conf.ext" in stale

    def test_matching_files_are_not_drift(
        self, configured: Config, tmp_path: Path
    ) -> None:
        from lightr.dovecot.manage import DovecotManager

        manager = DovecotManager(configured, conf_dir=tmp_path)
        _install_into(configured, tmp_path)

        assert manager.drift() == []

    def test_a_changed_database_shows_up(self, configured: Config, tmp_path: Path) -> None:
        """Moving to Postgres rewrites the userdb conf. Until it is
        applied, Dovecot is still looking in the old SQLite file."""
        from lightr.config import DatabaseDriver
        from lightr.dovecot.manage import DovecotManager

        manager = DovecotManager(configured, conf_dir=tmp_path)
        _install_into(configured, tmp_path)

        configured.database.driver = DatabaseDriver.POSTGRES
        configured.database.dsn = "postgresql://lightr:pw@127.0.0.1:5432/lightr"

        assert "lightr-userdb.conf.ext" in manager.drift()


def _install_into(cfg: Config, conf_dir: Path) -> None:
    """Write the generated files where the manager will look for them."""
    from lightr.dovecot.manage import DOVECOT_CONF_DIR

    for item in generate(cfg):
        try:
            relative = item.path.relative_to(DOVECOT_CONF_DIR)
        except ValueError:
            relative = Path(item.path.name)
        target = conf_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(item.content, encoding="utf-8")


class TestSpamFiling:
    """Flagged mail has to go somewhere. It used to be scored, flagged,
    and delivered to the inbox of any mailbox without its own rule."""

    def test_the_spam_script_is_generated_under_sieve_dir(
        self, configured: Config
    ) -> None:
        from lightr.dovecot.config import spam_script_path

        files = {f.path: f for f in generate(configured)}
        script = files[spam_script_path(configured)]

        assert script.path.is_relative_to(configured.dovecot.sieve_dir)
        assert '"X-Lightr-Spam-Action"' in script.content
        assert 'fileinto :create "Junk";' in script.content
        assert "stop;" in script.content
        # Its header describes what rewrites it, not filter-rule changes.
        assert "lightr setup" in script.content
        assert "filter rules change" not in script.content
        assert script.content.count('require ["fileinto", "mailbox"];') == 1

    def test_dovecot_runs_it_before_each_mailbox_script(
        self, configured: Config
    ) -> None:
        from lightr.dovecot.config import spam_script_path

        plugin = dovecot_conf(configured).split("plugin {", 1)[1].split("}", 1)[0]
        assert f"sieve_before = {spam_script_path(configured).as_posix()}" in plugin

    def test_the_action_header_cannot_be_forged(self) -> None:
        from lightr.mail.headers import CONTROLLED_HEADERS

        assert "X-Lightr-Spam-Action" in CONTROLLED_HEADERS


class TestSpamScriptCompilation:
    """Precompiling with sievec, run here through the Python interpreter
    so the tests do not need Pigeonhole installed."""

    def _manager(self, configured: Config, tmp_path: Path, code: str):
        import sys

        from lightr.dovecot.manage import DovecotManager

        manager = DovecotManager(configured, conf_dir=tmp_path)
        manager.sievec_command = [sys.executable, "-c", code]
        return manager

    async def test_a_script_that_compiles_raises_no_warning(
        self, configured: Config, tmp_path: Path
    ) -> None:
        manager = self._manager(configured, tmp_path, "import sys; sys.exit(0)")
        assert await manager.compile_spam_script() is None

    async def test_a_script_that_does_not_compile_is_a_warning_not_a_failure(
        self, configured: Config, tmp_path: Path
    ) -> None:
        manager = self._manager(
            configured, tmp_path,
            "import sys; sys.stderr.write('line 3: unknown extension'); sys.exit(1)",
        )

        warning = await manager.compile_spam_script()

        assert warning is not None
        assert "unknown extension" in warning
        assert "inbox" in warning

    async def test_no_sievec_is_a_warning_naming_the_package(
        self, configured: Config, tmp_path: Path
    ) -> None:
        """Without sievec there is no Sieve, and spam goes to the inbox.
        Silence here would leave that for the Dovecot log to reveal."""
        from lightr.dovecot.manage import DovecotManager

        manager = DovecotManager(configured, conf_dir=tmp_path)
        manager.sievec_command = None

        warning = await manager.compile_spam_script()

        assert warning is not None
        assert "dovecot-sieve" in warning


class TestIMAPCertificates:
    """IMAPS used to present Dovecot's stock certificate -- on Ubuntu a
    self-signed snakeoil one -- while SMTP presented the real one."""

    def _with_certs(self, configured: Config, tmp_path: Path) -> Config:
        from lightr.config import DomainCertConfig

        configured.tls.cert_file = tmp_path / "live" / "mail.example.com" / "fullchain.pem"
        configured.tls.key_file = tmp_path / "live" / "mail.example.com" / "privkey.pem"
        configured.tls.domain_certs = {
            "Mail.Other.Test": DomainCertConfig(
                cert_file=tmp_path / "other" / "fullchain.pem",
                key_file=tmp_path / "other" / "privkey.pem",
            )
        }
        for path in (
            configured.tls.cert_file, configured.tls.key_file,
            tmp_path / "other" / "fullchain.pem", tmp_path / "other" / "privkey.pem",
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("placeholder", encoding="utf-8")
        return configured

    def test_the_default_certificate_is_lightrs(
        self, configured: Config, tmp_path: Path
    ) -> None:
        cfg = self._with_certs(configured, tmp_path)
        conf = dovecot_conf(cfg)

        assert f"ssl_cert = <{cfg.tls.cert_file.as_posix()}" in conf
        assert f"ssl_key = <{cfg.tls.key_file.as_posix()}" in conf

    def test_each_hostname_gets_its_own_certificate(
        self, configured: Config, tmp_path: Path
    ) -> None:
        cfg = self._with_certs(configured, tmp_path)
        conf = dovecot_conf(cfg)

        block = conf.split("local_name mail.other.test {", 1)[1].split("}", 1)[0]
        assert (tmp_path / "other" / "fullchain.pem").as_posix() in block
        assert (tmp_path / "other" / "privkey.pem").as_posix() in block

    def test_without_a_certificate_it_says_so_and_sets_none(
        self, configured: Config
    ) -> None:
        conf = dovecot_conf(configured)
        settings = [
            line.strip() for line in conf.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert not any(s.startswith("ssl_cert") for s in settings)
        assert "lightr setup" in conf

    @pytest.mark.parametrize("name", ["evil } ssl = no {", "has space.test", "no-dot", ""])
    def test_a_hostname_that_could_escape_the_block_is_refused(
        self, configured: Config, tmp_path: Path, name: str
    ) -> None:
        from lightr.config import DomainCertConfig

        cfg = self._with_certs(configured, tmp_path)
        cfg.tls.domain_certs = {
            name: DomainCertConfig(cert_file=tmp_path / "c.pem", key_file=tmp_path / "k.pem")
        }
        with pytest.raises(DovecotConfigError, match="invalid hostname"):
            dovecot_conf(cfg)

    def test_a_hostname_whose_certificate_is_missing_is_skipped(
        self, configured: Config, tmp_path: Path
    ) -> None:
        """A missing file would stop Dovecot starting at all."""
        from lightr.config import DomainCertConfig

        cfg = self._with_certs(configured, tmp_path)
        cfg.tls.domain_certs["gone.example.test"] = DomainCertConfig(
            cert_file=tmp_path / "gone" / "fullchain.pem",
            key_file=tmp_path / "gone" / "privkey.pem",
        )
        conf = dovecot_conf(cfg)

        assert "local_name gone.example.test" not in conf
        assert "gone.example.test: certificate not found" in conf
        assert "local_name mail.other.test {" in conf

    def test_the_default_placeholder_paths_are_not_used(self, configured: Config) -> None:
        """Config defaults tls to data_dir/tls/server.crt, which is not
        there on a fresh install."""
        assert configured.tls.cert_file is not None
        assert not configured.tls.cert_file.exists()
        assert "ssl_cert = <" not in dovecot_conf(configured)


class TestMailUserUid:
    """first_valid_uid was 1000; the lightr system account is 998, and
    Dovecot refused every delivery and IMAP login because of it."""

    def _setting(self, conf: str) -> int:
        (line,) = [
            s.strip() for s in conf.splitlines()
            if s.strip().startswith("first_valid_uid")
        ]
        return int(line.split("=", 1)[1])

    def test_the_floor_is_the_mail_users_own_uid(
        self, configured: Config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from lightr.dovecot import config as dovecot_config

        monkeypatch.setattr(dovecot_config, "mail_user_uid", lambda: 998)

        assert self._setting(dovecot_conf(configured)) == 998

    def test_a_system_account_uid_is_looked_up(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys
        import types

        from lightr.dovecot.config import mail_user_uid

        fake = types.ModuleType("pwd")
        fake.getpwnam = lambda name: types.SimpleNamespace(pw_uid=998)  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "pwd", fake)

        assert mail_user_uid() == 998

    def test_without_the_user_it_falls_back_below_system_accounts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys
        import types

        from lightr.dovecot.config import SYSTEM_UID_FLOOR, mail_user_uid

        def missing(name: str):
            raise KeyError(name)

        fake = types.ModuleType("pwd")
        fake.getpwnam = missing  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "pwd", fake)

        assert mail_user_uid() == SYSTEM_UID_FLOOR
        assert SYSTEM_UID_FLOOR < 1000
