"""Preflight checks.

Written after a deployment where ten things were wrong and every one
was discovered by a mail client failing to log in. The engine started,
reported itself healthy, and could not deliver a message.

So the property under test is not "does it notice" but **"does it
refuse"**. The failure that made that deployment expensive was a
warning that should have been fatal.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lightr import preflight
from lightr.config import Config, DatabaseDriver
from lightr.preflight import Level


class TestSeverity:
    def test_a_report_with_a_failure_is_not_ok(self) -> None:
        report = preflight.Report()
        report.add("x", Level.FAIL, "broken")

        assert not report.ok

    def test_warnings_alone_do_not_stop_a_start(self) -> None:
        """"Will work worse" must not read the same as "cannot work"."""
        report = preflight.Report()
        report.add("x", Level.WARN, "degraded")

        assert report.ok
        assert report.warnings


class TestPython:
    def test_the_supported_version_passes(self) -> None:
        report = preflight.Report()
        preflight.check_python(report)

        assert report.ok

    def test_an_old_python_is_fatal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Ubuntu 22.04 ships 3.10 and Lightr needs 3.11 -- StrEnum,
        datetime.UTC and typing.Self are all 3.11."""
        monkeypatch.setattr(preflight.sys, "version_info", (3, 10, 12))
        report = preflight.Report()
        preflight.check_python(report)

        assert not report.ok
        assert "3.10" in report.failures[0].detail

    def test_it_names_the_way_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight.sys, "version_info", (3, 10, 12))
        report = preflight.Report()
        preflight.check_python(report)

        assert "deadsnakes" in (report.failures[0].fix or "")


class TestPlatform:
    def test_non_linux_is_fatal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight.platform, "system", lambda: "Windows")
        report = preflight.Report()
        preflight.check_platform(report)

        assert not report.ok

    def test_linux_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight.platform, "system", lambda: "Linux")
        report = preflight.Report()
        preflight.check_platform(report)

        assert report.ok


class TestDovecot:
    def test_a_missing_dovecot_is_fatal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """There are no mailboxes without it."""
        monkeypatch.setattr(preflight, "dovecot_version", lambda: None)
        report = preflight.Report()
        preflight.check_dovecot(report)

        assert not report.ok
        assert "apt install" in (report.failures[0].fix or "")

    def test_2_3_passes_but_is_noted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """It works -- checkpassword needs nothing from 2.4 -- but the
        version decides what is even possible, so it is reported."""
        monkeypatch.setattr(preflight, "dovecot_version", lambda: (2, 3, 16))
        report = preflight.Report()
        preflight.check_dovecot(report)

        assert report.ok
        assert "2.3" in report.checks[0].detail

    def test_2_4_passes_without_the_note(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(preflight, "dovecot_version", lambda: (2, 4, 0))
        report = preflight.Report()
        preflight.check_dovecot(report)

        assert report.ok
        assert "no HTTP" not in report.checks[0].detail


class TestDovecotModules:
    def test_a_missing_sql_driver_is_fatal(
        self, cfg: Config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without it Dovecot cannot answer "where does this mailbox
        live", so nothing is delivered -- and it fails with "Unknown
        database driver", which points at nothing."""
        monkeypatch.setattr(preflight, "dovecot_version", lambda: (2, 3, 16))
        monkeypatch.setattr(Path, "exists", lambda self: False)

        report = preflight.Report()
        preflight.check_dovecot_modules(report, cfg)

        names = {c.name for c in report.failures}
        assert "dovecot-sql" in names

    def test_the_fix_names_the_debian_package(
        self, cfg: Config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`dovecot-lua` cost an afternoon; the package is
        `dovecot-auth-lua`. Names come from one place now."""
        monkeypatch.setattr(preflight, "dovecot_version", lambda: (2, 3, 16))
        monkeypatch.setattr(Path, "exists", lambda self: False)

        report = preflight.Report()
        preflight.check_dovecot_modules(report, cfg)

        sql = next(c for c in report.failures if c.name == "dovecot-sql")
        assert sql.fix == "apt install dovecot-sqlite"

    def test_postgres_asks_for_the_postgres_driver(
        self, cfg: Config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg.database.driver = DatabaseDriver.POSTGRES
        cfg.database.dsn = "postgresql://u:p@127.0.0.1/lightr"
        monkeypatch.setattr(preflight, "dovecot_version", lambda: (2, 3, 16))
        monkeypatch.setattr(Path, "exists", lambda self: False)

        report = preflight.Report()
        preflight.check_dovecot_modules(report, cfg)

        sql = next(c for c in report.failures if c.name == "dovecot-sql")
        assert sql.fix == "apt install dovecot-pgsql"

    def test_nothing_is_checked_without_dovecot(
        self, cfg: Config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One "Dovecot is missing" beats five module failures."""
        monkeypatch.setattr(preflight, "dovecot_version", lambda: None)
        report = preflight.Report()
        preflight.check_dovecot_modules(report, cfg)

        assert report.checks == []


class TestDatabaseDriver:
    def test_a_missing_driver_is_fatal(
        self, cfg: Config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Configured for Postgres with no asyncpg is the error every
        Postgres install hit."""
        cfg.database.driver = DatabaseDriver.POSTGRES

        def missing(name: str, *args: object, **kwargs: object) -> None:
            raise ImportError(name)

        monkeypatch.setattr("builtins.__import__", missing)

        report = preflight.Report()
        preflight.check_database_driver(report, cfg)

        assert not report.ok
        assert "lightr[postgres]" in (report.failures[0].fix or "")

    def test_sqlite_passes_when_aiosqlite_is_there(self, cfg: Config) -> None:
        report = preflight.Report()
        preflight.check_database_driver(report, cfg)

        assert report.ok


class TestConfigPermissions:
    def test_a_world_readable_config_is_a_warning(self, tmp_path: Path) -> None:
        """It holds a database password and the Dovecot internal key."""
        import os

        if os.name == "nt":  # pragma: no cover - POSIX only
            pytest.skip("POSIX permissions")

        path = tmp_path / "config.yaml"
        path.write_text("server: {}\n", encoding="utf-8")
        path.chmod(0o644)

        report = preflight.Report()
        preflight.check_config_readable(report, path)

        assert report.ok  # not fatal: it still runs
        assert report.warnings
        assert "chmod 640" in (report.warnings[0].fix or "")

    def test_a_missing_config_is_only_a_warning(self, tmp_path: Path) -> None:
        report = preflight.Report()
        preflight.check_config_readable(report, tmp_path / "absent.yaml")

        assert report.ok
        assert report.warnings


class TestTheServiceCanReadItsConfig:
    """The unit runs as User=lightr, and the file is 0640 root:lightr.

    Get the group wrong and the service starts, cannot read its own
    config, falls back to defaults, and looks healthy while pointing at
    the wrong database. That is the same shape as the Lua passdb
    failure -- everything green, nothing working -- so it is fatal.
    """

    def test_a_config_the_service_cannot_read_is_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os

        if os.name == "nt":  # pragma: no cover - POSIX only
            pytest.skip("POSIX permissions")

        monkeypatch.setattr(
            preflight, "_readable_by_service", lambda *args: False
        )
        path = tmp_path / "config.yaml"
        path.write_text("server: {}\n", encoding="utf-8")
        path.chmod(0o600)

        report = preflight.Report()
        preflight.check_config_readable(report, path)

        assert not report.ok
        assert "lightr" in (report.failures[0].fix or "")

    def test_it_says_nothing_when_there_is_no_service_user(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pip install run by a person has no lightr user, and
        failing that install would be wrong."""
        import os

        if os.name == "nt":  # pragma: no cover - POSIX only
            pytest.skip("POSIX permissions")

        monkeypatch.setattr(preflight, "_readable_by_service", lambda *args: True)
        path = tmp_path / "config.yaml"
        path.write_text("server: {}\n", encoding="utf-8")
        path.chmod(0o600)

        report = preflight.Report()
        preflight.check_config_readable(report, path)

        assert report.ok


class TestSystemAuth:
    """Ubuntu's 10-auth.conf puts a PAM passdb ahead of Lightr's."""

    def _conf(self, tmp_path: Path, text: str) -> Path:
        path = tmp_path / "conf.d" / "10-auth.conf"
        path.parent.mkdir(parents=True)
        path.write_text(text, encoding="utf-8")
        return tmp_path

    def test_an_active_include_is_a_warning_with_the_exact_fix(
        self, tmp_path: Path
    ) -> None:
        conf_dir = self._conf(tmp_path, "!include auth-system.conf.ext\n")

        report = preflight.Report()
        preflight.check_system_auth(report, conf_dir)

        (check,) = report.checks
        assert check.level is Level.WARN
        assert report.ok, "logins still work, so it must not refuse to start"
        assert check.fix is not None
        assert "lightr dovecot install" in check.fix
        assert "!include auth-system.conf.ext" in check.fix

    def test_a_commented_include_says_nothing(self, tmp_path: Path) -> None:
        conf_dir = self._conf(tmp_path, "#!include auth-system.conf.ext\n")

        report = preflight.Report()
        preflight.check_system_auth(report, conf_dir)

        assert report.checks == []

    def test_no_conf_d_says_nothing(self, tmp_path: Path) -> None:
        report = preflight.Report()
        preflight.check_system_auth(report, tmp_path)

        assert report.checks == []
