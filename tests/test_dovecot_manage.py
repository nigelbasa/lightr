"""Lightr managing Dovecot as an internal component.

Lightr writes files outside its own tree and reloads another daemon, so
what matters here is what happens when that goes wrong: nothing is left
half-written, nothing already there is lost, and a configuration that
does not parse never reaches the running service.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_doveadm import FakeDoveadm

from lightr.config import Config
from lightr.dovecot.doveadm import DoveadmError
from lightr.dovecot.manage import (
    DEFAULT_MASTER_USER,
    DovecotManagementError,
    DovecotManager,
    write_atomic,
)


@pytest.fixture
def cfg_with_key(cfg: Config) -> Config:
    cfg.dovecot.internal_key = "test-internal-key"
    return cfg


def _manager(cfg: Config, conf_dir: Path, **kwargs) -> DovecotManager:
    doveadm = kwargs.pop("doveadm", None) or FakeDoveadm(output="{CRYPT}$2y$05$hash")
    return DovecotManager(cfg, doveadm=doveadm, conf_dir=conf_dir)


class TestAtomicWrites:
    def test_writes_a_new_file(self, tmp_path: Path) -> None:
        change = write_atomic(tmp_path / "a" / "conf", "content\n")
        assert change.action == "written"
        assert change.path.read_text(encoding="utf-8") == "content\n"

    def test_identical_content_is_left_alone(self, tmp_path: Path) -> None:
        target = tmp_path / "conf"
        write_atomic(target, "same\n")
        assert write_atomic(target, "same\n").action == "unchanged"

    def test_an_existing_file_is_backed_up(self, tmp_path: Path) -> None:
        """Never replace an operator's file in the dark."""
        target = tmp_path / "conf"
        target.write_text("theirs\n", encoding="utf-8")

        change = write_atomic(target, "ours\n")

        assert change.backup is not None
        assert change.backup.read_text(encoding="utf-8") == "theirs\n"
        assert target.read_text(encoding="utf-8") == "ours\n"

    def test_no_temporary_files_survive(self, tmp_path: Path) -> None:
        write_atomic(tmp_path / "conf", "x\n")
        assert [p.name for p in tmp_path.iterdir()] == ["conf"]

    def test_a_failed_write_leaves_the_original(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "conf"
        target.write_text("original\n", encoding="utf-8")

        def boom(*args: object, **kwargs: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr("pathlib.Path.replace", boom)

        with pytest.raises(OSError, match="disk full"):
            write_atomic(target, "replacement\n")

        assert target.read_text(encoding="utf-8") == "original\n"


class TestInstall:
    async def test_writes_config_and_master_users(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        cfg_with_key.dovecot.master_user = "lightr-master"
        cfg_with_key.dovecot.master_password = "generated"
        conf_dir = tmp_path / "dovecot"

        report = await _manager(cfg_with_key, conf_dir).install(reload=False)

        written = {c.path.name for c in report.changes if c.action == "written"}
        assert "99-lightr.conf" in written
        assert "lightr-auth.lua" in written
        assert "master-users" in written

    async def test_the_master_password_is_hashed_by_doveadm(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        """The format is whatever this Dovecot accepts, not a guess."""
        cfg_with_key.dovecot.master_user = "lightr-master"
        cfg_with_key.dovecot.master_password = "generated"
        conf_dir = tmp_path / "dovecot"

        await _manager(cfg_with_key, conf_dir).install(reload=False)

        content = (conf_dir / "master-users").read_text(encoding="utf-8")
        assert content.startswith("lightr-master:{CRYPT}")
        assert "generated" not in content

    async def test_the_master_users_file_is_owner_only(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        """It is a credential that opens every mailbox."""
        import os

        cfg_with_key.dovecot.master_user = "m"
        cfg_with_key.dovecot.master_password = "p"
        conf_dir = tmp_path / "dovecot"

        await _manager(cfg_with_key, conf_dir).install(reload=False)

        if os.name != "nt":  # pragma: no cover - POSIX only
            assert (conf_dir / "master-users").stat().st_mode & 0o077 == 0

    async def test_no_master_user_means_no_file(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        conf_dir = tmp_path / "dovecot"
        await _manager(cfg_with_key, conf_dir).install(reload=False)
        assert not (conf_dir / "master-users").exists()

    async def test_a_second_install_changes_nothing(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        conf_dir = tmp_path / "dovecot"
        manager = _manager(cfg_with_key, conf_dir)

        await manager.install(reload=False)
        second = await manager.install(reload=False)

        assert not second.changed

    async def test_reload_is_requested(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        doveadm = FakeDoveadm(output="{CRYPT}$hash")
        manager = _manager(cfg_with_key, tmp_path / "d", doveadm=doveadm)

        report = await manager.install(reload=True)

        assert report.reloaded
        assert ("reload",) in [c[0] for c in doveadm.calls]

    async def test_a_failed_reload_is_a_warning_not_a_failure(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        """The configuration is already written and valid; the operator
        just needs to reload it themselves."""

        class ReloadFails(FakeDoveadm):
            async def reload(self) -> None:
                raise DoveadmError("reload", 1, "no such service")

        manager = _manager(
            cfg_with_key, tmp_path / "d", doveadm=ReloadFails(output="{CRYPT}$h")
        )
        report = await manager.install(reload=True)

        assert not report.reloaded
        assert any("systemctl reload" in w for w in report.warnings)


class TestRollback:
    async def test_a_failure_leaves_nothing_behind(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        """A half-written configuration is worse than none: Dovecot may
        still start and behave in a way nobody configured."""

        class HashFails(FakeDoveadm):
            async def pw(self, password: str, scheme: str = "CRYPT") -> str:
                raise DoveadmError("pw", 1, "nope")

        cfg_with_key.dovecot.master_user = "m"
        cfg_with_key.dovecot.master_password = "p"
        conf_dir = tmp_path / "dovecot"

        with pytest.raises(DovecotManagementError):
            await _manager(conf_dir=conf_dir, cfg=cfg_with_key,
                           doveadm=HashFails()).install(reload=False)

        assert list(conf_dir.rglob("*.conf")) == []
        assert list(conf_dir.rglob("*.lua")) == []

    async def test_rollback_restores_a_previous_file(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        """An operator's existing config must come back intact."""

        class HashFails(FakeDoveadm):
            async def pw(self, password: str, scheme: str = "CRYPT") -> str:
                raise DoveadmError("pw", 1, "nope")

        conf_dir = tmp_path / "dovecot"
        existing = conf_dir / "conf.d" / "99-lightr.conf"
        existing.parent.mkdir(parents=True)
        existing.write_text("# theirs\n", encoding="utf-8")

        cfg_with_key.dovecot.master_user = "m"
        cfg_with_key.dovecot.master_password = "p"

        with pytest.raises(DovecotManagementError):
            await _manager(conf_dir=conf_dir, cfg=cfg_with_key,
                           doveadm=HashFails()).install(reload=False)

        assert existing.read_text(encoding="utf-8") == "# theirs\n"

    async def test_a_config_dovecot_rejects_is_not_activated(
        self, cfg_with_key: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify before reload: an unparseable config would otherwise
        take the mail server down."""
        conf_dir = tmp_path / "dovecot"
        doveadm = FakeDoveadm(output="{CRYPT}$h")
        manager = _manager(cfg_with_key, conf_dir, doveadm=doveadm)

        async def rejects(self) -> str:
            return "line 3: syntax error"

        monkeypatch.setattr(DovecotManager, "verify", rejects)

        with pytest.raises(DovecotManagementError, match="syntax error"):
            await manager.install(reload=True)

        assert ("reload",) not in [c[0] for c in doveadm.calls]
        assert list(conf_dir.rglob("*.conf")) == []


class TestMasterUser:
    async def test_one_is_generated_when_absent(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        """An operator should never have to invent, hash, or type this."""
        manager = _manager(cfg_with_key, tmp_path / "d")

        name = await manager.ensure_master_user()

        assert name == DEFAULT_MASTER_USER
        assert cfg_with_key.dovecot.has_master_user
        assert len(cfg_with_key.dovecot.master_password) >= 32

    async def test_an_existing_one_is_kept(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        cfg_with_key.dovecot.master_user = "already-there"
        cfg_with_key.dovecot.master_password = "existing"

        assert await _manager(cfg_with_key, tmp_path / "d").ensure_master_user() == (
            "already-there"
        )
        assert cfg_with_key.dovecot.master_password == "existing"


class TestStatus:
    async def test_reports_doveadm_availability(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        info = await _manager(cfg_with_key, tmp_path / "d").status()
        assert info["doveadm_available"] is True

    async def test_a_broken_doveadm_does_not_raise(
        self, cfg_with_key: Config, tmp_path: Path
    ) -> None:
        """Status is what an operator runs when things are wrong."""
        manager = _manager(
            cfg_with_key, tmp_path / "d", doveadm=FakeDoveadm(fail=True)
        )
        info = await manager.status()
        assert "unavailable" in str(info["version"])
