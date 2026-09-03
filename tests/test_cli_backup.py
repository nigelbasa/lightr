"""The backup commands, driven the way an operator drives them.

The module tests cover the archive format; these cover the part an
operator actually touches -- that a backup taken by one command is
restored by another, and that the destructive one asks first.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lightr.cli.main import app
from lightr.config import Config
from lightr.db import migrate

runner = CliRunner()


@pytest.fixture
def installed(tmp_path: Path) -> Path:
    cfg = Config.model_validate({"data_dir": str(tmp_path)})
    path = tmp_path / "config.yaml"
    cfg.save(path)
    migrate.upgrade(cfg)
    return path


def cli(config: Path, *args: str, input: str | None = None):  # noqa: A002
    return runner.invoke(app, ["--config", str(config), *args], input=input)


@pytest.fixture
def populated(installed: Path) -> Path:
    assert cli(installed, "domain", "create", "acme.test").exit_code == 0
    assert (
        cli(installed, "account", "create", "ops@acme.test", "--no-password").exit_code == 0
    )
    return installed


@pytest.fixture
def archive(populated: Path, tmp_path: Path) -> Path:
    target = tmp_path / "backup.tar.gz"
    result = cli(populated, "backup", "create", str(target))
    assert result.exit_code == 0, result.output
    return target


class TestCreate:
    def test_it_writes_an_archive(self, archive: Path) -> None:
        assert archive.is_file()
        assert archive.stat().st_size > 0

    def test_it_says_what_the_file_contains(self, populated: Path, tmp_path: Path) -> None:
        """An operator who does not know the file holds private keys
        will store it somewhere it should not be."""
        result = cli(populated, "backup", "create", str(tmp_path / "b.tar.gz"))
        assert "DKIM private keys" in result.output

    def test_a_directory_argument_gets_a_generated_name(
        self, populated: Path, tmp_path: Path
    ) -> None:
        outdir = tmp_path / "backups"
        outdir.mkdir()

        assert cli(populated, "backup", "create", str(outdir)).exit_code == 0
        assert list(outdir.glob("lightr-backup-*.tar.gz"))

    def test_account_without_include_mail_is_refused(
        self, populated: Path, tmp_path: Path
    ) -> None:
        result = cli(
            populated, "backup", "create", str(tmp_path / "b.tar.gz"),
            "--account", "ops@acme.test",
        )
        assert result.exit_code == 1
        assert "--include-mail" in result.output


class TestInspect:
    def test_it_reports_the_contents(self, populated: Path, archive: Path) -> None:
        result = cli(populated, "backup", "inspect", str(archive), "--format", "json")
        report = json.loads(result.stdout)

        assert report["schema_revision"] == migrate.head_revision(
            Config.load(populated)
        )
        assert report["tables"]["accounts"] == 1
        assert report["includes_mail"] is False

    def test_a_file_that_is_not_a_backup_is_named_as_such(
        self, populated: Path, tmp_path: Path
    ) -> None:
        junk = tmp_path / "notes.txt"
        junk.write_text("hello", encoding="utf-8")

        result = cli(populated, "backup", "inspect", str(junk))
        assert result.exit_code == 1
        assert "could not open" in result.output or "not a Lightr backup" in result.output


class TestRestore:
    def test_the_round_trip(self, populated: Path, archive: Path) -> None:
        """Delete everything, restore, and find it back."""
        assert cli(populated, "account", "delete", "ops@acme.test", "--yes").exit_code == 0
        assert cli(populated, "domain", "delete", "acme.test", "--yes").exit_code == 0

        result = cli(populated, "backup", "restore", str(archive), "--yes")
        assert result.exit_code == 0, result.output

        listed = cli(populated, "account", "list", "--format", "json")
        assert json.loads(listed.stdout)[0]["email"] == "ops@acme.test"

    def test_it_asks_before_replacing_what_is_there(
        self, populated: Path, archive: Path
    ) -> None:
        result = cli(populated, "backup", "restore", str(archive), input="n\n")

        # Rich wraps to the terminal width, so the phrase arrives split
        # across a line break on a narrower terminal than this was
        # written on. What matters is that the warning was shown, not
        # where it happened to fold.
        unwrapped = " ".join(result.output.split())
        assert "will be deleted" in unwrapped
        assert "Cancelled" in unwrapped

    def test_declining_changes_nothing(self, populated: Path, archive: Path) -> None:
        cli(populated, "backup", "restore", str(archive), input="n\n")

        listed = cli(populated, "account", "list", "--format", "json")
        assert len(json.loads(listed.stdout)) == 1

    def test_a_mismatched_revision_is_refused(
        self, populated: Path, tmp_path: Path
    ) -> None:
        """Loading a dump from another schema half-succeeds, which is
        worse than not loading it at all."""
        from lightr import backup as backups

        stale = tmp_path / "stale.tar.gz"
        backups.write_archive(
            stale,
            backups.Manifest(
                format=backups.FORMAT_VERSION,
                lightr_version="0.1.0",
                revision="0001",
                created_at="",
                tables={},
            ),
            {},
        )

        result = cli(populated, "backup", "restore", str(stale), "--yes")
        assert result.exit_code == 1
        assert "0001" in result.output

    def test_the_refusal_can_be_overridden_deliberately(
        self, populated: Path, tmp_path: Path
    ) -> None:
        from lightr import backup as backups

        stale = tmp_path / "stale.tar.gz"
        backups.write_archive(
            stale,
            backups.Manifest(
                format=backups.FORMAT_VERSION,
                lightr_version="0.1.0",
                revision="0001",
                created_at="",
                tables={},
            ),
            {},
        )

        result = cli(
            populated, "backup", "restore", str(stale), "--yes", "--ignore-revision"
        )
        assert result.exit_code == 0, result.output
