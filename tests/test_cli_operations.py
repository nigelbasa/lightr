"""The apikey, queue, and suppression command groups."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lightr.cli.main import app
from lightr.config import Config
from lightr.db import migrate

runner = CliRunner()


def cli(config: Path, *args: str, input: str | None = None):  # noqa: A002
    return runner.invoke(app, ["--config", str(config), *args], input=input)


@pytest.fixture
def installed(tmp_path: Path) -> Path:
    cfg = Config.model_validate(
        {
            "data_dir": str(tmp_path),
            "dovecot": {
                "maildir_root": str(tmp_path / "mail"),
                "sieve_dir": str(tmp_path / "sieve"),
                "lmtp_socket": None,
            },
        }
    )
    path = tmp_path / "config.yaml"
    cfg.save(path)
    migrate.upgrade(cfg)

    assert cli(path, "domain", "create", "acme.test").exit_code == 0
    assert cli(path, "account", "create", "ops@acme.test", "--no-password").exit_code == 0
    return path


class TestAPIKeys:
    def test_create_shows_the_secret_once(self, installed: Path) -> None:
        result = cli(installed, "apikey", "create", "ci", "--type", "admin")
        assert result.exit_code == 0, result.output
        assert "shown once" in result.output
        assert "lk_" in result.output

    def test_the_secret_never_appears_again(self, installed: Path) -> None:
        cli(installed, "apikey", "create", "ci", "--type", "admin")

        listed = cli(installed, "apikey", "list", "--format", "json")
        assert "lk_" not in listed.stdout.split('"prefix"')[0]
        assert all(k["key_hash"] == "(stored)" for k in json.loads(listed.stdout))

    def test_an_account_scoped_key_names_its_mailbox(self, installed: Path) -> None:
        result = cli(
            installed, "apikey", "create", "ops-mail",
            "--type", "account", "--account", "ops@acme.test",
        )
        assert result.exit_code == 0, result.output
        # The address, not the account's UUID: which mailbox a key was
        # just cut for is the one thing the operator needs to read back.
        assert "ops@acme.test" in result.output

    def test_rotate_replaces_the_secret(self, installed: Path) -> None:
        cli(installed, "apikey", "create", "ci", "--type", "admin")

        rotated = cli(installed, "apikey", "rotate", "ci", "--yes")
        assert rotated.exit_code == 0
        assert "lk_" in rotated.output

    def test_rotate_warns_before_breaking_things(self, installed: Path) -> None:
        cli(installed, "apikey", "create", "ci", "--type", "admin")

        result = cli(installed, "apikey", "rotate", "ci", input="n\n")
        assert "stops working" in result.output
        assert "Cancelled" in result.output

    def test_revoke_requires_confirmation(self, installed: Path) -> None:
        cli(installed, "apikey", "create", "ci", "--type", "admin")

        result = cli(installed, "apikey", "revoke", "ci", input="n\n")
        assert "Cancelled" in result.output

    def test_unknown_key_suggests_list(self, installed: Path) -> None:
        result = cli(installed, "apikey", "revoke", "nope", "--yes")
        assert result.exit_code == 1
        assert "lightr apikey list" in result.output

    def test_a_scoped_key_requires_its_scope(self, installed: Path) -> None:
        result = cli(installed, "apikey", "create", "bad", "--type", "domain")
        assert result.exit_code == 1
        assert "domain" in result.output


class TestQueue:
    def test_empty_queue_reports_nothing(self, installed: Path) -> None:
        result = cli(installed, "queue", "list", "--format", "json")
        assert result.exit_code == 0
        assert json.loads(result.stdout) == []

    def test_stats_on_an_empty_queue(self, installed: Path) -> None:
        result = cli(installed, "queue", "stats", "--format", "json")
        assert result.exit_code == 0

    def test_a_bad_queue_id_is_rejected(self, installed: Path) -> None:
        result = cli(installed, "queue", "get", "not-a-uuid")
        assert result.exit_code != 0

    def test_purge_confirms_first(self, installed: Path) -> None:
        result = cli(installed, "queue", "purge", input="n\n")
        assert "Cancelled" in result.output

    def test_retry_all_confirms_first(self, installed: Path) -> None:
        result = cli(installed, "queue", "retry", input="n\n")
        assert "Cancelled" in result.output


class TestSuppression:
    def test_a_clean_address_is_reported_clean(self, installed: Path) -> None:
        result = cli(installed, "suppression", "check", "nobody@example.test")
        assert result.exit_code == 0
        assert "not suppressed" in result.output

    def test_a_manually_suppressed_address_is_reported_suppressed(
        self, installed: Path
    ) -> None:
        """The bug this replaced: an address suppressed by hand has no
        bounce history, and the check reported it as clean -- exactly
        the wrong answer when someone asks why mail stopped."""
        cli(installed, "suppression", "add", "spam@example.test", "--reason", "manual")

        result = cli(installed, "suppression", "check", "spam@example.test")

        assert "is suppressed" in result.output
        assert "not suppressed" not in result.output

    def test_the_check_says_how_to_undo_it(self, installed: Path) -> None:
        cli(installed, "suppression", "add", "spam@example.test")

        result = cli(installed, "suppression", "check", "spam@example.test")
        assert "lightr suppression remove spam@example.test" in result.output

    def test_no_bounce_history_is_stated_rather_than_implied(
        self, installed: Path
    ) -> None:
        cli(installed, "suppression", "add", "spam@example.test")

        result = cli(installed, "suppression", "check", "spam@example.test")
        assert "No bounce history" in result.output

    def test_add_then_list(self, installed: Path) -> None:
        cli(installed, "suppression", "add", "spam@example.test", "--reason", "complaint")

        listed = json.loads(
            cli(installed, "suppression", "list", "--format", "json").stdout
        )
        assert listed[0]["email"] == "spam@example.test"
        assert listed[0]["reason"] == "complaint"

    def test_remove_allows_it_again(self, installed: Path) -> None:
        cli(installed, "suppression", "add", "spam@example.test")
        cli(installed, "suppression", "remove", "spam@example.test")

        result = cli(installed, "suppression", "check", "spam@example.test")
        assert "not suppressed" in result.output

    def test_removing_something_absent_says_so(self, installed: Path) -> None:
        result = cli(installed, "suppression", "remove", "never@seen.test")
        assert "was not suppressed" in result.output

    def test_addresses_are_matched_case_insensitively(self, installed: Path) -> None:
        cli(installed, "suppression", "add", "Spam@Example.Test")

        result = cli(installed, "suppression", "check", "spam@example.test")
        assert "is suppressed" in result.output
