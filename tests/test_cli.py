"""CLI behaviour.

Covers the three gaps the Go CLI had: no mailbox commands, no password
reset, and inconsistent output. Plus the error messages, which used to
be raw SQL.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lightr.cli import imap_client
from lightr.cli.main import app
from lightr.config import Config
from lightr.db import migrate

runner = CliRunner()


@pytest.fixture
def installed(tmp_path: Path) -> Path:
    """A config file backed by an initialised database."""
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


class TestOutputFormats:
    """--format is uniform across every group."""

    @pytest.mark.parametrize("group", ["org", "domain", "account", "alias"])
    def test_every_list_accepts_format(self, populated: Path, group: str) -> None:
        for fmt in ("table", "json", "yaml"):
            result = cli(populated, group, "list", "--format", fmt)
            assert result.exit_code == 0, result.output

    def test_json_is_parseable(self, populated: Path) -> None:
        result = cli(populated, "account", "list", "--format", "json")
        assert json.loads(result.stdout)[0]["email"] == "ops@acme.test"

    def test_table_shows_the_email(self, populated: Path) -> None:
        """The address is the identifier a human uses -- not the UUID."""
        result = cli(populated, "account", "list", "--format", "table")
        assert "ops@acme.test" in result.stdout

    def test_quota_is_human_readable_in_tables(self, installed: Path) -> None:
        cli(installed, "domain", "create", "acme.test")
        cli(installed, "account", "create", "big@acme.test", "--no-password", "--quota", "2GB")

        result = cli(installed, "account", "list", "--format", "table")
        assert "2.0 GB" in result.stdout


class TestReferenceResolution:
    """No command should ever require a UUID."""

    def test_account_by_email(self, populated: Path) -> None:
        assert cli(populated, "account", "get", "ops@acme.test").exit_code == 0

    def test_account_by_bare_local_part(self, populated: Path) -> None:
        assert cli(populated, "account", "get", "ops").exit_code == 0

    def test_domain_by_an_email_address(self, populated: Path) -> None:
        assert cli(populated, "domain", "get", "ops@acme.test").exit_code == 0

    def test_account_by_uuid_still_works(self, populated: Path) -> None:
        listing = json.loads(cli(populated, "account", "list", "--format", "json").stdout)
        assert cli(populated, "account", "get", listing[0]["id"]).exit_code == 0


class TestPasswords:
    """Passwords never come from argv."""

    def test_password_is_not_a_flag_on_passwd(self, populated: Path) -> None:
        result = cli(populated, "account", "passwd", "ops", "--password", "hunter22")
        assert result.exit_code != 0
        assert "no such option" in result.output.lower()

    def test_password_is_not_a_flag_on_create(self, populated: Path) -> None:
        result = cli(
            populated, "account", "create", "new@acme.test", "--password", "hunter22"
        )
        assert result.exit_code != 0

    def test_stdin(self, populated: Path) -> None:
        result = cli(populated, "account", "passwd", "ops", "--stdin",
                     input="correct-horse-battery\n")
        assert result.exit_code == 0, result.output
        assert "Password updated" in result.output

    def test_generate_prints_the_password_once(self, populated: Path) -> None:
        result = cli(populated, "account", "passwd", "ops", "--generate")
        assert result.exit_code == 0
        assert "shown once" in result.output

    def test_prompt_confirms_and_hides_input(self, populated: Path) -> None:
        result = cli(
            populated, "account", "passwd", "ops",
            input="correct-horse-battery\ncorrect-horse-battery\n",
        )
        assert result.exit_code == 0, result.output

    def test_mismatched_confirmation_fails(self, populated: Path) -> None:
        result = cli(populated, "account", "passwd", "ops", input="aaaaaaaa\nbbbbbbbb\n")
        assert result.exit_code != 0

    def test_short_password_gives_one_clean_line(self, populated: Path) -> None:
        result = cli(populated, "account", "passwd", "ops", "--stdin", input="short\n")
        assert result.exit_code == 1
        assert "at least 8 characters" in result.output
        assert "Traceback" not in result.output

    def test_stdin_and_generate_conflict(self, populated: Path) -> None:
        result = cli(populated, "account", "passwd", "ops", "--stdin", "--generate")
        assert result.exit_code != 0

    def test_hash_is_never_printed(self, populated: Path) -> None:
        cli(populated, "account", "passwd", "ops", "--stdin", input="correct-horse\n")

        result = cli(populated, "account", "get", "ops", "--format", "json")
        assert "$2b$" not in result.stdout
        assert json.loads(result.stdout)["password_hash"] == "(set)"


class TestErrorMessages:
    """Errors name the next command, rather than leaking SQL."""

    def test_unknown_account_suggests_list(self, populated: Path) -> None:
        result = cli(populated, "account", "get", "nobody@acme.test")
        assert result.exit_code == 1
        assert "lightr account list" in result.output

    def test_unknown_domain_suggests_list(self, populated: Path) -> None:
        result = cli(populated, "domain", "get", "nosuch.test")
        assert "lightr domain list" in result.output

    def test_uninitialised_database_suggests_migrate(self, tmp_path: Path) -> None:
        cfg = Config.model_validate({"data_dir": str(tmp_path)})
        path = tmp_path / "config.yaml"
        cfg.save(path)  # config, but no migrations run

        result = cli(path, "account", "list")
        assert result.exit_code == 1
        assert "lightr migrate" in result.output

    def test_domain_with_accounts_refuses_and_explains(self, populated: Path) -> None:
        result = cli(populated, "domain", "delete", "acme.test", "--yes")
        assert result.exit_code == 1
        assert "still has 1 account" in result.output
        assert "lightr account list --domain acme.test" in result.output

    def test_create_account_without_a_domain_part(self, populated: Path) -> None:
        result = cli(populated, "account", "create", "just-a-name", "--no-password")
        assert result.exit_code != 0
        assert "ops@acme.test" in result.output  # the example in the message


class TestConfirmation:
    def test_delete_prompts_by_default(self, populated: Path) -> None:
        result = cli(populated, "account", "delete", "ops@acme.test", input="n\n")
        assert "Cancelled" in result.output
        assert cli(populated, "account", "get", "ops").exit_code == 0

    def test_yes_skips_the_prompt(self, populated: Path) -> None:
        result = cli(populated, "account", "delete", "ops@acme.test", "--yes")
        assert result.exit_code == 0
        assert cli(populated, "account", "get", "ops").exit_code == 1

    def test_prompt_names_what_will_be_destroyed(self, populated: Path) -> None:
        result = cli(populated, "account", "delete", "ops@acme.test", input="n\n")
        assert "ops@acme.test" in result.output


class TestMailboxGroup:
    """The group that did not exist in the Go CLI."""

    @pytest.fixture(autouse=True)
    def fake_dovecot(self) -> Iterator[None]:
        from tests.test_mailbox import FakeIMAP

        imap_client.set_client_factory(lambda cfg, email: FakeIMAP())
        yield
        imap_client.set_client_factory(None)

    def test_folders(self, populated: Path) -> None:
        result = cli(populated, "mailbox", "folders", "ops@acme.test", "--format", "json")
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)[0]["name"] == "INBOX"

    def test_list_messages(self, populated: Path) -> None:
        result = cli(populated, "mailbox", "list", "ops@acme.test", "--format", "json")
        assert result.exit_code == 0, result.output
        assert [m["uid"] for m in json.loads(result.stdout)] == [3, 2, 1]

    def test_unread_filter(self, populated: Path) -> None:
        result = cli(
            populated, "mailbox", "list", "ops@acme.test", "--unread", "--format", "json"
        )
        assert [m["uid"] for m in json.loads(result.stdout)] == [3, 2]

    def test_read_a_message(self, populated: Path) -> None:
        result = cli(populated, "mailbox", "read", "ops@acme.test", "1")
        assert result.exit_code == 0, result.output
        assert "Plain body." in result.output

    def test_read_headers_only(self, populated: Path) -> None:
        result = cli(populated, "mailbox", "read", "ops@acme.test", "1", "--headers")
        assert "Plain body." not in result.output

    def test_read_raw_source(self, populated: Path) -> None:
        result = cli(populated, "mailbox", "read", "ops@acme.test", "1", "--raw")
        assert "Subject: First" in result.output

    def test_attachments_are_listed(self, populated: Path) -> None:
        result = cli(
            populated, "mailbox", "attachments", "ops@acme.test", "3", "--format", "json"
        )
        assert json.loads(result.stdout)[0]["filename"] == "invoice.pdf"

    def test_download_an_attachment(self, populated: Path, tmp_path: Path) -> None:
        target = tmp_path / "saved.pdf"
        listing = json.loads(
            cli(populated, "mailbox", "attachments", "ops@acme.test", "3",
                "--format", "json").stdout
        )
        result = cli(
            populated, "mailbox", "download", "ops@acme.test", "3",
            "--attachment", str(listing[0]["index"]), "--out", str(target),
        )
        assert result.exit_code == 0, result.output
        assert target.read_bytes().startswith(b"%PDF")

    def test_search_by_sender(self, populated: Path) -> None:
        result = cli(
            populated, "mailbox", "search", "ops@acme.test",
            "--from", "sender@example.test", "--format", "json",
        )
        assert result.exit_code == 0, result.output

    def test_search_rejects_a_bad_date(self, populated: Path) -> None:
        result = cli(
            populated, "mailbox", "search", "ops@acme.test", "--since", "last tuesday"
        )
        assert result.exit_code == 1
        assert "YYYY-MM-DD" in result.output

    def test_mark_requires_a_flag(self, populated: Path) -> None:
        result = cli(populated, "mailbox", "mark", "ops@acme.test", "1")
        assert result.exit_code != 0

    def test_delete_moves_to_trash_without_prompting(self, populated: Path) -> None:
        result = cli(populated, "mailbox", "delete", "ops@acme.test", "1")
        assert result.exit_code == 0, result.output
        assert "moved to Trash" in result.output

    def test_purge_requires_confirmation(self, populated: Path) -> None:
        result = cli(populated, "mailbox", "delete", "ops@acme.test", "1", "--purge",
                     input="n\n")
        assert "Cancelled" in result.output

    def test_mailbox_takes_the_same_references(self, populated: Path) -> None:
        """A bare local part works here too, not just an address."""
        assert cli(populated, "mailbox", "folders", "ops").exit_code == 0


class TestTopLevel:
    def test_version(self, installed: Path) -> None:
        from lightr import __version__

        result = cli(installed, "--version")
        assert __version__ in result.stdout

    def test_status_reports_revision_and_counts(self, populated: Path) -> None:
        result = cli(populated, "status", "--format", "json")
        report = json.loads(result.stdout)
        assert report["database"]["up_to_date"] is True
        assert report["counts"]["accounts"] == 1

    def test_status_warns_about_the_missing_master_user(self, populated: Path) -> None:
        result = cli(populated, "status")
        assert "master user" in result.output

    def test_migrate_is_idempotent(self, populated: Path) -> None:
        result = cli(populated, "migrate")
        assert result.exit_code == 0
        assert "Nothing to do" in result.output

    def test_init_refuses_to_clobber(self, installed: Path) -> None:
        result = cli(installed, "init")
        assert result.exit_code == 1
        assert "--force" in result.output
