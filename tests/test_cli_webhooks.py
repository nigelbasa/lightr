"""The webhook CLI group."""

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
def registered(installed: Path) -> Path:
    result = cli(
        installed, "webhook", "create", "billing", "https://hooks.example.test/lightr"
    )
    assert result.exit_code == 0, result.output
    return installed


class TestCreate:
    def test_the_secret_is_printed(self, installed: Path) -> None:
        """And described honestly: unlike an API key it is stored, so
        telling an operator it is unrecoverable would have them rotate
        one they could simply have looked up."""
        result = cli(
            installed, "webhook", "create", "billing", "https://hooks.example.test/h"
        )

        assert result.exit_code == 0
        assert "Signing secret" in result.output
        assert "not recoverable" not in result.output

    def test_a_bad_url_is_an_error_not_a_traceback(self, installed: Path) -> None:
        result = cli(installed, "webhook", "create", "bad", "file:///etc/passwd")

        assert result.exit_code == 1
        assert "Traceback" not in result.output
        assert "scheme" in result.output

    def test_a_misspelt_event_names_the_valid_ones(self, installed: Path) -> None:
        result = cli(
            installed, "webhook", "create", "typo", "https://x.example.test/h",
            "--event", "mail.recieved",
        )

        assert result.exit_code == 1
        assert "mail.received" in result.output


class TestListAndGet:
    def test_listing_is_json_when_piped(self, registered: Path) -> None:
        result = cli(registered, "webhook", "list", "--format", "json")
        assert json.loads(result.stdout)[0]["name"] == "billing"

    def test_the_secret_is_not_in_a_listing(self, registered: Path) -> None:
        """Not because the CLI cannot show it -- `webhook secret` does
        -- but because a listing is the thing people paste."""
        result = cli(registered, "webhook", "list", "--format", "json")
        assert json.loads(result.stdout)[0]["secret"] == "(set)"

    def test_addressable_by_name(self, registered: Path) -> None:
        result = cli(registered, "webhook", "get", "billing", "--format", "json")
        assert json.loads(result.stdout)["url"].endswith("/lightr")

    def test_an_unknown_name_says_what_to_run(self, registered: Path) -> None:
        result = cli(registered, "webhook", "get", "nope")
        assert result.exit_code == 1
        assert "lightr webhook list" in result.output

    def test_the_events_command_lists_what_is_valid(self, installed: Path) -> None:
        result = cli(installed, "webhook", "events", "--format", "json")
        assert "mail.received" in result.stdout


class TestUpdate:
    def test_only_what_is_named_changes(self, registered: Path) -> None:
        assert cli(
            registered, "webhook", "update", "billing", "--url",
            "https://moved.example.test/h",
        ).exit_code == 0

        shown = json.loads(
            cli(registered, "webhook", "get", "billing", "--format", "json").stdout
        )
        assert shown["url"] == "https://moved.example.test/h"
        assert shown["name"] == "billing"

    def test_nothing_to_change_is_an_error(self, registered: Path) -> None:
        result = cli(registered, "webhook", "update", "billing")
        assert result.exit_code == 1
        assert "at least one option" in result.output

    def test_disabling_shows_in_the_listing(self, registered: Path) -> None:
        cli(registered, "webhook", "update", "billing", "--disable")

        listed = json.loads(
            cli(registered, "webhook", "list", "--format", "json").stdout
        )
        assert listed[0]["active"] is False

    def test_rotation_prints_a_new_secret(self, registered: Path) -> None:
        before = cli(registered, "webhook", "secret", "billing").stdout.strip()
        cli(registered, "webhook", "rotate", "billing")
        after = cli(registered, "webhook", "secret", "billing").stdout.strip()

        assert before and after and before != after


class TestDelete:
    def test_it_asks_first(self, registered: Path) -> None:
        result = cli(registered, "webhook", "delete", "billing", input="n\n")

        assert "Cancelled" in result.output
        assert json.loads(
            cli(registered, "webhook", "list", "--format", "json").stdout
        )

    def test_yes_skips_the_prompt(self, registered: Path) -> None:
        assert cli(registered, "webhook", "delete", "billing", "--yes").exit_code == 0
        assert cli(registered, "webhook", "list", "--format", "json").stdout.strip() in (
            "[]",
            "",
        )


class TestTest:
    def test_an_unreachable_receiver_exits_non_zero(self, registered: Path) -> None:
        """The point of a test fire is to find out it does not work."""
        result = cli(registered, "webhook", "test", "billing")

        assert result.exit_code == 1
        assert "did not accept the test" in result.output

    def test_the_attempt_shows_up_in_deliveries(self, registered: Path) -> None:
        cli(registered, "webhook", "test", "billing")

        result = cli(registered, "webhook", "deliveries", "billing", "--format", "json")
        assert json.loads(result.stdout)[0]["event_type"] == "ping"


@pytest.fixture(autouse=True)
def _no_real_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test fires must not leave the machine."""
    import socket

    def refuse(*args: object, **kwargs: object):
        raise socket.gaierror("blocked in tests")

    monkeypatch.setattr("lightr.webhooks.ssrf.socket.getaddrinfo", refuse)
