"""The `lightr auth` group.

The command worth its weight is `auth test`: "login failed" is useless
to whoever has to fix it, and what they need is which provider was
asked and what it said.
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
    assert cli(
        installed, "account", "create", "ops@acme.test", "--no-password"
    ).exit_code == 0
    assert cli(
        installed, "account", "passwd", "ops@acme.test", "--stdin",
        input="correct horse battery\n",
    ).exit_code == 0
    return installed


@pytest.fixture
def with_provider(populated: Path) -> Path:
    result = cli(
        populated, "auth", "add", "webhook", "corp",
        "--domain", "acme.test",
        "--set", "url=https://idp.example.test/auth",
        "--set", "secret=shared",
    )
    assert result.exit_code == 0, result.output
    return populated


class TestAdd:
    def test_a_provider_is_added(self, with_provider: Path) -> None:
        listed = json.loads(
            cli(with_provider, "auth", "list", "--format", "json").stdout
        )
        assert listed[0]["name"] == "corp"
        assert listed[0]["kind"] == "webhook"

    def test_a_kind_lightr_does_not_implement_is_refused(self, populated: Path) -> None:
        """RADIUS is in the schema's comment and is not built. Accepting
        the row and ignoring it would be worse."""
        result = cli(
            populated, "auth", "add", "radius", "rad", "--set", "host=1.2.3.4"
        )

        assert result.exit_code == 1
        assert "radius" in result.output
        assert "ldap" in result.output  # says what it does support

    def test_a_typod_domain_fails_here_not_at_login(self, populated: Path) -> None:
        result = cli(
            populated, "auth", "add", "webhook", "corp",
            "--domain", "acme.tset",
            "--set", "url=https://idp.example.test/auth",
        )

        assert result.exit_code == 1
        assert "acme.tset" in result.output

    def test_a_provider_covering_nothing_says_so(self, populated: Path) -> None:
        result = cli(
            populated, "auth", "add", "webhook", "orphan",
            "--set", "url=https://idp.example.test/auth",
        )

        assert result.exit_code == 0
        assert "answers for nothing" in result.output

    def test_set_coerces_obvious_types(self, with_provider: Path) -> None:
        cli(with_provider, "auth", "update", "corp", "--set", "timeout=3")
        cli(with_provider, "auth", "update", "corp", "--set", "start_tls=true")

        shown = json.loads(
            cli(with_provider, "auth", "get", "corp", "--format", "json").stdout
        )
        assert shown["config"]["timeout"] == 3
        assert shown["config"]["start_tls"] is True

    def test_a_config_file_is_accepted(self, populated: Path, tmp_path: Path) -> None:
        """An LDAP config is a dozen fields; nobody wants a dozen flags."""
        config = tmp_path / "ldap.json"
        config.write_text(
            json.dumps({"uri": "ldaps://dc.corp", "base_dn": "ou=people,dc=corp"}),
            encoding="utf-8",
        )

        result = cli(
            populated, "auth", "add", "ldap", "corp",
            "--domain", "acme.test", "--config-file", str(config),
        )

        assert result.exit_code == 0, result.output
        shown = json.loads(
            cli(populated, "auth", "get", "corp", "--format", "json").stdout
        )
        assert shown["config"]["base_dn"] == "ou=people,dc=corp"

    def test_a_malformed_set_is_an_error_not_a_traceback(
        self, populated: Path
    ) -> None:
        result = cli(
            populated, "auth", "add", "webhook", "corp", "--set", "nonsense"
        )

        assert result.exit_code == 1
        assert "key=value" in result.output


class TestSecrets:
    def test_a_shared_secret_is_masked(self, with_provider: Path) -> None:
        shown = json.loads(
            cli(with_provider, "auth", "get", "corp", "--format", "json").stdout
        )
        assert shown["config"]["secret"] == "(set)"

    def test_the_rest_of_the_config_stays_readable(
        self, with_provider: Path
    ) -> None:
        """Masking the whole blob would make `auth get` useless for the
        one job it has."""
        shown = json.loads(
            cli(with_provider, "auth", "get", "corp", "--format", "json").stdout
        )
        assert shown["config"]["url"] == "https://idp.example.test/auth"


class TestSwitchingAnAccount:
    def test_enable_makes_it_external(self, with_provider: Path) -> None:
        result = cli(with_provider, "auth", "enable", "ops@acme.test", "--yes")

        assert result.exit_code == 0
        shown = json.loads(
            cli(with_provider, "account", "get", "ops@acme.test", "--format", "json").stdout
        )
        assert shown["auth_mode"] == "external"

    def test_it_warns_that_the_local_password_stops_working(
        self, with_provider: Path
    ) -> None:
        result = cli(with_provider, "auth", "enable", "ops@acme.test", input="n\n")

        assert "no longer work" in result.output
        assert "Cancelled" in result.output

    def test_the_local_hash_is_cleared(self, with_provider: Path) -> None:
        """Leaving it is how a revoked account keeps working after
        someone switches back."""
        cli(with_provider, "auth", "enable", "ops@acme.test", "--yes")

        shown = json.loads(
            cli(with_provider, "account", "get", "ops@acme.test", "--format", "json").stdout
        )
        assert not shown.get("password_hash")

    def test_switching_back_says_there_is_no_password(
        self, with_provider: Path
    ) -> None:
        cli(with_provider, "auth", "enable", "ops@acme.test", "--yes")
        result = cli(with_provider, "auth", "local", "ops@acme.test")

        assert result.exit_code == 0
        assert "account passwd" in result.output


class TestTest:
    def test_a_local_password_reports_how_it_got_in(self, populated: Path) -> None:
        result = cli(
            populated, "auth", "test", "ops@acme.test", "--stdin",
            input="correct horse battery\n",
        )

        assert result.exit_code == 0, result.output
        assert "the local password" in result.output

    def test_a_wrong_password_exits_non_zero(self, populated: Path) -> None:
        result = cli(
            populated, "auth", "test", "ops@acme.test", "--stdin", input="wrong\n"
        )

        assert result.exit_code == 1
        assert "bad_password" in result.output

    def test_an_external_account_with_no_provider_names_the_problem(
        self, populated: Path
    ) -> None:
        cli(populated, "auth", "enable", "ops@acme.test", "--yes")

        result = cli(
            populated, "auth", "test", "ops@acme.test", "--stdin", input="anything\n"
        )

        assert result.exit_code == 1
        # Rich wraps to the terminal width, so match on the phrase
        # rather than the line.
        assert "no provider covers" in result.output

    def test_a_provider_problem_is_called_one(self, populated: Path) -> None:
        """So nobody spends the outage resetting passwords."""
        cli(populated, "auth", "enable", "ops@acme.test", "--yes")

        result = cli(
            populated, "auth", "test", "ops@acme.test", "--stdin", input="anything\n"
        )

        assert "not a wrong password" in result.output


class TestDelete:
    def test_it_asks_first(self, with_provider: Path) -> None:
        result = cli(with_provider, "auth", "delete", "corp", input="n\n")

        assert "Cancelled" in result.output
        assert json.loads(
            cli(with_provider, "auth", "list", "--format", "json").stdout
        )

    def test_yes_removes_it(self, with_provider: Path) -> None:
        assert cli(with_provider, "auth", "delete", "corp", "--yes").exit_code == 0
        assert cli(with_provider, "auth", "list", "--format", "json").stdout.strip() in (
            "[]",
            "",
        )

    def test_it_warns_about_accounts_left_stranded(
        self, with_provider: Path
    ) -> None:
        cli(with_provider, "auth", "enable", "ops@acme.test", "--yes")

        result = cli(with_provider, "auth", "delete", "corp", input="n\n")

        assert "authenticate externally" in result.output
