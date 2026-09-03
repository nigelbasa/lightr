"""Creating an API key by being asked.

Handing someone a key is the operator task most likely to be done by
somebody who has never read the help text, and the thing they get
wrong is the scope: a key meant for one domain created against the
whole organization looks identical until it is used somewhere it
should not reach.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from lightr.cli.main import app
from lightr.config import Config
from lightr.db import migrate

runner = CliRunner()


@pytest.fixture
def tenanted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cfg = Config.model_validate({"data_dir": str(tmp_path)})
    path = tmp_path / "config.yaml"
    cfg.save(path)
    migrate.upgrade(cfg)

    assert cli(path, "domain", "create", "acme.test").exit_code == 0
    assert cli(path, "domain", "create", "other.test").exit_code == 0
    assert (
        cli(path, "account", "create", "ops@acme.test", "--no-password").exit_code == 0
    )

    # The wizard only runs on a terminal; the runner is a pipe.
    monkeypatch.setattr("lightr.cli.operations.interactive", lambda: True)
    return path


def cli(config: Path, *args: str, input: str | None = None):  # noqa: A002
    return runner.invoke(app, ["--config", str(config), *args], input=input)


class TestItAsks:
    def test_a_domain_scoped_key_can_be_made_without_flags(
        self, tenanted: Path
    ) -> None:
        # scope 2 (domain), the second domain, default name, no expiry
        result = cli(tenanted, "apikey", "create", input="2\n2\n\nn\n")

        assert result.exit_code == 0, result.output
        assert "other.test" in result.output

    def test_the_scope_it_offers_is_the_scope_it_creates(
        self, tenanted: Path
    ) -> None:
        """The failure this guards is a key that says "domain" in the
        prompt and is stored against the organization."""
        result = cli(tenanted, "apikey", "create", input="3\n1\n\nn\n")

        assert result.exit_code == 0, result.output
        listed = cli(tenanted, "apikey", "list", "--format", "json")
        import json

        keys = json.loads(listed.stdout)
        assert [k["type"] for k in keys] == ["account"]

    def test_it_explains_the_scopes_rather_than_naming_the_enum(
        self, tenanted: Path
    ) -> None:
        result = cli(tenanted, "apikey", "create", input="2\n1\n\nn\n")

        assert "one domain" in result.output
        assert "every domain and mailbox it owns" in result.output

    def test_it_warns_before_an_admin_key(self, tenanted: Path) -> None:
        """It reaches every tenant on the server."""
        result = cli(tenanted, "apikey", "create", input="4\n\nn\n")

        assert result.exit_code == 0, result.output
        assert "every tenant" in result.output

    def test_an_expiry_can_be_chosen(self, tenanted: Path) -> None:
        result = cli(tenanted, "apikey", "create", input="2\n1\n\ny\n30\n")

        assert result.exit_code == 0, result.output

    def test_the_secret_is_shown_once(self, tenanted: Path) -> None:
        result = cli(tenanted, "apikey", "create", input="2\n1\n\nn\n")

        assert "lk" in result.output


class TestItDoesNotAskWhenItShouldNot:
    def test_flags_still_work_unprompted(self, tenanted: Path) -> None:
        result = cli(
            tenanted, "apikey", "create", "ci", "--type", "domain",
            "--domain", "acme.test",
        )

        assert result.exit_code == 0, result.output
        assert "acme.test" in result.output

    def test_a_pipe_with_no_name_fails_instead_of_hanging(
        self, tenanted: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A script that omits the name must get an error, not a
        prompt it will never answer."""
        monkeypatch.setattr("lightr.cli.operations.interactive", lambda: False)

        result = cli(tenanted, "apikey", "create")

        assert result.exit_code == 1
        assert "Pass one" in result.output
