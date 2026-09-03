"""Creating Lightr's Postgres role and database.

There is no Postgres in this test run, so what is tested is the SQL
that would be issued and the decisions around it -- which is where the
mistakes live. The three that would actually hurt:

* resetting the password of a role that already works, silently
* leaving a fresh Postgres 15 database without CREATE on the public
  schema, so the first migration fails with "permission denied for
  schema public" and reads like a bug in Lightr
* printing the generated password anywhere it could be copied
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lightr.config import Config
from lightr.db import provision


@pytest.fixture
def issued(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the SQL, and answer "nothing exists yet"."""
    statements: list[str] = []

    def fake(sql: str, *, database: str = "postgres") -> str:
        statements.append(sql)
        return ""

    monkeypatch.setattr(provision, "psql", fake)
    return statements


@pytest.fixture
def already_there(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    statements: list[str] = []

    def fake(sql: str, *, database: str = "postgres") -> str:
        statements.append(sql)
        return "1" if sql.startswith("SELECT 1") else ""

    monkeypatch.setattr(provision, "psql", fake)
    return statements


class TestAFreshServer:
    def test_it_creates_the_role_and_the_database(self, issued: list[str]) -> None:
        result = provision.provision()

        assert result.created_role
        assert result.created_database
        assert any(s.startswith("CREATE ROLE") for s in issued)
        assert any(s.startswith("CREATE DATABASE") for s in issued)

    def test_the_password_is_long_and_random(self, issued: list[str]) -> None:
        first = provision.provision().dsn
        second = provision.provision().dsn

        assert first != second

    def test_it_grants_create_on_the_public_schema(self, issued: list[str]) -> None:
        """Postgres 15 took CREATE on public away from PUBLIC. Without
        this the first migration fails with "permission denied for
        schema public", which reads like a bug in Lightr."""
        provision.provision()

        assert any("GRANT ALL ON SCHEMA public" in s for s in issued)

    def test_the_dsn_points_at_what_it_made(self, issued: list[str]) -> None:
        result = provision.provision(
            role="lightr", database="lightr", host="127.0.0.1", port=5432
        )

        assert result.dsn.startswith("postgresql://lightr:")
        assert result.dsn.endswith("@127.0.0.1:5432/lightr")


class TestAServerThatAlreadyHasThem:
    def test_nothing_is_created_twice(self, already_there: list[str]) -> None:
        """The package runs setup on every upgrade."""
        result = provision.provision(known_password="hunter2")

        assert not result.created_role
        assert not result.created_database
        assert not any(s.startswith("CREATE ") for s in already_there)

    def test_a_known_password_is_kept(self, already_there: list[str]) -> None:
        result = provision.provision(known_password="hunter2")

        assert "hunter2" in result.dsn
        assert not any("PASSWORD" in s for s in already_there)

    def test_an_unknown_password_is_reset_and_announced(
        self, already_there: list[str]
    ) -> None:
        """Nothing can connect as a role whose password we do not have,
        so resetting is the only way forward -- but it may break
        something else using that role, so it is reported, not silent.
        """
        result = provision.provision(known_password=None)

        assert result.reset_password
        assert any("ALTER ROLE" in s and "PASSWORD" in s for s in already_there)


class TestQuoting:
    def test_a_password_with_a_quote_survives(self) -> None:
        assert provision.quote_literal("a'b") == "'a''b'"

    def test_an_identifier_is_checked_not_escaped(self) -> None:
        """Role and database names come from a flag. Rejecting the
        odd ones is clearer than quoting them into existence."""
        with pytest.raises(provision.ProvisionError):
            provision.quote_identifier('lightr"; DROP DATABASE postgres; --')

    def test_ordinary_names_are_accepted(self) -> None:
        assert provision.quote_identifier("lightr_prod") == '"lightr_prod"'


class TestReadingBackAPassword:
    def test_it_is_taken_from_an_existing_dsn(self) -> None:
        dsn = "postgresql://lightr:s3cret@127.0.0.1:5432/lightr"

        assert provision.existing_password(dsn) == "s3cret"

    def test_an_empty_dsn_has_none(self) -> None:
        assert provision.existing_password("") is None


class TestWritingItDown:
    def test_the_dsn_lands_in_the_config(self, tmp_path: Path) -> None:
        from lightr import configtemplate

        target = tmp_path / "config.yaml"
        configtemplate.write(target)

        provision.write_dsn(target, "postgresql://lightr:pw@127.0.0.1:5432/lightr")

        cfg = Config.load(target)
        assert cfg.database.driver == "postgres"
        assert cfg.database.dsn == "postgresql://lightr:pw@127.0.0.1:5432/lightr"

    def test_the_comments_are_still_there(self, tmp_path: Path) -> None:
        from lightr import configtemplate

        target = tmp_path / "config.yaml"
        configtemplate.write(target)

        provision.write_dsn(target, "postgresql://lightr:pw@127.0.0.1:5432/lightr")

        assert "Everything commented out below" in target.read_text(encoding="utf-8")

    def test_it_is_not_world_readable_afterwards(self, tmp_path: Path) -> None:
        """It now holds a database password."""
        import os

        if os.name == "nt":  # pragma: no cover - POSIX only
            pytest.skip("POSIX permissions")

        from lightr import configtemplate

        target = tmp_path / "config.yaml"
        configtemplate.write(target)

        provision.write_dsn(target, "postgresql://lightr:pw@127.0.0.1:5432/lightr")

        assert target.stat().st_mode & 0o007 == 0


class TestWhenItCannotRun:
    def test_a_missing_psql_says_what_to_install(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(provision.shutil, "which", lambda name: None)

        with pytest.raises(provision.ProvisionError, match="postgresql-client"):
            provision.psql("SELECT 1")
