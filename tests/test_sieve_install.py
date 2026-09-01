"""Installing generated Sieve scripts.

Dovecot reads these on every delivery, so the write has to be atomic:
a half-written script is a syntax error that stops mail for that
account.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from lightr.db import schema
from lightr.dovecot.maildir import MaildirError
from lightr.dovecot.sieve import SieveError
from lightr.dovecot.sieve_install import (
    SieveInstaller,
    _rule_from_row,
    script_path,
    write_script,
)
from lightr.models import Account, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo


@pytest_asyncio.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as c:
        yield c


@pytest_asyncio.fixture
async def account(conn: AsyncConnection) -> Account:
    org = await OrganizationRepo(conn).create(Organization(name="Acme"))
    domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
    created = await AccountRepo(conn).create(
        Account(domain_id=domain.id, local_part="ops")
    )
    return created.with_domain(domain)


async def _add_rule(conn: AsyncConnection, account: Account, **overrides) -> None:
    from datetime import UTC, datetime

    values = {
        "id": str(uuid4()),
        "org_id": str(uuid4()),
        "account_id": str(account.id),
        "name": "File invoices",
        "priority": 10,
        "conditions": json.dumps(
            [{"field": "subject", "operator": "contains", "value": "invoice"}]
        ),
        "match_type": "all",
        "actions": json.dumps([{"type": "file_into", "value": "Invoices"}]),
        "is_active": True,
        "stop_on_match": False,
        "created_at": datetime.now(UTC).replace(tzinfo=None),
        "updated_at": datetime.now(UTC).replace(tzinfo=None),
    }
    values.update(overrides)
    await conn.execute(insert(schema.filter_rules).values(**values))


class TestScriptPath:
    def test_layout_matches_the_dovecot_config(self, tmp_path: Path) -> None:
        """The generated dovecot.conf points at %d/%n."""
        path = script_path(tmp_path, "ops@acme.test")
        assert path == tmp_path / "acme.test" / "ops" / "active.sieve"

    def test_address_is_lowercased(self, tmp_path: Path) -> None:
        assert script_path(tmp_path, "OPS@ACME.TEST").parent.name == "ops"

    def test_non_address_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(MaildirError):
            script_path(tmp_path, "not-an-address")

    def test_traversal_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(MaildirError, match="unsafe"):
            script_path(tmp_path, "../../etc@acme.test")


class TestAtomicWrite:
    def test_creates_the_file(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "active.sieve"
        assert write_script(target, "# script\n")
        assert target.read_text(encoding="utf-8") == "# script\n"

    def test_identical_content_is_not_rewritten(self, tmp_path: Path) -> None:
        target = tmp_path / "active.sieve"
        write_script(target, "# script\n")
        assert not write_script(target, "# script\n")

    def test_changed_content_is_written(self, tmp_path: Path) -> None:
        target = tmp_path / "active.sieve"
        write_script(target, "# one\n")
        assert write_script(target, "# two\n")
        assert target.read_text(encoding="utf-8") == "# two\n"

    def test_no_temporary_files_are_left_behind(self, tmp_path: Path) -> None:
        target = tmp_path / "active.sieve"
        write_script(target, "# script\n")
        assert [p.name for p in tmp_path.iterdir()] == ["active.sieve"]

    def test_a_failed_write_leaves_the_old_script_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reason for the temp-file dance: Dovecot must never read
        a partial script."""
        target = tmp_path / "active.sieve"
        write_script(target, "# original\n")

        def boom(*args: object, **kwargs: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr("pathlib.Path.replace", boom)

        with pytest.raises(OSError, match="disk full"):
            write_script(target, "# replacement\n")

        assert target.read_text(encoding="utf-8") == "# original\n"
        assert [p.name for p in tmp_path.iterdir()] == ["active.sieve"]

    @pytest.mark.skipif(
        os.name == "nt", reason="Windows does not honour POSIX mode bits"
    )
    def test_script_is_owner_only(self, tmp_path: Path) -> None:
        target = tmp_path / "active.sieve"
        write_script(target, "# script\n")
        assert target.stat().st_mode & 0o077 == 0


class TestRuleConversion:
    def test_a_stored_row_compiles(self) -> None:
        rule = _rule_from_row(
            {
                "name": "Junk",
                "priority": 5,
                "conditions": json.dumps(
                    [{"field": "spam_score", "operator": "gt", "value": "4"}]
                ),
                "actions": json.dumps([{"type": "file_into", "value": "Junk"}]),
                "match_type": "all",
                "is_active": True,
                "stop_on_match": True,
            }
        )
        assert rule.name == "Junk"
        assert rule.stop_on_match
        assert len(rule.conditions) == 1

    def test_an_unknown_field_is_reported_by_name(self) -> None:
        with pytest.raises(SieveError, match="unsupported condition"):
            _rule_from_row(
                {
                    "name": "Bad rule",
                    "conditions": json.dumps(
                        [{"field": "moon_phase", "operator": "gt", "value": "1"}]
                    ),
                    "actions": json.dumps([{"type": "discard"}]),
                }
            )

    def test_an_unknown_action_is_reported(self) -> None:
        with pytest.raises(SieveError, match="unsupported action"):
            _rule_from_row(
                {
                    "name": "Bad action",
                    "conditions": json.dumps(
                        [{"field": "subject", "operator": "contains", "value": "x"}]
                    ),
                    "actions": json.dumps([{"type": "launch_missiles"}]),
                }
            )

    def test_malformed_json_yields_no_conditions(self) -> None:
        rule = _rule_from_row({"name": "x", "conditions": "{{{", "actions": "[]"})
        assert rule.conditions == []


class TestInstallation:
    async def test_installs_a_script(
        self, conn: AsyncConnection, account: Account, cfg
    ) -> None:
        await _add_rule(conn, account)
        installer = SieveInstaller(conn, cfg.dovecot.sieve_dir)

        result = await installer.install(account.id, "ops@acme.test")

        assert result.changed
        assert result.rules == 1
        assert 'fileinto :create "Invoices";' in result.path.read_text(encoding="utf-8")

    async def test_no_rules_still_writes_a_valid_script(
        self, conn: AsyncConnection, account: Account, cfg
    ) -> None:
        """Dovecot needs a script it can parse, even an empty one."""
        installer = SieveInstaller(conn, cfg.dovecot.sieve_dir)
        result = await installer.install(account.id, "ops@acme.test")

        assert "No active rules" in result.path.read_text(encoding="utf-8")

    async def test_inactive_rules_are_excluded(
        self, conn: AsyncConnection, account: Account, cfg
    ) -> None:
        await _add_rule(conn, account, is_active=False)
        installer = SieveInstaller(conn, cfg.dovecot.sieve_dir)

        result = await installer.install(account.id, "ops@acme.test")
        assert result.rules == 0

    async def test_rules_are_ordered_by_priority(
        self, conn: AsyncConnection, account: Account, cfg
    ) -> None:
        await _add_rule(conn, account, name="Later", priority=900)
        await _add_rule(conn, account, name="Sooner", priority=1)

        installer = SieveInstaller(conn, cfg.dovecot.sieve_dir)
        content = (await installer.install(account.id, "ops@acme.test")).path.read_text(
            encoding="utf-8"
        )

        assert content.index("# Sooner") < content.index("# Later")

    async def test_reinstalling_unchanged_rules_is_a_no_op(
        self, conn: AsyncConnection, account: Account, cfg
    ) -> None:
        await _add_rule(conn, account)
        installer = SieveInstaller(conn, cfg.dovecot.sieve_dir)

        await installer.install(account.id, "ops@acme.test")
        second = await installer.install(account.id, "ops@acme.test")

        assert not second.changed

    async def test_generation_timestamp_is_recorded(
        self, conn: AsyncConnection, account: Account, cfg
    ) -> None:
        from sqlalchemy import select

        await _add_rule(conn, account)
        await SieveInstaller(conn, cfg.dovecot.sieve_dir).install(
            account.id, "ops@acme.test"
        )

        stamp = (
            await conn.execute(select(schema.filter_rules.c.sieve_generated_at))
        ).scalar_one()
        assert stamp is not None

    async def test_install_all_covers_every_account(
        self, conn: AsyncConnection, account: Account, cfg
    ) -> None:
        domain_id = account.domain_id
        await AccountRepo(conn).create(
            Account(domain_id=domain_id, local_part="team")
        )

        results = await SieveInstaller(conn, cfg.dovecot.sieve_dir).install_all()

        assert {r.email for r in results} == {"ops@acme.test", "team@acme.test"}

    async def test_one_broken_rule_does_not_stop_the_others(
        self, conn: AsyncConnection, account: Account, cfg
    ) -> None:
        """One bad rule must not leave every other mailbox unfiltered."""
        other = await AccountRepo(conn).create(
            Account(domain_id=account.domain_id, local_part="team")
        )
        await _add_rule(
            conn,
            account,
            conditions=json.dumps([{"field": "moon_phase", "operator": "gt", "value": "1"}]),
        )
        await _add_rule(conn, other)

        results = await SieveInstaller(conn, cfg.dovecot.sieve_dir).install_all()

        assert [r.email for r in results] == ["team@acme.test"]
