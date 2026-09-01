"""Backup and restore.

The test that matters is the round trip: take a backup, empty the
database, restore, and check that the things an operator would need
back are actually back -- an account resolvable by address, and a
domain's DKIM private key intact. A file that was written is not
evidence of a backup that works.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr import backup
from lightr.auth import hash_password
from lightr.models import Account, Alias, Domain, Organization
from lightr.repo import AccountRepo, AliasRepo, DomainRepo, OrganizationRepo


async def _seed(engine: AsyncEngine) -> dict[str, object]:
    """An install with something worth losing in it."""
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme Ltd"))
        domain = await DomainRepo(conn).create(
            Domain(
                org_id=org.id,
                name="acme.test",
                dkim_private_key="-----BEGIN PRIVATE KEY-----\nsecret\n",
                dkim_selector="default",
                relay_password="relay-secret",
            )
        )
        account = await AccountRepo(conn).create(
            Account(
                domain_id=domain.id,
                local_part="ops",
                display_name="Operations",
                password_hash=hash_password("correct horse battery", rounds=4),
            )
        )
        await AliasRepo(conn).create(
            Alias(domain_id=domain.id, source="sales", destinations=["ops@acme.test"])
        )
    return {"org": org, "domain": domain, "account": account}


@pytest.fixture
async def seeded(engine: AsyncEngine) -> dict[str, object]:
    return await _seed(engine)


@pytest.fixture
async def archive(engine: AsyncEngine, seeded: dict, tmp_path: Path) -> Path:
    async with engine.begin() as conn:
        report = await backup.create(
            conn, tmp_path / "backup.tar.gz", revision="0003"
        )
    return report.path


class TestRoundTrip:
    async def test_everything_comes_back(
        self, engine: AsyncEngine, archive: Path
    ) -> None:
        """The only test that proves the feature works at all."""
        async with engine.begin() as conn:
            await backup.load_database(conn, {}, wipe=True)
            assert sum((await backup.count_rows(conn)).values()) == 0

            await backup.restore(conn, archive, current_revision="0003", wipe=True)

            account = await AccountRepo(conn).resolve("ops@acme.test")
            domain = await DomainRepo(conn).resolve("acme.test")

        assert account.display_name == "Operations"
        assert account.email == "ops@acme.test"
        assert domain.dkim_private_key is not None
        assert "BEGIN PRIVATE KEY" in domain.dkim_private_key

    async def test_secrets_are_not_redacted(
        self, engine: AsyncEngine, archive: Path
    ) -> None:
        """A backup that masked credentials would restore an install
        where nobody can log in and no domain can sign."""
        data = backup.read_database(archive)

        domain = data["domains"][0]
        account = data["accounts"][0]

        assert "BEGIN PRIVATE KEY" in domain["dkim_private_key"]
        assert domain["relay_password"] == "relay-secret"
        assert account["password_hash"].startswith("$2")

    async def test_a_password_still_works_after_a_restore(
        self, engine: AsyncEngine, archive: Path
    ) -> None:
        from lightr.auth import Authenticator

        async with engine.begin() as conn:
            await backup.restore(conn, archive, current_revision="0003", wipe=True)
            result = await Authenticator(conn).authenticate(
                "ops@acme.test", "correct horse battery"
            )

        assert result.ok

    async def test_timestamps_survive_the_trip(
        self, engine: AsyncEngine, seeded: dict, archive: Path
    ) -> None:
        """Naive UTC in, naive UTC out.

        Stamping a timezone on the way through would come back as a
        tz-aware value that Postgres refuses to store in a naive
        column, and SQLite would silently accept.
        """
        original = seeded["account"]

        async with engine.begin() as conn:
            await backup.restore(conn, archive, current_revision="0003", wipe=True)
            restored = await AccountRepo(conn).resolve("ops@acme.test")

        assert restored.created_at == original.created_at
        assert restored.created_at.tzinfo is None


class TestManifest:
    async def test_records_the_schema_revision(self, archive: Path) -> None:
        assert backup.read_manifest(archive).revision == "0003"

    async def test_counts_the_rows(self, archive: Path) -> None:
        manifest = backup.read_manifest(archive)
        assert manifest.tables["accounts"] == 1
        assert manifest.tables["domains"] == 1
        assert manifest.rows >= 4

    async def test_a_restore_across_revisions_is_refused(self, archive: Path) -> None:
        """A 0003 dump half-loading into a 0002 database is the failure
        that costs someone their evening."""
        with pytest.raises(backup.BackupError, match="0003"):
            backup.check_revision(backup.read_manifest(archive), "0002")

    async def test_the_refusal_names_the_way_out(self, archive: Path) -> None:
        with pytest.raises(backup.BackupError, match="lightr migrate"):
            backup.check_revision(backup.read_manifest(archive), "0002")

    async def test_a_newer_format_is_refused_rather_than_guessed(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "future.tar.gz"
        manifest = backup.Manifest(
            format=backup.FORMAT_VERSION + 1,
            lightr_version="99.0",
            revision="0009",
            created_at="",
            tables={},
        )
        backup.write_archive(path, manifest, {})

        with pytest.raises(backup.BackupError, match="Upgrade Lightr"):
            backup.read_manifest(path)

    async def test_a_random_tarball_is_not_a_backup(self, tmp_path: Path) -> None:
        path = tmp_path / "random.tar.gz"
        (tmp_path / "file.txt").write_text("hello", encoding="utf-8")
        with tarfile.open(path, "w:gz") as archive:
            archive.add(tmp_path / "file.txt", arcname="file.txt")

        with pytest.raises(backup.BackupError, match="not a Lightr backup"):
            backup.read_manifest(path)


class TestTheFileItself:
    async def test_it_is_owner_only(self, archive: Path) -> None:
        """It holds password hashes and private keys."""
        import os

        if os.name == "nt":  # pragma: no cover - POSIX only
            pytest.skip("POSIX permissions")
        assert archive.stat().st_mode & 0o077 == 0

    async def test_a_failed_write_leaves_no_partial_file(
        self, engine: AsyncEngine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "backup.tar.gz"

        def boom(*args: object, **kwargs: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr("pathlib.Path.replace", boom)

        with pytest.raises(OSError, match="disk full"):
            backup.write_archive(target, _empty_manifest(), {})

        assert not target.exists()
        assert list(tmp_path.glob(".lightr-backup-*")) == []


class TestUnknownColumns:
    async def test_a_newer_backup_is_refused_not_silently_truncated(
        self, engine: AsyncEngine, tmp_path: Path
    ) -> None:
        """Dropping a column we do not recognise would lose data
        without saying so."""
        path = tmp_path / "newer.tar.gz"
        backup.write_archive(
            path,
            _empty_manifest(),
            {"organizations": [{"id": "x", "name": "n", "created_at": None,
                                "future_column": "value"}]},
        )

        async with engine.begin() as conn:
            with pytest.raises(backup.BackupError, match="future_column"):
                await backup.restore(
                    conn, path, current_revision=None, wipe=True
                )


class TestMail:
    @pytest.fixture
    def maildir(self, tmp_path: Path) -> Path:
        root = tmp_path / "mail" / "acme.test" / "ops"
        (root / "cur").mkdir(parents=True)
        (root / "new").mkdir()
        # No ":2,S" flag suffix: a colon is an ordinary Maildir filename
        # character on Linux and an alternate-data-stream marker on
        # Windows, and this assertion is about the archive, not NTFS.
        (root / "cur" / "1234.M1.host").write_bytes(b"Subject: hi\n\nbody\n")
        return root

    async def test_mail_round_trips(
        self, engine: AsyncEngine, seeded: dict, tmp_path: Path, maildir: Path
    ) -> None:
        path = tmp_path / "with-mail.tar.gz"
        async with engine.begin() as conn:
            await backup.create(
                conn, path, revision="0003", maildirs={"ops@acme.test": maildir}
            )

        assert backup.read_manifest(path).mail_accounts == ["ops@acme.test"]

        destination = tmp_path / "restored"
        written = backup.extract_mail(path, {"ops@acme.test": destination})

        assert written == {"ops@acme.test": 1}
        assert (destination / "cur" / "1234.M1.host").read_bytes() == b"Subject: hi\n\nbody\n"

    async def test_mail_goes_back_where_the_account_says_it_lives(
        self, engine: AsyncEngine, seeded: dict, tmp_path: Path, maildir: Path
    ) -> None:
        """An account whose mail was moved has maildir_path pointing at
        where it actually went. A backup reads from there, so a restore
        has to write back to the same place -- otherwise a recovery
        quietly puts every mailbox somewhere Dovecot is not looking.
        """
        moved = tmp_path / "elsewhere" / "ops"
        async with engine.begin() as conn:
            account = await AccountRepo(conn).resolve("ops@acme.test")
            account.maildir_path = str(moved)
            await AccountRepo(conn).update(account)

        path = tmp_path / "moved.tar.gz"
        async with engine.begin() as conn:
            await backup.create(
                conn, path, revision="0003", maildirs={"ops@acme.test": maildir}
            )

        async with engine.begin() as conn:
            report = await backup.restore(
                conn,
                path,
                current_revision="0003",
                wipe=True,
                maildir_root=tmp_path / "default-root",
            )

        assert report.mail == {"ops@acme.test": 1}
        assert (moved / "cur" / "1234.M1.host").is_file()
        assert not (tmp_path / "default-root").exists()

    async def test_mail_falls_back_to_the_computed_layout(
        self, engine: AsyncEngine, seeded: dict, tmp_path: Path, maildir: Path
    ) -> None:
        """An account with no maildir_path set goes where the layout
        says, which is what a fresh install looks like."""
        path = tmp_path / "plain.tar.gz"
        async with engine.begin() as conn:
            await backup.create(
                conn, path, revision="0003", maildirs={"ops@acme.test": maildir}
            )

        root = tmp_path / "restored-root"
        async with engine.begin() as conn:
            report = await backup.restore(
                conn, path, current_revision="0003", wipe=True, maildir_root=root
            )

        assert report.mail == {"ops@acme.test": 1}
        assert (root / "acme.test" / "ops" / "cur" / "1234.M1.host").is_file()

    async def test_mail_is_left_out_unless_asked_for(
        self, archive: Path
    ) -> None:
        """The database is kilobytes and the mail is gigabytes."""
        assert backup.read_manifest(archive).includes_mail is False

    async def test_an_archive_naming_a_path_outside_the_target_is_refused(
        self, tmp_path: Path
    ) -> None:
        """Extracting a tar member blindly writes wherever it says."""
        path = tmp_path / "evil.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("mail/ops@acme.test/../../escaped")
            info.size = 0
            archive.addfile(info)

        with pytest.raises(backup.BackupError, match="unsafe path"):
            backup.extract_mail(path, {"ops@acme.test": tmp_path / "out"})

    async def test_a_symlink_member_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "link.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("mail/ops@acme.test/passwd")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)

        with pytest.raises(backup.BackupError, match="link"):
            backup.extract_mail(path, {"ops@acme.test": tmp_path / "out"})

    async def test_mail_for_an_account_we_did_not_ask_for_is_ignored(
        self, engine: AsyncEngine, seeded: dict, tmp_path: Path, maildir: Path
    ) -> None:
        path = tmp_path / "with-mail.tar.gz"
        async with engine.begin() as conn:
            await backup.create(
                conn, path, revision="0003", maildirs={"ops@acme.test": maildir}
            )

        assert backup.extract_mail(path, {"other@acme.test": tmp_path / "out"}) == {}


class TestEncoding:
    def test_a_datetime_is_written_without_a_timezone(self) -> None:
        from datetime import datetime

        assert backup._encode(datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02T03:04:05"

    def test_the_dump_is_plain_json(
        self, tmp_path: Path
    ) -> None:
        """So an operator can read it, and any tool can."""
        path = tmp_path / "b.tar.gz"
        backup.write_archive(path, _empty_manifest(), {"organizations": []})

        with tarfile.open(path) as archive:
            member = archive.extractfile(backup.DATABASE_NAME)
            assert member is not None
            assert json.loads(member.read()) == {"organizations": []}


def _empty_manifest() -> backup.Manifest:
    return backup.Manifest(
        format=backup.FORMAT_VERSION,
        lightr_version="0.0.0",
        revision=None,
        created_at="",
        tables={},
    )
