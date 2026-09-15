"""Binary columns in backups.

Since migration 0005 the outbound queue stores messages whole, as
bytes. The backup format refused binary values outright, so the first
message sitting in the queue would have made every backup fail -- and
a mail server's queue is rarely empty for long.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr import backup
from lightr.mail.queue import Queue
from lightr.models import Domain, Organization
from lightr.repo import DomainRepo, OrganizationRepo

#: Not valid UTF-8, and containing a NUL -- what a real attachment is.
RAW = b"Subject: figures\r\n\r\n\x00\xff\xfe%PDF-1.4\r\n"


async def _queue_one(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        await Queue(conn).enqueue(
            org_id=org.id, domain_id=domain.id, from_addr="ops@acme.test",
            to_addrs=["someone@external.test"], subject="figures", body="",
            raw=RAW,
        )


class TestAQueuedMessageDoesNotBreakBackups:
    async def test_a_database_with_a_queued_message_dumps(
        self, engine: AsyncEngine
    ) -> None:
        await _queue_one(engine)

        async with engine.begin() as conn:
            dumped = await backup.dump_database(conn)

        # It has to survive the JSON the archive is written as.
        json.dumps(dumped, default=str)

    async def test_the_message_comes_back_byte_for_byte(
        self, engine: AsyncEngine
    ) -> None:
        await _queue_one(engine)
        async with engine.begin() as conn:
            dumped = json.loads(json.dumps(await backup.dump_database(conn), default=str))

        async with engine.begin() as conn:
            await backup.load_database(conn, dumped, wipe=True)
            (restored,) = await Queue(conn).list()

        assert restored.raw == RAW

    def test_text_that_looks_like_the_marker_is_not_decoded(self) -> None:
        """Only a value that is exactly the marker object is binary."""
        from lightr.db import schema

        row = {"id": "x", "subject": "$base64"}
        decoded = backup._decode_row(schema.email_queue, row)

        assert decoded["subject"] == "$base64"

    def test_corrupt_binary_data_is_reported_not_inserted(self) -> None:
        from lightr.db import schema

        row = {"raw": {backup.BINARY_MARKER: "not base64 at all!!"}}

        with pytest.raises(backup.BackupError, match="does not decode"):
            backup._decode_row(schema.email_queue, row)
