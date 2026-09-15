"""Who may send, as whom, and who may receive.

The bug this file is for: submission checked that *someone* had logged
in, and nothing else. Any account could send as any address on any
domain this server hosts, and Lightr DKIM-signed the result -- so the
forgery arrived at its destination looking genuine.

And the gap: an operator's only lever was `disabled`, which stops an
account logging in, sending and receiving all at once. A compromised
account needs to stop sending while its owner logs in to fix it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from email.message import EmailMessage
from pathlib import Path

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from lightr.config import Config
from lightr.dovecot.lmtp import DeliveryResult, RecipientStatus
from lightr.mail.queue import Queue
from lightr.mail.routing import RejectReason, Router
from lightr.mail.smtp import LightrHandler
from lightr.models import Account, Alias, Domain, Organization
from lightr.repo import AccountRepo, AliasRepo, DomainRepo, OrganizationRepo


class RecordingLMTP:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    async def deliver(self, sender, recipients, message):
        self.calls.append(list(recipients))
        return DeliveryResult(statuses=[RecipientStatus(r, 250, "ok") for r in recipients])


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        acme = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
        other = await DomainRepo(conn).create(Domain(org_id=org.id, name="other.test"))
        accounts = AccountRepo(conn)
        ops = await accounts.create(Account(domain_id=acme.id, local_part="ops"))
        await accounts.create(Account(domain_id=acme.id, local_part="ceo"))
        await accounts.create(Account(domain_id=other.id, local_part="billing"))
        await AliasRepo(conn).create(
            Alias(domain_id=acme.id, source="sales", destinations=["ops@acme.test"])
        )
    return {"ops": ops}


@pytest_asyncio.fixture
async def submission(
    cfg: Config, engine: AsyncEngine, world: dict
) -> AsyncIterator[LightrHandler]:
    handler = LightrHandler(cfg, engine, require_auth=True)
    handler.lmtp = RecordingLMTP()  # type: ignore[assignment]
    yield handler
    await handler.webhooks.drain()


def _raw(sender: str = "ops@acme.test") -> bytes:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "friend@external.test"
    message["Subject"] = "hello"
    message.set_content("hi")
    return message.as_bytes()


async def _send(handler: LightrHandler, *, login: str, sender: str):
    return await handler.deliver(
        mail_from=sender,
        recipients=["friend@external.test"],
        raw=_raw(sender),
        authenticated_as=login,
    )


async def _queued(engine: AsyncEngine) -> int:
    async with engine.begin() as conn:
        return len(await Queue(conn).list())


class TestNobodyCanSendAsSomeoneElse:
    async def test_an_account_sends_as_itself(
        self, submission: LightrHandler, engine: AsyncEngine
    ) -> None:
        outcome = await _send(submission, login="ops@acme.test", sender="ops@acme.test")

        assert outcome.smtp_response().startswith("250")
        assert await _queued(engine) == 1

    async def test_it_cannot_send_as_a_colleague(
        self, submission: LightrHandler, engine: AsyncEngine
    ) -> None:
        """ops@ sending as ceo@ -- same domain, and signed as genuine."""
        outcome = await _send(submission, login="ops@acme.test", sender="ceo@acme.test")

        assert outcome.smtp_response().startswith("554")
        assert await _queued(engine) == 0

    async def test_it_cannot_send_as_another_hosted_domain(
        self, submission: LightrHandler, engine: AsyncEngine
    ) -> None:
        """One tenant forging another is worse than forging a colleague."""
        outcome = await _send(
            submission, login="ops@acme.test", sender="billing@other.test"
        )

        assert outcome.smtp_response().startswith("554")
        assert await _queued(engine) == 0

    async def test_it_can_send_as_an_alias_that_delivers_to_it(
        self, submission: LightrHandler, engine: AsyncEngine
    ) -> None:
        """sales@ forwards to ops@, so ops answers sales mail. Refusing
        that would break the ordinary use of an alias."""
        outcome = await _send(submission, login="ops@acme.test", sender="sales@acme.test")

        assert outcome.smtp_response().startswith("250")

    async def test_case_does_not_matter(self, submission: LightrHandler) -> None:
        outcome = await _send(submission, login="OPS@acme.test", sender="ops@ACME.test")

        assert outcome.smtp_response().startswith("250")

    async def test_the_refusal_is_permanent(self, submission: LightrHandler) -> None:
        """A 4xx would have the client retry the forgery for days."""
        outcome = await _send(submission, login="ops@acme.test", sender="ceo@acme.test")

        assert outcome.smtp_response()[0] == "5"

    async def test_a_local_recipient_is_protected_too(
        self, submission: LightrHandler
    ) -> None:
        """Forging a colleague to a colleague is the phishing case."""
        outcome = await submission.deliver(
            mail_from="ceo@acme.test", recipients=["billing@other.test"],
            raw=_raw("ceo@acme.test"), authenticated_as="ops@acme.test",
        )

        lmtp: RecordingLMTP = submission.lmtp  # type: ignore[assignment]
        assert lmtp.calls == []
        assert outcome.smtp_response().startswith("554")


class TestTheSessionIdentityReachesTheCheck:
    async def test_handle_data_passes_who_logged_in(
        self, submission: LightrHandler, engine: AsyncEngine
    ) -> None:
        """The check is worthless if the real SMTP path does not feed
        it: deliver() used to have no way to know who had logged in."""

        class Session:
            peer = ("203.0.113.9", 40000)
            host_name = "client.example"
            ssl = object()
            authenticated = True
            auth_data = "ops@acme.test"

        class Envelope:
            def __init__(self) -> None:
                self.mail_from = "ceo@acme.test"
                self.rcpt_tos = ["friend@external.test"]
                self.content = _raw("ceo@acme.test")
                self.mail_options: list[str] = []

        reply = await submission.handle_DATA(None, Session(), Envelope())

        assert reply.startswith("554")
        assert await _queued(engine) == 0


class TestBlockingSending:
    async def test_a_blocked_account_cannot_send(
        self, submission: LightrHandler, engine: AsyncEngine, world: dict
    ) -> None:
        async with engine.begin() as conn:
            ops = await AccountRepo(conn).find("ops@acme.test")
            assert ops is not None
            ops.can_send = False
            await AccountRepo(conn).update(ops)

        outcome = await _send(submission, login="ops@acme.test", sender="ops@acme.test")

        assert outcome.smtp_response().startswith("554")
        assert "not allowed to send" in outcome.smtp_response()
        assert await _queued(engine) == 0

    async def test_it_can_still_log_in(self, engine: AsyncEngine, world: dict) -> None:
        """The point of blocking sending rather than disabling: the
        owner logs in and changes the password."""
        from lightr.auth import Authenticator, hash_password

        async with engine.begin() as conn:
            ops = await AccountRepo(conn).find("ops@acme.test")
            assert ops is not None
            ops.can_send = False
            ops.password_hash = hash_password("correct-horse", rounds=4)
            await AccountRepo(conn).update(ops)

            result = await Authenticator(conn).authenticate(
                "ops@acme.test", "correct-horse"
            )

        assert result.ok

    async def test_it_can_still_receive(self, engine: AsyncEngine, world: dict) -> None:
        async with engine.begin() as conn:
            ops = await AccountRepo(conn).find("ops@acme.test")
            assert ops is not None
            ops.can_send = False
            await AccountRepo(conn).update(ops)

            route = await Router(conn).route("ops@acme.test")

        assert not route.rejected


class TestBlockingReceiving:
    async def test_a_blocked_account_refuses_new_mail(
        self, engine: AsyncEngine, world: dict
    ) -> None:
        async with engine.begin() as conn:
            ops = await AccountRepo(conn).find("ops@acme.test")
            assert ops is not None
            ops.can_receive = False
            await AccountRepo(conn).update(ops)

            route = await Router(conn).route("ops@acme.test")

        assert route.rejected
        assert route.reason is RejectReason.RECEIVING_BLOCKED

    async def test_the_refusal_does_not_say_why(self) -> None:
        """Telling a stranger why a mailbox refuses mail tells them
        which accounts an operator has acted on."""
        assert (
            RejectReason.RECEIVING_BLOCKED.smtp_message
            == RejectReason.ACCOUNT_DISABLED.smtp_message
        )

    async def test_it_can_still_send(
        self, submission: LightrHandler, engine: AsyncEngine
    ) -> None:
        async with engine.begin() as conn:
            ops = await AccountRepo(conn).find("ops@acme.test")
            assert ops is not None
            ops.can_receive = False
            await AccountRepo(conn).update(ops)

        outcome = await _send(submission, login="ops@acme.test", sender="ops@acme.test")

        assert outcome.smtp_response().startswith("250")


class TestTheOperatorSurfaces:
    def test_the_cli_blocks_and_unblocks(self, tmp_path: Path) -> None:
        from lightr.cli.main import app
        from lightr.db import migrate

        cfg = Config.model_validate({"data_dir": str(tmp_path)})
        path = tmp_path / "config.yaml"
        cfg.save(path)
        migrate.upgrade(cfg)
        runner = CliRunner()

        def cli(*args: str):
            return runner.invoke(app, ["--config", str(path), *args])

        assert cli("domain", "create", "acme.test").exit_code == 0
        assert cli("account", "create", "ops@acme.test", "--no-password").exit_code == 0

        blocked = cli("account", "update", "ops@acme.test", "--block-send",
                      "--block-receive")
        assert blocked.exit_code == 0, blocked.output
        assert "blocked from sending" in blocked.output

        shown = cli("account", "get", "ops@acme.test", "--format", "json")
        assert '"can_send": false' in shown.stdout
        assert '"can_receive": false' in shown.stdout

        assert cli("account", "update", "ops@acme.test", "--allow-send").exit_code == 0
        shown = cli("account", "get", "ops@acme.test", "--format", "json")
        assert '"can_send": true' in shown.stdout
        assert '"can_receive": false' in shown.stdout

    async def test_the_api_blocks_sending(
        self, cfg: Config, engine: AsyncEngine, world: dict
    ) -> None:
        import httpx

        from lightr.api.app import create_app
        from lightr.apikeys import APIKeyRepo, KeyType

        async with engine.begin() as conn:
            _, secret = await APIKeyRepo(conn).create("root", key_type=KeyType.ADMIN)

        app = create_app(cfg, engine=engine)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.patch(
                f"/v1/accounts/{world['ops'].id}",
                headers={"X-API-Key": secret},
                json={"can_send": False},
            )
            assert response.status_code == 200, response.text
            assert response.json()["can_send"] is False

            refused = await client.patch(
                f"/v1/accounts/{world['ops'].id}",
                headers={"X-API-Key": secret},
                json={"password_hash": "$2b$04$attacker-chosen"},
            )
            assert refused.status_code == 400

            wrong_type = await client.patch(
                f"/v1/accounts/{world['ops'].id}",
                headers={"X-API-Key": secret},
                json={"can_send": "no"},
            )
            assert wrong_type.status_code == 400
