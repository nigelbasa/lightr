"""Where spam goes: the domain's spam policy, applied at delivery.

Lightr marks each copy for the server-wide Sieve script, which files
"junk" into Junk. These tests look at what LMTP was actually handed.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine
from tests.test_forwarding import RecordingLMTP

from lightr.config import Config
from lightr.mail import headers as header_tools
from lightr.mail.smtp import LightrHandler
from lightr.models import Account, Domain, Organization, SpamPolicy
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo

RAW = (
    b"From: someone@example.net\r\n"
    b"Subject: Cheap watches\r\n"
    b"X-Lightr-Spam-Action: \r\n"
    b"\r\n"
    b"Buy now.\r\n"
)


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domains = DomainRepo(conn)
        accounts = AccountRepo(conn)
        for name, policy in (("junked.test", SpamPolicy.JUNK),
                             ("tagged.test", SpamPolicy.TAG),
                             ("rejecting.test", SpamPolicy.REJECT)):
            domain = await domains.create(
                Domain(org_id=org.id, name=name, spam_policy=policy)
            )
            await accounts.create(Account(domain_id=domain.id, local_part="ops"))


def _handler(cfg: Config, engine: AsyncEngine, monkeypatch, *, spam: bool) -> LightrHandler:
    handler = LightrHandler(cfg, engine)
    handler.lmtp = RecordingLMTP()  # type: ignore[assignment]

    async def analysed(message, **kwargs) -> header_tools.Analysis:
        return header_tools.Analysis(is_spam=spam, score=9.0 if spam else 0.0)

    monkeypatch.setattr(handler, "analyse", analysed)
    return handler


def _calls(handler: LightrHandler) -> list[tuple[list[str], bytes]]:
    return [(recipients, payload) for _, recipients, payload in handler.lmtp.calls]  # type: ignore[attr-defined]


async def test_spam_to_a_junk_domain_is_marked_for_junk(
    cfg: Config, engine: AsyncEngine, world: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    handler = _handler(cfg, engine, monkeypatch, spam=True)

    await handler.deliver(mail_from="someone@example.net",
                          recipients=["ops@junked.test"], raw=RAW)

    ((recipients, payload),) = _calls(handler)
    assert recipients == ["ops@junked.test"]
    assert b"X-Lightr-Spam-Action: junk" in payload
    assert b"X-Spam-Flag: YES" in payload


async def test_spam_to_a_tag_domain_stays_in_the_inbox(
    cfg: Config, engine: AsyncEngine, world: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    handler = _handler(cfg, engine, monkeypatch, spam=True)

    await handler.deliver(mail_from="someone@example.net",
                          recipients=["ops@tagged.test"], raw=RAW)

    ((_, payload),) = _calls(handler)
    assert b"X-Lightr-Spam-Action" not in payload
    assert b"X-Spam-Flag: YES" in payload


async def test_reject_files_into_junk_rather_than_refusing(
    cfg: Config, engine: AsyncEngine, world: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    handler = _handler(cfg, engine, monkeypatch, spam=True)

    outcome = await handler.deliver(mail_from="someone@example.net",
                                    recipients=["ops@rejecting.test"], raw=RAW)

    assert outcome.smtp_response().startswith("250")
    ((_, payload),) = _calls(handler)
    assert b"X-Lightr-Spam-Action: junk" in payload


async def test_two_policies_in_one_message_get_two_copies(
    cfg: Config, engine: AsyncEngine, world: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    handler = _handler(cfg, engine, monkeypatch, spam=True)

    outcome = await handler.deliver(
        mail_from="someone@example.net",
        recipients=["ops@junked.test", "ops@tagged.test"], raw=RAW,
    )

    calls = {tuple(recipients): payload for recipients, payload in _calls(handler)}
    assert b"X-Lightr-Spam-Action: junk" in calls[("ops@junked.test",)]
    assert b"X-Lightr-Spam-Action" not in calls[("ops@tagged.test",)]
    assert sorted(outcome.delivered) == ["ops@junked.test", "ops@tagged.test"]


async def test_clean_mail_carries_no_action_even_if_the_sender_wrote_one(
    cfg: Config, engine: AsyncEngine, world: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    handler = _handler(cfg, engine, monkeypatch, spam=False)
    forged = RAW.replace(b"X-Lightr-Spam-Action: \r\n", b"X-Lightr-Spam-Action: junk\r\n")

    await handler.deliver(mail_from="someone@example.net",
                          recipients=["ops@junked.test"], raw=forged)

    ((_, payload),) = _calls(handler)
    assert b"X-Lightr-Spam-Action" not in payload
