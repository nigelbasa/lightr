"""Sending a domain's mail through a smarthost.

The relay sees every message a domain sends, and holds a provider
password that can send as every domain on that provider account. So the
tests are about the rules: no password in the clear, no relay without a
host, no key confined to one domain repointing its mail, and port 465
spoken to the way it expects.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from lightr.api.app import create_app
from lightr.apikeys import APIKeyRepo, KeyType
from lightr.config import Config
from lightr.mail import relay
from lightr.mail.relay import RelayChange, RelayError
from lightr.mail.sender import Sender
from lightr.models import Domain, Organization
from lightr.repo import DomainRepo, OrganizationRepo


def _domain(**fields: object) -> Domain:
    return Domain(org_id=uuid4(), name="acme.test", **fields)


class TestTheRules:
    def test_setting_a_login_over_starttls(self) -> None:
        domain = relay.apply(_domain(), RelayChange(
            enabled=True, host="SMTP.Resend.com.", port=587,
            username="resend", password="s3cret", use_tls=True,
        ))
        assert domain.relay_enabled
        assert domain.relay_host == "smtp.resend.com"
        assert domain.relay_password == "s3cret"

    def test_no_relay_without_a_host(self) -> None:
        with pytest.raises(RelayError, match="needs a host"):
            relay.apply(_domain(), RelayChange(enabled=True))

    def test_a_password_is_never_sent_in_the_clear(self) -> None:
        with pytest.raises(RelayError, match="without TLS"):
            relay.apply(_domain(), RelayChange(
                enabled=True, host="smtp.relay.test", port=587,
                username="u", password="p", use_tls=False,
            ))

    def test_port_465_counts_as_tls(self) -> None:
        domain = relay.apply(_domain(), RelayChange(
            enabled=True, host="smtp.relay.test", port=465, username="u", password="p",
        ))
        assert relay.uses_tls(domain)

    def test_a_username_needs_a_password(self) -> None:
        with pytest.raises(RelayError, match="both"):
            relay.apply(_domain(), RelayChange(
                enabled=True, host="smtp.relay.test", username="u", use_tls=True,
            ))

    @pytest.mark.parametrize("host", ["not a host", "-bad.test", "nodot", "a..b"])
    def test_hosts_are_checked(self, host: str) -> None:
        with pytest.raises(RelayError, match="not a hostname"):
            relay.apply(_domain(), RelayChange(host=host))

    def test_an_ip_address_is_a_host(self) -> None:
        assert relay.apply(_domain(), RelayChange(host="192.0.2.25")).relay_host == "192.0.2.25"

    @pytest.mark.parametrize("port", [0, 70000, -1])
    def test_ports_are_checked(self, port: int) -> None:
        with pytest.raises(RelayError, match="port"):
            relay.apply(_domain(), RelayChange(port=port))

    def test_disabling_keeps_the_settings(self) -> None:
        domain = relay.apply(_domain(), RelayChange(
            enabled=True, host="smtp.relay.test", username="u", password="p", use_tls=True,
        ))
        relay.apply(domain, RelayChange(enabled=False))
        assert not domain.relay_enabled
        assert domain.relay_host == "smtp.relay.test"
        assert domain.relay_password == "p"

    def test_clear_removes_everything(self) -> None:
        domain = relay.apply(_domain(), RelayChange(
            enabled=True, host="smtp.relay.test", username="u", password="p", use_tls=True,
        ))
        relay.apply(domain, RelayChange(clear=True))
        assert (domain.relay_enabled, domain.relay_host, domain.relay_username,
                domain.relay_password) == (False, None, None, None)

    def test_the_view_never_shows_the_password(self) -> None:
        domain = relay.apply(_domain(), RelayChange(
            enabled=True, host="smtp.relay.test", username="u", password="p", use_tls=True,
        ))
        shown = relay.view(domain)
        assert shown["password"] == "(set)"
        assert "p" not in [v for k, v in shown.items() if k != "password"]


class TestConnection:
    def test_465_is_tls_from_the_first_byte(self) -> None:
        settings = relay.connection(_domain(relay_host="smtp.relay.test", relay_port=465,
                                            relay_use_tls=True))
        assert settings["use_tls"] is True
        assert settings["start_tls"] is False

    def test_587_negotiates_starttls(self) -> None:
        settings = relay.connection(_domain(relay_host="smtp.relay.test", relay_port=587,
                                            relay_use_tls=True))
        assert (settings["use_tls"], settings["start_tls"]) == (False, True)

    def test_the_default_port_is_submission(self) -> None:
        assert relay.connection(_domain(relay_host="smtp.relay.test"))["port"] == 587

    async def test_the_sender_uses_it(
        self, cfg: Config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[dict] = []

        async def fake_send(payload, **kwargs):
            calls.append(kwargs)

        monkeypatch.setattr("aiosmtplib.send", fake_send)
        domain = _domain(relay_enabled=True, relay_host="smtp.relay.test", relay_port=465,
                         relay_username="u", relay_password="p")
        message = SimpleNamespace(sender="ops@acme.test", to_addrs=["a@external.test"])

        result = await Sender(cfg, engine=None)._send_via_relay(  # type: ignore[arg-type]
            message, domain, b"x", "mail.acme.test"  # type: ignore[arg-type]
        )

        assert result.ok
        (sent,) = calls
        assert sent["hostname"] == "smtp.relay.test"
        assert (sent["use_tls"], sent["start_tls"]) == (True, False)
        assert (sent["username"], sent["password"]) == ("u", "p")
        assert sent["local_hostname"] == "mail.acme.test"


class FakeSMTP:
    instances: ClassVar[list[FakeSMTP]] = []
    refuse_login: ClassVar[bool] = False

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.steps: list[str] = []
        self.is_connected = False
        FakeSMTP.instances.append(self)

    async def connect(self) -> None:
        self.is_connected = True
        self.steps.append("connect")

    async def login(self, username: str, password: str) -> None:
        if FakeSMTP.refuse_login:
            raise RuntimeError("535 5.7.8 Authentication failed")
        self.steps.append(f"login {username}")

    async def quit(self) -> None:
        self.is_connected = False
        self.steps.append("quit")

    def close(self) -> None:
        self.is_connected = False


class TestTheLoginTest:
    @pytest.fixture(autouse=True)
    def fake(self, monkeypatch: pytest.MonkeyPatch) -> None:
        FakeSMTP.instances = []
        FakeSMTP.refuse_login = False
        monkeypatch.setattr("aiosmtplib.SMTP", FakeSMTP)

    async def test_it_logs_in_and_sends_nothing(self) -> None:
        domain = _domain(relay_host="smtp.relay.test", relay_port=587, relay_use_tls=True,
                         relay_username="u", relay_password="p")
        said = await relay.test_login(domain, local_hostname="mail.acme.test")

        (client,) = FakeSMTP.instances
        assert client.steps == ["connect", "login u", "quit"]
        assert client.kwargs["start_tls"] is True
        assert "STARTTLS" in said and "logged in as u" in said

    async def test_a_refused_login_says_why(self) -> None:
        FakeSMTP.refuse_login = True
        domain = _domain(relay_host="smtp.relay.test", relay_port=465,
                         relay_username="u", relay_password="wrong")
        with pytest.raises(RelayError, match="535"):
            await relay.test_login(domain, local_hostname="mail.acme.test")


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    async with engine.begin() as conn:
        orgs, domains, keys = OrganizationRepo(conn), DomainRepo(conn), APIKeyRepo(conn)
        acme = await orgs.create(Organization(name="Acme"))
        globex = await orgs.create(Organization(name="Globex"))
        acme_domain = await domains.create(Domain(org_id=acme.id, name="acme.test"))
        globex_domain = await domains.create(Domain(org_id=globex.id, name="globex.test"))
        _, admin_secret = await keys.create("root", key_type=KeyType.ADMIN)
        _, acme_secret = await keys.create("acme-ci", organization_id=acme.id)
        _, domain_secret = await keys.create(
            "acme-domain", key_type=KeyType.DOMAIN,
            organization_id=acme.id, domain_id=acme_domain.id,
        )
    return {
        "acme": acme, "acme_domain": acme_domain, "globex_domain": globex_domain,
        "admin_key": admin_secret, "acme_key": acme_secret, "domain_key": domain_secret,
    }


@pytest_asyncio.fixture
async def client(cfg: Config, engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(cfg, engine=engine))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestTheAPI:
    async def test_an_org_key_sets_its_domains_relay(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        response = await client.patch(
            f"/v1/domains/{world['acme_domain'].id}",
            json={"relay_enabled": True, "relay_host": "smtp.resend.com", "relay_port": 587,
                  "relay_use_tls": True, "relay_username": "resend",
                  "relay_password": "re_secret"},
            headers={"X-API-Key": world["acme_key"]},
        )
        assert response.status_code == 200, response.text
        assert response.json()["relay_password"] == "(set)"
        assert "re_secret" not in response.text

        async with engine.begin() as conn:
            stored = await DomainRepo(conn).resolve("acme.test")
        assert stored.relay_enabled and stored.relay_password == "re_secret"

    async def test_another_orgs_domain_is_refused(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.patch(
            f"/v1/domains/{world['globex_domain'].id}",
            json={"relay_enabled": False},
            headers={"X-API-Key": world["acme_key"]},
        )
        assert response.status_code == 403

    async def test_a_key_for_one_domain_cannot_repoint_its_mail(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """It can reach the domain, but the relay receives every message
        the domain sends; that is an organization's decision."""
        response = await client.patch(
            f"/v1/domains/{world['acme_domain'].id}",
            json={"relay_enabled": True, "relay_host": "smtp.attacker.test"},
            headers={"X-API-Key": world["domain_key"]},
        )
        assert response.status_code == 403
        assert "organization or admin key" in response.text

    async def test_other_fields_are_not_settable(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.patch(
            f"/v1/domains/{world['acme_domain'].id}",
            json={"name": "evil.test"},
            headers={"X-API-Key": world["admin_key"]},
        )
        assert response.status_code == 400
        assert "cannot change: name" in response.text

    async def test_a_password_in_the_clear_is_refused(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.patch(
            f"/v1/domains/{world['acme_domain'].id}",
            json={"relay_enabled": True, "relay_host": "smtp.relay.test",
                  "relay_username": "u", "relay_password": "p", "relay_use_tls": False},
            headers={"X-API-Key": world["admin_key"]},
        )
        assert response.status_code == 400
        assert "without TLS" in response.text

    async def test_null_clears_a_value(
        self, client: httpx.AsyncClient, world: dict, engine: AsyncEngine
    ) -> None:
        key = {"X-API-Key": world["admin_key"]}
        url = f"/v1/domains/{world['acme_domain'].id}"
        await client.patch(url, headers=key, json={
            "relay_host": "smtp.relay.test", "relay_port": 2525,
        })
        response = await client.patch(url, headers=key, json={"relay_port": None})
        assert response.status_code == 200, response.text

        async with engine.begin() as conn:
            stored = await DomainRepo(conn).resolve("acme.test")
        assert stored.relay_host == "smtp.relay.test"
        assert stored.relay_port is None


class TestTheCLI:
    def test_set_show_and_clear(self, tmp_path: Path) -> None:
        from lightr.cli.main import app
        from lightr.db import migrate

        cfg = Config.model_validate({"data_dir": str(tmp_path)})
        path = tmp_path / "config.yaml"
        cfg.save(path)
        migrate.upgrade(cfg)
        runner = CliRunner()

        def cli(*args: str, stdin: str | None = None):
            return runner.invoke(app, ["--config", str(path), *args], input=stdin)

        assert cli("domain", "create", "acme.test").exit_code == 0

        set_ = cli("domain", "relay", "acme.test", "--host", "smtp.relay.test",
                   "--username", "u", "--password-stdin", "--format", "json",
                   stdin="hunter22\n")
        assert set_.exit_code == 0, set_.output
        assert "hunter22" not in set_.output
        assert '"enabled": true' in set_.stdout
        assert '"tls": "starttls"' in set_.stdout, "TLS defaults on with a host"

        shown = cli("domain", "get", "acme.test", "--format", "json")
        assert '"relay_password": "(set)"' in shown.stdout
        assert "hunter22" not in shown.stdout

        cleartext = cli("domain", "relay", "acme.test", "--no-tls")
        assert cleartext.exit_code != 0
        assert "without TLS" in cleartext.output

        cleared = cli("domain", "relay", "acme.test", "--clear", "--yes", "--format", "json")
        assert cleared.exit_code == 0, cleared.output
        assert '"enabled": false' in cleared.stdout
        assert '"host": null' in cleared.stdout
