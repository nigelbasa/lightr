"""What the sender calls itself when it greets a remote server.

Unset, aiosmtplib used the machine's own name, and the first message the
production server sent reached Gmail as "Received: from localhost".
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from lightr.config import Config, DomainCertConfig
from lightr.mail.sender import Sender


@pytest.fixture
def sender(cfg: Config, tmp_path: Path) -> Sender:
    cert = DomainCertConfig(cert_file=tmp_path / "c.pem", key_file=tmp_path / "k.pem")
    cfg.tls.domain_certs = {"mail.acme.test": cert, "mail.notacme.test": cert}
    return Sender(cfg, engine=None)  # type: ignore[arg-type]


class TestHeloName:
    def test_a_certificate_host_under_the_sending_domain(self, sender: Sender) -> None:
        assert sender.helo_name(SimpleNamespace(name="acme.test")) == "mail.acme.test"

    def test_case_and_trailing_dot_do_not_matter(self, sender: Sender) -> None:
        assert sender.helo_name(SimpleNamespace(name="ACME.test.")) == "mail.acme.test"

    def test_a_suffix_that_is_not_a_subdomain_does_not_count(
        self, sender: Sender, cfg: Config
    ) -> None:
        """mail.notacme.test ends with "acme.test" but is not under it."""
        cfg.tls.domain_certs.pop("mail.acme.test")
        assert sender.helo_name(SimpleNamespace(name="acme.test")) == cfg.server.hostname

    def test_otherwise_the_server_name(self, sender: Sender, cfg: Config) -> None:
        cfg.server.hostname = "mail.example.test"
        assert sender.helo_name(SimpleNamespace(name="other.test")) == "mail.example.test"


class TestGreeting:
    async def test_direct_and_relay_delivery_greet_with_it(
        self, sender: Sender, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        greetings: list[str | None] = []

        async def fake_send(payload, **kwargs):
            greetings.append(kwargs.get("local_hostname"))

        async def mx_hosts(self, domain):
            return ["mx.external.test"]

        monkeypatch.setattr("aiosmtplib.send", fake_send)
        monkeypatch.setattr(Sender, "_mx_hosts", mx_hosts)

        message = SimpleNamespace(sender="ops@acme.test", to_addrs=["a@external.test"])
        domain = SimpleNamespace(name="acme.test", relay_host="smtp.relay.test")
        helo = sender.helo_name(domain)

        assert (await sender._send_direct(message, b"x", helo)).ok  # type: ignore[arg-type]
        assert (await sender._send_via_relay(message, domain, b"x", helo)).ok  # type: ignore[arg-type]
        assert greetings == ["mail.acme.test", "mail.acme.test"]
