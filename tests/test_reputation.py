"""Reputation lists: what is looked up, and what an answer means.

The failure worth fearing is not a missed listing but a false one -- a
list refusing queries, read as "listed", junking every message the
server receives. So refusals and lying resolvers get as many tests as
listings do.
"""

from __future__ import annotations

import asyncio
import logging
from email.message import EmailMessage

import pytest

from lightr.config import Config, SpamConfig
from lightr.mail import authentication as mail_auth
from lightr.mail import reputation
from lightr.mail.authentication import DKIMResult, DMARCResult, Result, SPFResult
from lightr.mail.reputation import (
    Listing,
    ReputationChecker,
    domain_query,
    ip_query,
    link_domains,
    probe,
)
from lightr.mail.spam import BLOCKLIST_CAP, Score, score_message


class FakeDNS:
    def __init__(self, answers: dict[str, list[str]] | None = None, *,
                 delay: float = 0.0, error: Exception | None = None) -> None:
        self.answers = answers or {}
        self.asked: list[str] = []
        self.delay = delay
        self.error = error

    async def __call__(self, name: str) -> list[str]:
        self.asked.append(name)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return self.answers.get(name, [])


@pytest.fixture(autouse=True)
def fresh_warnings() -> None:
    reputation._warned.clear()


def _message(body: str = "Hello.", html: str | None = None) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "sender@example.net"
    message["Subject"] = "Hi"
    # A well-formed message, so the scoring tests measure the listing
    # rather than a missing header.
    message["Date"] = "Tue, 15 Sep 2026 10:00:00 +0000"
    message["Message-ID"] = "<hi@example.net>"
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")
    return message


def _spam(address: list[str] | None = None, domain: list[str] | None = None) -> SpamConfig:
    return SpamConfig(dnsbl_zones=address or [], domain_blocklist_zones=domain or [])


class TestQueryNames:
    def test_ipv4_octets_are_reversed(self) -> None:
        assert ip_query("1.2.3.4", "zen.example") == "4.3.2.1.zen.example"

    def test_zone_is_normalised(self) -> None:
        assert ip_query("1.2.3.4", " ZEN.Example. ") == "4.3.2.1.zen.example"

    def test_ipv6_nibbles_are_reversed(self) -> None:
        name = ip_query("2a00:1450:4001:80b::200e", "zen.example")
        # 2a00:1450:4001:080b:0000:0000:0000:200e, every nibble written out.
        expected = ".".join(reversed("2a0014504001080b000000000000200e")) + ".zen.example"
        assert name == expected
        assert len(name.split(".")) == 32 + 2

    def test_an_ipv4_mapped_address_is_looked_up_as_ipv4(self) -> None:
        """What a dual-stack listener reports for an IPv4 client."""
        assert ip_query("::ffff:1.2.3.4", "zen.example") == "4.3.2.1.zen.example"

    @pytest.mark.parametrize(
        "ip", ["", "not-an-ip", "1.2.3", "10.0.0.1", "192.168.1.5", "127.0.0.1",
               "::1", "fe80::1", "2001:db8::1", "1.2.3.4; rm -rf"],
    )
    def test_no_query_for_what_no_list_can_know(self, ip: str) -> None:
        assert ip_query(ip, "zen.example") is None

    def test_domain(self) -> None:
        assert domain_query("Example.COM.", "dbl.example") == "example.com.dbl.example"

    def test_www_is_dropped(self) -> None:
        assert domain_query("www.example.com", "dbl.example") == "example.com.dbl.example"

    def test_international_domain_is_encoded(self) -> None:
        assert domain_query("bücher.de", "dbl.example") == "xn--bcher-kva.de.dbl.example"

    @pytest.mark.parametrize(
        "domain", ["", "localhost", "a..b", "bad domain.com", "1.2.3.4",
                   "evil.com.\nx", "-lead.com"],
    )
    def test_no_query_for_what_is_not_a_domain(self, domain: str) -> None:
        assert domain_query(domain, "dbl.example") is None


class TestLinkDomains:
    def test_links_in_text_and_html(self) -> None:
        message = _message(
            "See https://www.shop.example/deal and http://tracker.example:8080/x",
            html='<a href="https://phish.example/login?x=1">here</a>',
        )
        assert link_domains(message) == ["shop.example", "tracker.example", "phish.example"]

    def test_capped(self) -> None:
        body = " ".join(f"https://d{n}.example/" for n in range(50))
        assert len(link_domains(_message(body))) == reputation.MAX_LINK_DOMAINS

    def test_credentials_in_a_link_are_not_the_domain(self) -> None:
        message = _message("https://user:pass@real.example/")
        assert link_domains(message) == ["real.example"]


class TestLookups:
    async def test_a_listed_address(self) -> None:
        dns = FakeDNS({"4.3.2.1.zen.example": ["127.0.0.2"]})
        checker = ReputationChecker(_spam(["zen.example"]), resolver=dns)

        (listing,) = await checker.check(remote_ip="1.2.3.4")

        assert listing.zone == "zen.example"
        assert listing.is_address
        assert "1.2.3.4 listed on zen.example" in listing.reason

    async def test_an_unlisted_address(self) -> None:
        checker = ReputationChecker(_spam(["zen.example"]), resolver=FakeDNS())
        assert await checker.check(remote_ip="1.2.3.4") == []

    async def test_nothing_configured_means_no_lookups_at_all(self) -> None:
        dns = FakeDNS()
        checker = ReputationChecker(_spam(), resolver=dns)

        await checker.check(remote_ip="1.2.3.4", sender_domains=["example.net"],
                            message=_message("https://x.example/"))

        assert dns.asked == []

    async def test_sender_and_link_domains_are_looked_up(self) -> None:
        dns = FakeDNS({"phish.example.dbl.example": ["127.0.1.2"]})
        checker = ReputationChecker(_spam(domain=["dbl.example"]), resolver=dns)

        listings = await checker.check(
            remote_ip="1.2.3.4", sender_domains=["example.net", "example.net"],
            message=_message("https://phish.example/login"),
        )

        assert set(dns.asked) == {"example.net.dbl.example", "phish.example.dbl.example"}
        assert [(x.subject, x.kind) for x in listings] == [("phish.example", "link domain")]

    async def test_a_slow_list_adds_nothing(self) -> None:
        dns = FakeDNS({"4.3.2.1.zen.example": ["127.0.0.2"]}, delay=1.0)
        checker = ReputationChecker(_spam(["zen.example"]), resolver=dns, timeout=0.01)
        assert await checker.check(remote_ip="1.2.3.4") == []

    async def test_a_failing_lookup_adds_nothing(self) -> None:
        dns = FakeDNS(error=OSError("network unreachable"))
        checker = ReputationChecker(_spam(["zen.example"]), resolver=dns)
        assert await checker.check(remote_ip="1.2.3.4") == []


class TestAnswersThatAreNotListings:
    @pytest.mark.parametrize("answer", ["127.255.255.254", "127.255.255.252", "127.0.0.1"])
    async def test_a_refusal_is_not_a_listing_and_is_reported_once(
        self, answer: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Spamhaus answers 127.255.255.254 to every query that comes
        through a public resolver. Counted as a listing, that junks all
        inbound mail."""
        dns = FakeDNS({"4.3.2.1.zen.example": [answer], "8.7.6.5.zen.example": [answer]})
        checker = ReputationChecker(_spam(["zen.example"]), resolver=dns)

        with caplog.at_level(logging.WARNING, logger="lightr.reputation"):
            assert await checker.check(remote_ip="1.2.3.4") == []
            assert await checker.check(remote_ip="5.6.7.8") == []

        warnings = [r for r in caplog.records if "refused" in r.getMessage()]
        assert len(warnings) == 1
        assert "lightr spam lists" in warnings[0].getMessage()

    async def test_a_resolver_that_rewrites_answers_is_not_believed(self) -> None:
        dns = FakeDNS({"4.3.2.1.zen.example": ["203.0.113.80"]})
        checker = ReputationChecker(_spam(["zen.example"]), resolver=dns)
        assert await checker.check(remote_ip="1.2.3.4") == []


class TestScoring:
    def _score(self, listings: list[Listing]) -> Score:
        return score_message(
            _message(),
            spf=SPFResult(Result.NONE), dkim=DKIMResult(Result.NONE),
            dmarc=DMARCResult(Result.NONE), listings=listings,
        )

    def test_one_listed_address_is_not_junk_on_its_own(self) -> None:
        listing = Listing("zen.example", "1.2.3.4", "address", ("127.0.0.2",))
        score = self._score([listing])

        assert any("listed on zen.example" in r for r in score.reasons)
        _, junk = score.verdict(SpamConfig())
        assert not junk

    def test_two_lists_agreeing_is_junk(self) -> None:
        score = self._score([
            Listing("zen.example", "1.2.3.4", "address", ("127.0.0.2",)),
            Listing("bl.example", "1.2.3.4", "address", ("127.0.0.2",)),
        ])
        assert score.verdict(SpamConfig())[1]

    def test_many_listings_are_capped(self) -> None:
        listings = [
            Listing(f"list{n}.example", "1.2.3.4", "address", ("127.0.0.2",))
            for n in range(12)
        ]
        baseline = self._score([]).points
        assert self._score(listings).points - baseline == pytest.approx(BLOCKLIST_CAP)


class TestOnDelivery:
    @pytest.fixture
    def handler(self, cfg: Config, engine, monkeypatch: pytest.MonkeyPatch):
        from lightr.mail.smtp import LightrHandler

        async def no_spf(ip: str, mail_from: str, helo: str) -> SPFResult:
            return SPFResult(Result.NONE)

        monkeypatch.setattr(mail_auth, "check_spf", no_spf)
        cfg.spam.dnsbl_zones = ["zen.example"]
        return LightrHandler(cfg, engine)

    async def test_a_listed_connection_is_scored(
        self, handler, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dns = FakeDNS({"4.3.2.1.zen.example": ["127.0.0.2"]})
        monkeypatch.setattr(reputation, "dns_resolver", dns)
        message = _message()

        analysis = await handler.analyse(
            message, mail_from="sender@example.net", helo="mx.example.net",
            raw=message.as_bytes(), remote_ip="1.2.3.4",
        )

        assert any("listed on zen.example" in r for r in analysis.reasons)

    async def test_rspamd_answering_means_no_list_lookups(
        self, handler, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """rspamd checks lists itself; asking again counts them twice."""
        from lightr.mail.spam import RspamdClient

        dns = FakeDNS({"4.3.2.1.zen.example": ["127.0.0.2"]})
        monkeypatch.setattr(reputation, "dns_resolver", dns)

        async def rspamd_says(self, raw: bytes) -> Score:
            return Score(points=1.0, reasons=["RBL_SPAMHAUS (+1.0)"])

        monkeypatch.setattr(RspamdClient, "score", rspamd_says)
        message = _message()

        analysis = await handler.analyse(
            message, mail_from="sender@example.net", helo="mx.example.net",
            raw=message.as_bytes(), remote_ip="1.2.3.4",
        )

        assert dns.asked == []
        assert analysis.score == 1.0


class TestProbe:
    async def test_a_working_list(self) -> None:
        dns = FakeDNS({"2.0.0.127.zen.example": ["127.0.0.2"]})
        health = await probe("zen.example", "address", resolver=dns)
        assert health.status == "working"

    async def test_a_refusing_list(self) -> None:
        dns = FakeDNS({"2.0.0.127.zen.example": ["127.255.255.254"]})
        health = await probe("zen.example", "address", resolver=dns)
        assert health.status == "refused"
        assert "public resolver" in health.detail

    async def test_a_list_that_lists_everything(self) -> None:
        dns = FakeDNS({"test.dbl.example": ["127.0.1.2"],
                       "invalid.dbl.example": ["127.0.1.2"]})
        health = await probe("dbl.example", "domain", resolver=dns)
        assert health.status == "lists everything"

    async def test_a_silent_list(self) -> None:
        health = await probe("gone.example", "address", resolver=FakeDNS())
        assert health.status == "no answer"


class TestListsCommand:
    """`lightr spam lists`: the operator's way to find out a list is
    refusing before it quietly checks nothing for a month."""

    def _config(self, tmp_path, **spam) -> str:
        from pathlib import Path

        cfg = Config.model_validate({"data_dir": str(tmp_path), "spam": spam})
        path = Path(tmp_path) / "config.yaml"
        cfg.save(path)
        return str(path)

    def _run(self, config: str, *args: str):
        from typer.testing import CliRunner

        from lightr.cli.main import app

        return CliRunner().invoke(app, ["--config", config, "spam", "lists", *args])

    def test_a_working_list_passes(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        monkeypatch.setattr(
            reputation, "dns_resolver", FakeDNS({"2.0.0.127.zen.example": ["127.0.0.2"]})
        )
        result = self._run(
            self._config(tmp_path, dnsbl_zones=["zen.example"]), "--format", "json"
        )

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)[0]["status"] == "working"

    def test_a_refusing_list_fails_the_command(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            reputation, "dns_resolver",
            FakeDNS({"2.0.0.127.zen.example": ["127.255.255.254"]}),
        )
        result = self._run(self._config(tmp_path, dnsbl_zones=["zen.example"]))

        assert result.exit_code == 1
        assert "refused" in result.output

    def test_nothing_configured_says_so(self, tmp_path) -> None:
        result = self._run(self._config(tmp_path))

        assert result.exit_code == 0
        assert "No blocklists are configured" in result.output
