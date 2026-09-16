"""Automatic setup: the XML Thunderbird and Outlook fetch.

Two properties matter here. The first is that these routes answer
without a key -- a client cannot authenticate before it knows where to
connect, so requiring one would defeat the point. The second is that
they answer *only* for domains this server hosts: claiming to be the
mail host for someone else's domain is how a mail app ends up sending
a password to the wrong place.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.api.app import create_app
from lightr.api.autoconfig import AUTOCONFIG_PATHS, _candidates
from lightr.config import Config
from lightr.models import Domain, Organization
from lightr.repo import DomainRepo, OrganizationRepo


@pytest_asyncio.fixture
async def world(engine: AsyncEngine) -> dict:
    """One hosted domain, so an unhosted one has something to differ from."""
    async with engine.begin() as conn:
        org = await OrganizationRepo(conn).create(Organization(name="Acme"))
        domain = await DomainRepo(conn).create(Domain(org_id=org.id, name="acme.test"))
    return {"org": org, "domain": domain}


@pytest_asyncio.fixture
async def client(cfg: Config, engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(cfg, engine=engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

MOZILLA = "/mail/config-v1.1.xml"
WELL_KNOWN = "/.well-known/autoconfig/mail/config-v1.1.xml"
AUTODISCOVER = "/autodiscover/autodiscover.xml"

REQUEST_BODY = """<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>ops@acme.test</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
  </Request>
</Autodiscover>
"""


class TestUnauthenticated:
    """No key, because the client does not have one yet."""

    def test_every_route_is_public(self) -> None:
        from lightr.api.app import PUBLIC_PATHS

        assert AUTOCONFIG_PATHS
        assert AUTOCONFIG_PATHS <= PUBLIC_PATHS

    async def test_thunderbird_answers_without_a_key(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(MOZILLA, params={"emailaddress": "ops@acme.test"})

        assert response.status_code == 200
        assert "xml" in response.headers["content-type"]

    async def test_outlook_answers_without_a_key(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(AUTODISCOVER, content=REQUEST_BODY)

        assert response.status_code == 200


class TestThunderbird:
    async def test_it_names_the_mail_host_and_ports(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        body = (
            await client.get(MOZILLA, params={"emailaddress": "ops@acme.test"})
        ).text

        assert "<hostname>acme.test</hostname>" in body
        assert "<port>993</port>" in body
        assert "<port>587</port>" in body

    async def test_both_imap_ports_are_offered(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """993 first, 143 with STARTTLS for a client that cannot do
        implicit TLS."""
        body = (await client.get(MOZILLA, params={"emailaddress": "ops@acme.test"})).text

        assert body.index("<port>993</port>") < body.index("<port>143</port>")
        assert "STARTTLS" in body

    async def test_the_login_is_the_full_address(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        body = (await client.get(MOZILLA, params={"emailaddress": "ops@acme.test"})).text

        assert "%EMAILADDRESS%" in body

    async def test_the_well_known_path_answers_too(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(
            WELL_KNOWN, params={"emailaddress": "ops@acme.test"}
        )

        assert response.status_code == 200
        assert "acme.test" in response.text

    async def test_an_unhosted_domain_is_404(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """Answering for a domain we do not host would tell a mail app
        to send someone else's password here."""
        response = await client.get(
            MOZILLA, params={"emailaddress": "someone@notours.test"}
        )

        assert response.status_code == 404

    async def test_no_address_and_no_usable_host_is_404(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        assert (await client.get(MOZILLA)).status_code == 404


class TestTheHostHeaderIsAFallback:
    """A client that fetches autoconfig.acme.test sends no address."""

    async def test_the_client_prefix_is_stripped(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(MOZILLA, headers={"Host": "autoconfig.acme.test"})

        assert response.status_code == 200
        assert "acme.test" in response.text

    async def test_the_mail_host_works_too(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(MOZILLA, headers={"Host": "mail.acme.test"})

        assert response.status_code == 200

    async def test_a_port_on_the_host_is_ignored(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.get(MOZILLA, headers={"Host": "acme.test:443"})

        assert response.status_code == 200

    async def test_an_unhosted_address_is_not_rescued_by_the_host(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """Caught in production, where every request carries a real Host.

        Asking about someone@notours.test on a host we *do* serve used
        to fall back to that host and return a working configuration for
        acme.test. Every hostname in it was true and it was still wrong:
        a client applying it would send notours.test's password here.
        """
        response = await client.get(
            MOZILLA,
            params={"emailaddress": "someone@notours.test"},
            headers={"Host": "autoconfig.acme.test"},
        )

        assert response.status_code == 404

    async def test_the_host_still_answers_when_no_address_is_given(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """The fallback is not gone, it is only for when there is
        nothing better -- which is how Thunderbird's own fetch arrives."""
        response = await client.get(MOZILLA, headers={"Host": "autoconfig.acme.test"})

        assert response.status_code == 200


class TestOutlook:
    async def test_the_address_is_read_from_the_body(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        body = (await client.post(AUTODISCOVER, content=REQUEST_BODY)).text

        assert "<Server>acme.test</Server>" in body
        assert "<Type>IMAP</Type>" in body
        assert "<Type>SMTP</Type>" in body

    async def test_a_namespaced_element_is_read_too(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        payload = (
            "<Request><a:EMailAddress>ops@acme.test</a:EMailAddress></Request>"
        )
        response = await client.post(AUTODISCOVER, content=payload)

        assert response.status_code == 200

    async def test_get_works_as_well_as_post(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """Some Outlook builds GET it."""
        response = await client.get(
            AUTODISCOVER, params={"emailaddress": "ops@acme.test"}
        )

        assert response.status_code == 200

    async def test_the_capitalised_spelling_is_served(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            "/Autodiscover/Autodiscover.xml", content=REQUEST_BODY
        )

        assert response.status_code == 200

    async def test_an_unhosted_domain_is_404_with_a_reason(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        response = await client.post(
            AUTODISCOVER,
            content=REQUEST_BODY.replace("acme.test", "notours.test"),
        )

        assert response.status_code == 404
        assert "Error" in response.text

    async def test_a_body_that_is_not_xml_does_not_raise(
        self, client: httpx.AsyncClient, world: dict
    ) -> None:
        """The body is unauthenticated input."""
        response = await client.post(AUTODISCOVER, content=b"\xff\xfe not xml")

        assert response.status_code == 404


class TestCandidateDomains:
    """Unit-level, because the ordering is the whole security property."""

    def _request(self, host: str) -> object:
        from starlette.datastructures import Headers

        class _Fake:
            headers = Headers({"host": host})

        return _Fake()

    @pytest.mark.parametrize(
        "host,expected",
        [
            ("autoconfig.acme.test", "acme.test"),
            ("autodiscover.acme.test", "acme.test"),
            ("mail.acme.test", "acme.test"),
            ("www.acme.test", "acme.test"),
        ],
    )
    def test_known_prefixes_are_stripped(self, host: str, expected: str) -> None:
        assert expected in _candidates(self._request(host))  # type: ignore[arg-type]

    def test_the_full_host_is_tried_first(self) -> None:
        """mail.acme.test may itself be a hosted domain."""
        found = _candidates(self._request("mail.acme.test"))  # type: ignore[arg-type]
        assert found[0] == "mail.acme.test"

    def test_the_address_comes_before_the_host(self) -> None:
        found = _candidates(
            self._request("autoconfig.other.test"),  # type: ignore[arg-type]
            "ops@acme.test",
        )
        assert found[0] == "acme.test"

    def test_a_bare_hostname_is_not_a_candidate(self) -> None:
        """httpx's default Host is "test"; a name with no dot is not a
        domain and must not be looked up."""
        assert _candidates(self._request("test")) == []  # type: ignore[arg-type]

    def test_duplicates_are_collapsed(self) -> None:
        found = _candidates(
            self._request("acme.test"),  # type: ignore[arg-type]
            "ops@acme.test",
        )
        assert found == ["acme.test"]
