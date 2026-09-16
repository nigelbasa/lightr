"""Automatic setup for mail clients.

A mail app asks the server for its own settings rather than making
someone type four hostnames and two port numbers. Three conventions,
none of them standardised together:

* **Thunderbird** fetches ``autoconfig.<domain>/mail/config-v1.1.xml``,
  and ``<domain>/.well-known/autoconfig/mail/config-v1.1.xml``.
* **Outlook** POSTs to
  ``autodiscover.<domain>/autodiscover/autodiscover.xml``, and some
  builds GET it.
* **Everything else** reads the SRV records, which are DNS, not HTTP --
  ``lightr domain dns`` lists them.

These answer without authentication on purpose: they carry hostnames
and ports, which are public, and no client can authenticate before it
knows where to connect. What they must not do is describe this server
as the mail host for a domain it does not host, so an unknown domain is
a 404.
"""

from __future__ import annotations

import re
from typing import Any
from xml.sax.saxutils import escape

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

#: Ports a client is told to use. IMAPS is Dovecot's; submission is
#: Lightr's own listener, which refuses a password without STARTTLS.
IMAPS_PORT = 993
IMAP_STARTTLS_PORT = 143
SUBMISSION_PORT = 587

#: Pulled out of Outlook's request body. A regex, not an XML parser:
#: the body is unauthenticated input, and one address is all that is
#: wanted from it.
_ADDRESS_IN_BODY = re.compile(
    r"<(?:\w+:)?EMailAddress>\s*([^<\s]+)\s*</(?:\w+:)?EMailAddress>", re.IGNORECASE
)

#: The host prefixes clients use, stripped to find the real domain.
_CLIENT_PREFIXES = ("autoconfig.", "autodiscover.", "mail.", "www.")


def _xml(body: str, status: int = 200) -> Response:
    return Response(body, status_code=status, media_type="application/xml")


def _domain_of(address: str) -> str:
    _, _, domain = address.strip().lower().rpartition("@")
    return domain


def _candidates(request: Request, address: str = "") -> list[str]:
    """Domains this request might be asking about, best first.

    An address settles it on its own. It is the client saying which
    mailbox it is configuring, so if this server does not host that
    domain the answer is "not here" -- falling back to the Host header
    would hand back a working configuration for *a different domain*,
    and a client that applied it would send that mailbox's password
    here. Answering about nigelbasa.tech when asked about example.org
    is wrong even though every hostname in the reply is true.

    Only when no address is given does the Host header stand in, with
    the prefix the client invented removed: a request to
    autoconfig.acme.test is about acme.test.
    """
    if address and (domain := _domain_of(address)):
        return [domain] if "." in domain else []

    found: list[str] = []
    host = request.headers.get("host", "").split(":")[0].strip().lower()
    if host:
        found.append(host)
        for prefix in _CLIENT_PREFIXES:
            if host.startswith(prefix):
                found.append(host[len(prefix):])
    return [d for d in dict.fromkeys(found) if d and "." in d]


async def _hosted(request: Request, address: str = "") -> Any | None:
    """The first candidate domain this server actually hosts.

    Runs on the transaction the middleware already opened, like every
    other handler -- a second connection per request is not free on a
    small box, and these routes are the unauthenticated ones.
    """
    from lightr.repo import DomainRepo

    repo = DomainRepo(request.state.conn)
    for name in _candidates(request, address):
        try:
            return await repo.resolve(name)
        except LookupError:
            continue
    return None


async def thunderbird(request: Request) -> Response:
    """Thunderbird, and everything else that reads Mozilla autoconfig."""
    address = request.query_params.get("emailaddress", "")
    domain = await _hosted(request, address)
    if domain is None:
        return _xml("<clientConfig/>", 404)

    name, host = escape(domain.name), escape(domain.hostname)
    incoming = "\n".join(
        f"""    <incomingServer type="imap">
      <hostname>{host}</hostname>
      <port>{port}</port>
      <socketType>{socket}</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>"""
        for port, socket in ((IMAPS_PORT, "SSL"), (IMAP_STARTTLS_PORT, "STARTTLS"))
    )
    return _xml(
        f"""<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{name}">
    <domain>{name}</domain>
    <displayName>{name}</displayName>
    <displayShortName>{name}</displayShortName>
{incoming}
    <outgoingServer type="smtp">
      <hostname>{host}</hostname>
      <port>{SUBMISSION_PORT}</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
      <addThisServer>true</addThisServer>
      <useGlobalPreferredServer>false</useGlobalPreferredServer>
    </outgoingServer>
  </emailProvider>
</clientConfig>
"""
    )


async def outlook(request: Request) -> Response:
    """Outlook's Autodiscover, POST and GET alike."""
    address = request.query_params.get("emailaddress", "")
    if request.method == "POST":
        body = (await request.body()).decode("utf-8", "replace")
        if match := _ADDRESS_IN_BODY.search(body):
            address = match.group(1)

    domain = await _hosted(request, address)
    if domain is None:
        return _xml(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/'
            'responseschema/2006"><Response><Error><Message>Not a domain this server '
            "hosts</Message></Error></Response></Autodiscover>",
            404,
        )

    host = escape(domain.hostname)
    login = escape(address) if "@" in address else "%EMAILADDRESS%"
    protocols = "\n".join(
        f"""      <Protocol>
        <Type>{kind}</Type>
        <Server>{host}</Server>
        <Port>{port}</Port>
        <SSL>on</SSL>
        <Encryption>{encryption}</Encryption>
        <SPA>off</SPA>
        <AuthRequired>on</AuthRequired>
        <LoginName>{login}</LoginName>
      </Protocol>"""
        for kind, port, encryption in (
            ("IMAP", IMAPS_PORT, "SSL"),
            ("SMTP", SUBMISSION_PORT, "TLS"),
        )
    )
    return _xml(
        f"""<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
{protocols}
    </Account>
  </Response>
</Autodiscover>
"""
    )


#: Every path a client may ask, and none of them authenticated.
AUTOCONFIG_ROUTES: list[Route] = [
    Route("/mail/config-v1.1.xml", thunderbird, methods=["GET"]),
    Route("/.well-known/autoconfig/mail/config-v1.1.xml", thunderbird, methods=["GET"]),
    Route("/autodiscover/autodiscover.xml", outlook, methods=["GET", "POST"]),
    # Outlook has shipped this spelling too.
    Route("/Autodiscover/Autodiscover.xml", outlook, methods=["GET", "POST"]),
]

AUTOCONFIG_PATHS = frozenset(route.path for route in AUTOCONFIG_ROUTES)

__all__ = ["AUTOCONFIG_PATHS", "AUTOCONFIG_ROUTES", "outlook", "thunderbird"]
