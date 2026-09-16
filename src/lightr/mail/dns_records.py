"""The DNS records a domain needs, and checking what is published.

CORE.md makes this a contract: Lightr generates recommended records and
verifies the live state, but never pushes anything into a DNS provider.
An operator publishes; Lightr checks.

Verification requires MX, SPF, DKIM, and DMARC. PTR is reported as
guidance only -- it is set by whoever owns the IP, which for most
operators is their hosting provider, so requiring it would block
domains that are otherwise correctly configured.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import StrEnum

log = logging.getLogger("lightr.dns")

DNS_TIMEOUT = 5.0

#: The recommended DMARC policy. Quarantine rather than reject: a new
#: domain that gets its SPF slightly wrong should have mail filed in
#: Junk, not destroyed.
DEFAULT_DMARC = "v=DMARC1; p=quarantine; adkim=s; aspf=s"


class RecordKind(StrEnum):
    MX = "MX"
    SPF = "SPF"
    DKIM = "DKIM"
    DMARC = "DMARC"
    PTR = "PTR"
    #: Where Thunderbird and Outlook look for settings, and the SRV
    #: records everything else reads. Mail is delivered without them;
    #: they only save someone typing hostnames in by hand.
    AUTOCONFIG = "AUTOCONFIG"
    AUTODISCOVER = "AUTODISCOVER"
    SRV_IMAP = "SRV_IMAP"
    SRV_SUBMISSION = "SRV_SUBMISSION"

    @property
    def required_for_verification(self) -> bool:
        """Whether a domain is unverified without this record.

        Only the four that decide whether mail is delivered and trusted.
        PTR is set by whoever owns the IP -- see the module docstring --
        and the client-discovery records are a convenience.
        """
        return self in _REQUIRED


_REQUIRED = frozenset(
    {RecordKind.MX, RecordKind.SPF, RecordKind.DKIM, RecordKind.DMARC}
)


class CheckState(StrEnum):
    OK = "ok"
    MISSING = "missing"
    MISMATCH = "mismatch"
    ERROR = "error"  # the lookup itself failed


@dataclass(frozen=True, slots=True)
class Record:
    """One record an operator should publish."""

    kind: RecordKind
    name: str
    type: str
    value: str
    priority: int | None = None

    def as_zone_line(self) -> str:
        priority = f"{self.priority} " if self.priority is not None else ""
        quoted = f'"{self.value}"' if self.type == "TXT" else self.value
        return f"{self.name}. IN {self.type} {priority}{quoted}"


@dataclass(slots=True)
class CheckResult:
    """What is actually published for one record."""

    kind: RecordKind
    state: CheckState
    expected: str = ""
    found: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.state is CheckState.OK


@dataclass(slots=True)
class Verification:
    domain: str
    checks: list[CheckResult]

    @property
    def verified(self) -> bool:
        """Whether the domain passes.

        A lookup error is not a pass. Treating "could not check" as
        success would mark a domain verified during a DNS outage.
        """
        return all(
            check.ok
            for check in self.checks
            if check.kind.required_for_verification
        )

    @property
    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.ok]


def records_for(
    domain: str,
    *,
    mail_hostname: str,
    dkim_selector: str = "default",
    dkim_public_key: str | None = None,
    dmarc: str = DEFAULT_DMARC,
    include_optional: bool = False,
) -> list[Record]:
    """The records this domain should publish.

    ``include_optional`` adds the client-discovery records -- autoconfig,
    autodiscover and the SRV pair. They are off by default because
    ``verify()`` checks everything this returns, and a domain whose mail
    works must not be reported as unverified for want of a CNAME that
    only saves someone typing.
    """
    host = mail_hostname or domain
    generated = [
        Record(RecordKind.MX, domain, "MX", f"{host}.", priority=10),
        Record(
            RecordKind.SPF,
            domain,
            "TXT",
            f"v=spf1 mx a:{host} ~all",
        ),
        Record(RecordKind.DMARC, f"_dmarc.{domain}", "TXT", dmarc),
    ]

    if dkim_public_key:
        generated.insert(
            2,
            Record(
                RecordKind.DKIM,
                f"{dkim_selector}._domainkey.{domain}",
                "TXT",
                f"v=DKIM1; k=rsa; p={dkim_public_key}",
            ),
        )

    if include_optional:
        generated.extend(
            [
                Record(RecordKind.AUTOCONFIG, f"autoconfig.{domain}", "CNAME", f"{host}."),
                Record(
                    RecordKind.AUTODISCOVER, f"autodiscover.{domain}", "CNAME", f"{host}."
                ),
                Record(
                    RecordKind.SRV_IMAP,
                    f"_imaps._tcp.{domain}",
                    "SRV",
                    f"0 1 993 {host}.",
                ),
                Record(
                    RecordKind.SRV_SUBMISSION,
                    f"_submission._tcp.{domain}",
                    "SRV",
                    f"0 1 587 {host}.",
                ),
            ]
        )
    return generated


async def _resolve(name: str, record_type: str) -> list[str]:
    """Look up a name, returning the record values as text."""
    try:
        import dns.asyncresolver
    except ImportError:  # pragma: no cover - depends on install
        raise LookupError("dnspython is not installed") from None

    try:
        answers = await asyncio.wait_for(
            dns.asyncresolver.resolve(name, record_type), timeout=DNS_TIMEOUT
        )
    except Exception as exc:
        raise LookupError(str(exc)) from exc

    values: list[str] = []
    for answer in answers:
        if record_type == "TXT":
            values.append(b"".join(answer.strings).decode("utf-8", "replace"))
        elif record_type == "MX":
            values.append(f"{answer.preference} {str(answer.exchange).rstrip('.')}")
        else:
            values.append(str(answer).rstrip("."))
    return values


async def check(record: Record) -> CheckResult:
    """Check one record against what is published."""
    try:
        found = await _resolve(record.name, record.type)
    except LookupError as exc:
        state = (
            CheckState.MISSING
            if "NXDOMAIN" in str(exc) or "no answer" in str(exc).lower()
            else CheckState.ERROR
        )
        return CheckResult(record.kind, state, record.value, [], str(exc))

    if not found:
        return CheckResult(record.kind, CheckState.MISSING, record.value)

    if _matches(record, found):
        return CheckResult(record.kind, CheckState.OK, record.value, found)
    return CheckResult(
        record.kind,
        CheckState.MISMATCH,
        record.value,
        found,
        "published, but not what Lightr expects",
    )


def _matches(record: Record, found: list[str]) -> bool:
    """Whether a published value satisfies the requirement.

    Deliberately lenient: an operator may have a stricter SPF than we
    suggest, or list several MX hosts. What matters is that the mail
    host is reachable and the mechanism is present, not that the string
    is identical to our suggestion.
    """
    match record.kind:
        case RecordKind.MX:
            wanted = record.value.rstrip(".").lower()
            return any(wanted in value.lower() for value in found)
        case RecordKind.SPF:
            return any(value.lower().startswith("v=spf1") for value in found)
        case RecordKind.DKIM:
            key = record.value.split("p=", 1)[-1].strip()
            return any(key and key in value.replace(" ", "") for value in found)
        case RecordKind.DMARC:
            return any(value.lower().startswith("v=dmarc1") for value in found)
        case RecordKind.PTR:
            return bool(found)
        case RecordKind.AUTOCONFIG | RecordKind.AUTODISCOVER:
            wanted = record.value.rstrip(".").lower()
            return any(wanted == value.rstrip(".").lower() for value in found)
        case RecordKind.SRV_IMAP | RecordKind.SRV_SUBMISSION:
            # Weight and priority are the operator's to choose; the port
            # and target are what a client actually connects to.
            _, _, port_and_host = record.value.partition(" ")
            wanted = port_and_host.partition(" ")[2].rstrip(".").lower()
            return any(wanted in value.rstrip(".").lower() for value in found)
    return False


async def verify(
    domain: str,
    *,
    mail_hostname: str,
    dkim_selector: str = "default",
    dkim_public_key: str | None = None,
) -> Verification:
    """Check every record a domain needs."""
    records = records_for(
        domain,
        mail_hostname=mail_hostname,
        dkim_selector=dkim_selector,
        dkim_public_key=dkim_public_key,
    )

    if dkim_public_key is None:
        # No key means DKIM cannot pass; report it rather than skipping,
        # so `domain verify` says why the domain is not verified.
        records.append(
            Record(
                RecordKind.DKIM,
                f"{dkim_selector}._domainkey.{domain}",
                "TXT",
                "(no DKIM key generated yet)",
            )
        )

    checks = await asyncio.gather(*(check(r) for r in records))
    return Verification(domain=domain, checks=list(checks))


__all__ = [
    "DEFAULT_DMARC",
    "CheckResult",
    "CheckState",
    "Record",
    "RecordKind",
    "Verification",
    "check",
    "records_for",
    "verify",
]
