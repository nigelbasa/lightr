"""SPF, DKIM verification, and DMARC.

These decide whether a message really came from where it claims. Their
results become the ``Authentication-Results`` header that Sieve rules
test, so the vocabulary here is fixed by RFC 8601 and by what the
Sieve generator emits: ``pass``, ``fail``, ``softfail``, ``neutral``,
``none``, ``temperror``, ``permerror``.

One rule runs through all of it: **a lookup that fails is not a
verification that failed**. DNS being slow must produce ``temperror``,
never ``fail`` -- treating an outage as a forgery would reject
legitimate mail from everyone at once.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from enum import StrEnum

log = logging.getLogger("lightr.auth.mail")

#: Every DNS lookup here is bounded. A sender controls the domain being
#: queried, so an unbounded lookup is a way to stall the receive path.
DNS_TIMEOUT = 5.0


class Result(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"

    @property
    def is_failure(self) -> bool:
        """Whether this result indicates a forgery.

        Deliberately excludes temperror and permerror: those are
        problems with the check, not evidence against the sender.
        """
        return self is Result.FAIL

    @property
    def is_inconclusive(self) -> bool:
        return self in (Result.NONE, Result.TEMPERROR, Result.PERMERROR, Result.NEUTRAL)


@dataclass(frozen=True, slots=True)
class SPFResult:
    result: Result
    domain: str = ""
    explanation: str = ""


@dataclass(frozen=True, slots=True)
class DKIMResult:
    result: Result
    domain: str = ""
    selector: str = ""


@dataclass(frozen=True, slots=True)
class DMARCResult:
    result: Result
    policy: str = "none"  # none | quarantine | reject
    aligned_spf: bool = False
    aligned_dkim: bool = False

    @property
    def should_reject(self) -> bool:
        return self.result is Result.FAIL and self.policy == "reject"

    @property
    def should_quarantine(self) -> bool:
        return self.result is Result.FAIL and self.policy == "quarantine"


# --------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------


async def check_spf(ip: str, mail_from: str, helo: str) -> SPFResult:
    """Evaluate SPF for the connecting IP.

    Uses the envelope sender's domain, falling back to the HELO name
    for a null sender (a bounce), which is what RFC 7208 prescribes.
    """
    if not ip:
        return SPFResult(Result.NONE, explanation="no client address")

    domain = mail_from.split("@", 1)[1].lower() if "@" in mail_from else helo.lower()
    if not domain:
        return SPFResult(Result.NONE, explanation="no domain to check")

    try:
        import spf
    except ImportError:  # pragma: no cover - depends on install
        log.warning("pyspf is not installed; SPF is not being checked")
        return SPFResult(Result.NONE, domain, "pyspf not installed")

    def _check() -> tuple[str, str]:
        return spf.check2(i=ip, s=mail_from or f"postmaster@{domain}", h=helo or domain)

    try:
        verdict, explanation = await asyncio.wait_for(
            asyncio.to_thread(_check), timeout=DNS_TIMEOUT
        )
    except TimeoutError:
        # A slow DNS server is not a forgery.
        return SPFResult(Result.TEMPERROR, domain, "DNS timeout")
    except Exception as exc:
        log.debug("SPF check failed for %s: %s", domain, exc)
        return SPFResult(Result.TEMPERROR, domain, str(exc))

    try:
        result = Result(verdict)
    except ValueError:
        result = Result.NEUTRAL
    return SPFResult(result, domain, explanation)


# --------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------

_DKIM_DOMAIN = re.compile(rb"[;\s]d=([^;\s]+)")
_DKIM_SELECTOR = re.compile(rb"[;\s]s=([^;\s]+)")


async def check_dkim(raw: bytes) -> DKIMResult:
    """Verify a message's DKIM signature."""
    if b"DKIM-Signature:" not in raw:
        return DKIMResult(Result.NONE)

    domain, selector = _signature_identity(raw)

    try:
        import dkim as dkimpy
    except ImportError:  # pragma: no cover - depends on install
        return DKIMResult(Result.NONE, domain, selector)

    try:
        verified = await asyncio.wait_for(
            asyncio.to_thread(dkimpy.verify, raw), timeout=DNS_TIMEOUT
        )
    except TimeoutError:
        return DKIMResult(Result.TEMPERROR, domain, selector)
    except Exception as exc:
        # A malformed signature is a permanent problem with the
        # message, not a transient one with us.
        log.debug("DKIM verification failed for %s: %s", domain, exc)
        return DKIMResult(Result.PERMERROR, domain, selector)

    return DKIMResult(Result.PASS if verified else Result.FAIL, domain, selector)


def _signature_identity(raw: bytes) -> tuple[str, str]:
    """The d= and s= tags of the first DKIM-Signature header."""
    header = raw.split(b"DKIM-Signature:", 1)[-1].split(b"\r\n\r\n", 1)[0][:2000]
    domain_match = _DKIM_DOMAIN.search(b";" + header)
    selector_match = _DKIM_SELECTOR.search(b";" + header)
    return (
        domain_match.group(1).decode("ascii", "replace") if domain_match else "",
        selector_match.group(1).decode("ascii", "replace") if selector_match else "",
    )


# --------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------


async def check_dmarc(
    from_domain: str, spf: SPFResult, dkim: DKIMResult
) -> DMARCResult:
    """Evaluate DMARC alignment and look up the published policy.

    DMARC passes when *either* SPF or DKIM passes **and** its domain
    aligns with the From header. Alignment is the point: SPF passing for
    a domain the sender happens to control says nothing about whether
    they may use this From address.
    """
    if not from_domain:
        return DMARCResult(Result.NONE)

    policy = await _dmarc_policy(from_domain)
    if policy is None:
        return DMARCResult(Result.NONE)

    aligned_spf = spf.result is Result.PASS and _aligned(spf.domain, from_domain)
    aligned_dkim = dkim.result is Result.PASS and _aligned(dkim.domain, from_domain)

    if aligned_spf or aligned_dkim:
        result = Result.PASS
    elif spf.result is Result.TEMPERROR or dkim.result is Result.TEMPERROR:
        # Could not complete the checks DMARC depends on.
        result = Result.TEMPERROR
    else:
        result = Result.FAIL

    return DMARCResult(
        result=result,
        policy=policy,
        aligned_spf=aligned_spf,
        aligned_dkim=aligned_dkim,
    )


def _aligned(candidate: str, from_domain: str) -> bool:
    """Relaxed alignment: the organizational domain must match.

    Strict alignment would reject mail signed by a subdomain, which is
    common and legitimate.
    """
    if not candidate:
        return False
    candidate, from_domain = candidate.lower().rstrip("."), from_domain.lower().rstrip(".")
    if candidate == from_domain:
        return True
    return candidate.endswith("." + from_domain) or from_domain.endswith(
        "." + candidate
    )


async def _dmarc_policy(domain: str) -> str | None:
    """The p= value from a domain's _dmarc TXT record, if published."""
    try:
        import dns.asyncresolver
    except ImportError:  # pragma: no cover - depends on install
        return None

    try:
        answers = await asyncio.wait_for(
            dns.asyncresolver.resolve(f"_dmarc.{domain}", "TXT"),
            timeout=DNS_TIMEOUT,
        )
    except Exception:
        return None

    for record in answers:
        text = b"".join(record.strings).decode("ascii", "replace")
        if not text.lower().startswith("v=dmarc1"):
            continue
        for tag in text.split(";"):
            name, _, value = tag.partition("=")
            if name.strip().lower() == "p":
                return value.strip().lower() or "none"
        return "none"
    return None


def from_domain_of(raw: bytes) -> str:
    """The domain of a message's From header."""
    from email import message_from_bytes
    from email.utils import parseaddr

    try:
        header = message_from_bytes(raw).get("From", "")
    except Exception:
        return ""
    _, address = parseaddr(str(header))
    return address.split("@", 1)[1].lower() if "@" in address else ""


__all__ = [
    "DNS_TIMEOUT",
    "DKIMResult",
    "DMARCResult",
    "Result",
    "SPFResult",
    "check_dkim",
    "check_dmarc",
    "check_spf",
    "from_domain_of",
]
