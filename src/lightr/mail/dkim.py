"""DKIM key generation and signing.

Signing is what stops outbound mail landing in spam folders, so the
failure mode that matters most is signing *wrongly* -- a broken
signature is worse than none, because it turns a neutral verdict into
a failure. Anything that cannot be signed correctly is therefore sent
unsigned, with a warning, rather than signed badly.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass

log = logging.getLogger("lightr.dkim")

DEFAULT_SELECTOR = "default"
DEFAULT_KEY_BITS = 2048

#: Headers worth signing. Over-signing a header that is absent breaks
#: verification, so this is the set that is reliably present plus the
#: ones a forger would want to change.
SIGNED_HEADERS = (
    b"From",
    b"To",
    b"Subject",
    b"Date",
    b"Message-ID",
    b"MIME-Version",
    b"Content-Type",
)


class DKIMError(RuntimeError):
    """A key could not be generated, or a message could not be signed."""


@dataclass(frozen=True, slots=True)
class DKIMKey:
    """A generated key pair, with the DNS record to publish."""

    selector: str
    private_key_pem: str
    public_key_b64: str
    bits: int

    def dns_name(self, domain: str) -> str:
        return f"{self.selector}._domainkey.{domain}"

    def dns_value(self) -> str:
        return f"v=DKIM1; k=rsa; p={self.public_key_b64}"

    def dns_record(self, domain: str) -> str:
        """The full TXT record an operator publishes."""
        return f'{self.dns_name(domain)}. IN TXT "{self.dns_value()}"'


def generate_key(
    selector: str = DEFAULT_SELECTOR, bits: int = DEFAULT_KEY_BITS
) -> DKIMKey:
    """Generate an RSA key pair for DKIM signing.

    2048 bits by default. 1024 is still widely accepted but is no
    longer considered adequate; anything below that is refused rather
    than silently producing a weak key.
    """
    if bits < 1024:
        raise DKIMError(f"{bits}-bit DKIM keys are too weak; use 2048")

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as exc:  # pragma: no cover - depends on install
        raise DKIMError(
            "DKIM key generation needs the 'cryptography' package"
        ) from exc

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return DKIMKey(
        selector=selector,
        private_key_pem=private_pem,
        public_key_b64=base64.b64encode(public_der).decode("ascii"),
        bits=bits,
    )


def sign(
    message: bytes,
    *,
    domain: str,
    selector: str,
    private_key_pem: str,
) -> bytes:
    """Return ``message`` with a DKIM-Signature header prepended.

    Raises DKIMError if signing fails. Callers on the sending path
    should catch it and send unsigned -- an invalid signature is worse
    than no signature.
    """
    if not private_key_pem:
        raise DKIMError(f"no DKIM private key configured for {domain}")

    try:
        import dkim as dkimpy
    except ImportError as exc:  # pragma: no cover - depends on install
        raise DKIMError("DKIM signing needs the 'dkimpy' package") from exc

    try:
        signature = dkimpy.sign(
            message=message,
            selector=selector.encode("ascii"),
            domain=domain.encode("ascii"),
            privkey=private_key_pem.encode("ascii"),
            include_headers=[h for h in SIGNED_HEADERS if _has_header(message, h)],
        )
    except Exception as exc:
        raise DKIMError(f"could not sign for {domain}: {exc}") from exc

    return signature + message


def sign_or_warn(
    message: bytes, *, domain: str, selector: str, private_key_pem: str
) -> bytes:
    """Sign if possible; otherwise return the message untouched.

    Used on the sending path, where refusing to send would be a worse
    outcome than sending unsigned.
    """
    try:
        return sign(
            message, domain=domain, selector=selector, private_key_pem=private_key_pem
        )
    except DKIMError as exc:
        log.warning("sending unsigned: %s", exc)
        return message


def _has_header(message: bytes, header: bytes) -> bool:
    """Whether a header is present, without parsing the whole message.

    Signing a header that is not there causes verifiers to fail the
    signature, so the header list is filtered to what actually exists.
    """
    needle = header.lower() + b":"
    for line in message.split(b"\n"):
        if not line.strip():
            break  # end of headers
        if line.lower().startswith(needle):
            return True
    return False


__all__ = [
    "DEFAULT_KEY_BITS",
    "DEFAULT_SELECTOR",
    "SIGNED_HEADERS",
    "DKIMError",
    "DKIMKey",
    "generate_key",
    "sign",
    "sign_or_warn",
]
