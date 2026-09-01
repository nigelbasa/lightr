"""Headers Lightr injects before handing a message to Dovecot.

This is the contract between Lightr's analysis and the Sieve scripts
Dovecot runs. Sieve cannot compute a spam score or verify SPF, so
Lightr does that work on the way in and writes the result into headers
the generated scripts test against.

Rewriting rules:

* Lightr's own headers are **replaced**, never appended to. A message
  arriving with a forged ``X-Spam-Score: 0`` must not survive into the
  mailbox, or a sender could opt themselves out of filtering.
* ``Received`` is prepended, per RFC 5321.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import Message
from email.utils import format_datetime, make_msgid

from lightr.dovecot.sieve import (
    HEADER_AUTH_RESULTS,
    HEADER_HAS_ATTACHMENT,
    HEADER_SPAM_FLAG,
    HEADER_SPAM_SCORE,
)

#: Every header Lightr controls. Stripped from inbound mail before the
#: engine writes its own, so an external sender cannot forge them.
CONTROLLED_HEADERS = (
    HEADER_SPAM_SCORE,
    HEADER_SPAM_FLAG,
    HEADER_HAS_ATTACHMENT,
    HEADER_AUTH_RESULTS,
    "X-Lightr-Spam-Reasons",
)


@dataclass(slots=True)
class AuthResults:
    """The outcome of SPF, DKIM, and DMARC evaluation."""

    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    mail_from: str = ""
    helo: str = ""

    def render(self, hostname: str) -> str:
        """An RFC 8601 Authentication-Results header value."""
        parts = [hostname]
        if self.spf != "none":
            smtp_from = f" smtp.mailfrom={self.mail_from}" if self.mail_from else ""
            parts.append(f"spf={self.spf}{smtp_from}")
        else:
            parts.append("spf=none")
        parts.append(f"dkim={self.dkim}")
        parts.append(f"dmarc={self.dmarc}")
        return "; ".join(parts)


@dataclass(slots=True)
class Analysis:
    """Everything Lightr worked out about a message."""

    score: float = 0.0
    is_spam: bool = False
    reasons: list[str] = field(default_factory=list)
    auth: AuthResults = field(default_factory=AuthResults)
    has_attachment: bool = False


def strip_controlled(message: Message) -> list[str]:
    """Remove headers Lightr owns. Returns what was removed.

    An inbound message claiming ``X-Spam-Score: 0`` is either confused
    or hostile; either way its claim must not reach Sieve.
    """
    removed: list[str] = []
    for name in CONTROLLED_HEADERS:
        while name in message:
            removed.append(name)
            del message[name]
    return removed


def has_attachment(message: Message) -> bool:
    """Whether the message carries a real attachment.

    Sieve cannot walk MIME structure portably, so Lightr decides and
    records the answer as a header.
    """
    if not message.is_multipart():
        return False
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment":
            return True
        if part.get_filename() and disposition != "inline":
            return True
    return False


def apply(message: Message, analysis: Analysis, hostname: str) -> Message:
    """Stamp Lightr's analysis onto the message, in place."""
    strip_controlled(message)

    message[HEADER_SPAM_SCORE] = f"{analysis.score:.1f}"
    message[HEADER_SPAM_FLAG] = "YES" if analysis.is_spam else "NO"
    message[HEADER_HAS_ATTACHMENT] = "yes" if analysis.has_attachment else "no"
    message[HEADER_AUTH_RESULTS] = analysis.auth.render(hostname)
    if analysis.reasons:
        message["X-Lightr-Spam-Reasons"] = ", ".join(analysis.reasons)

    return message


def add_received(
    message: Message,
    *,
    hostname: str,
    remote_ip: str,
    helo: str,
    recipient: str,
    protocol: str = "ESMTP",
) -> Message:
    """Prepend a Received header, as RFC 5321 requires."""
    stamp = format_datetime(datetime.now(UTC))
    value = (
        f"from {helo or remote_ip} ([{remote_ip}])\r\n"
        f"\tby {hostname} with {protocol} id {make_msgid(domain=hostname)}\r\n"
        f"\tfor <{recipient}>; {stamp}"
    )
    # Received must be the topmost header, and the stdlib email package
    # has no public API for prepending. Message._headers is the usual
    # way; guard it so a future change degrades to appending -- which
    # still records the hop, just out of order -- rather than losing
    # the trace entirely.
    headers = getattr(message, "_headers", None)
    if isinstance(headers, list):
        headers.insert(0, ("Received", value))
    else:  # pragma: no cover - only on a future stdlib change
        message["Received"] = value
    return message


def ensure_message_id(message: Message, hostname: str) -> Message:
    """Give a message an ID if it arrived without one."""
    if "Message-ID" not in message:
        message["Message-ID"] = make_msgid(domain=hostname)
    return message


def ensure_date(message: Message) -> Message:
    if "Date" not in message:
        message["Date"] = format_datetime(datetime.now(UTC))
    return message


__all__ = [
    "CONTROLLED_HEADERS",
    "Analysis",
    "AuthResults",
    "add_received",
    "apply",
    "ensure_date",
    "ensure_message_id",
    "has_attachment",
    "strip_controlled",
]
