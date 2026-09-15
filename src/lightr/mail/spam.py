"""Spam scoring.

A small additive scorer: each signal contributes points, and the total
crosses a configurable threshold. It is not trying to beat rspamd --
where rspamd is configured, Lightr defers to it. This exists so that a
default install still classifies mail rather than marking everything
clean.

Two design rules:

* **Authentication failures dominate.** A forged sender is the single
  strongest signal available, and it is cheap and reliable.
* **Nothing scores so high on its own that one heuristic can junk
  legitimate mail.** Content heuristics are weak evidence and are
  weighted accordingly; the thresholds assume several must agree.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from email.message import Message

from lightr.config import SpamConfig
from lightr.mail.authentication import DKIMResult, DMARCResult, Result, SPFResult
from lightr.mail.reputation import Listing

log = logging.getLogger("lightr.spam")


@dataclass(slots=True)
class Score:
    """An accumulated spam score with its reasons."""

    points: float = 0.0
    reasons: list[str] = field(default_factory=list)

    def add(self, points: float, reason: str) -> None:
        if points:
            self.points += points
            self.reasons.append(f"{reason} ({points:+.1f})")

    def verdict(self, cfg: SpamConfig) -> tuple[bool, bool]:
        """Returns (is_suspicious, is_junk)."""
        return self.points >= cfg.suspicious_threshold, self.points >= cfg.junk_threshold


#: Authentication signals. A DMARC failure where the domain publishes
#: p=reject is the strongest thing we can observe.
SPF_FAIL = 3.0
SPF_SOFTFAIL = 1.0
DKIM_FAIL = 2.5
DMARC_FAIL = 3.5
DMARC_FAIL_REJECT = 5.0
NO_AUTHENTICATION_AT_ALL = 0.5

#: Content signals, weighted low on purpose.
NO_MESSAGE_ID = 0.5
NO_DATE = 0.5
SUBJECT_ALL_CAPS = 0.7
EXCESSIVE_PUNCTUATION = 0.5
HTML_ONLY = 0.5
SUSPICIOUS_ATTACHMENT = 2.0
MANY_RECIPIENTS = 0.5
EMPTY_BODY = 0.7

#: Reputation lists. One listed address is not enough to junk mail on
#: its own (under the default 4.0); a listing plus a failed check, or
#: two lists agreeing, is. Capped so a dozen lists naming the same
#: sender count as strong evidence, not as a dozen times it.
BLOCKLISTED_ADDRESS = 3.0
BLOCKLISTED_DOMAIN = 2.5
BLOCKLIST_CAP = 6.0

#: Extensions that are executable on a common desktop. Weighted high
#: because the cost of a false negative here is malware, not annoyance.
DANGEROUS_EXTENSIONS = frozenset({
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".jar", ".lnk", ".ps1",
})

_ALL_CAPS = re.compile(r"^[^a-z]*[A-Z]{4,}[^a-z]*$")
_PUNCTUATION = re.compile(r"[!?]{3,}")


def score_message(
    message: Message,
    *,
    spf: SPFResult,
    dkim: DKIMResult,
    dmarc: DMARCResult,
    recipient_count: int = 1,
    listings: Iterable[Listing] = (),
) -> Score:
    """Score a message from its authentication results, content, and
    any reputation-list listings found for it."""
    score = Score()
    _score_authentication(score, spf, dkim, dmarc)
    _score_reputation(score, listings)
    _score_headers(score, message, recipient_count)
    _score_content(score, message)
    return score


def _score_reputation(score: Score, listings: Iterable[Listing]) -> None:
    remaining = BLOCKLIST_CAP
    for listing in listings:
        points = min(
            BLOCKLISTED_ADDRESS if listing.is_address else BLOCKLISTED_DOMAIN,
            remaining,
        )
        if points <= 0:
            break
        score.add(points, listing.reason)
        remaining -= points


def _score_authentication(
    score: Score, spf: SPFResult, dkim: DKIMResult, dmarc: DMARCResult
) -> None:
    if spf.result is Result.FAIL:
        score.add(SPF_FAIL, "spf=fail")
    elif spf.result is Result.SOFTFAIL:
        score.add(SPF_SOFTFAIL, "spf=softfail")

    if dkim.result is Result.FAIL:
        score.add(DKIM_FAIL, "dkim=fail")

    if dmarc.result is Result.FAIL:
        if dmarc.policy == "reject":
            score.add(DMARC_FAIL_REJECT, "dmarc=fail p=reject")
        else:
            score.add(DMARC_FAIL, "dmarc=fail")

    # Nothing to verify at all is mildly suspicious in 2026, but only
    # mildly -- plenty of small senders still publish nothing.
    if all(
        r.is_inconclusive for r in (spf.result, dkim.result, dmarc.result)
    ) and spf.result is Result.NONE:
        score.add(NO_AUTHENTICATION_AT_ALL, "no spf, dkim, or dmarc")


def _score_headers(score: Score, message: Message, recipient_count: int) -> None:
    if "Message-ID" not in message:
        score.add(NO_MESSAGE_ID, "no message-id")
    if "Date" not in message:
        score.add(NO_DATE, "no date header")

    subject = str(message.get("Subject", "") or "")
    if subject:
        if len(subject) > 8 and _ALL_CAPS.match(subject):
            score.add(SUBJECT_ALL_CAPS, "subject is all caps")
        if _PUNCTUATION.search(subject):
            score.add(EXCESSIVE_PUNCTUATION, "excessive punctuation in subject")

    if recipient_count > 20:
        score.add(MANY_RECIPIENTS, f"{recipient_count} recipients")


def _score_content(score: Score, message: Message) -> None:
    has_text = False
    has_html = False
    body_length = 0

    for part in message.walk():
        content_type = part.get_content_type()
        if content_type == "text/plain":
            has_text = True
            payload = part.get_payload(decode=True)
            body_length += len(payload or b"")
        elif content_type == "text/html":
            has_html = True
            payload = part.get_payload(decode=True)
            body_length += len(payload or b"")

        filename = part.get_filename()
        if filename:
            lowered = filename.lower()
            for extension in DANGEROUS_EXTENSIONS:
                if lowered.endswith(extension):
                    score.add(SUSPICIOUS_ATTACHMENT, f"executable attachment {extension}")
                    break

    if has_html and not has_text:
        score.add(HTML_ONLY, "html with no plain-text alternative")
    if body_length == 0:
        score.add(EMPTY_BODY, "empty body")


class RspamdClient:
    """Defers scoring to rspamd when one is configured.

    Lightr's own scorer is a floor, not a ceiling: an operator who runs
    rspamd should get rspamd's verdict.
    """

    def __init__(self, cfg: SpamConfig) -> None:
        self._url = cfg.rspamd_url.rstrip("/")
        self._password = cfg.rspamd_password
        self._timeout = cfg.timeout_seconds

    @property
    def configured(self) -> bool:
        return bool(self._url)

    async def score(self, raw: bytes) -> Score | None:
        """Ask rspamd. Returns None if it is unreachable or unconfigured.

        A None means "fall back to the local scorer" -- rspamd being
        down must not mean every message is treated as clean.
        """
        if not self.configured:
            return None

        try:
            import httpx
        except ImportError:  # pragma: no cover - depends on install
            return None

        headers = {"Password": self._password} if self._password else {}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._url}/checkv2", content=raw, headers=headers
                )
                response.raise_for_status()
                body = response.json()
        except Exception as exc:
            log.warning("rspamd unavailable, using the local scorer: %s", exc)
            return None

        score = Score(points=float(body.get("score", 0.0)))
        symbols = body.get("symbols") or {}
        if isinstance(symbols, dict):
            score.reasons = [
                f"{name} ({data.get('score', 0):+.1f})"
                for name, data in list(symbols.items())[:10]
                if isinstance(data, dict)
            ]
        return score


__all__ = [
    "DANGEROUS_EXTENSIONS",
    "RspamdClient",
    "Score",
    "score_message",
]
