"""LMTP delivery into Dovecot.

The handoff point. Lightr accepts mail on :25/:587, runs SPF, DKIM,
DMARC and spam analysis, resolves aliases, injects the headers the
generated Sieve scripts test against, and then hands the message to
Dovecot over LMTP. Dovecot writes it into Maildir and runs Sieve.

LMTP differs from SMTP in one way that matters here: it returns a
*separate* status per recipient after DATA. A message to three
mailboxes can succeed for two and fail for one, and the caller has to
be told which -- retrying the whole message would duplicate mail in
the two that worked.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from email.message import Message
from email.policy import SMTP as SMTP_POLICY

from lightr.config import DovecotConfig

# LMTP status classes we treat as retryable.
_TRANSIENT_PREFIX = "4"


class LMTPError(RuntimeError):
    """Delivery to Dovecot failed outright."""


@dataclass(frozen=True, slots=True)
class RecipientStatus:
    """The per-recipient outcome LMTP reports after DATA."""

    recipient: str
    code: int
    message: str

    @property
    def ok(self) -> bool:
        return 200 <= self.code < 300

    @property
    def retryable(self) -> bool:
        return str(self.code).startswith(_TRANSIENT_PREFIX)


@dataclass(slots=True)
class DeliveryResult:
    """Outcome of one LMTP transaction."""

    statuses: list[RecipientStatus] = field(default_factory=list)

    @property
    def delivered(self) -> list[str]:
        return [s.recipient for s in self.statuses if s.ok]

    @property
    def failed(self) -> list[RecipientStatus]:
        return [s for s in self.statuses if not s.ok]

    @property
    def retryable(self) -> list[RecipientStatus]:
        return [s for s in self.statuses if s.retryable]

    @property
    def all_ok(self) -> bool:
        return bool(self.statuses) and all(s.ok for s in self.statuses)


class LMTPClient:
    """Delivers messages to Dovecot's LMTP listener.

    Prefers the unix socket -- it avoids the network stack entirely and
    is what a default Dovecot install exposes.
    """

    def __init__(self, cfg: DovecotConfig, *, timeout: float = 30.0) -> None:
        self._cfg = cfg
        self._timeout = timeout

    async def deliver(
        self,
        sender: str,
        recipients: list[str],
        message: Message | bytes,
    ) -> DeliveryResult:
        """Deliver one message to one or more local mailboxes."""
        if not recipients:
            raise LMTPError("no recipients")

        payload = (
            message
            if isinstance(message, bytes)
            else message.as_bytes(policy=SMTP_POLICY)
        )

        try:
            return await asyncio.wait_for(
                self._transaction(sender, recipients, payload), self._timeout
            )
        except TimeoutError as exc:
            raise LMTPError(
                f"Dovecot did not respond within {self._timeout}s"
            ) from exc

    async def _transaction(
        self, sender: str, recipients: list[str], payload: bytes
    ) -> DeliveryResult:
        reader, writer = await self._connect()
        try:
            await self._expect(reader, 220)

            await self._command(writer, f"LHLO {self._cfg.imap_host}")
            await self._read_multiline(reader, 250)

            await self._command(writer, f"MAIL FROM:<{sender}>")
            await self._expect(reader, 250)

            accepted: list[str] = []
            rejected: list[RecipientStatus] = []
            for rcpt in recipients:
                await self._command(writer, f"RCPT TO:<{rcpt}>")
                code, text = await self._read_response(reader)
                if 200 <= code < 300:
                    accepted.append(rcpt)
                else:
                    rejected.append(RecipientStatus(rcpt, code, text))

            if not accepted:
                await self._quit(writer)
                return DeliveryResult(statuses=rejected)

            await self._command(writer, "DATA")
            await self._expect(reader, 354)

            writer.write(_dot_stuff(payload))
            writer.write(b"\r\n.\r\n")
            await writer.drain()

            # One response per accepted recipient, in order.
            statuses = list(rejected)
            for rcpt in accepted:
                code, text = await self._read_response(reader)
                statuses.append(RecipientStatus(rcpt, code, text))

            await self._quit(writer)
            return DeliveryResult(statuses=statuses)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            if self._cfg.uses_lmtp_socket:
                assert self._cfg.lmtp_socket is not None
                return await asyncio.open_unix_connection(str(self._cfg.lmtp_socket))
            return await asyncio.open_connection(self._cfg.lmtp_host, self._cfg.lmtp_port)
        except (OSError, NotImplementedError) as exc:
            target = (
                self._cfg.lmtp_socket
                if self._cfg.uses_lmtp_socket
                else f"{self._cfg.lmtp_host}:{self._cfg.lmtp_port}"
            )
            raise LMTPError(f"cannot reach Dovecot LMTP at {target}: {exc}") from exc

    @staticmethod
    async def _command(writer: asyncio.StreamWriter, line: str) -> None:
        writer.write(line.encode("utf-8") + b"\r\n")
        await writer.drain()

    @staticmethod
    async def _read_response(reader: asyncio.StreamReader) -> tuple[int, str]:
        line = await reader.readline()
        if not line:
            raise LMTPError("Dovecot closed the connection unexpectedly")
        text = line.decode("utf-8", "replace").strip()
        try:
            return int(text[:3]), text[4:]
        except ValueError as exc:
            raise LMTPError(f"malformed LMTP response: {text!r}") from exc

    async def _read_multiline(self, reader: asyncio.StreamReader, expect: int) -> None:
        """Consume a multi-line response such as the LHLO capability list."""
        while True:
            line = await reader.readline()
            if not line:
                raise LMTPError("Dovecot closed the connection during LHLO")
            text = line.decode("utf-8", "replace").strip()
            code = int(text[:3])
            if code != expect:
                raise LMTPError(f"LHLO refused: {text}")
            if len(text) < 4 or text[3] != "-":
                return

    async def _expect(self, reader: asyncio.StreamReader, code: int) -> str:
        got, text = await self._read_response(reader)
        if got != code:
            raise LMTPError(f"expected {code}, got {got} {text}")
        return text

    async def _quit(self, writer: asyncio.StreamWriter) -> None:
        try:
            await self._command(writer, "QUIT")
        except (ConnectionError, OSError):
            pass


def _dot_stuff(payload: bytes) -> bytes:
    """Escape leading dots and normalise line endings for the DATA phase.

    A body line of "." would otherwise end the message early.
    """
    normalised = payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = normalised.split(b"\n")
    stuffed = [b"." + line if line.startswith(b".") else line for line in lines]
    return b"\r\n".join(stuffed)


__all__ = ["DeliveryResult", "LMTPClient", "LMTPError", "RecipientStatus"]
