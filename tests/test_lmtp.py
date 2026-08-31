"""LMTP delivery into Dovecot, against a scripted fake server."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from email.message import EmailMessage

import pytest
import pytest_asyncio

from lightr.config import DovecotConfig
from lightr.dovecot.lmtp import LMTPClient, LMTPError, _dot_stuff


class FakeLMTPServer:
    """A minimal LMTP server that records what it was sent."""

    def __init__(self, *, rcpt_codes: dict[str, int] | None = None,
                 data_codes: list[int] | None = None) -> None:
        self.rcpt_codes = rcpt_codes or {}
        self.data_codes = data_codes
        self.received: list[str] = []
        self.body = b""
        self.server: asyncio.AbstractServer | None = None
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        accepted: list[str] = []
        writer.write(b"220 dovecot LMTP ready\r\n")
        await writer.drain()

        while True:
            raw = await reader.readline()
            if not raw:
                break
            line = raw.decode().strip()
            self.received.append(line)
            upper = line.upper()

            if upper.startswith("LHLO"):
                writer.write(b"250-dovecot\r\n250 PIPELINING\r\n")
            elif upper.startswith("MAIL FROM"):
                writer.write(b"250 2.1.0 OK\r\n")
            elif upper.startswith("RCPT TO"):
                rcpt = line.split("<", 1)[1].rstrip(">")
                code = self.rcpt_codes.get(rcpt, 250)
                if 200 <= code < 300:
                    accepted.append(rcpt)
                writer.write(f"{code} recipient\r\n".encode())
            elif upper == "DATA":
                writer.write(b"354 End with .\r\n")
                await writer.drain()
                chunks: list[bytes] = []
                while True:
                    data_line = await reader.readline()
                    if not data_line or data_line.strip() == b".":
                        break
                    chunks.append(data_line)
                self.body = b"".join(chunks)
                codes = self.data_codes or [250] * len(accepted)
                for code in codes[: len(accepted)]:
                    writer.write(f"{code} 2.0.0 delivered\r\n".encode())
            elif upper == "QUIT":
                writer.write(b"221 bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"500 unknown\r\n")
            await writer.drain()

        writer.close()


@pytest_asyncio.fixture
async def server() -> AsyncIterator[FakeLMTPServer]:
    srv = FakeLMTPServer()
    await srv.start()
    yield srv
    await srv.stop()


def _cfg(port: int) -> DovecotConfig:
    # Force TCP: unix sockets do not exist on every dev machine.
    return DovecotConfig(lmtp_socket=None, lmtp_host="127.0.0.1", lmtp_port=port)


def _message(subject: str = "Hello") -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "sender@example.test"
    msg["To"] = "ops@acme.test"
    msg["Subject"] = subject
    msg.set_content("Body text.")
    return msg


class TestDelivery:
    async def test_single_recipient_succeeds(self, server: FakeLMTPServer) -> None:
        result = await LMTPClient(_cfg(server.port)).deliver(
            "sender@example.test", ["ops@acme.test"], _message()
        )

        assert result.all_ok
        assert result.delivered == ["ops@acme.test"]

    async def test_protocol_sequence_is_lmtp_not_smtp(
        self, server: FakeLMTPServer
    ) -> None:
        await LMTPClient(_cfg(server.port)).deliver(
            "sender@example.test", ["ops@acme.test"], _message()
        )

        assert any(line.startswith("LHLO") for line in server.received)
        assert not any(line.startswith("EHLO") for line in server.received)

    async def test_message_body_arrives(self, server: FakeLMTPServer) -> None:
        await LMTPClient(_cfg(server.port)).deliver(
            "sender@example.test", ["ops@acme.test"], _message("Invoice 42")
        )

        assert b"Invoice 42" in server.body
        assert b"Body text." in server.body

    async def test_bytes_payload_is_accepted(self, server: FakeLMTPServer) -> None:
        raw = b"Subject: Raw\r\n\r\nprecomposed"
        await LMTPClient(_cfg(server.port)).deliver(
            "sender@example.test", ["ops@acme.test"], raw
        )
        assert b"precomposed" in server.body


class TestPerRecipientStatus:
    """LMTP reports one status per recipient -- the reason it isn't SMTP."""

    async def test_partial_failure_is_reported_per_recipient(self) -> None:
        srv = FakeLMTPServer(rcpt_codes={"full@acme.test": 452})
        await srv.start()
        try:
            result = await LMTPClient(_cfg(srv.port)).deliver(
                "sender@example.test",
                ["ops@acme.test", "full@acme.test", "team@acme.test"],
                _message(),
            )
        finally:
            await srv.stop()

        assert sorted(result.delivered) == ["ops@acme.test", "team@acme.test"]
        assert [f.recipient for f in result.failed] == ["full@acme.test"]
        assert not result.all_ok

    async def test_transient_failures_are_marked_retryable(self) -> None:
        srv = FakeLMTPServer(rcpt_codes={"busy@acme.test": 451})
        await srv.start()
        try:
            result = await LMTPClient(_cfg(srv.port)).deliver(
                "s@example.test", ["busy@acme.test"], _message()
            )
        finally:
            await srv.stop()

        assert [s.recipient for s in result.retryable] == ["busy@acme.test"]

    async def test_permanent_failures_are_not_retryable(self) -> None:
        srv = FakeLMTPServer(rcpt_codes={"gone@acme.test": 550})
        await srv.start()
        try:
            result = await LMTPClient(_cfg(srv.port)).deliver(
                "s@example.test", ["gone@acme.test"], _message()
            )
        finally:
            await srv.stop()

        assert result.failed
        assert result.retryable == []

    async def test_post_data_failure_for_one_of_two(self) -> None:
        """Dovecot accepted both at RCPT, then failed one at DATA."""
        srv = FakeLMTPServer(data_codes=[250, 552])
        await srv.start()
        try:
            result = await LMTPClient(_cfg(srv.port)).deliver(
                "s@example.test", ["a@acme.test", "b@acme.test"], _message()
            )
        finally:
            await srv.stop()

        assert result.delivered == ["a@acme.test"]
        assert [f.recipient for f in result.failed] == ["b@acme.test"]

    async def test_all_recipients_rejected_skips_data(self) -> None:
        srv = FakeLMTPServer(rcpt_codes={"gone@acme.test": 550})
        await srv.start()
        try:
            result = await LMTPClient(_cfg(srv.port)).deliver(
                "s@example.test", ["gone@acme.test"], _message()
            )
        finally:
            await srv.stop()

        assert "DATA" not in srv.received
        assert result.delivered == []


class TestErrors:
    async def test_no_recipients_is_rejected(self) -> None:
        with pytest.raises(LMTPError, match="no recipients"):
            await LMTPClient(_cfg(9)).deliver("s@example.test", [], _message())

    async def test_unreachable_server_is_reported_clearly(self) -> None:
        # Port 1 is reserved and never listening.
        with pytest.raises(LMTPError, match="cannot reach Dovecot LMTP"):
            await LMTPClient(_cfg(1)).deliver(
                "s@example.test", ["ops@acme.test"], _message()
            )


class TestDotStuffing:
    def test_leading_dot_is_escaped(self) -> None:
        """A body line of '.' would otherwise terminate the message."""
        assert _dot_stuff(b"line\n.\nmore") == b"line\r\n..\r\nmore"

    def test_line_endings_are_normalised_to_crlf(self) -> None:
        assert _dot_stuff(b"a\nb\r\nc\rd") == b"a\r\nb\r\nc\r\nd"

    def test_ordinary_text_is_unchanged_apart_from_endings(self) -> None:
        assert _dot_stuff(b"hello world") == b"hello world"

    def test_dot_mid_line_is_untouched(self) -> None:
        assert _dot_stuff(b"a.b") == b"a.b"
