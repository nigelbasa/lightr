"""Server startup: address parsing and bind-failure reporting.

The address handling is tested carefully because getting it wrong is
silent: a server that binds only to loopback starts cleanly, logs
nothing unusual, and receives no mail from the internet.
"""

from __future__ import annotations

import asyncio
import datetime
import smtplib
import ssl
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.config import Config, DomainCertConfig
from lightr.server import (
    ANY_HOST,
    SHUTDOWN_GRACE_SECONDS,
    Server,
    ServerError,
    _bind_failure,
    parse_addr,
    tls_context,
)


class TestAddressParsing:
    @pytest.mark.parametrize(
        ("addr", "expected"),
        [
            (":25", (ANY_HOST, 25)),
            (":587", (ANY_HOST, 587)),
            ("", (ANY_HOST, 25)),
            ("   ", (ANY_HOST, 25)),
            ("127.0.0.1:2525", ("127.0.0.1", 2525)),
            ("localhost:8080", ("localhost", 8080)),
            ("localhost", ("localhost", 25)),
            ("0.0.0.0:25", ("0.0.0.0", 25)),
        ],
    )
    def test_parsing(self, addr: str, expected: tuple[str, int]) -> None:
        assert parse_addr(addr, 25) == expected

    def test_any_host_is_the_empty_string(self) -> None:
        """Not None, and not "0.0.0.0".

        None makes aiosmtpd bind IPv6 loopback only -- a production
        server would start cleanly and never receive external mail.
        "0.0.0.0" and "::" are rejected outright on some platforms.
        Only "" binds dual-stack.
        """
        assert ANY_HOST == ""
        assert ANY_HOST is not None

    def test_default_port_is_used_when_absent(self) -> None:
        assert parse_addr("mail.acme.test", 587)[1] == 587

    def test_explicit_port_beats_the_default(self) -> None:
        assert parse_addr(":2525", 25)[1] == 2525

    def test_ipv6_literal_with_a_port(self) -> None:
        """rpartition splits on the last colon, so a bracketed literal
        keeps its address intact."""
        host, port = parse_addr("[::1]:2525", 25)
        assert host == "[::1]"
        assert port == 2525


class TestBindFailureMessages:
    def test_privileged_port_explains_the_capability(self) -> None:
        message = _bind_failure("smtp", 25, OSError("permission denied"))
        assert "below 1024" in message
        assert "cap_net_bind_service" in message

    def test_high_port_does_not_claim_a_privilege_problem(self) -> None:
        """The first version said 'ports below 1024 need root' for every
        failure, which was actively misleading on a high port."""
        message = _bind_failure("smtp", 2525, OSError("address unavailable"))
        assert "below 1024" not in message
        assert "root" not in message

    @pytest.mark.parametrize("errno", [48, 98, 10048])
    def test_address_in_use_is_named(self, errno: int) -> None:
        exc = OSError("in use")
        exc.errno = errno
        assert "already listening" in _bind_failure("smtp", 2525, exc)

    def test_the_port_is_always_named(self) -> None:
        assert "2525" in _bind_failure("smtp", 2525, OSError("nope"))

    def test_the_underlying_error_survives(self) -> None:
        assert "nope" in _bind_failure("smtp", 2525, OSError("nope"))


class TestShutdown:
    def test_grace_period_is_generous_enough_to_finish_a_delivery(self) -> None:
        """The LMTP client's own timeout is 30s by default, so the
        grace period must not be so short that it always truncates."""
        assert SHUTDOWN_GRACE_SECONDS >= 20


def _self_signed(directory: Path, name: str) -> DomainCertConfig:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = directory / f"{name}.crt", directory / f"{name}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return DomainCertConfig(cert_file=cert_file, key_file=key_file)


def _common_name(der: bytes) -> str:
    cert = x509.load_der_x509_certificate(der)
    return str(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)


def _unverified_client() -> ssl.SSLContext:
    client = ssl.create_default_context()
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    return client


def _served_name(server: ssl.SSLContext, server_name: str | None) -> str:
    """Handshake in memory and return the CN of the certificate served."""
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = _unverified_client().wrap_bio(c_in, c_out, server_hostname=server_name)
    peer = server.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        for side in (client, peer):
            try:
                side.do_handshake()
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        try:
            client.do_handshake()
            break
        except ssl.SSLWantReadError:
            continue
    der = client.getpeercert(binary_form=True)
    assert der is not None
    return _common_name(der)


@pytest.fixture
def with_certs(cfg: Config, tmp_path: Path) -> Config:
    default = _self_signed(tmp_path, "mail.default.test")
    cfg.tls.cert_file, cfg.tls.key_file = default.cert_file, default.key_file
    cfg.tls.domain_certs = {"mail.other.test": _self_signed(tmp_path, "mail.other.test")}
    return cfg


class TestTLSContext:
    def test_no_certificate_means_no_starttls(self, cfg: Config, tmp_path: Path) -> None:
        cfg.tls.cert_file = tmp_path / "missing.crt"
        cfg.tls.key_file = tmp_path / "missing.key"
        assert tls_context(cfg) is None

    def test_sni_picks_the_domain_certificate(self, with_certs: Config) -> None:
        context = tls_context(with_certs)
        assert context is not None
        assert _served_name(context, "mail.other.test") == "mail.other.test"
        assert _served_name(context, "MAIL.OTHER.TEST.") == "mail.other.test"

    def test_unknown_or_absent_sni_gets_the_default(self, with_certs: Config) -> None:
        context = tls_context(with_certs)
        assert context is not None
        assert _served_name(context, "elsewhere.test") == "mail.default.test"
        assert _served_name(context, None) == "mail.default.test"

    def test_a_certificate_that_will_not_load_stops_the_engine(
        self, with_certs: Config
    ) -> None:
        assert with_certs.tls.key_file is not None
        with_certs.tls.key_file.write_text("not a key")
        with pytest.raises(ServerError, match="cannot load the TLS certificate"):
            tls_context(with_certs)


class TestSMTPListeners:
    """The listeners, over real sockets.

    Both bugs here reached production: the listeners ran on aiosmtpd's
    private thread loops, so every RCPT on Postgres failed with a
    permanent 500, and neither listener was given a TLS context, so
    STARTTLS was never offered.
    """

    async def test_starttls_offered_and_rcpt_runs_on_the_server_loop(
        self,
        with_certs: Config,
        engine: AsyncEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        loops: list[asyncio.AbstractEventLoop] = []

        class RecordingRouter:
            def __init__(self, conn: object) -> None:
                pass

            async def route(self, address: str) -> SimpleNamespace:
                loops.append(asyncio.get_running_loop())
                return SimpleNamespace(rejected=False, reason=None)

        monkeypatch.setattr("lightr.mail.smtp.Router", RecordingRouter)
        with_certs.smtp.addr = "127.0.0.1:0"
        with_certs.smtp.submission_addr = "127.0.0.1:0"

        server = Server(with_certs, engine=engine)
        await server._start_smtp()
        try:
            receive_port, submission_port = server.smtp_ports

            def converse(port: int) -> tuple[bool, int, bool]:
                with smtplib.SMTP("127.0.0.1", port, timeout=10) as client:
                    client.ehlo("client.test")
                    offered = client.has_extn("starttls")
                    client.starttls(context=_unverified_client())
                    client.ehlo("client.test")
                    code = client.mail("sender@example.test")[0]
                    if port == receive_port:
                        code = client.rcpt("someone@acme.test")[0]
                    return offered, code, client.has_extn("auth")

            offered, code, _ = await asyncio.to_thread(converse, receive_port)
            assert offered
            assert code == 250
            assert loops == [asyncio.get_running_loop()]

            offered, _, auth = await asyncio.to_thread(converse, submission_port)
            assert offered
            assert auth, "AUTH is advertised once the session is encrypted"
        finally:
            await server.stop()
