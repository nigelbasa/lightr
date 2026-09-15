"""Running the engine.

Starts the HTTP API, the two SMTP listeners, and the outbound sender in
one asyncio process, and shuts them down in an order that does not lose
mail: stop accepting first, then let in-flight work finish, then close
the database.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import ssl
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.config import Config
from lightr.db.engine import create_engine
from lightr.mail.sender import Sender
from lightr.mail.smtp import LightrHandler

log = logging.getLogger("lightr.server")

#: How long to let in-flight deliveries finish before giving up.
SHUTDOWN_GRACE_SECONDS = 20.0


#: What a config address of ":25" means: every interface.
#:
#: The empty string, specifically. The three plausible alternatives are
#: all wrong: ``None`` makes aiosmtpd bind IPv6 *loopback only*, so a
#: production server would silently receive no mail from the internet;
#: ``"0.0.0.0"`` and ``"::"`` are rejected outright by aiosmtpd on some
#: platforms. Only "" binds dual-stack 0.0.0.0 and [::].
ANY_HOST = ""


def parse_addr(addr: str, default_port: int) -> tuple[str, int]:
    """Split a ``host:port`` or ``:port`` binding into its parts.

    A missing or empty host means every interface -- see ANY_HOST.
    """
    value = addr.strip()
    if not value:
        return ANY_HOST, default_port
    if value.startswith(":"):
        return ANY_HOST, int(value[1:])
    if ":" not in value:
        return value, default_port
    host, _, port = value.rpartition(":")
    return (host or ANY_HOST), int(port)


@dataclass
class Server:
    """The running engine."""

    cfg: Config
    engine: AsyncEngine | None = None
    _controllers: list[object] = field(default_factory=list)
    _handlers: list[object] = field(default_factory=list)
    _tasks: list[asyncio.Task] = field(default_factory=list)
    _sender: Sender | None = None
    _stopping: asyncio.Event = field(default_factory=asyncio.Event)

    async def start(self) -> None:
        """Bring every listener up."""
        self.engine = self.engine or create_engine(self.cfg)

        await self._start_smtp()
        self._start_sender()
        await self._start_http()

        log.info("lightr is up as %s", self.cfg.server.hostname)

    async def _start_smtp(self) -> None:
        # Served on this process's own event loop, not through aiosmtpd's
        # Controller. The Controller runs each listener on a private loop
        # in a thread, and asyncpg connections belong to the loop that
        # opened them: on Postgres every RCPT failed with "another
        # operation is in progress" and senders got a permanent 500.
        # SQLite hid it, because aiosqlite works from any loop.
        from aiosmtpd.smtp import SMTP

        assert self.engine is not None
        loop = asyncio.get_running_loop()

        receive_host, receive_port = parse_addr(self.cfg.smtp.addr, 25)
        submit_host, submit_port = parse_addr(self.cfg.smtp.submission_addr, 587)

        receive_handler = LightrHandler(self.cfg, self.engine, require_auth=False)
        submission_handler = LightrHandler(self.cfg, self.engine, require_auth=True)
        self._handlers = [receive_handler, submission_handler]

        tls = tls_context(self.cfg)
        ident = f"lightr {self.cfg.server.hostname}"

        listeners = (
            # :25 takes mail from the internet and must never relay.
            ("smtp", receive_handler, receive_host, receive_port, {}),
            # :587 is for authenticated users and may send anywhere.
            # No authenticator= here on purpose: aiosmtpd calls that
            # synchronously and would not await our check. The handler
            # implements auth_PLAIN / auth_LOGIN instead, which are
            # awaited. See the comment in mail/smtp.py.
            (
                "submission",
                submission_handler,
                submit_host,
                submit_port,
                {"auth_require_tls": self.cfg.security.require_tls_for_auth},
            ),
        )
        for label, handler, host, port, extra in listeners:

            def protocol(handler: LightrHandler = handler, extra: dict = extra) -> SMTP:
                return SMTP(
                    handler,
                    hostname=self.cfg.server.hostname,
                    ident=ident,
                    tls_context=tls,
                    loop=loop,
                    **extra,
                )

            try:
                listener = await loop.create_server(protocol, host=host, port=port)
            except OSError as exc:
                raise ServerError(_bind_failure(label, port, exc)) from exc
            self._controllers.append(listener)

        log.info("smtp on %s:%s, submission on %s:%s (STARTTLS %s)",
                 receive_host, receive_port, submit_host, submit_port,
                 "on" if tls is not None else "OFF")

    @property
    def smtp_ports(self) -> list[int]:
        """The ports the SMTP listeners bound, in start order."""
        return [
            listener.sockets[0].getsockname()[1]  # type: ignore[attr-defined]
            for listener in self._controllers
        ]

    def _start_sender(self) -> None:
        assert self.engine is not None
        self._sender = Sender(self.cfg, self.engine)
        self._tasks.append(asyncio.create_task(self._sender.run(), name="sender"))

    async def _start_http(self) -> None:
        import uvicorn

        from lightr.api.app import create_app

        assert self.engine is not None
        host, port = parse_addr(self.cfg.http.addr, 8080)

        config = uvicorn.Config(
            create_app(self.cfg, engine=self.engine),
            host=host or "0.0.0.0",
            port=port,
            log_level=self.cfg.logging.level.lower(),
            access_log=False,
        )
        server = uvicorn.Server(config)
        self._tasks.append(asyncio.create_task(server.serve(), name="http"))
        self._uvicorn = server  # type: ignore[attr-defined]
        log.info("http on %s:%s", host, port)

    async def serve_forever(self) -> None:
        """Run until a signal arrives."""
        await self.start()
        self._install_signal_handlers()
        await self._stopping.wait()
        await self.stop()

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError, AttributeError):
                loop.add_signal_handler(sig, self._stopping.set)

    async def stop(self) -> None:
        """Shut down without losing in-flight mail.

        Order matters: stop accepting new connections first, so nothing
        new arrives while in-flight deliveries finish, and only then
        close the database everything depends on.
        """
        log.info("shutting down")

        for listener in self._controllers:
            listener.close()  # type: ignore[attr-defined]
        for listener in self._controllers:
            # wait_closed() also waits for open sessions on 3.12+; a
            # client idling mid-transaction must not hold up shutdown.
            with contextlib.suppress(Exception):
                await asyncio.wait_for(
                    listener.wait_closed(), timeout=5.0  # type: ignore[attr-defined]
                )
        self._controllers.clear()

        if self._sender is not None:
            self._sender.stop()

        # In-flight webhook deliveries are fire-and-forget tasks. Give
        # them a moment to land: dropping them here would silently lose
        # events on every restart.
        for handler in self._handlers:
            emitter = getattr(handler, "webhooks", None)
            if emitter is not None:
                with contextlib.suppress(Exception):
                    await emitter.drain(timeout=5.0)
        self._handlers.clear()

        server = getattr(self, "_uvicorn", None)
        if server is not None:
            server.should_exit = True

        if self._tasks:
            done, pending = await asyncio.wait(
                self._tasks, timeout=SHUTDOWN_GRACE_SECONDS
            )
            for task in pending:
                log.warning("forcing %s to stop", task.get_name())
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            del done
        self._tasks.clear()

        if self.engine is not None:
            await self.engine.dispose()
        log.info("stopped")


def tls_context(cfg: Config) -> ssl.SSLContext | None:
    """The STARTTLS context for both SMTP listeners.

    Serves ``tls.cert_file`` by default, and a ``tls.domain_certs`` entry
    when the client's SNI names that host. Missing files leave STARTTLS
    off with a warning -- a development box has no certificate -- but a
    certificate that exists and will not load stops the engine: a
    production server quietly offering no TLS is worse than one that
    refuses to start.
    """
    if not _present(cfg.tls.cert_file, cfg.tls.key_file):
        log.warning(
            "no TLS certificate at %s; SMTP will not offer STARTTLS", cfg.tls.cert_file
        )
        return None
    assert cfg.tls.cert_file is not None and cfg.tls.key_file is not None
    default = _load_context(cfg.tls.cert_file, cfg.tls.key_file)

    by_name: dict[str, ssl.SSLContext] = {}
    for name, cert in cfg.tls.domain_certs.items():
        if not _present(cert.cert_file, cert.key_file):
            log.warning(
                "no certificate for %s at %s; it will be offered the default",
                name, cert.cert_file,
            )
            continue
        by_name[name.lower().rstrip(".")] = _load_context(cert.cert_file, cert.key_file)

    if by_name:

        def choose(
            conn: ssl.SSLSocket | ssl.SSLObject, server_name: str | None, _: ssl.SSLContext
        ) -> None:
            if server_name:
                chosen = by_name.get(server_name.lower().rstrip("."))
                if chosen is not None:
                    conn.context = chosen

        default.sni_callback = choose
    return default


def _present(cert: Path | None, key: Path | None) -> bool:
    return cert is not None and key is not None and cert.is_file() and key.is_file()


def _load_context(cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(cert, key)
    except (OSError, ssl.SSLError) as exc:
        raise ServerError(f"cannot load the TLS certificate {cert}: {exc}") from exc
    return context


def _bind_failure(label: str, port: int, exc: OSError) -> str:
    """Explain a bind failure without guessing at the cause.

    The previous version asserted "ports below 1024 need root" for
    every failure, which was actively misleading on a high port.
    """
    message = f"could not bind {label} on port {port}: {exc}"
    if port < 1024:
        return (
            f"{message}\n"
            "Ports below 1024 need root, or: "
            "setcap 'cap_net_bind_service=+ep' $(which python3)"
        )
    if getattr(exc, "errno", None) in (48, 98, 10048):
        return f"{message}\nSomething is already listening there."
    return message


class ServerError(RuntimeError):
    """The engine could not start."""


__all__ = [
    "ANY_HOST",
    "SHUTDOWN_GRACE_SECONDS",
    "Server",
    "ServerError",
    "parse_addr",
    "tls_context",
]
