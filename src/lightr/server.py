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
from dataclasses import dataclass, field

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

        self._start_smtp()
        self._start_sender()
        await self._start_http()

        log.info("lightr is up as %s", self.cfg.server.hostname)

    def _start_smtp(self) -> None:
        from aiosmtpd.controller import Controller

        assert self.engine is not None

        receive_host, receive_port = parse_addr(self.cfg.smtp.addr, 25)
        submit_host, submit_port = parse_addr(self.cfg.smtp.submission_addr, 587)

        receive_handler = LightrHandler(self.cfg, self.engine, require_auth=False)
        submission_handler = LightrHandler(self.cfg, self.engine, require_auth=True)
        self._handlers = [receive_handler, submission_handler]

        # :25 takes mail from the internet and must never relay.
        receive = Controller(
            receive_handler,
            hostname=receive_host,
            port=receive_port,
            ident=f"lightr {self.cfg.server.hostname}",
        )
        # :587 is for authenticated users and may send anywhere.
        submission = Controller(
            submission_handler,
            hostname=submit_host,
            port=submit_port,
            # No authenticator= here on purpose: aiosmtpd calls that
            # synchronously and would not await our check. The handler
            # implements auth_PLAIN / auth_LOGIN instead, which are
            # awaited. See the comment in mail/smtp.py.
            auth_require_tls=self.cfg.security.require_tls_for_auth,
            ident=f"lightr {self.cfg.server.hostname}",
        )

        for controller, label, port in (
            (receive, "smtp", receive_port),
            (submission, "submission", submit_port),
        ):
            try:
                controller.start()
            except OSError as exc:
                raise ServerError(_bind_failure(label, port, exc)) from exc
            self._controllers.append(controller)

        log.info("smtp on %s:%s, submission on %s:%s",
                 receive_host, receive_port, submit_host, submit_port)

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

        for controller in self._controllers:
            with contextlib.suppress(Exception):
                controller.stop()  # type: ignore[attr-defined]
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


__all__ = ["ANY_HOST", "SHUTDOWN_GRACE_SECONDS", "Server", "ServerError", "parse_addr"]
