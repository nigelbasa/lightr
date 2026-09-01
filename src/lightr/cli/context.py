"""Shared CLI plumbing: config loading, DB sessions, error rendering.

Commands are written as ordinary async functions and wrapped by
``run``, which owns the event loop, the connection, and turning
exceptions into messages that say what to do next.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, TypeVar

import typer
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.apikeys import APIKeyError
from lightr.auth import PasswordError
from lightr.config import Config
from lightr.db.engine import create_engine
from lightr.dovecot.lmtp import LMTPError
from lightr.dovecot.mailbox import MailboxError
from lightr.dovecot.maildir import MaildirError
from lightr.dovecot.sieve import SieveError
from lightr.repo import AmbiguousReferenceError, ConflictError, NotFoundError

from . import output

T = TypeVar("T")


@dataclass
class CLIState:
    """Options set on the root command, read by every subcommand.

    A single process may invoke more than one command -- the test
    suite does, and so does anything embedding the CLI -- so the
    cached config is keyed to the path it came from and reloaded when
    that path changes.
    """

    config_path: Path | None = None
    _config: Config | None = None
    _loaded_from: Path | None = None

    def use(self, path: Path | None) -> None:
        """Point at a config file, discarding any stale cached one."""
        self.config_path = path
        if path != self._loaded_from:
            self._config = None

    def set_config(self, config: Config) -> None:
        """Install an already-built config (used by `lightr init`)."""
        self._config = config
        self._loaded_from = self.config_path

    @property
    def config(self) -> Config:
        if self._config is None:
            try:
                self._config = Config.load(self.config_path)
            except (OSError, ValueError) as exc:
                raise typer.BadParameter(f"could not load config: {exc}") from exc
            self._loaded_from = self.config_path
        return self._config


state = CLIState()


@asynccontextmanager
async def db() -> AsyncIterator[AsyncConnection]:
    """A committed connection for the duration of one command."""
    engine = create_engine(state.config)
    try:
        async with engine.begin() as conn:
            yield conn
    finally:
        await engine.dispose()


def run(coro_fn: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
    """Run an async command body, rendering failures as advice.

    The Go CLI surfaced raw SQL errors. Every exception this engine
    can reasonably predict is turned into a sentence that names the
    next command to try.
    """
    try:
        return asyncio.run(coro_fn(*args, **kwargs))
    except (NotFoundError, AmbiguousReferenceError) as exc:
        _fail(str(exc))
    except ConflictError as exc:
        _fail(str(exc))
    except PasswordError as exc:
        _fail(str(exc))
    except APIKeyError as exc:
        _fail(str(exc))
    except (MailboxError, MaildirError, SieveError) as exc:
        _fail(str(exc))
    except LMTPError as exc:
        _fail(f"{exc}\nIs Dovecot running? Try: systemctl status dovecot")
    except IntegrityError as exc:
        _fail(_explain_integrity_error(exc))
    except OperationalError as exc:
        _fail(_explain_operational_error(exc))
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        _fail("cancelled")
    raise AssertionError("unreachable")  # pragma: no cover


def fail(message: str) -> NoReturn:
    """Print an error and exit non-zero."""
    _fail(message)


def _fail(message: str) -> NoReturn:
    output.stderr.print(f"[red]error[/red] {message}")
    raise typer.Exit(1)


def _explain_integrity_error(exc: IntegrityError) -> str:
    text = str(exc.orig if exc.orig else exc).lower()
    if "unique" in text:
        return "that already exists -- pick a different name, or update the existing one"
    if "foreign key" in text:
        return (
            "the parent record does not exist, or something still refers to this one. "
            "Delete the dependants first, or check the reference you passed."
        )
    if "not null" in text:
        return f"a required field was missing: {exc.orig}"
    return str(exc.orig or exc)


def _explain_operational_error(exc: OperationalError) -> str:
    text = str(exc.orig if exc.orig else exc).lower()
    if "no such table" in text:
        return "the database is not initialised or is out of date -- run: lightr migrate"
    if "unable to open database" in text:
        return (
            f"cannot open the database at {state.config.database.path}. "
            "Check the path and permissions, or run: lightr init"
        )
    if "locked" in text:
        return "the database is locked by another process -- is lightr already running?"
    if "connection refused" in text or "could not connect" in text:
        return "cannot reach the database server -- check database.dsn in your config"
    return str(exc.orig or exc)


def confirm(action: str, *, yes: bool, detail: str | None = None) -> None:
    """Require confirmation for a destructive action unless --yes.

    The Go CLI deleted accounts without asking. Deleting an account
    now takes a mailbox with it, so it asks and says what it will
    destroy.
    """
    if yes:
        return
    if detail:
        output.stderr.print(detail)
    if not typer.confirm(action):
        output.info("Cancelled. Nothing was changed.")
        raise typer.Exit(0)


__all__ = ["CLIState", "confirm", "db", "fail", "run", "state"]
