"""Driving Dovecot through ``doveadm``.

Lightr manages Dovecot end to end: an operator interacts with Lightr,
and Lightr issues the Dovecot commands. This is the interface for
everything that is an action rather than a file -- installing Sieve
scripts, reading real quota usage, creating and listing mailboxes,
hashing master passwords, and reloading the service.

Two rules run through it:

* **Never a shell.** Every call passes an argument list to
  ``create_subprocess_exec``. Addresses and folder names come from
  users, and a shell would turn a mailbox called ``x; rm -rf /`` into
  exactly what it looks like.
* **Every call is bounded.** doveadm can block on a broken index or an
  unreachable backend, and an unbounded call on the delivery path
  would hang the engine rather than fail it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("lightr.doveadm")

DEFAULT_TIMEOUT = 30.0
DEFAULT_BINARY = "doveadm"


class DoveadmError(RuntimeError):
    """A doveadm command failed."""

    def __init__(self, command: str, code: int, stderr: str) -> None:
        detail = stderr.strip().splitlines()[-1] if stderr.strip() else "no output"
        super().__init__(f"doveadm {command} failed ({code}): {detail}")
        self.command = command
        self.code = code
        self.stderr = stderr


class DoveadmUnavailableError(DoveadmError):
    """doveadm is not installed, or not on PATH."""

    def __init__(self, binary: str) -> None:
        RuntimeError.__init__(
            self,
            f"{binary!r} was not found. Lightr manages Dovecot directly, so "
            f"it must be installed on this host: apt install dovecot-core",
        )
        self.command = ""
        self.code = 127
        self.stderr = ""


@dataclass(frozen=True, slots=True)
class Quota:
    """One account's real usage, as Dovecot sees it."""

    used_bytes: int
    limit_bytes: int | None
    used_messages: int
    limit_messages: int | None

    @property
    def percent(self) -> float | None:
        if not self.limit_bytes:
            return None
        return round(100 * self.used_bytes / self.limit_bytes, 1)

    @property
    def over(self) -> bool:
        return self.limit_bytes is not None and self.used_bytes >= self.limit_bytes


@dataclass(frozen=True, slots=True)
class SieveScript:
    name: str
    active: bool


class Doveadm:
    """An async wrapper around the ``doveadm`` command."""

    def __init__(
        self,
        binary: str = DEFAULT_BINARY,
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._binary = binary
        self._timeout = timeout

    # -- process plumbing ------------------------------------------------

    @property
    def available(self) -> bool:
        return shutil.which(self._binary) is not None

    async def run(
        self,
        *args: str,
        stdin: bytes | None = None,
        timeout: float | None = None,
    ) -> str:
        """Run a doveadm command and return stdout.

        Arguments are passed as a list -- never through a shell -- so a
        mailbox name or address cannot become a command.
        """
        if not self.available:
            raise DoveadmUnavailableError(self._binary)

        command = " ".join(args)
        try:
            process = await asyncio.create_subprocess_exec(
                self._binary,
                *args,
                stdin=asyncio.subprocess.PIPE if stdin is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (OSError, NotImplementedError) as exc:
            raise DoveadmError(command, 127, str(exc)) from exc

        try:
            out, err = await asyncio.wait_for(
                process.communicate(input=stdin), timeout=timeout or self._timeout
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            raise DoveadmError(
                command, 124, f"timed out after {timeout or self._timeout}s"
            ) from None

        stdout = out.decode("utf-8", "replace")
        stderr = err.decode("utf-8", "replace")

        if process.returncode:
            raise DoveadmError(command, process.returncode or 1, stderr)
        return stdout

    async def run_json(self, *args: str, timeout: float | None = None) -> Any:
        """Run a command with ``-f json`` and parse the result."""
        raw = await self.run("-f", "json", *args, timeout=timeout)
        if not raw.strip():
            return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DoveadmError(
                " ".join(args), 0, f"could not parse doveadm output: {exc}"
            ) from exc

    # -- Sieve ------------------------------------------------------------

    async def sieve_put(self, user: str, name: str, script: str) -> None:
        """Upload a Sieve script for a user.

        The script arrives on stdin rather than as an argument: it is
        multi-line, can be large, and would otherwise land in the
        process table for anyone on the host to read.
        """
        await self.run(
            "sieve", "put", "-u", user, name, stdin=script.encode("utf-8")
        )

    async def sieve_activate(self, user: str, name: str) -> None:
        await self.run("sieve", "activate", "-u", user, name)

    async def sieve_deactivate(self, user: str) -> None:
        await self.run("sieve", "deactivate", "-u", user)

    async def sieve_list(self, user: str) -> list[SieveScript]:
        rows = await self.run_json("sieve", "list", "-u", user)
        return [
            SieveScript(
                name=str(row.get("script") or row.get("name") or ""),
                active=str(row.get("active", "")).lower() in ("yes", "true", "1"),
            )
            for row in _as_rows(rows)
        ]

    async def sieve_delete(self, user: str, name: str) -> None:
        await self.run("sieve", "delete", "-u", user, name)

    async def install_sieve(self, user: str, script: str, name: str = "lightr") -> None:
        """Upload a script and make it the active one.

        Two steps, in this order: uploading first means that if
        activation fails the mailbox keeps whatever was working before,
        rather than being left with no active script at all.
        """
        await self.sieve_put(user, name, script)
        await self.sieve_activate(user, name)

    # -- quota ------------------------------------------------------------

    async def quota_get(self, user: str) -> Quota:
        """Read an account's real usage.

        Lightr configures the limit through the userdb response;
        Dovecot enforces it and is the only thing that knows what has
        actually been used.
        """
        rows = _as_rows(await self.run_json("quota", "get", "-u", user))

        used_bytes = limit_bytes = used_messages = limit_messages = 0
        for row in rows:
            kind = str(row.get("type", "")).lower()
            value = _int(row.get("value"))
            limit = _int(row.get("limit"))
            if kind.startswith("storage"):
                used_bytes, limit_bytes = value * 1024, limit * 1024
            elif kind.startswith("message"):
                used_messages, limit_messages = value, limit

        return Quota(
            used_bytes=used_bytes,
            limit_bytes=limit_bytes or None,
            used_messages=used_messages,
            limit_messages=limit_messages or None,
        )

    async def quota_recalc(self, user: str) -> None:
        """Recompute usage. Needed after mail is moved in behind Dovecot."""
        await self.run("quota", "recalc", "-u", user)

    # -- mailboxes --------------------------------------------------------

    async def mailbox_list(self, user: str) -> list[str]:
        rows = _as_rows(await self.run_json("mailbox", "list", "-u", user))
        return [str(row.get("mailbox", "")) for row in rows if row.get("mailbox")]

    async def mailbox_create(self, user: str, *names: str) -> None:
        if not names:
            return
        await self.run("mailbox", "create", "-u", user, *names)

    async def mailbox_delete(self, user: str, name: str) -> None:
        await self.run("mailbox", "delete", "-u", user, name)

    async def force_resync(self, user: str) -> None:
        """Rebuild a mailbox's index. The fix for a corrupt index."""
        await self.run("force-resync", "-u", user, "INBOX*")

    # -- passwords and service --------------------------------------------

    async def pw(self, password: str, scheme: str = "CRYPT") -> str:
        """Hash a password the way Dovecot expects in a passwd-file.

        The password goes in on stdin, not as an argument -- doveadm
        accepts ``-p`` but that would put it in the process table.
        """
        out = await self.run("pw", "-s", scheme, stdin=f"{password}\n{password}\n".encode())
        return out.strip()

    async def reload(self) -> None:
        """Ask Dovecot to re-read its configuration."""
        await self.run("reload")

    async def auth_cache_flush(self, user: str | None = None) -> None:
        """Drop cached authentication results.

        Dovecot caches passdb answers so a reconnecting mail client
        does not cost an HTTP call into Lightr -- and, for an offloaded
        account, a call out to LDAP or an OIDC provider. That cache has
        to be dropped when a password changes, or the old one keeps
        working until the TTL expires.
        """
        args = ["auth", "cache", "flush"]
        if user:
            args += ["-u", user]
        await self.run(*args)

    async def who(self) -> list[dict[str, Any]]:
        """Currently connected users. Useful before a restart."""
        return _as_rows(await self.run_json("who"))

    async def version(self) -> str:
        return (await self.run("--version")).strip()


def _as_rows(value: Any) -> list[dict[str, Any]]:
    """Normalise doveadm's JSON, which nests one level in some versions."""
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            rows.append(item)
        elif isinstance(item, list):
            rows.extend(sub for sub in item if isinstance(sub, dict))
    return rows


def _int(value: Any) -> int:
    """doveadm reports '-' for 'no limit' and quotes its numbers."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


__all__ = [
    "DEFAULT_BINARY",
    "DEFAULT_TIMEOUT",
    "Doveadm",
    "DoveadmError",
    "DoveadmUnavailableError",
    "Quota",
    "SieveScript",
]
