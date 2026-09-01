"""Installing generated Sieve scripts where Dovecot will run them.

The generator turns filter rules into a script; this puts that script
on disk in the layout the generated ``dovecot.conf`` points at:

    <sieve_dir>/<domain>/<local_part>/active.sieve

Writes are atomic. A Sieve script is read by Dovecot on every delivery,
and a half-written one is a syntax error that stops mail for that
account -- so the new script is written beside the old one and renamed
into place, which is atomic on POSIX.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema
from lightr.dovecot.maildir import MaildirError, _reject_unsafe
from lightr.dovecot.sieve import (
    Action,
    Condition,
    Field,
    MatchType,
    Operator,
    Rule,
    SieveError,
    compile_script,
)

log = logging.getLogger("lightr.sieve")

ACTIVE_SCRIPT = "active.sieve"


@dataclass(frozen=True, slots=True)
class InstallResult:
    email: str
    path: Path
    rules: int
    changed: bool


def script_path(sieve_dir: Path, email: str) -> Path:
    """Where an account's active script lives.

    Mirrors the ``%d/%n`` layout in the generated Dovecot config.
    """
    if "@" not in email:
        raise MaildirError(f"{email!r} is not an email address")
    local, _, domain = email.partition("@")
    local, domain = local.lower(), domain.lower()
    _reject_unsafe(local)
    _reject_unsafe(domain)
    return sieve_dir / domain / local / ACTIVE_SCRIPT


def write_script(path: Path, content: str) -> bool:
    """Write a script atomically. Returns whether it changed.

    Dovecot reads this on every delivery. A partially written file is a
    syntax error that stops mail for the account, so the write goes to
    a temporary file in the same directory and is renamed into place.
    """
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=".sieve-", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    path.chmod(0o600)
    return True


def _rule_from_row(row: dict[str, object]) -> Rule:
    """Turn a stored filter_rules row into a compilable Rule."""
    conditions = []
    for entry in _json_list(row.get("conditions")):
        if not isinstance(entry, dict):
            continue
        try:
            conditions.append(
                Condition(
                    field=Field(str(entry.get("field", "")).lower()),
                    operator=Operator(str(entry.get("operator", "contains")).lower()),
                    value=str(entry.get("value", "")),
                    header=entry.get("header"),
                )
            )
        except ValueError as exc:
            raise SieveError(
                f"rule {row.get('name')!r} has an unsupported condition: {exc}"
            ) from exc

    actions: list[tuple[Action, str]] = []
    for entry in _json_list(row.get("actions")):
        if not isinstance(entry, dict):
            continue
        try:
            actions.append(
                (
                    Action(str(entry.get("type", "")).lower()),
                    str(entry.get("value", "") or ""),
                )
            )
        except ValueError as exc:
            raise SieveError(
                f"rule {row.get('name')!r} has an unsupported action: {exc}"
            ) from exc

    return Rule(
        name=str(row.get("name") or "unnamed"),
        conditions=conditions,
        actions=actions,
        match_type=MatchType(str(row.get("match_type") or "all").lower()),
        priority=int(row.get("priority") or 100),
        stop_on_match=bool(row.get("stop_on_match")),
        is_active=bool(row.get("is_active", True)),
    )


def _json_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        return parsed if isinstance(parsed, list) else []
    return []


class SieveInstaller:
    """Compiles an account's rules and installs the result."""

    def __init__(self, conn: AsyncConnection, sieve_dir: Path) -> None:
        self._conn = conn
        self._sieve_dir = sieve_dir

    async def rules_for(self, account_id: UUID) -> list[Rule]:
        rows = await self._conn.execute(
            select(schema.filter_rules)
            .where(schema.filter_rules.c.account_id == str(account_id))
            .order_by(schema.filter_rules.c.priority)
        )
        return [_rule_from_row(dict(r._mapping)) for r in rows]

    async def install(self, account_id: UUID, email: str) -> InstallResult:
        """Generate and install one account's script."""
        rules = await self.rules_for(account_id)
        script = compile_script(rules)
        path = script_path(self._sieve_dir, email)

        changed = write_script(path, script.render())
        if changed:
            await self._conn.execute(
                update(schema.filter_rules)
                .where(schema.filter_rules.c.account_id == str(account_id))
                .values(sieve_generated_at=datetime.now(UTC).replace(tzinfo=None))
            )
            log.info("installed %d rule(s) for %s", len(rules), email)

        return InstallResult(
            email=email,
            path=path,
            rules=len([r for r in rules if r.is_active]),
            changed=changed,
        )

    async def install_all(self) -> list[InstallResult]:
        """Regenerate every account's script.

        A rule that will not compile stops that account only -- one bad
        rule must not leave every other mailbox unfiltered.
        """
        from lightr.repo import AccountRepo

        results: list[InstallResult] = []
        for account in await AccountRepo(self._conn).list(limit=10_000):
            if account.email is None:
                continue
            try:
                results.append(await self.install(account.id, account.email))
            except (SieveError, MaildirError, OSError) as exc:
                log.error("could not install Sieve for %s: %s", account.email, exc)
        return results


__all__ = [
    "ACTIVE_SCRIPT",
    "InstallResult",
    "SieveInstaller",
    "script_path",
    "write_script",
]
