"""Installing generated Sieve scripts where Dovecot will run them.

Installation goes through ``doveadm sieve put`` / ``activate``. Dovecot
then compiles the script and reports a syntax error, which writing the
file directly would not -- a bad script would simply start failing
deliveries at run time with nothing to point at.

Uploading before activating also matters: if the new script does not
compile, the mailbox keeps whatever was working before rather than
being left with no active script.

There is a direct-file fallback for the case where doveadm is not
available. It writes atomically -- into a temporary file in the same
directory, then renames -- because Dovecot reads the script on every
delivery, and a half-written one stops mail for that account.
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
from lightr.dovecot.doveadm import Doveadm, DoveadmError
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
    via: str = "file"  # doveadm | file


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
        Path(temporary).replace(path)
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
    """Compiles an account's rules and installs the result.

    Prefers doveadm, which compiles the script and rejects a broken one
    up front. Falls back to writing the file when doveadm is absent.
    """

    def __init__(
        self,
        conn: AsyncConnection,
        sieve_dir: Path,
        doveadm: Doveadm | None = None,
    ) -> None:
        self._conn = conn
        self._sieve_dir = sieve_dir
        self._doveadm = doveadm if doveadm is not None else Doveadm()

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
        rendered = script.render()
        path = script_path(self._sieve_dir, email)

        changed, via = await self._deliver_script(email, rendered, path)
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
            via=via,
        )

    async def _deliver_script(
        self, email: str, rendered: str, path: Path
    ) -> tuple[bool, str]:
        """Hand the script to Dovecot. Returns (changed, how)."""
        if self._doveadm.available:
            try:
                await self._doveadm.install_sieve(email, rendered)
            except DoveadmError as exc:
                # A compile failure is the useful case: doveadm rejected
                # the script, so name that rather than silently writing
                # a file Dovecot will choke on at delivery time.
                raise SieveError(
                    f"Dovecot rejected the Sieve script for {email}: {exc}"
                ) from exc
            # doveadm has no "was it different" answer, so compare
            # against the local copy to keep the result meaningful.
            changed = write_script(path, rendered)
            return changed, "doveadm"

        log.warning(
            "doveadm is unavailable; writing %s directly. Dovecot will not "
            "check the script until it next delivers mail.", path,
        )
        return write_script(path, rendered), "file"

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
            except (SieveError, MaildirError, DoveadmError, OSError) as exc:
                log.error("could not install Sieve for %s: %s", account.email, exc)
        return results


__all__ = [
    "ACTIVE_SCRIPT",
    "InstallResult",
    "SieveInstaller",
    "script_path",
    "write_script",
]
