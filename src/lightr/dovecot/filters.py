"""Filter rules as a mail client manages them.

The ``filter_rules`` table predates any way to write to it: the Sieve
installer read it, and rows only got there by hand. This is the
writing half -- validation and an account-scoped repository -- so a
client can offer "move mail from the bank to Receipts" without an
operator.

Validation compiles the rule. A rule that is stored but will not
compile breaks every rule for that mailbox the next time the script is
installed, so the time to say no is before it is stored.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.db import schema
from lightr.dovecot.sieve import Action, MatchType, SieveError, compile_script

#: How many rules one mailbox may have. Every delivery runs all of them.
MAX_RULES = 200
MAX_CONDITIONS = 20
MAX_ACTIONS = 10

SETTABLE = frozenset(
    {"name", "description", "priority", "conditions", "actions",
     "match_type", "is_active", "stop_on_match"}
)

#: Actions a mailbox's own key may not use.
#:
#: Sieve's redirect sends mail off the server from inside Dovecot, past
#: everything forwarding does to stay deliverable -- the rewritten
#: envelope sender, the spam check, the reply routing. Forwarding is
#: /v1/mailbox/forwarding.
REFUSED_ACTIONS = {
    Action.REDIRECT: "redirect is not available to filters; "
    "use PUT /v1/mailbox/forwarding to forward mail",
}


class FilterError(ValueError):
    """A rule that cannot be stored, and why."""


def normalise(body: dict[str, Any]) -> dict[str, Any]:
    """A request body as the columns to store. Raises FilterError."""
    from lightr.dovecot.sieve_install import _rule_from_row

    unknown = set(body) - SETTABLE
    if unknown:
        raise FilterError(
            f"unknown field(s): {', '.join(sorted(unknown))}. "
            f"Settable: {', '.join(sorted(SETTABLE))}"
        )

    name = body.get("name")
    if not isinstance(name, str) or not name.strip():
        raise FilterError("name is required")
    if len(name) > 200:
        raise FilterError("name can be at most 200 characters")

    description = body.get("description")
    if description is not None and not isinstance(description, str):
        raise FilterError("description must be text")

    priority = body.get("priority", 100)
    if not isinstance(priority, int) or isinstance(priority, bool) or not (
        0 <= priority <= 10_000
    ):
        raise FilterError("priority must be a whole number from 0 to 10000")

    match_type = body.get("match_type", "all")
    if match_type not in {m.value for m in MatchType}:
        raise FilterError("match_type must be all or any")

    flags = {}
    for flag, default in (("is_active", True), ("stop_on_match", False)):
        value = body.get(flag, default)
        if not isinstance(value, bool):
            raise FilterError(f"{flag} must be true or false")
        flags[flag] = value

    conditions = _entries(
        body.get("conditions"), "conditions", MAX_CONDITIONS,
        required=("field", "operator", "value"), optional=("header",),
    )
    actions = _entries(
        body.get("actions"), "actions", MAX_ACTIONS,
        required=("type",), optional=("value",),
    )

    row = {
        "name": name.strip(),
        "description": description,
        "priority": priority,
        "conditions": json.dumps(conditions),
        "match_type": match_type,
        "actions": json.dumps(actions),
        **flags,
    }

    try:
        rule = _rule_from_row(row)
        for action, _ in rule.actions:
            if action in REFUSED_ACTIONS:
                raise FilterError(REFUSED_ACTIONS[action])
        # Compiled as active whatever it is stored as: a rule switched
        # off today is switched on tomorrow, and must compile then.
        compile_script([replace(rule, is_active=True)])
    except SieveError as exc:
        raise FilterError(str(exc)) from exc
    return row


def _entries(
    value: Any,
    name: str,
    maximum: int,
    *,
    required: tuple[str, ...],
    optional: tuple[str, ...],
) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise FilterError(f"{name} must be a non-empty list")
    if len(value) > maximum:
        raise FilterError(f"at most {maximum} {name} per rule")

    cleaned = []
    for position, entry in enumerate(value, 1):
        if not isinstance(entry, dict):
            raise FilterError(f"{name}[{position}] must be an object")
        extra = set(entry) - set(required) - set(optional)
        if extra:
            raise FilterError(
                f"{name}[{position}] has unknown key(s): {', '.join(sorted(extra))}"
            )
        item: dict[str, str] = {}
        for key in (*required, *optional):
            if key not in entry or entry[key] is None:
                if key in required:
                    raise FilterError(f"{name}[{position}] needs {key}")
                continue
            if not isinstance(entry[key], str | int | float) or isinstance(
                entry[key], bool
            ):
                raise FilterError(f"{name}[{position}].{key} must be text")
            text = str(entry[key])
            if len(text) > 1000:
                raise FilterError(f"{name}[{position}].{key} is too long")
            item[key] = text
        cleaned.append(item)
    return cleaned


def view(row: Any) -> dict[str, Any]:
    """A stored rule as the API shows it."""
    data = dict(row._mapping if hasattr(row, "_mapping") else row)
    for key in ("conditions", "actions"):
        try:
            data[key] = json.loads(data.get(key) or "[]")
        except json.JSONDecodeError:
            data[key] = []
    data.pop("org_id", None)
    data.pop("account_id", None)
    return data


class FilterRepo:
    """One mailbox's rules. Every query is scoped by account."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn

    async def list(self, account_id: UUID) -> list[dict[str, Any]]:
        table = schema.filter_rules
        rows = await self._conn.execute(
            select(table)
            .where(table.c.account_id == str(account_id))
            .order_by(table.c.priority, table.c.created_at)
        )
        return [view(r) for r in rows]

    async def get(self, account_id: UUID, rule_id: str) -> dict[str, Any] | None:
        parsed = _as_uuid(rule_id)
        if parsed is None:
            return None
        table = schema.filter_rules
        row = (
            await self._conn.execute(
                select(table).where(
                    table.c.id == str(parsed),
                    table.c.account_id == str(account_id),
                )
            )
        ).first()
        return view(row) if row else None

    async def count(self, account_id: UUID) -> int:
        table = schema.filter_rules
        return int(
            (
                await self._conn.execute(
                    select(func.count())
                    .select_from(table)
                    .where(table.c.account_id == str(account_id))
                )
            ).scalar_one()
        )

    async def create(
        self, *, org_id: UUID, account_id: UUID, values: dict[str, Any]
    ) -> str:
        rule_id = str(uuid4())
        now = _now()
        await self._conn.execute(
            insert(schema.filter_rules).values(
                id=rule_id,
                org_id=str(org_id),
                account_id=str(account_id),
                created_at=now,
                updated_at=now,
                **values,
            )
        )
        return rule_id

    async def update(
        self, account_id: UUID, rule_id: str, values: dict[str, Any]
    ) -> None:
        table = schema.filter_rules
        await self._conn.execute(
            update(table)
            .where(table.c.id == rule_id, table.c.account_id == str(account_id))
            .values(updated_at=_now(), **values)
        )

    async def delete(self, account_id: UUID, rule_id: str) -> bool:
        parsed = _as_uuid(rule_id)
        if parsed is None:
            return False
        table = schema.filter_rules
        result = await self._conn.execute(
            delete(table).where(
                table.c.id == str(parsed), table.c.account_id == str(account_id)
            )
        )
        return bool(result.rowcount)


def _as_uuid(value: str) -> UUID | None:
    try:
        return UUID(str(value))
    except ValueError:
        return None


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


__all__ = [
    "MAX_RULES",
    "REFUSED_ACTIONS",
    "FilterError",
    "FilterRepo",
    "normalise",
    "view",
]
