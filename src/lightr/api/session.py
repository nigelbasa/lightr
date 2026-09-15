"""Signing in to the mailbox API, and changing a mailbox's password.

A mail client should not need an operator to mint it a key. POST
/v1/auth/session takes the mailbox's own address and password -- checked
exactly as IMAP and SMTP check them, external providers included -- and
returns a bearer token for that one mailbox.

Underneath it is an ordinary API key: account-scoped, expiring,
revocable, and limited like any other. It is named ``session:<address>``
so a mailbox's sessions can be listed per device and revoked together
when its password changes, and it carries mailbox and send permissions
only. Not READ: an account key with READ reaches the operator listing
routes, and a token handed to a mail client has no business there.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import delete, or_, select, update
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from lightr.api.auth import AuthError, Principal, client_ip
from lightr.apikeys import APIKey, APIKeyRepo, KeyType, Permission
from lightr.db import schema

log = logging.getLogger("lightr.api.session")

SIGN_IN_PATH = "/v1/auth/session"
SESSION_PREFIX = "session:"
SESSION_LIFETIME = timedelta(days=30)
SESSION_PERMISSIONS = (Permission.MAILBOX, Permission.SEND)

#: Wrong passwords for one address, from anywhere, before it is refused
#: for a while. The per-address budget alone would let a botnet try a
#: mailbox's password from ten thousand addresses.
ACCOUNT_FAILURES = 10
ACCOUNT_WINDOW = 900.0

#: Kept with the session so a list of them means something to a person.
MAX_USER_AGENT = 200


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _limits(request: Request) -> tuple[Any, Any]:
    """(per client address, per mailbox) limiters, made once per app."""
    state = request.app.state
    limits = getattr(state, "session_limits", None)
    if limits is None:
        from lightr.ratelimit import limiter

        limits = (
            limiter(state.config.limits.auth_failures_per_minute, 60.0),
            limiter(ACCOUNT_FAILURES, ACCOUNT_WINDOW),
        )
        state.session_limits = limits
    return limits


def _spend(limits: list[tuple[Any, str]]) -> int | None:
    """Charge every attempt up front; seconds to wait if one is spent.

    Charged before the password is checked, not after it fails: a limit
    applied afterwards has already let the guess be tried. A sign-in
    that succeeds is refunded, so a person who mistypes a few times is
    never locked out by it.
    """
    for bucket, key in limits:
        if bucket is not None and not bucket.allow(key):
            return int(bucket.retry_after(key))
    return None


def _refund(limits: list[tuple[Any, str]]) -> None:
    for bucket, key in limits:
        if bucket is not None:
            bucket.forget(key)


def _iso(value: datetime | None) -> str | None:
    return f"{value.isoformat()}Z" if value else None


async def create_session(request: Request) -> Response:
    """Exchange a mailbox's address and password for a token."""
    from lightr.api.app import error, ok, parse_body, too_many
    from lightr.auth import Authenticator

    body = await parse_body(request)
    email, password = body.get("email"), body.get("password")
    if not (isinstance(email, str) and email.strip() and isinstance(password, str)
            and password):
        raise AuthError(400, "email and password are required")
    email = email.strip().lower()

    by_address, by_account = _limits(request)
    charged = [(by_address, client_ip(request) or "unknown"), (by_account, email)]
    if (wait := _spend(charged)) is not None:
        return too_many(wait)

    result = await Authenticator(request.state.conn).authenticate(email, password)
    if not result.ok or result.account is None:
        if result.temporary:
            # "Wrong password" here would send people to reset a password
            # that is fine, because a directory is down.
            log.warning("sign-in for %s could not be checked: %s", email, result.detail)
            return error(503, "the password could not be checked right now; try again shortly")
        # One answer for a wrong password, an unknown address and a
        # disabled mailbox: anything more tells a stranger which exist.
        raise AuthError(401, "wrong email or password")
    _refund(charged)

    account = result.account
    expires_at = _now() + SESSION_LIFETIME
    key, secret = await APIKeyRepo(request.state.conn).create(
        f"{SESSION_PREFIX}{account.email}",
        key_type=KeyType.ACCOUNT,
        account_id=account.id,
        permissions=list(SESSION_PERMISSIONS),
        expires_at=expires_at,
        description=(request.headers.get("User-Agent") or "")[:MAX_USER_AGENT] or None,
    )
    return ok(
        {
            "token": secret,
            "token_type": "Bearer",
            "expires_at": _iso(expires_at),
            "session_id": str(key.id),
            "account": {"email": account.email, "display_name": account.display_name},
        },
        201,
    )


async def end_session(request: Request) -> Response:
    """Sign out: revoke the token this request was made with."""
    from lightr.api.mailbox import _account_for

    await _account_for(request)
    principal: Principal = request.state.principal
    if not principal.key.name.startswith(SESSION_PREFIX):
        raise AuthError(
            400,
            "this is an API key, not a session; revoke it with: lightr apikey revoke",
        )
    await APIKeyRepo(request.state.conn).revoke(principal.key.id)
    return Response(status_code=204)


async def _sessions(conn: Any, account_id: UUID) -> list[APIKey]:
    table = schema.api_keys
    rows = await conn.execute(
        select(table)
        .where(
            table.c.account_id == str(account_id),
            table.c.name.like(f"{SESSION_PREFIX}%"),
            table.c.active.is_(True),
        )
        .order_by(table.c.created_at.desc())
    )
    return [k for k in (APIKeyRepo._to_model(r._mapping) for r in rows) if k.usable]


async def list_sessions(request: Request) -> Response:
    """The devices signed in to this mailbox."""
    from lightr.api.app import ok
    from lightr.api.mailbox import _account_for

    account = await _account_for(request)
    current = request.state.principal.key.id
    return ok([
        {
            "id": str(key.id),
            "created_at": _iso(key.created_at),
            "expires_at": _iso(key.expires_at),
            "last_used_at": _iso(key.last_used_at),
            "last_used_ip": key.last_used_ip,
            "user_agent": key.description,
            "current": key.id == current,
        }
        for key in await _sessions(request.state.conn, account.id)
    ])


async def revoke_session(request: Request) -> Response:
    """Sign another device out."""
    from lightr.api.app import error
    from lightr.api.mailbox import _account_for

    account = await _account_for(request)
    wanted = request.path_params["id"]
    for key in await _sessions(request.state.conn, account.id):
        if str(key.id) == wanted:
            await APIKeyRepo(request.state.conn).revoke(key.id)
            return Response(status_code=204)
    return error(404, "no such session")


async def change_password(request: Request) -> Response:
    """Change this mailbox's password, given the current one.

    Every other session is signed out -- whoever changes a password
    because it leaked expects the leak to stop working -- and Dovecot's
    cached answer is dropped, or the old password keeps working over IMAP
    for as long as the cache holds it.
    """
    from lightr.api.app import ok, parse_body, too_many
    from lightr.api.mailbox import _account_for
    from lightr.auth import (
        Authenticator,
        PasswordError,
        hash_password_async,
        validate_password,
    )
    from lightr.models import AuthMode
    from lightr.repo import AccountRepo

    account = await _account_for(request)
    body = await parse_body(request)
    current, new = body.get("current_password"), body.get("new_password")
    if not (isinstance(current, str) and current and isinstance(new, str) and new):
        raise AuthError(400, "current_password and new_password are required")
    if account.auth_mode is not AuthMode.NATIVE:
        raise AuthError(
            409,
            "this mailbox signs in through your organization's identity provider; "
            "change the password there",
        )

    email = account.email or ""
    _, by_account = _limits(request)
    charged = [(by_account, email)]
    if (wait := _spend(charged)) is not None:
        return too_many(wait)
    result = await Authenticator(request.state.conn).authenticate(email, current)
    if not result.ok:
        raise AuthError(403, "the current password is wrong")
    _refund(charged)

    if new == current:
        raise AuthError(400, "the new password is the same as the current one")
    try:
        validate_password(new)
    except PasswordError as exc:
        raise AuthError(400, str(exc)) from exc

    conn = request.state.conn
    await AccountRepo(conn).set_password_hash(account.id, await hash_password_async(new))

    table = schema.api_keys
    revoked = await conn.execute(
        update(table)
        .where(
            table.c.account_id == str(account.id),
            table.c.name.like(f"{SESSION_PREFIX}%"),
            table.c.active.is_(True),
            table.c.id != str(request.state.principal.key.id),
        )
        .values(active=False, updated_at=_now())
    )

    return ok({
        "changed": True,
        "sessions_revoked": int(revoked.rowcount or 0),
        "imap_cache_cleared": await _flush_auth_cache(request, email),
    })


async def _flush_auth_cache(request: Request, email: str) -> bool:
    from lightr.dovecot.doveadm import Doveadm, DoveadmError

    doveadm = getattr(request.app.state, "doveadm", None) or Doveadm()
    if not getattr(doveadm, "available", False):
        return False
    try:
        await doveadm.auth_cache_flush(email)
    except DoveadmError as exc:
        log.warning(
            "password changed for %s but Dovecot's auth cache was not cleared: %s",
            email, exc,
        )
        return False
    return True


async def purge_expired(conn: Any) -> int:
    """Delete sessions that have expired or been revoked.

    One row per sign-in adds up; nothing reads a dead session again.
    """
    table = schema.api_keys
    result = await conn.execute(
        delete(table).where(
            table.c.name.like(f"{SESSION_PREFIX}%"),
            or_(table.c.expires_at < _now(), table.c.active.is_(False)),
        )
    )
    return int(result.rowcount or 0)


SESSION_ROUTES: list[Route] = [
    Route(SIGN_IN_PATH, create_session, methods=["POST"]),
    Route("/v1/mailbox/session", end_session, methods=["DELETE"]),
    Route("/v1/mailbox/sessions", list_sessions, methods=["GET"]),
    Route("/v1/mailbox/sessions/{id}", revoke_session, methods=["DELETE"]),
    Route("/v1/mailbox/password", change_password, methods=["POST"]),
]

__all__ = [
    "SESSION_LIFETIME",
    "SESSION_PREFIX",
    "SESSION_ROUTES",
    "SIGN_IN_PATH",
    "purge_expired",
]
