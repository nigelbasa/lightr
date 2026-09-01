"""The ``/v1/mailbox/*`` routes.

A different principal from the operator routes. These act on **one**
mailbox — whichever the presenting key is scoped to — so an
account-scoped key cannot read someone else's mail by changing a path
parameter. There is no account id in these paths at all, which is the
simplest way to guarantee that.

Reads go through the same IMAP adapter the CLI uses, so the two cannot
disagree about what is in a mailbox.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from lightr.api.auth import AuthError, Principal
from lightr.apikeys import Permission
from lightr.dovecot.mailbox import (
    Mailbox,
    MessageNotFoundError,
    build_search_criteria,
)
from lightr.models import Account
from lightr.repo import AccountRepo


async def _account_for(request: Request) -> Account:
    """The one mailbox this request may touch.

    Taken from the key's scope, never from the request, so there is no
    parameter to tamper with.
    """
    principal: Principal = request.state.principal
    principal.require(Permission.MAILBOX)

    if principal.key.account_id is None:
        raise AuthError(
            403,
            "the mailbox API needs an account-scoped key; "
            "create one with: lightr apikey create --type account",
        )

    return await AccountRepo(request.state.conn).resolve(str(principal.key.account_id))


@asynccontextmanager
async def _open(request: Request) -> AsyncIterator[tuple[Mailbox, Account]]:
    from lightr.cli.imap_client import _connect

    account = await _account_for(request)
    email = account.email
    if email is None:  # pragma: no cover - resolve always sets it
        raise AuthError(500, "could not determine the mailbox address")

    client = await _connect(request.app.state.config, email)
    try:
        yield Mailbox(client), account
    finally:
        try:
            await client.logout()
        except Exception:
            pass


def _json(payload: Any, status: int = 200) -> JSONResponse:
    from lightr.api.app import ok

    return ok(payload, status)


def _summary(message: Any) -> dict[str, Any]:
    return {
        "uid": message.uid,
        "folder": message.folder,
        "subject": message.subject,
        "from": message.from_,
        "to": message.to,
        "date": message.date,
        "size": message.size,
        "seen": message.seen,
        "flagged": message.flagged,
        "answered": message.answered,
    }


# --------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------


async def get_mailbox(request: Request) -> Response:
    """Who this key's mailbox belongs to."""
    async with _open(request) as (mailbox, account):
        folders = await mailbox.folders()
        inbox = next((f for f in folders if f.is_inbox), None)

    return _json(
        {
            "email": account.email,
            "display_name": account.display_name,
            "quota_bytes": account.quota_bytes,
            "folders": len(folders),
            "messages": inbox.messages if inbox else 0,
            "unseen": inbox.unseen if inbox else 0,
        }
    )


async def list_folders(request: Request) -> Response:
    async with _open(request) as (mailbox, _):
        folders = await mailbox.folders()
    return _json(
        [
            {
                "name": f.name,
                "messages": f.messages,
                "unseen": f.unseen,
                "uidvalidity": f.uidvalidity,
            }
            for f in folders
        ]
    )


async def list_messages(request: Request) -> Response:
    params = request.query_params
    folder = params.get("folder", "INBOX")
    criteria = build_search_criteria(
        unread=params.get("unread") in ("1", "true", "yes"),
        flagged=params.get("flagged") in ("1", "true", "yes"),
        sender=params.get("from"),
        recipient=params.get("to"),
        subject=params.get("subject"),
        text=params.get("text"),
        since=params.get("since"),
        before=params.get("before"),
    )

    async with _open(request) as (mailbox, _):
        messages = await mailbox.list(
            folder,
            limit=_int(params.get("limit"), 50, maximum=200),
            offset=_int(params.get("offset"), 0),
            criteria=criteria,
        )
    return _json([_summary(m) for m in messages])


async def get_message(request: Request) -> Response:
    folder = request.query_params.get("folder", "INBOX")
    uid = _uid(request)

    async with _open(request) as (mailbox, _):
        try:
            message = await mailbox.get(folder, uid)
        except MessageNotFoundError as exc:
            return _json({"error": str(exc)}, 404)

    return _json(
        {
            **_summary(message),
            "text": message.text,
            "html": message.html,
            "attachments": [
                {
                    "index": a.index,
                    "filename": a.filename,
                    "content_type": a.content_type,
                    "size": a.size,
                }
                for a in message.attachments
            ],
        }
    )


async def mark_message(request: Request) -> Response:
    from lightr.api.app import parse_body

    folder = request.query_params.get("folder", "INBOX")
    uid = _uid(request)
    body = await parse_body(request)

    seen = body.get("read", body.get("seen"))
    flagged = body.get("flagged")
    move_to = body.get("folder")

    if seen is None and flagged is None and move_to is None:
        raise AuthError(400, "give at least one of: read, flagged, folder")

    async with _open(request) as (mailbox, _):
        if seen is not None or flagged is not None:
            await mailbox.mark(
                folder,
                uid,
                seen=bool(seen) if seen is not None else None,
                flagged=bool(flagged) if flagged is not None else None,
            )
        if move_to:
            await mailbox.move(folder, uid, str(move_to))

    return _json({"uid": uid, "folder": move_to or folder, "updated": True})


async def delete_message(request: Request) -> Response:
    folder = request.query_params.get("folder", "INBOX")
    uid = _uid(request)
    purge = request.query_params.get("purge") in ("1", "true", "yes")

    async with _open(request) as (mailbox, _):
        await mailbox.delete(folder, uid, expunge=purge)
    return Response(status_code=204)


async def get_attachment(request: Request) -> Response:
    folder = request.query_params.get("folder", "INBOX")
    uid = _uid(request)
    try:
        index = int(request.path_params["att_id"])
    except (KeyError, ValueError) as exc:
        raise AuthError(400, "attachment id must be a number") from exc

    async with _open(request) as (mailbox, _):
        try:
            filename, content_type, payload = await mailbox.attachment(
                folder, uid, index
            )
        except MessageNotFoundError as exc:
            return _json({"error": str(exc)}, 404)

    # Quote the filename: it comes from the message, so it is attacker
    # -influenced and must not be able to inject header syntax.
    safe = filename.replace('"', "").replace("\r", "").replace("\n", "")
    return Response(
        content=payload,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{safe}"'},
    )


def _uid(request: Request) -> int:
    try:
        return int(request.path_params["id"])
    except (KeyError, ValueError) as exc:
        raise AuthError(400, "message id must be a UID number") from exc


def _int(raw: str | None, default: int, *, maximum: int | None = None) -> int:
    try:
        value = int(raw) if raw is not None else default
    except ValueError:
        return default
    value = max(value, 0)
    return min(value, maximum) if maximum is not None else value


MAILBOX_ROUTES: list[Route] = [
    Route("/v1/mailbox", get_mailbox, methods=["GET"]),
    Route("/v1/mailbox/folders", list_folders, methods=["GET"]),
    Route("/v1/mailbox/messages", list_messages, methods=["GET"]),
    Route("/v1/mailbox/messages/{id}", get_message, methods=["GET"]),
    Route("/v1/mailbox/messages/{id}", mark_message, methods=["PATCH"]),
    Route("/v1/mailbox/messages/{id}", delete_message, methods=["DELETE"]),
    Route(
        "/v1/mailbox/messages/{id}/attachments/{att_id}",
        get_attachment,
        methods=["GET"],
    ),
]

__all__ = ["MAILBOX_ROUTES"]
