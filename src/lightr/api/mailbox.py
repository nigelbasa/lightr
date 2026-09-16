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

import logging
from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager
from typing import Any, TypeVar

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from lightr.api.auth import AuthError, Principal
from lightr.apikeys import Permission
from lightr.dovecot.mailbox import (
    FLAG_DRAFT,
    FLAG_SEEN,
    Mailbox,
    MailboxError,
    MessageNotFoundError,
    build_search_criteria,
)
from lightr.models import Account
from lightr.repo import AccountRepo

T = TypeVar("T")

log = logging.getLogger("lightr.api.mailbox")


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


def _thread(thread: Any) -> dict[str, Any]:
    return {
        "uid": thread.root,
        "uids": thread.uids,
        "count": len(thread),
        "folder": thread.latest.folder,
        "subject": thread.subject,
        "participants": thread.participants,
        "date": thread.date,
        "unseen": thread.unseen,
        "flagged": thread.flagged,
        "size": thread.size,
        "messages": [_summary(m) for m in thread.messages],
    }


async def list_threads(request: Request) -> Response:
    """The same messages as `/messages`, grouped into conversations.

    Dovecot does the grouping, by References and In-Reply-To, so a
    client gets the same threads a desktop mail app would show. The
    filters are the ones `/messages` takes, and `limit` counts threads:
    a page never cuts a conversation in half.
    """
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
        threads = await mailbox.threads(
            folder,
            limit=_int(params.get("limit"), 50, maximum=100),
            offset=_int(params.get("offset"), 0),
            criteria=criteria,
        )
    return _json([_thread(t) for t in threads])


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


#: Flags a client may set, and the body keys that name them. `read` is
#: what people say; `seen` is what IMAP says. Both work.
_FLAG_KEYS = {
    "seen": ("read", "seen"),
    "flagged": ("flagged",),
    "answered": ("answered",),
    "draft": ("draft",),
}

#: The most messages one bulk request may touch. A UID set this long is
#: still one IMAP command, but an unbounded one is a way to make
#: Dovecot do arbitrary work on a single request.
MAX_BULK = 1000

#: Folders "empty" works on. Emptying anything else is one request away
#: from destroying an inbox; a client that means it can purge by UID.
EMPTYABLE = ("Trash", "Junk")


def _flags(body: dict[str, Any]) -> dict[str, bool | None]:
    flags: dict[str, bool | None] = {}
    for name, keys in _FLAG_KEYS.items():
        value = next((body[k] for k in keys if k in body), None)
        if value is not None and not isinstance(value, bool):
            raise AuthError(400, f"{keys[0]} must be true or false")
        flags[name] = value
    return flags


async def mark_message(request: Request) -> Response:
    from lightr.api.app import parse_body

    folder = request.query_params.get("folder", "INBOX")
    uid = _uid(request)
    body = await parse_body(request)

    flags = _flags(body)
    move_to = body.get("folder")

    if all(v is None for v in flags.values()) and move_to is None:
        raise AuthError(
            400, "give at least one of: read, flagged, answered, draft, folder"
        )

    async with _open(request) as (mailbox, _):
        await _mailbox_call(mailbox.mark(folder, uid, **flags))
        if move_to:
            await _mailbox_call(mailbox.move(folder, uid, str(move_to)))

    return _json({"uid": uid, "folder": move_to or folder, "updated": True})


async def bulk_messages(request: Request) -> Response:
    """Flag, move or delete many messages in one request.

    What a client's multi-select needs. Flags are applied before a move
    or delete, so "mark read and archive" is one call.
    """
    from lightr.api.app import parse_body

    body = await parse_body(request)
    folder = str(body.get("folder") or "INBOX")
    uids = body.get("uids")
    if (
        not isinstance(uids, list)
        or not uids
        or not all(isinstance(u, int) and not isinstance(u, bool) and u > 0
                   for u in uids)
    ):
        raise AuthError(400, "uids must be a non-empty list of message UIDs")
    if len(uids) > MAX_BULK:
        raise AuthError(400, f"at most {MAX_BULK} messages per request")

    flags = _flags(body)
    move_to = body.get("move_to")
    delete = body.get("delete")
    purge = body.get("purge")
    for name, value in (("delete", delete), ("purge", purge)):
        if value is not None and not isinstance(value, bool):
            raise AuthError(400, f"{name} must be true or false")
    if move_to and (delete or purge):
        raise AuthError(400, "move_to and delete cannot be combined")
    if all(v is None for v in flags.values()) and not (move_to or delete or purge):
        raise AuthError(
            400,
            "give at least one of: read, flagged, answered, draft, move_to, delete",
        )

    async with _open(request) as (mailbox, _):
        await _mailbox_call(mailbox.mark(folder, uids, **flags))
        if move_to:
            await _mailbox_call(mailbox.move(folder, uids, str(move_to)))
        elif delete or purge:
            await _mailbox_call(mailbox.delete(folder, uids, expunge=bool(purge)))

    return _json({"folder": move_to or folder, "uids": uids, "updated": len(uids)})


async def delete_message(request: Request) -> Response:
    folder = request.query_params.get("folder", "INBOX")
    uid = _uid(request)
    purge = request.query_params.get("purge") in ("1", "true", "yes")

    async with _open(request) as (mailbox, _):
        await mailbox.delete(folder, uid, expunge=purge)
    return Response(status_code=204)


async def create_folder(request: Request) -> Response:
    from lightr.api.app import parse_body

    body = await parse_body(request)
    name = body.get("name")
    if not isinstance(name, str):
        raise AuthError(400, "name is required")

    async with _open(request) as (mailbox, _):
        await _mailbox_call(mailbox.create_folder(name))
    return _json({"name": name}, 201)


async def rename_folder(request: Request) -> Response:
    from lightr.api.app import parse_body

    name = request.path_params["name"]
    body = await parse_body(request)
    new_name = body.get("name")
    if not isinstance(new_name, str):
        raise AuthError(400, "name (the new name) is required")

    async with _open(request) as (mailbox, _):
        await _mailbox_call(mailbox.rename_folder(name, new_name))
    return _json({"name": new_name, "was": name})


async def delete_folder(request: Request) -> Response:
    name = request.path_params["name"]
    async with _open(request) as (mailbox, _):
        await _mailbox_call(mailbox.delete_folder(name))
    return Response(status_code=204)


async def empty_folder(request: Request) -> Response:
    """Empty Trash or Junk -- the button every client has."""
    name = request.path_params["name"]
    if name not in EMPTYABLE:
        raise AuthError(
            400,
            f"only {' and '.join(EMPTYABLE)} can be emptied; to remove mail "
            "elsewhere for good, use POST /v1/mailbox/messages/bulk with purge",
        )
    async with _open(request) as (mailbox, _):
        removed = await _mailbox_call(mailbox.empty(name))
    return _json({"folder": name, "removed": removed})


async def save_draft(request: Request) -> Response:
    """Save a draft into Drafts, optionally replacing an older copy.

    IMAP has no "update a message"; a client saves a new copy and
    removes the old one, and `replace` does both in one request. The
    new copy is stored before the old one is removed, so a failure in
    between leaves two drafts rather than none.
    """
    from lightr.api.app import parse_body

    body = await parse_body(request)
    replace = body.get("replace")
    if replace is not None and (not isinstance(replace, int) or isinstance(replace, bool)):
        raise AuthError(400, "replace must be the UID of the draft to replace")

    async with _open(request) as (mailbox, account):
        raw = compose(account, body, require_recipients=False)
        await _mailbox_call(
            mailbox.append(DRAFTS, raw, flags=(FLAG_DRAFT, FLAG_SEEN))
        )
        if replace is not None:
            await _mailbox_call(mailbox.delete(DRAFTS, replace, expunge=True))

    return _json({"folder": DRAFTS, "saved": True, "replaced": replace}, 201)


async def send_message(request: Request) -> Response:
    """Send mail from this mailbox, and file a copy in Sent.

    Goes through exactly the path SMTP submission does -- the same
    sender check, routing, queue and DKIM signing -- with the key's
    account standing in for the SMTP login. A second sending path with
    its own rules is how the forged-sender hole submission used to
    have would come back.

    `reply_to` (`{"folder", "uid"}`) marks the message being answered,
    which is what makes a client show the replied arrow.
    """
    from email import message_from_bytes
    from email.utils import getaddresses

    from lightr.api.app import parse_body
    from lightr.cli.imap_client import _connect

    body = await parse_body(request)
    account = await _account_for(request)
    if account.email is None:  # pragma: no cover - resolve always sets it
        raise AuthError(500, "could not determine the mailbox address")

    reply_to = body.get("reply_to")
    if reply_to is not None and not (
        isinstance(reply_to, dict)
        and isinstance(reply_to.get("uid"), int)
        and isinstance(reply_to.get("folder", "INBOX"), str)
    ):
        raise AuthError(400, 'reply_to must be {"folder": ..., "uid": ...}')

    is_raw = bool(body.get("raw"))
    raw = compose(account, body, require_recipients=not is_raw)
    parsed = message_from_bytes(raw)

    if is_raw:
        recipients = _addresses(body.get("recipients"), "recipients") or [
            address
            for _, address in getaddresses(
                [*parsed.get_all("To", []), *parsed.get_all("Cc", []),
                 *parsed.get_all("Bcc", [])]
            )
            if address
        ]
    else:
        recipients = [
            *_addresses(body.get("to"), "to"),
            *_addresses(body.get("cc"), "cc"),
            *_addresses(body.get("bcc"), "bcc"),
        ]
    recipients = list(dict.fromkeys(r.lower() for r in recipients))
    if not recipients:
        raise AuthError(400, "give at least one recipient")
    if len(recipients) > MAX_RECIPIENTS:
        raise AuthError(400, f"at most {MAX_RECIPIENTS} recipients per message")

    mail_from = body.get("from") or account.email
    if not isinstance(mail_from, str):
        raise AuthError(400, "from must be an address")

    # Bcc is kept in the Sent copy -- the sender should see who they
    # blind-copied -- and removed from what goes out, or every
    # recipient would see it.
    wire = raw
    if parsed.get_all("Bcc"):
        del parsed["Bcc"]
        wire = parsed.as_bytes()

    # Release this request's transaction before handing off. It has
    # already written (the key's last-used time), and on SQLite an open
    # write blocks the queue insert that delivery makes on its own
    # connection -- the send would wait out the lock timeout and fail.
    #
    # Safe inside the middleware's engine.begin(): its exit sees the
    # transaction is no longer active and neither commits nor rolls back
    # again (SQLAlchemy's TransactionalContext, the same on any driver).
    # What is not safe is using the connection afterwards: it would
    # autobegin a transaction nothing commits, and the write would be
    # silently rolled back when the connection closes. So it is taken
    # away, and a later use fails loudly instead.
    await request.state.conn.commit()
    request.state.conn = None

    outcome = await _submission(request).deliver(
        mail_from=mail_from,
        recipients=recipients,
        raw=wire,
        remote_ip="api",
        authenticated_as=account.email,
    )

    rejected = [
        {"recipient": recipient, "reason": reason.smtp_message}
        for recipient, reason in outcome.rejected
    ]
    if outcome.error:
        return _json(
            {"error": outcome.error, "rejected": rejected},
            403 if outcome.permanent else 503,
        )
    if not (outcome.delivered or outcome.forwarded or outcome.accepted):
        return _json({"error": "no recipient accepted the message",
                      "rejected": rejected}, 422)

    saved = True
    try:
        client = await _connect(request.app.state.config, account.email)
        try:
            mailbox = Mailbox(client)
            await mailbox.append(SENT, raw, flags=(FLAG_SEEN,))
            if reply_to is not None:
                await mailbox.mark(
                    reply_to.get("folder", "INBOX"), reply_to["uid"], answered=True
                )
        finally:
            await client.logout()
    except MailboxError:
        # The mail has gone; failing the request now would have the
        # client send it again. Say what did not happen instead.
        log.warning("sent mail for %s but could not file it in Sent",
                    account.email, exc_info=True)
        saved = False

    return _json(
        {
            "message_id": str(parsed.get("Message-ID", "") or ""),
            "queued": outcome.forwarded,
            "delivered": outcome.delivered,
            "rejected": rejected,
            "saved_to_sent": saved,
        },
        202,
    )


#: Where a mailbox's own key may forward it. An operator's alias can go
#: wider; self-service is kept to what a person forwards to.
MAX_FORWARD_DESTINATIONS = 10


async def _own_alias(request: Request, account: Account) -> Any:
    """The alias with this mailbox's own address, if there is one."""
    from lightr.repo import AliasRepo, NotFoundError

    try:
        return await AliasRepo(request.state.conn).resolve(
            account.local_part, domain_id=account.domain_id
        )
    except NotFoundError:
        return None


def _forwarding_view(alias: Any) -> dict[str, Any]:
    from lightr.models import AliasType

    active = alias is not None and alias.is_active and alias.type is AliasType.BRIDGE
    return {
        "enabled": active,
        "destinations": list(alias.destinations) if active else [],
        # Always true: a forward that dropped the local copy would make
        # this mailbox stop receiving, and routing ignores a plain
        # forward with a mailbox's own name for exactly that reason.
        "keeps_copy": True,
        # Replies from a destination go back to the original sender
        # from this address, not from the destination's.
        "replies_routed": True,
    }


async def get_forwarding(request: Request) -> Response:
    account = await _account_for(request)
    return _json(_forwarding_view(await _own_alias(request, account)))


async def set_forwarding(request: Request) -> Response:
    """Forward this mailbox's mail, keeping a copy.

    Stored as a bridge alias on the mailbox's own address -- the same
    thing an operator would create -- so routing, the rewritten
    envelope sender, the spam check and reply routing all apply.
    """
    from lightr.api.app import _destinations, parse_body
    from lightr.models import Alias, AliasType
    from lightr.repo import AliasRepo

    account = await _account_for(request)
    body = await parse_body(request)
    unknown = set(body) - {"destinations"}
    if unknown:
        raise AuthError(400, f"unknown field(s): {', '.join(sorted(unknown))}")

    destinations = _destinations(body.get("destinations"))
    if len(destinations) > MAX_FORWARD_DESTINATIONS:
        raise AuthError(
            400, f"a mailbox can forward to at most {MAX_FORWARD_DESTINATIONS} addresses"
        )
    if account.email and account.email.lower() in destinations:
        raise AuthError(400, "a mailbox cannot forward to itself")

    repo = AliasRepo(request.state.conn)
    alias = await _own_alias(request, account)
    if alias is None:
        alias = await repo.create(
            Alias(
                domain_id=account.domain_id,
                source=account.local_part,
                destinations=destinations,
                type=AliasType.BRIDGE,
            )
        )
    else:
        alias.destinations = destinations
        alias.type = AliasType.BRIDGE
        alias.is_active = True
        await repo.update(alias)
    return _json(_forwarding_view(alias))


async def stop_forwarding(request: Request) -> Response:
    from lightr.repo import AliasRepo

    account = await _account_for(request)
    alias = await _own_alias(request, account)
    if alias is not None:
        await AliasRepo(request.state.conn).delete(alias.id)
    return Response(status_code=204)


def _submission(request: Request) -> Any:
    """One submission handler per app, created on first send."""
    from lightr.mail.smtp import LightrHandler

    state = request.app.state
    handler = getattr(state, "submission", None)
    if handler is None:
        handler = LightrHandler(state.config, state.engine, require_auth=True)
        state.submission = handler
    return handler


DRAFTS = "Drafts"
SENT = "Sent"

#: Recipients one API send may address. Submission clients rarely go
#: past a few dozen; a mailing list belongs somewhere else.
MAX_RECIPIENTS = 100

#: The largest message the API will compose or accept whole.
MAX_MESSAGE_BYTES = 25 * 1024 * 1024


def compose(account: Account, body: dict[str, Any], *, require_recipients: bool) -> bytes:
    """Build a message from JSON, or take one whole.

    `raw` is for clients that build their own MIME (attachments,
    inline images). Otherwise the message is assembled from to, cc,
    bcc, subject, text, html, in_reply_to and references.

    From is always this mailbox. A client that wants to send as an
    alias passes `from`, and sending checks that the mailbox may use
    it; a draft is only stored, so it is not checked there.
    """
    from email.message import EmailMessage
    from email.utils import formataddr, formatdate, make_msgid

    if raw := body.get("raw"):
        if not isinstance(raw, str):
            raise AuthError(400, "raw must be the message as a string")
        data = raw.encode("utf-8", errors="surrogateescape")
        if len(data) > MAX_MESSAGE_BYTES:
            raise AuthError(413, "message is too large")
        return data

    message = EmailMessage()
    sender = body.get("from") or account.email or ""
    if not isinstance(sender, str):
        raise AuthError(400, "from must be an address")
    message["From"] = (
        formataddr((account.display_name, sender))
        if account.display_name and sender == account.email
        else sender
    )

    any_recipient = False
    for header in ("to", "cc", "bcc"):
        addresses = _addresses(body.get(header), header)
        if addresses:
            any_recipient = True
            message[header.capitalize()] = ", ".join(addresses)
    if require_recipients and not any_recipient:
        raise AuthError(400, "give at least one recipient in to, cc or bcc")

    subject = body.get("subject") or ""
    if not isinstance(subject, str):
        raise AuthError(400, "subject must be text")
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    domain = (account.email or "localhost").rsplit("@", 1)[-1]
    message["Message-ID"] = make_msgid(domain=domain)
    for key, header in (("in_reply_to", "In-Reply-To"), ("references", "References")):
        if value := body.get(key):
            if not isinstance(value, str):
                raise AuthError(400, f"{key} must be text")
            message[header] = value

    text = body.get("text")
    html = body.get("html")
    if text is not None and not isinstance(text, str):
        raise AuthError(400, "text must be text")
    if html is not None and not isinstance(html, str):
        raise AuthError(400, "html must be text")
    message.set_content(text or "")
    if html:
        message.add_alternative(html, subtype="html")

    data = message.as_bytes()
    if len(data) > MAX_MESSAGE_BYTES:
        raise AuthError(413, "message is too large")
    return data


def _addresses(value: Any, name: str) -> list[str]:
    if value is None:
        return []
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not all(isinstance(a, str) for a in items):
        raise AuthError(400, f"{name} must be an address or a list of addresses")
    cleaned = [a.strip() for a in items if a.strip()]
    for address in cleaned:
        if "@" not in address or any(c in address for c in "\r\n,;"):
            raise AuthError(400, f"{address!r} in {name} is not a single address")
    return cleaned


async def _mailbox_call(operation: Awaitable[T]) -> T:
    """Run a mailbox operation, reporting Dovecot's refusal as a 400.

    Dovecot refusing a request (no such folder, a name it will not
    take) is the caller's to fix. Not reaching Dovecot at all is raised
    earlier, when the connection opens, and stays a server error.
    """
    try:
        return await operation
    except MessageNotFoundError as exc:
        raise AuthError(404, str(exc)) from exc
    except MailboxError as exc:
        raise AuthError(400, str(exc)) from exc


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
    Route("/v1/mailbox/folders", create_folder, methods=["POST"]),
    # Before the catch-all folder routes: `{name:path}` would otherwise
    # swallow the trailing /empty as part of the folder name.
    Route("/v1/mailbox/folders/{name:path}/empty", empty_folder, methods=["POST"]),
    Route("/v1/mailbox/folders/{name:path}", rename_folder, methods=["PATCH"]),
    Route("/v1/mailbox/folders/{name:path}", delete_folder, methods=["DELETE"]),
    Route("/v1/mailbox/drafts", save_draft, methods=["POST"]),
    Route("/v1/mailbox/send", send_message, methods=["POST"]),
    Route("/v1/mailbox/forwarding", get_forwarding, methods=["GET"]),
    Route("/v1/mailbox/forwarding", set_forwarding, methods=["PUT"]),
    Route("/v1/mailbox/forwarding", stop_forwarding, methods=["DELETE"]),
    Route("/v1/mailbox/messages", list_messages, methods=["GET"]),
    Route("/v1/mailbox/threads", list_threads, methods=["GET"]),
    Route("/v1/mailbox/messages/bulk", bulk_messages, methods=["POST"]),
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
