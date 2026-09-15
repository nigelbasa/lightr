"""The Lightr HTTP API.

Starlette, with routes registered explicitly rather than by decorator
so the whole surface is visible in one list -- the same property the
Go engine's ``ServeMux`` block had, and worth keeping.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from lightr import __version__
from lightr.api.auth import AuthError, Principal, authenticate, client_ip
from lightr.api.filters import FILTER_ROUTES
from lightr.api.internal import INTERNAL_PATHS, INTERNAL_ROUTES
from lightr.api.mailbox import MAILBOX_ROUTES
from lightr.apikeys import APIKeyError, APIKeyRepo, KeyType, Permission
from lightr.config import Config
from lightr.db.engine import create_engine, ping
from lightr.dovecot.mailbox import MailboxError
from lightr.models import Account, Alias, AliasType, AuthMode, Domain, Organization
from lightr.ratelimit import KeyLimiter, limiter
from lightr.repo import (
    AccountRepo,
    AliasRepo,
    AmbiguousReferenceError,
    ConflictError,
    DomainRepo,
    NotFoundError,
    OrganizationRepo,
)

Handler = Callable[[Request], Awaitable[Response]]


def json_default(value: Any) -> str:
    if isinstance(value, UUID | datetime):
        return str(value)
    return str(value)


def ok(payload: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(json.loads(json.dumps(payload, default=json_default)), status)


def error(status: int, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": message, **extra}, status)


def too_many(retry_after: int) -> JSONResponse:
    """429 with a Retry-After, so a client can behave.

    A limit that does not say when to come back trains callers to
    retry immediately, which is the traffic the limit was meant to
    stop.
    """
    return JSONResponse(
        {"error": f"rate limited -- retry in {retry_after}s"},
        429,
        headers={"Retry-After": str(retry_after)},
    )


def dump(record: Any) -> dict[str, Any]:
    data = record.model_dump()
    # Credentials never cross the wire, in either direction.
    for field in ("password_hash", "dkim_private_key", "relay_password",
                  "auth_webhook_secret", "key_hash", "secret", "auth_value"):
        if data.get(field):
            data[field] = "(set)"
    return data


async def parse_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise AuthError(400, "request body must be JSON") from exc
    if not isinstance(body, dict):
        raise AuthError(400, "request body must be a JSON object")
    return body


def require(body: dict[str, Any], *names: str) -> None:
    missing = [n for n in names if not body.get(n)]
    if missing:
        raise AuthError(400, f"missing required field(s): {', '.join(missing)}")


# --------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------


async def health(request: Request) -> Response:
    """Unauthenticated liveness check."""
    engine: AsyncEngine = request.app.state.engine
    reachable = await ping(engine)
    return ok(
        {"status": "ok" if reachable else "degraded",
         "version": __version__,
         "database": reachable},
        200 if reachable else 503,
    )


async def list_orgs(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    repo = OrganizationRepo(request.state.conn)

    if scoped := principal.scoped_org():
        return ok([dump(await repo.resolve(str(scoped)))])
    return ok([dump(o) for o in await repo.list()])


async def create_org(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require_admin()
    body = await parse_body(request)
    require(body, "name")

    org = await OrganizationRepo(request.state.conn).create(Organization(name=body["name"]))
    return ok(dump(org), 201)


async def get_org(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    org = await OrganizationRepo(request.state.conn).resolve(request.path_params["id"])
    if not principal.may_reach_org(org.id):
        raise AuthError(403, "this key is scoped to a different organization")
    return ok(dump(org))


async def list_domains(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    repo = DomainRepo(request.state.conn)

    org_ref = request.path_params.get("org_id")
    if org_ref:
        org = await OrganizationRepo(request.state.conn).resolve(org_ref)
        if not principal.may_reach_org(org.id):
            raise AuthError(403, "this key is scoped to a different organization")
        return ok([dump(d) for d in await repo.list(org_id=org.id)])

    return ok([dump(d) for d in await repo.list(org_id=principal.scoped_org())])


async def create_domain(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    body = await parse_body(request)
    require(body, "name")

    conn = request.state.conn
    orgs = OrganizationRepo(conn)
    if org_ref := body.get("org_id"):
        org = await orgs.resolve(str(org_ref))
        if not principal.may_reach_org(org.id):
            raise AuthError(403, "this key is scoped to a different organization")
    elif scoped := principal.scoped_org():
        org = await orgs.resolve(str(scoped))
    else:
        org = await orgs.default()

    domain = await DomainRepo(conn).create(
        Domain(
            org_id=org.id,
            name=body["name"],
            mail_hostname=body.get("mail_hostname"),
        )
    )
    return ok(dump(domain), 201)


async def get_domain(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    domain = await DomainRepo(request.state.conn).resolve(request.path_params["id"])
    if not principal.may_reach_domain(domain.id, domain.org_id):
        raise AuthError(403, "this key cannot reach that domain")
    return ok(dump(domain))


#: What PATCH /v1/domains/{id} may change.
RELAY_FIELDS = frozenset({
    "relay_enabled", "relay_host", "relay_port", "relay_username",
    "relay_password", "relay_use_tls", "relay_tls_skip_verify",
})


async def update_domain(request: Request) -> Response:
    """Change a domain's outbound relay.

    Only an organization-wide or admin key may: the relay receives every
    message the domain sends, so a key confined to one domain or one
    account must not be able to point that mail somewhere else.
    """
    from lightr.mail import relay as relay_tools

    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    body = await parse_body(request)
    conn = request.state.conn

    domain = await DomainRepo(conn).resolve(request.path_params["id"])
    if not principal.may_reach_domain(domain.id, domain.org_id):
        raise AuthError(403, "this key cannot reach that domain")
    if principal.key.domain_id is not None or getattr(principal.key, "account_id", None):
        raise AuthError(403, "relay settings need an organization or admin key")

    unknown = set(body) - RELAY_FIELDS
    if unknown:
        raise AuthError(
            400,
            f"cannot change: {', '.join(sorted(unknown))}. "
            f"Settable: {', '.join(sorted(RELAY_FIELDS))}",
        )
    for flag in ("relay_enabled", "relay_use_tls", "relay_tls_skip_verify"):
        if flag in body and not isinstance(body[flag], bool):
            raise AuthError(400, f"{flag} must be true or false")
    for text_field in ("relay_host", "relay_username", "relay_password"):
        if body.get(text_field) is not None and not isinstance(body[text_field], str):
            raise AuthError(400, f"{text_field} must be a string or null")

    # null clears a value; an absent field leaves it alone.
    if "relay_port" in body and body["relay_port"] is None:
        domain.relay_port = None
    change = relay_tools.RelayChange(
        enabled=body.get("relay_enabled"),
        host="" if "relay_host" in body and body["relay_host"] is None
        else body.get("relay_host"),
        port=body.get("relay_port"),
        username="" if "relay_username" in body and body["relay_username"] is None
        else body.get("relay_username"),
        password="" if "relay_password" in body and body["relay_password"] is None
        else body.get("relay_password"),
        use_tls=body.get("relay_use_tls"),
        skip_verify=body.get("relay_tls_skip_verify"),
    )
    try:
        relay_tools.apply(domain, change)
    except relay_tools.RelayError as exc:
        raise AuthError(400, str(exc)) from exc

    await DomainRepo(conn).update(domain)
    return ok(dump(domain))


async def delete_domain(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    conn = request.state.conn
    domain = await DomainRepo(conn).resolve(request.path_params["id"])
    if not principal.may_reach_domain(domain.id, domain.org_id):
        raise AuthError(403, "this key cannot reach that domain")

    remaining = await AccountRepo(conn).count(domain_id=domain.id)
    if remaining:
        return error(
            409,
            f"{domain.name} still has {remaining} account(s)",
            hint="delete its accounts first",
        )

    await DomainRepo(conn).delete(domain.id)
    return Response(status_code=204)


async def _visible_domains(request: Request) -> list[UUID] | None:
    """The domains a listing may show, or None for all of them.

    A `?domain=` the key cannot reach is refused rather than quietly
    emptied, so a mistyped domain and a forbidden one do not look alike
    to the operator but neither leaks anything.
    """
    principal: Principal = request.state.principal
    conn = request.state.conn

    if domain_ref := request.query_params.get("domain"):
        domain = await DomainRepo(conn).resolve(domain_ref)
        if not principal.may_reach_domain(domain.id, domain.org_id):
            raise AuthError(403, "this key cannot reach that domain")
        return [domain.id]
    if principal.key.domain_id is not None and not principal.is_admin:
        return [principal.key.domain_id]
    if (org_id := principal.scoped_org()) is not None:
        return [d.id for d in await DomainRepo(conn).list(org_id=org_id)]
    if principal.is_admin:
        return None
    # Neither admin nor scoped to anything: nothing to show.
    return []


async def _reach_account(request: Request, account: Account) -> None:
    """Refuse an account outside the key's scope.

    `may_reach_account` only compares account-scoped keys; for an org
    or domain key it answers True and leaves the rest to the caller.
    This is the rest: the account's own domain has to be reachable.
    """
    principal: Principal = request.state.principal
    domain = await DomainRepo(request.state.conn).resolve(str(account.domain_id))
    if not (
        principal.may_reach_account(account.id)
        and principal.may_reach_domain(domain.id, domain.org_id)
    ):
        raise AuthError(403, "this key cannot reach that account")


async def list_accounts(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    repo = AccountRepo(request.state.conn)

    domains = await _visible_domains(request)
    if domains is None:
        accounts = await repo.list()
    else:
        accounts = [a for d in domains for a in await repo.list(domain_id=d)]
    return ok([dump(a) for a in accounts])


async def create_account(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    body = await parse_body(request)
    require(body, "email")

    email = str(body["email"])
    if "@" not in email:
        raise AuthError(400, "email must be a full address, e.g. ops@acme.test")

    conn = request.state.conn
    local_part, domain_name = email.split("@", 1)
    domain = await DomainRepo(conn).resolve(domain_name)
    if not principal.may_reach_domain(domain.id, domain.org_id):
        raise AuthError(403, "this key cannot reach that domain")

    account = Account(
        domain_id=domain.id,
        local_part=local_part,
        display_name=body.get("display_name"),
        quota_bytes=body.get("quota_bytes"),
        auth_mode=AuthMode(body.get("auth_mode", "native")),
    )
    if password := body.get("password"):
        from lightr.auth import hash_password_async

        account.password_hash = await hash_password_async(str(password))

    created = await AccountRepo(conn).create(account)
    created.with_domain(domain)
    return ok(dump(created), 201)


async def get_account(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    account = await AccountRepo(request.state.conn).resolve(request.path_params["id"])
    await _reach_account(request, account)
    return ok(dump(account))


async def update_account(request: Request) -> Response:
    """Change an account's settings, including whether it may send or
    receive. The password is not settable here -- that is `passwd`,
    and it is hashed on the server, never accepted pre-hashed."""
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    body = await parse_body(request)
    conn = request.state.conn

    account = await AccountRepo(conn).resolve(request.path_params["id"])
    await _reach_account(request, account)

    allowed = {"display_name", "quota_bytes", "can_send", "can_receive", "disabled"}
    unknown = set(body) - allowed
    if unknown:
        raise AuthError(
            400,
            f"cannot change: {', '.join(sorted(unknown))}. "
            f"Settable: {', '.join(sorted(allowed))}",
        )

    for flag in ("can_send", "can_receive", "disabled"):
        if flag in body and not isinstance(body[flag], bool):
            raise AuthError(400, f"{flag} must be true or false")

    if "display_name" in body:
        account.display_name = body["display_name"]
    if "quota_bytes" in body:
        quota = body["quota_bytes"]
        if quota is not None and (not isinstance(quota, int) or quota < 0):
            raise AuthError(400, "quota_bytes must be a non-negative integer or null")
        account.quota_bytes = quota
    if "can_send" in body:
        account.can_send = body["can_send"]
    if "can_receive" in body:
        account.can_receive = body["can_receive"]
    if "disabled" in body:
        account.auth_mode = (
            AuthMode.DISABLED
            if body["disabled"]
            else (AuthMode.EXTERNAL if account.external_id else AuthMode.NATIVE)
        )

    await AccountRepo(conn).update(account)
    return ok(dump(account))


async def delete_account(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    conn = request.state.conn
    account = await AccountRepo(conn).resolve(request.path_params["id"])
    await _reach_account(request, account)
    await AccountRepo(conn).delete(account.id)
    return Response(status_code=204)


async def list_aliases(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    repo = AliasRepo(request.state.conn)

    domains = await _visible_domains(request)
    if domains is None:
        aliases = await repo.list()
    else:
        aliases = [a for d in domains for a in await repo.list(domain_id=d)]
    return ok([dump(a) for a in aliases])


async def _reachable_alias(request: Request) -> Alias:
    principal: Principal = request.state.principal
    conn = request.state.conn
    alias = await AliasRepo(conn).resolve(request.path_params["id"])
    domain = await DomainRepo(conn).resolve(str(alias.domain_id))
    if not principal.may_reach_domain(domain.id, domain.org_id):
        raise AuthError(403, "this key cannot reach that alias")
    return alias


#: Where one alias may send mail. Enough for a team; not a mailing list.
MAX_ALIAS_DESTINATIONS = 50


def _destinations(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise AuthError(400, "destinations must be a non-empty list of addresses")
    if len(value) > MAX_ALIAS_DESTINATIONS:
        raise AuthError(400, f"at most {MAX_ALIAS_DESTINATIONS} destinations")
    cleaned = []
    for item in value:
        if (
            not isinstance(item, str)
            or item.count("@") != 1
            or not all(item.split("@"))
            or any(c.isspace() or c in ",;<>" for c in item)
        ):
            raise AuthError(400, f"{item!r} is not an email address")
        cleaned.append(item.strip().lower())
    return list(dict.fromkeys(cleaned))


def _alias_type(value: Any) -> AliasType:
    try:
        return AliasType(value)
    except ValueError as exc:
        raise AuthError(
            400, f"type must be one of: {', '.join(t.value for t in AliasType)}"
        ) from exc


async def update_alias(request: Request) -> Response:
    """Change where an alias delivers, its type, or whether it is on.

    The source is not changeable: a different address is a different
    alias, and renaming one in place would silently re-route mail
    already addressed to the old name.
    """
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    body = await parse_body(request)
    alias = await _reachable_alias(request)

    allowed = {"destinations", "type", "is_active"}
    unknown = set(body) - allowed
    if unknown:
        raise AuthError(
            400,
            f"cannot change: {', '.join(sorted(unknown))}. "
            f"Settable: {', '.join(sorted(allowed))}",
        )
    if "destinations" in body:
        alias.destinations = _destinations(body["destinations"])
    if "type" in body:
        alias.type = _alias_type(body["type"])
    if "is_active" in body:
        if not isinstance(body["is_active"], bool):
            raise AuthError(400, "is_active must be true or false")
        alias.is_active = body["is_active"]

    await AliasRepo(request.state.conn).update(alias)
    return ok(dump(alias))


async def create_alias(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    body = await parse_body(request)
    require(body, "source", "destinations")

    conn = request.state.conn
    source = str(body["source"])
    if "@" not in source:
        raise AuthError(400, "source must be a full address, e.g. sales@acme.test")

    domain = await DomainRepo(conn).resolve(source.split("@", 1)[1])
    if not principal.may_reach_domain(domain.id, domain.org_id):
        raise AuthError(403, "this key cannot reach that domain")

    alias = await AliasRepo(conn).create(
        Alias(
            domain_id=domain.id,
            source=source,
            destinations=_destinations(body["destinations"]),
            type=_alias_type(body.get("type", "forward")),
        )
    )
    return ok(dump(alias), 201)


async def delete_alias(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    alias = await _reachable_alias(request)
    await AliasRepo(request.state.conn).delete(alias.id)
    return Response(status_code=204)


async def list_api_keys(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    keys = await APIKeyRepo(request.state.conn).list(
        organization_id=principal.scoped_org()
    )
    return ok([dump(k) for k in keys])


async def create_api_key(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require_admin()
    body = await parse_body(request)
    require(body, "name")

    conn = request.state.conn
    key_type = KeyType(body.get("type", "org"))

    organization_id = None
    if org_ref := body.get("org_id"):
        organization_id = (await OrganizationRepo(conn).resolve(str(org_ref))).id
    elif key_type is KeyType.ORG:
        organization_id = (await OrganizationRepo(conn).default()).id

    key, secret = await APIKeyRepo(conn).create(
        str(body["name"]),
        key_type=key_type,
        organization_id=organization_id,
        allowed_ips=body.get("allowed_ips"),
        expires_in_days=body.get("expires_in_days"),
        description=body.get("description"),
    )
    # The only response that ever carries the secret.
    return ok({**dump(key), "key": secret}, 201)


async def revoke_api_key(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require_admin()
    conn = request.state.conn
    key = await APIKeyRepo(conn).resolve(request.path_params["id"])
    await APIKeyRepo(conn).revoke(key.id)
    return ok({"revoked": str(key.id)})


async def rotate_api_key(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require_admin()
    conn = request.state.conn
    key = await APIKeyRepo(conn).resolve(request.path_params["id"])
    secret = await APIKeyRepo(conn).rotate(key.id)
    return ok({"id": str(key.id), "key": secret})


async def delete_api_key(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require_admin()
    conn = request.state.conn
    key = await APIKeyRepo(conn).resolve(request.path_params["id"])
    await APIKeyRepo(conn).delete(key.id)
    return Response(status_code=204)


# --------------------------------------------------------------------
# Webhooks
# --------------------------------------------------------------------


def dump_webhook(hook: Any) -> dict[str, Any]:
    """A webhook as JSON, without its signing secret.

    The secret is stored in the clear because HMAC needs it, which is
    exactly why it must not be handed back over the wire: a read-scoped
    key would otherwise be able to forge every event this server sends.
    """
    return {
        "id": str(hook.id),
        "name": hook.name,
        "description": hook.description,
        "url": hook.url,
        "events": list(hook.events),
        "active": hook.active,
        "organization_id": str(hook.organization_id) if hook.organization_id else None,
        "domain_filter": hook.domain_filter,
        "timeout": hook.timeout,
        "max_retries": hook.max_retries,
        "secret": "(set)" if hook.secret else None,
        "failure_count": hook.failure_count,
        "last_success": hook.last_success,
        "last_failure": hook.last_failure,
        "created_at": hook.created_at,
        "updated_at": hook.updated_at,
    }


async def _reachable_webhook(request: Request, ref: str) -> Any:
    """Resolve a webhook this principal is allowed to touch."""
    from lightr.webhooks.delivery import WebhookRepo

    principal: Principal = request.state.principal
    hook = await WebhookRepo(request.state.conn).resolve(ref)

    if principal.is_admin:
        return hook
    # A webhook with no organization is the operator's, not a tenant's.
    if hook.organization_id is None or hook.organization_id != principal.key.organization_id:
        raise AuthError(403, "this key cannot reach that webhook")
    return hook


async def list_webhooks(request: Request) -> Response:
    from lightr.webhooks.delivery import WebhookRepo

    principal: Principal = request.state.principal
    principal.require(Permission.READ)

    hooks = await WebhookRepo(request.state.conn).list(org_id=principal.scoped_org())
    if not principal.is_admin:
        # `list` includes org-less webhooks so delivery sees them; a
        # tenant must not.
        hooks = [h for h in hooks if h.organization_id is not None]
    return ok([dump_webhook(h) for h in hooks])


async def create_webhook(request: Request) -> Response:
    from lightr.webhooks.delivery import WebhookRepo

    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    body = await parse_body(request)
    require(body, "name", "url")

    conn = request.state.conn
    organization_id = principal.scoped_org()
    if organization_id is None and (org_ref := body.get("org_id")):
        organization_id = (await OrganizationRepo(conn).resolve(str(org_ref))).id

    hook = await WebhookRepo(conn).create(
        str(body["name"]),
        str(body["url"]),
        events=body.get("events"),
        secret=body.get("secret"),
        organization_id=organization_id,
        description=body.get("description"),
        domain_filter=body.get("domain_filter"),
        timeout=int(body.get("timeout", 30)),
        max_retries=int(body.get("max_retries", 5)),
    )
    # The only response that carries the secret. A receiver cannot
    # verify anything without it, and it is not shown again.
    return ok({**dump_webhook(hook), "secret": hook.secret}, 201)


async def get_webhook(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    return ok(dump_webhook(await _reachable_webhook(request, request.path_params["id"])))


async def update_webhook(request: Request) -> Response:
    from lightr.webhooks.delivery import WebhookRepo

    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    hook = await _reachable_webhook(request, request.path_params["id"])
    body = await parse_body(request)

    repo = WebhookRepo(request.state.conn)
    await repo.update(hook.id, **body)
    return ok(dump_webhook(await repo.resolve(str(hook.id))))


async def delete_webhook(request: Request) -> Response:
    from lightr.webhooks.delivery import WebhookRepo

    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    hook = await _reachable_webhook(request, request.path_params["id"])
    await WebhookRepo(request.state.conn).delete(hook.id)
    return Response(status_code=204)


async def rotate_webhook_secret(request: Request) -> Response:
    from lightr.webhooks.delivery import WebhookRepo

    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    hook = await _reachable_webhook(request, request.path_params["id"])
    secret = await WebhookRepo(request.state.conn).rotate_secret(hook.id)
    return ok({"id": str(hook.id), "secret": secret})


async def test_webhook(request: Request) -> Response:
    """Send a ping and report exactly what the receiver said.

    This is the command that turns "I configured a webhook" into "the
    webhook works", and it exercises the real path -- SSRF vetting,
    signing, timeouts -- rather than a simulation of it.
    """
    from lightr.webhooks.delivery import WebhookDeliverer, WebhookRepo

    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    hook = await _reachable_webhook(request, request.path_params["id"])

    cfg: Config = request.app.state.config
    deliverer = WebhookDeliverer(allow_private=cfg.webhook.allow_private)
    attempt = await deliverer.deliver(
        hook, "ping", {"webhook": hook.name, "message": "This is a test from Lightr."}
    )
    await WebhookRepo(request.state.conn).record(hook.id, "ping", {}, attempt)

    return ok(
        {
            "ok": attempt.ok,
            "status_code": attempt.status_code,
            "duration_ms": attempt.duration_ms,
            "error": attempt.error or None,
            "body": attempt.body or None,
        },
        200 if attempt.ok else 502,
    )


async def list_webhook_deliveries(request: Request) -> Response:
    from lightr.webhooks.delivery import WebhookRepo

    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    hook = await _reachable_webhook(request, request.path_params["id"])

    repo = WebhookRepo(request.state.conn)
    limit = min(int(request.query_params.get("limit", 50)), 500)
    return ok(
        {
            "stats": await repo.stats(hook.id),
            "deliveries": await repo.deliveries(hook.id, limit=limit),
        }
    )


# --------------------------------------------------------------------
# Route table
# --------------------------------------------------------------------

ROUTES: list[Route] = [
    Route("/health", health, methods=["GET"]),

    Route("/v1/orgs", list_orgs, methods=["GET"]),
    Route("/v1/orgs", create_org, methods=["POST"]),
    Route("/v1/orgs/{id}", get_org, methods=["GET"]),
    Route("/v1/orgs/{org_id}/domains", list_domains, methods=["GET"]),

    Route("/v1/domains", list_domains, methods=["GET"]),
    Route("/v1/domains", create_domain, methods=["POST"]),
    Route("/v1/domains/{id}", get_domain, methods=["GET"]),
    Route("/v1/domains/{id}", update_domain, methods=["PATCH"]),
    Route("/v1/domains/{id}", delete_domain, methods=["DELETE"]),

    Route("/v1/accounts", list_accounts, methods=["GET"]),
    Route("/v1/accounts", create_account, methods=["POST"]),
    Route("/v1/accounts/{id}", get_account, methods=["GET"]),
    Route("/v1/accounts/{id}", update_account, methods=["PATCH"]),
    Route("/v1/accounts/{id}", delete_account, methods=["DELETE"]),

    Route("/v1/aliases", list_aliases, methods=["GET"]),
    Route("/v1/aliases", create_alias, methods=["POST"]),
    Route("/v1/aliases/{id}", update_alias, methods=["PATCH"]),
    Route("/v1/aliases/{id}", delete_alias, methods=["DELETE"]),

    Route("/v1/apikeys", list_api_keys, methods=["GET"]),
    Route("/v1/apikeys", create_api_key, methods=["POST"]),
    Route("/v1/apikeys/{id}/revoke", revoke_api_key, methods=["POST"]),
    Route("/v1/apikeys/{id}/rotate", rotate_api_key, methods=["POST"]),
    Route("/v1/apikeys/{id}", delete_api_key, methods=["DELETE"]),

    Route("/v1/webhooks", list_webhooks, methods=["GET"]),
    Route("/v1/webhooks", create_webhook, methods=["POST"]),
    Route("/v1/webhooks/{id}", get_webhook, methods=["GET"]),
    Route("/v1/webhooks/{id}", update_webhook, methods=["PATCH"]),
    Route("/v1/webhooks/{id}", delete_webhook, methods=["DELETE"]),
    Route("/v1/webhooks/{id}/test", test_webhook, methods=["POST"]),
    Route("/v1/webhooks/{id}/rotate", rotate_webhook_secret, methods=["POST"]),
    Route("/v1/webhooks/{id}/deliveries", list_webhook_deliveries, methods=["GET"]),
]

ROUTES.extend(MAILBOX_ROUTES)
ROUTES.extend(FILTER_ROUTES)
ROUTES.extend(INTERNAL_ROUTES)

#: Paths the API-key middleware does not guard. /health is public;
#: the internal routes carry their own shared-secret check.
PUBLIC_PATHS = frozenset({"/health"}) | INTERNAL_PATHS


def create_app(cfg: Config, engine: AsyncEngine | None = None) -> Starlette:
    """Build the ASGI application."""
    owned_engine = engine is None
    engine = engine or create_engine(cfg)

    # Two limiters, because the two failures are different. An address
    # failing to authenticate is guessing at a key and gets a small
    # budget; a key that has authenticated is a paying tenant and gets
    # whatever its own rate_limit says.
    failures = limiter(cfg.limits.auth_failures_per_minute, 60.0)
    anonymous = limiter(cfg.limits.api_requests_per_minute, 60.0)
    per_key = KeyLimiter()

    async def middleware(request: Request, call_next: Handler) -> Response:
        """Open a transaction, authenticate, limit, and translate errors."""
        address = client_ip(request) or "unknown"
        try:
            async with engine.begin() as conn:
                request.state.conn = conn
                if request.url.path not in PUBLIC_PATHS:
                    # Cheap first: refuse an address that is guessing
                    # before spending a database round trip on it.
                    if anonymous is not None and not anonymous.allow(address):
                        return too_many(anonymous.retry_after(address))

                    try:
                        request.state.principal = await authenticate(request)
                    except AuthError:
                        if failures is not None and not failures.allow(address):
                            return too_many(failures.retry_after(address))
                        raise

                    key = request.state.principal.key
                    wait = per_key.check(
                        str(key.id), key.rate_limit, key.daily_limit
                    )
                    if wait is not None:
                        return too_many(wait)

                    # It authenticated, so it was not a guess. Give the
                    # address its failure budget back -- otherwise a
                    # busy office behind one NAT locks itself out by
                    # mistyping a key a few times.
                    if failures is not None:
                        failures.forget(address)

                    await APIKeyRepo(conn).record_use(
                        key.id, request.headers.get("X-Forwarded-For")
                    )
                return await call_next(request)
        except AuthError as exc:
            return error(exc.status, exc.message)
        except NotFoundError as exc:
            return error(404, str(exc))
        except AmbiguousReferenceError as exc:
            return error(409, str(exc))
        except (ConflictError, APIKeyError) as exc:
            return error(409, str(exc))
        except IntegrityError:
            return error(409, "that conflicts with an existing record")
        except MailboxError as exc:
            # Handlers turn Dovecot's refusals into 4xx themselves; what
            # reaches here is not reaching Dovecot at all.
            return error(502, f"the mail store is unavailable: {exc}")
        except ValueError as exc:
            return error(400, str(exc))

    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        # A lifespan, not add_event_handler: Starlette 1.x removed the
        # event handlers, and the old owned-engine branch here would
        # have raised AttributeError for any caller not passing one.
        yield
        # Sending through the API creates a submission handler, whose
        # webhook announcements run as background tasks. Let them
        # finish, or a restart drops mail.received events on the floor.
        if (submission := getattr(app.state, "submission", None)) is not None:
            await submission.webhooks.drain()
        if owned_engine:
            await engine.dispose()

    app = Starlette(
        routes=ROUTES,
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=middleware)],
        lifespan=lifespan,
    )
    app.state.engine = engine
    app.state.config = cfg

    return app


__all__ = ["PUBLIC_PATHS", "ROUTES", "create_app"]
