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
from lightr.api.auth import AuthError, Principal, authenticate
from lightr.api.internal import INTERNAL_PATHS, INTERNAL_ROUTES
from lightr.api.mailbox import MAILBOX_ROUTES
from lightr.apikeys import APIKeyError, APIKeyRepo, KeyType, Permission
from lightr.config import Config
from lightr.db.engine import create_engine, ping
from lightr.models import Account, Alias, AuthMode, Domain, Organization
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


def dump(record: Any) -> dict[str, Any]:
    data = record.model_dump()
    # Credentials never cross the wire, in either direction.
    for field in ("password_hash", "dkim_private_key", "relay_password",
                  "auth_webhook_secret", "key_hash"):
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


async def list_accounts(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    conn = request.state.conn

    domain_id = None
    if domain_ref := request.query_params.get("domain"):
        domain = await DomainRepo(conn).resolve(domain_ref)
        if not principal.may_reach_domain(domain.id, domain.org_id):
            raise AuthError(403, "this key cannot reach that domain")
        domain_id = domain.id
    elif principal.key.domain_id is not None:
        domain_id = principal.key.domain_id

    accounts = await AccountRepo(conn).list(domain_id=domain_id)
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
    if not principal.may_reach_account(account.id):
        raise AuthError(403, "this key cannot reach that account")
    return ok(dump(account))


async def delete_account(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    conn = request.state.conn
    account = await AccountRepo(conn).resolve(request.path_params["id"])
    if not principal.may_reach_account(account.id):
        raise AuthError(403, "this key cannot reach that account")
    await AccountRepo(conn).delete(account.id)
    return Response(status_code=204)


async def list_aliases(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.READ)
    conn = request.state.conn

    domain_id = None
    if domain_ref := request.query_params.get("domain"):
        domain_id = (await DomainRepo(conn).resolve(domain_ref)).id

    return ok([dump(a) for a in await AliasRepo(conn).list(domain_id=domain_id)])


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
            destinations=body["destinations"],
            type=body.get("type", "forward"),
        )
    )
    return ok(dump(alias), 201)


async def delete_alias(request: Request) -> Response:
    principal: Principal = request.state.principal
    principal.require(Permission.WRITE)
    conn = request.state.conn
    alias = await AliasRepo(conn).resolve(request.path_params["id"])
    await AliasRepo(conn).delete(alias.id)
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
    Route("/v1/domains/{id}", delete_domain, methods=["DELETE"]),

    Route("/v1/accounts", list_accounts, methods=["GET"]),
    Route("/v1/accounts", create_account, methods=["POST"]),
    Route("/v1/accounts/{id}", get_account, methods=["GET"]),
    Route("/v1/accounts/{id}", delete_account, methods=["DELETE"]),

    Route("/v1/aliases", list_aliases, methods=["GET"]),
    Route("/v1/aliases", create_alias, methods=["POST"]),
    Route("/v1/aliases/{id}", delete_alias, methods=["DELETE"]),

    Route("/v1/apikeys", list_api_keys, methods=["GET"]),
    Route("/v1/apikeys", create_api_key, methods=["POST"]),
    Route("/v1/apikeys/{id}/revoke", revoke_api_key, methods=["POST"]),
    Route("/v1/apikeys/{id}/rotate", rotate_api_key, methods=["POST"]),
    Route("/v1/apikeys/{id}", delete_api_key, methods=["DELETE"]),
]

ROUTES.extend(MAILBOX_ROUTES)
ROUTES.extend(INTERNAL_ROUTES)

#: Paths the API-key middleware does not guard. /health is public;
#: the internal routes carry their own shared-secret check.
PUBLIC_PATHS = frozenset({"/health"}) | INTERNAL_PATHS


def create_app(cfg: Config, engine: AsyncEngine | None = None) -> Starlette:
    """Build the ASGI application."""
    owned_engine = engine is None
    engine = engine or create_engine(cfg)

    async def middleware(request: Request, call_next: Handler) -> Response:
        """Open a transaction, authenticate, and translate errors."""
        try:
            async with engine.begin() as conn:
                request.state.conn = conn
                if request.url.path not in PUBLIC_PATHS:
                    request.state.principal = await authenticate(request)
                    await APIKeyRepo(conn).record_use(
                        request.state.principal.key.id,
                        request.headers.get("X-Forwarded-For"),
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
        except ValueError as exc:
            return error(400, str(exc))

    app = Starlette(
        routes=ROUTES,
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=middleware)],
    )
    app.state.engine = engine
    app.state.config = cfg

    if owned_engine:
        async def _dispose() -> None:
            await engine.dispose()

        app.add_event_handler("shutdown", _dispose)

    return app


__all__ = ["PUBLIC_PATHS", "ROUTES", "create_app"]
