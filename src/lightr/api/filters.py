"""The ``/v1/mailbox/filters`` routes.

A mailbox's own rules, managed with its own key. Every change is
compiled and installed before the request returns, inside the same
transaction: if Dovecot will not take the script, the change is rolled
back rather than left in the table to break the next install.
"""

from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from lightr.api.auth import AuthError
from lightr.api.mailbox import _account_for, _json
from lightr.dovecot.filters import MAX_RULES, FilterError, FilterRepo, normalise
from lightr.models import Account
from lightr.repo import DomainRepo

log = logging.getLogger("lightr.api.filters")


async def _install(request: Request, account: Account) -> None:
    """Compile and install this mailbox's script, or refuse the change."""
    from lightr.dovecot.doveadm import DoveadmError
    from lightr.dovecot.maildir import MaildirError
    from lightr.dovecot.sieve import SieveError
    from lightr.dovecot.sieve_install import SieveInstaller

    if account.email is None:  # pragma: no cover - resolve always sets it
        raise AuthError(500, "could not determine the mailbox address")

    installer = SieveInstaller(
        request.state.conn,
        request.app.state.config.dovecot.sieve_dir,
        doveadm=getattr(request.app.state, "doveadm", None),
    )
    try:
        await installer.install(account.id, account.email)
    except SieveError as exc:
        raise AuthError(400, f"Dovecot will not accept these filters: {exc}") from exc
    except (DoveadmError, MaildirError, OSError) as exc:
        log.error("could not install Sieve for %s: %s", account.email, exc)
        raise AuthError(
            502, "the filters could not be installed; nothing was changed"
        ) from exc


def _body_error(exc: FilterError) -> AuthError:
    return AuthError(400, str(exc))


async def list_filters(request: Request) -> Response:
    account = await _account_for(request)
    return _json(await FilterRepo(request.state.conn).list(account.id))


async def get_filter(request: Request) -> Response:
    account = await _account_for(request)
    rule = await FilterRepo(request.state.conn).get(account.id, request.path_params["id"])
    if rule is None:
        return _json({"error": "no such filter"}, 404)
    return _json(rule)


async def create_filter(request: Request) -> Response:
    from lightr.api.app import parse_body

    account = await _account_for(request)
    body = await parse_body(request)
    try:
        values = normalise(body)
    except FilterError as exc:
        raise _body_error(exc) from exc

    conn = request.state.conn
    repo = FilterRepo(conn)
    if await repo.count(account.id) >= MAX_RULES:
        raise AuthError(400, f"a mailbox can have at most {MAX_RULES} filters")

    domain = await DomainRepo(conn).resolve(str(account.domain_id))
    rule_id = await repo.create(org_id=domain.org_id, account_id=account.id, values=values)
    await _install(request, account)
    return _json(await repo.get(account.id, rule_id), 201)


async def update_filter(request: Request) -> Response:
    """Change some fields; the rest keep their values."""
    from lightr.api.app import parse_body

    account = await _account_for(request)
    body = await parse_body(request)
    repo = FilterRepo(request.state.conn)
    current = await repo.get(account.id, request.path_params["id"])
    if current is None:
        return _json({"error": "no such filter"}, 404)

    merged = {
        key: current[key]
        for key in ("name", "description", "priority", "conditions", "actions",
                    "match_type", "is_active", "stop_on_match")
    }
    # Stored booleans come back from SQLite as integers.
    for flag in ("is_active", "stop_on_match"):
        merged[flag] = bool(merged[flag])
    merged["priority"] = int(merged["priority"] if merged["priority"] is not None else 100)
    merged.update(body)
    try:
        values = normalise(merged)
    except FilterError as exc:
        raise _body_error(exc) from exc

    await repo.update(account.id, current["id"], values)
    await _install(request, account)
    return _json(await repo.get(account.id, current["id"]))


async def delete_filter(request: Request) -> Response:
    account = await _account_for(request)
    if not await FilterRepo(request.state.conn).delete(
        account.id, request.path_params["id"]
    ):
        return _json({"error": "no such filter"}, 404)
    await _install(request, account)
    return Response(status_code=204)


async def show_script(request: Request) -> Response:
    """The Sieve script these rules compile to, for a client's
    "advanced" view and for working out why a rule did not fire."""
    from lightr.dovecot.sieve import compile_script
    from lightr.dovecot.sieve_install import SieveInstaller

    account = await _account_for(request)
    installer = SieveInstaller(
        request.state.conn, request.app.state.config.dovecot.sieve_dir
    )
    rules = await installer.rules_for(account.id)
    return Response(compile_script(rules).render(), media_type="text/plain")


FILTER_ROUTES: list[Route] = [
    Route("/v1/mailbox/filters", list_filters, methods=["GET"]),
    Route("/v1/mailbox/filters", create_filter, methods=["POST"]),
    # Before /{id}, which would otherwise take "script" as an id.
    Route("/v1/mailbox/filters/script", show_script, methods=["GET"]),
    Route("/v1/mailbox/filters/{id}", get_filter, methods=["GET"]),
    Route("/v1/mailbox/filters/{id}", update_filter, methods=["PATCH"]),
    Route("/v1/mailbox/filters/{id}", delete_filter, methods=["DELETE"]),
]

__all__ = ["FILTER_ROUTES"]
