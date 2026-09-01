"""LDAP and Active Directory.

Authentication is a **bind as the user**, not a password comparison.
Reading a hash out of the directory and checking it here would mean
holding a copy of every credential and reimplementing whatever scheme
the directory uses; binding asks the directory the question it exists
to answer.

Two shapes, because directories come in two:

*search-then-bind*
    Bind as a service account, find the entry whose mail or uid
    matches, then bind as that entry's DN. This is what almost every
    real directory needs, because the DN is not derivable from the
    address.
*direct bind*
    Build the DN from a template and bind. Simpler, and correct only
    when the directory is laid out that regularly.

``ldap3`` is synchronous, so every call goes through a thread. Called
directly it would block the loop that is serving SMTP and the API.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from lightr.authproviders.base import (
    Identity,
    ProviderBase,
    ProviderConfigError,
    ProviderError,
)

log = logging.getLogger("lightr.auth.ldap")


@dataclass(slots=True)
class LDAPProvider(ProviderBase):
    """Authenticates against an LDAP or Active Directory server."""

    kind = "ldap"

    async def authenticate(self, username: str, password: str) -> Identity | None:
        # An empty password is an *unauthenticated bind* in LDAP: the
        # server returns success and binds anonymously. Every LDAP
        # integration that has ever been broken has been broken here.
        if not password:
            return None

        return await self.bounded(asyncio.to_thread(self._authenticate, username, password))

    # -- everything below runs in a worker thread ------------------------

    def _connect(self, *, user: str | None = None, password: str | None = None) -> Any:
        try:
            import ldap3
        except ImportError as exc:  # pragma: no cover - depends on install
            raise ProviderConfigError(
                "LDAP authentication needs ldap3: pip install 'lightr[ldap]'"
            ) from exc

        uri = self.required("uri")
        server = ldap3.Server(uri, get_info=ldap3.NONE, connect_timeout=self.timeout)
        connection = ldap3.Connection(
            server,
            user=user,
            password=password,
            auto_bind=False,
            raise_exceptions=False,
            receive_timeout=self.timeout,
        )
        if self.config.get("start_tls"):
            if not connection.start_tls():
                raise ProviderError(
                    f"STARTTLS to {uri} failed: {connection.last_error}"
                )
        return connection

    def _authenticate(self, username: str, password: str) -> Identity | None:
        import ldap3

        dn, entry = self._resolve_dn(username)
        if dn is None:
            return None  # no such entry: a genuine refusal

        try:
            connection = self._connect(user=dn, password=password)
            bound = connection.bind()
        except ldap3.core.exceptions.LDAPException as exc:
            raise ProviderError(f"LDAP bind to {self.required('uri')} failed: {exc}") from exc

        if not bound:
            # Distinguish "wrong password" from "the server is unhappy".
            # invalidCredentials is the only result that means the user
            # got it wrong; everything else is our problem, not theirs.
            result = (connection.result or {}).get("description", "")
            if result in ("invalidCredentials", "insufficientAccessRights"):
                return None
            raise ProviderError(
                f"LDAP bind failed for {dn}: {result or connection.last_error}"
            )

        try:
            return self._identity(username, dn, entry)
        finally:
            connection.unbind()

    def _resolve_dn(self, username: str) -> tuple[str | None, Any]:
        """Find the entry's DN, by template or by search.

        Returns the entry alongside it when there was one, so the
        attribute read costs no second round trip.
        """
        if template := self.optional("user_dn_template"):
            local, _, domain = username.partition("@")
            return template.format(username=username, local=local, domain=domain), None

        return self._search_dn(username)

    def _search_dn(self, username: str) -> tuple[str | None, Any]:
        import ldap3

        base_dn = self.required("base_dn")
        user_filter = self.optional("user_filter", "(mail={username})")
        assert user_filter is not None
        local, _, _ = username.partition("@")
        query = user_filter.format(
            username=_escape(username), local=_escape(local)
        )

        connection = self._connect(
            user=self.optional("bind_dn"), password=self.optional("bind_password")
        )
        try:
            if not connection.bind():
                raise ProviderError(
                    f"could not bind as the service account: "
                    f"{(connection.result or {}).get('description', connection.last_error)}"
                )

            ok = connection.search(
                base_dn,
                query,
                search_scope=ldap3.SUBTREE,
                attributes=self._wanted_attributes(),
            )
            if not ok:
                raise ProviderError(
                    f"LDAP search failed: "
                    f"{(connection.result or {}).get('description', connection.last_error)}"
                )

            entries = list(connection.entries)
            if not entries:
                return None, None
            if len(entries) > 1:
                # Binding the first would let a filter that matches two
                # people log one in as the other.
                raise ProviderError(
                    f"{query} matched {len(entries)} entries; refine user_filter"
                )

            return str(entries[0].entry_dn), entries[0]
        finally:
            connection.unbind()

    def _wanted_attributes(self) -> list[str]:
        mapping = self.config.get("attributes") or {}
        wanted = {str(v) for v in mapping.values() if v}
        wanted.update({"cn", "displayName", "mail"})
        return sorted(wanted)

    def _identity(self, username: str, dn: str, entry: Any) -> Identity:
        mapping = self.config.get("attributes") or {}

        display = _attr(entry, mapping.get("display_name") or "displayName") or _attr(
            entry, "cn"
        )
        external = _attr(entry, mapping.get("external_id") or "entryUUID") or dn

        groups: tuple[str, ...] = ()
        if entry is not None and self.config.get("sync_groups"):
            groups = tuple(str(g) for g in (_attr_list(entry, "memberOf") or ()))

        return Identity(
            username=username,
            external_id=external,
            display_name=display,
            groups=groups,
        )


def _escape(value: str) -> str:
    """Escape an LDAP filter value (RFC 4515).

    Without this, a username containing ``*)(uid=`` rewrites the filter
    -- the LDAP equivalent of SQL injection.
    """
    out = []
    for char in value:
        if char in "\\*()\0":
            out.append(f"\\{ord(char):02x}")
        else:
            out.append(char)
    return "".join(out)


def _attr(entry: Any, name: str) -> str | None:
    if entry is None or not name:
        return None
    try:
        value = entry[name].value
    except (KeyError, LookupError, AttributeError):
        return None
    if isinstance(value, list | tuple):
        value = value[0] if value else None
    return str(value) if value else None


def _attr_list(entry: Any, name: str) -> list[str] | None:
    if entry is None:
        return None
    try:
        value = entry[name].value
    except (KeyError, LookupError, AttributeError):
        return None
    if value is None:
        return None
    return [str(v) for v in (value if isinstance(value, list | tuple) else [value])]


__all__ = ["LDAPProvider"]
