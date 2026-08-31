"""Authentication.

Local accounts use bcrypt, matching the hashes the Go engine wrote --
an existing password keeps working after the port.

The same ``authenticate`` call backs three callers: SMTP submission,
the REST API, and Dovecot's passdb lookup. Keeping one path means an
offloaded provider works for IMAP without any extra wiring, which is
the reason the passdb is an HTTP call to Lightr rather than a direct
SQL lookup.
"""

from __future__ import annotations

import asyncio
import secrets
import string
from dataclasses import dataclass
from enum import StrEnum

import bcrypt
from sqlalchemy.ext.asyncio import AsyncConnection

from lightr.models import Account, AuthMode
from lightr.repo import AccountRepo

# The Go engine used bcrypt.DefaultCost.
BCRYPT_ROUNDS = 12

# bcrypt silently truncates at 72 bytes; reject rather than truncate so
# a long passphrase never authenticates on a prefix.
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_LENGTH = 8


class AuthFailure(StrEnum):
    NO_SUCH_ACCOUNT = "no_such_account"
    BAD_PASSWORD = "bad_password"
    ACCOUNT_DISABLED = "account_disabled"
    NO_PASSWORD_SET = "no_password_set"
    PROVIDER_UNAVAILABLE = "provider_unavailable"


@dataclass(frozen=True, slots=True)
class AuthResult:
    """The outcome of an authentication attempt."""

    ok: bool
    account: Account | None = None
    failure: AuthFailure | None = None

    @property
    def email(self) -> str | None:
        return self.account.email if self.account else None

    @classmethod
    def success(cls, account: Account) -> AuthResult:
        return cls(ok=True, account=account)

    @classmethod
    def failed(cls, failure: AuthFailure, account: Account | None = None) -> AuthResult:
        return cls(ok=False, account=account, failure=failure)


class PasswordError(ValueError):
    """A password was rejected before it was ever hashed."""


def validate_password(password: str) -> None:
    """Reject passwords bcrypt would mishandle or that are too weak."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordError(
            f"password must be at most {MAX_PASSWORD_BYTES} bytes "
            f"({len(encoded)} given); bcrypt cannot hash more"
        )


def hash_password(password: str, *, rounds: int = BCRYPT_ROUNDS) -> str:
    """Hash a password. Blocking -- call via to_thread on hot paths."""
    validate_password(password)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time check of a password against a bcrypt hash."""
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        # A malformed or non-bcrypt hash is a failed login, not a crash.
        return False


async def hash_password_async(password: str, *, rounds: int = BCRYPT_ROUNDS) -> str:
    return await asyncio.to_thread(hash_password, password, rounds=rounds)


async def verify_password_async(password: str, password_hash: str) -> bool:
    return await asyncio.to_thread(verify_password, password, password_hash)


def generate_password(length: int = 24) -> str:
    """A random password for `lightr account passwd --generate`.

    Avoids characters that are easy to transcribe wrongly or that need
    shell quoting, so an operator can paste it into a mail client.
    """
    alphabet = string.ascii_letters + string.digits + "-_.@+"
    ambiguous = set("lI1O0")
    pool = [c for c in alphabet if c not in ambiguous]
    return "".join(secrets.choice(pool) for _ in range(length))


# A real bcrypt hash of a random value. Verifying against it burns the
# same time a genuine check would, so a missing account and a wrong
# password are indistinguishable by timing.
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt(BCRYPT_ROUNDS)).decode()


class Authenticator:
    """Authenticates an address against local or offloaded credentials."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._accounts = AccountRepo(conn)

    async def authenticate(self, username: str, password: str) -> AuthResult:
        account = await self._accounts.find(username)

        if account is None:
            # Burn equivalent time so account enumeration by timing fails.
            await verify_password_async(password, _DUMMY_HASH)
            return AuthResult.failed(AuthFailure.NO_SUCH_ACCOUNT)

        if account.auth_mode is AuthMode.DISABLED:
            return AuthResult.failed(AuthFailure.ACCOUNT_DISABLED, account)

        if account.auth_mode is AuthMode.EXTERNAL:
            return await self._authenticate_external(account, password)

        if not account.password_hash:
            return AuthResult.failed(AuthFailure.NO_PASSWORD_SET, account)

        if await verify_password_async(password, account.password_hash):
            return AuthResult.success(account)
        return AuthResult.failed(AuthFailure.BAD_PASSWORD, account)

    async def _authenticate_external(self, account: Account, password: str) -> AuthResult:
        """Delegate to a configured auth provider.

        Providers (LDAP, OAuth2, OIDC, webhook) land in phase 8; until
        then an external account cannot log in, and says so rather than
        falling back to a local hash it should not trust.
        """
        del password
        return AuthResult.failed(AuthFailure.PROVIDER_UNAVAILABLE, account)


__all__ = [
    "AuthFailure",
    "AuthResult",
    "Authenticator",
    "PasswordError",
    "generate_password",
    "hash_password",
    "hash_password_async",
    "validate_password",
    "verify_password",
    "verify_password_async",
]
