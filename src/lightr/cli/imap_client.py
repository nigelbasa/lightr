"""Opening a mailbox against Dovecot.

Lightr reads mailboxes as a Dovecot *master user*: it authenticates as
``<account>*<master_user>`` with the master password, which lets an
operator command open any mailbox without Lightr ever storing or
seeing users' own passwords.

The concrete client is created lazily so that importing the CLI does
not require aioimaplib, and so tests can substitute a fake without a
running Dovecot.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from lightr.config import Config
from lightr.dovecot.mailbox import IMAPProtocol, Mailbox, MailboxError
from lightr.repo import AccountRepo

from .context import db, state

#: Test seam. When set, ``open_mailbox`` uses this instead of connecting.
_client_factory: Callable[[Config, str], IMAPProtocol] | None = None


def set_client_factory(factory: Callable[[Config, str], IMAPProtocol] | None) -> None:
    """Install a client factory. Used by tests; None restores the real one."""
    global _client_factory
    _client_factory = factory


def master_login(email: str, master_user: str) -> str:
    """Dovecot's master-user login form."""
    return f"{email}*{master_user}"


async def _connect(cfg: Config, email: str) -> IMAPProtocol:
    if _client_factory is not None:
        return _client_factory(cfg, email)

    dovecot = cfg.dovecot
    if not dovecot.has_master_user:
        raise MailboxError(
            "reading mailboxes needs a Dovecot master user.\n"
            "Set dovecot.master_user and dovecot.master_password in your config, "
            "and add the matching passdb entry to Dovecot."
        )

    try:
        from lightr.dovecot.aioimap import AioIMAPClient
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise MailboxError(
            "aioimaplib is not installed -- reinstall with: pip install 'lightr[imap]'"
        ) from exc

    client = AioIMAPClient(
        host=dovecot.imap_host,
        port=dovecot.imap_port,
        use_tls=dovecot.imap_use_tls,
    )
    await client.login(master_login(email, dovecot.master_user), dovecot.master_password)
    return client


@asynccontextmanager
async def open_mailbox(account_ref: str) -> AsyncIterator[Mailbox]:
    """Resolve an account reference and open its mailbox.

    Takes the same references every other command does -- an email
    address, a bare local part, or an id -- so the mailbox commands
    are not the one group that demands a different form.
    """
    async with db() as conn:
        account = await AccountRepo(conn).resolve(account_ref)

    email = account.email
    if email is None:  # pragma: no cover - resolve always sets it
        raise MailboxError(f"could not determine the address for {account_ref!r}")

    client = await _connect(state.config, email)
    try:
        yield Mailbox(client)
    finally:
        try:
            await client.logout()
        except Exception:
            pass


__all__ = ["master_login", "open_mailbox", "set_client_factory"]
