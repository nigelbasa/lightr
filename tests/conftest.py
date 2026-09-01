"""Shared fixtures."""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from lightr.config import Config
from lightr.db.engine import create_all, create_engine

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def go_ddl() -> str:
    """The Go engine's verbatim schema at v0.1.0-go-final."""
    return (FIXTURES / "go_schema.sql").read_text(encoding="utf-8")


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    """A config with every path confined to a scratch directory.

    The Dovecot paths default to absolute system locations
    (/var/mail/lightr, /var/lib/lightr/sieve). Left alone, tests write
    Maildirs and Sieve scripts outside their tmp directory, leak state
    between runs, and could clobber a real install on a dev box.
    """
    return Config.model_validate(
        {
            "data_dir": str(tmp_path),
            "dovecot": {
                "maildir_root": str(tmp_path / "mail"),
                "sieve_dir": str(tmp_path / "sieve"),
                "lmtp_socket": None,
            },
        }
    )


@pytest_asyncio.fixture
async def engine(cfg: Config) -> AsyncIterator[AsyncEngine]:
    """An engine over a fresh database with the Python schema applied."""
    eng = create_engine(cfg)
    await create_all(eng)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def go_engine(cfg: Config, go_ddl: str) -> AsyncIterator[AsyncEngine]:
    """An engine over a database created by the *Go* engine's DDL.

    Built with plain sqlite3 so nothing in the Python schema layer can
    influence the result -- this has to be an honest reproduction of
    what the Go binary would have left on disk.
    """
    assert cfg.database.path is not None
    cfg.database.path.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(cfg.database.path)
    try:
        raw.executescript(go_ddl)
        raw.commit()
    finally:
        raw.close()

    eng = create_engine(cfg)
    yield eng
    await eng.dispose()


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop the suite from making real DNS queries.

    The delivery path evaluates SPF and DMARC, which resolve names. A
    test suite that reaches the network is slow and flaky, and its
    results depend on whoever owns the domain in the fixture. Tests
    that mean to exercise those paths patch them explicitly.

    Returns "no policy published", which is what a real lookup for a
    .test domain yields anyway -- so behaviour is unchanged, just
    hermetic and fast.
    """

    async def _no_policy(domain: str) -> None:
        return None

    monkeypatch.setattr(
        "lightr.mail.authentication._dmarc_policy", _no_policy, raising=False
    )
