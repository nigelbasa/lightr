"""Configuration model and loader.

Mirrors the YAML schema of the Go engine so existing config files keep
working, with two deliberate differences:

* the ``imap`` block is gone -- Dovecot owns IMAP now
* a ``dovecot`` block replaces it, describing how to reach Dovecot

Paths default to the Linux FHS locations the ``.deb`` installs into.
"""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

DEFAULT_CONFIG_PATH = Path("/etc/lightr/config.yaml")
DEFAULT_DATA_DIR = Path("/var/lib/lightr")
DEFAULT_LOG_FILE = Path("/var/log/lightr/lightr.log")

# Matches Gmail/Outlook/Yahoo, and the Go engine's default.
DEFAULT_MAX_MESSAGE_BYTES = 25 * 1024 * 1024


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class DatabaseDriver(StrEnum):
    SQLITE = "sqlite"
    POSTGRES = "postgres"


class ServerConfig(_Base):
    hostname: str = "localhost"
    bind_address: str = "0.0.0.0"


class DatabaseConfig(_Base):
    driver: DatabaseDriver = DatabaseDriver.SQLITE
    path: Path | None = None
    dsn: str = ""

    def url(self, data_dir: Path) -> str:
        """Build a SQLAlchemy URL for this database."""
        if self.driver is DatabaseDriver.POSTGRES:
            if not self.dsn:
                raise ValueError("database.dsn is required when driver is 'postgres'")
            # Accept a libpq DSN and normalise it onto the asyncpg driver.
            dsn = self.dsn
            for prefix in ("postgresql://", "postgres://"):
                if dsn.startswith(prefix):
                    return "postgresql+asyncpg://" + dsn[len(prefix) :]
            return dsn
        return f"sqlite+aiosqlite:///{self.path or data_dir / 'lightr.db'}"


class HTTPConfig(_Base):
    addr: str = ":8080"


class APIConfig(_Base):
    key: str = ""
    admin_key: str = ""


class DomainCertConfig(_Base):
    cert_file: Path
    key_file: Path


class TLSConfig(_Base):
    cert_file: Path | None = None
    key_file: Path | None = None
    domain_certs: dict[str, DomainCertConfig] = Field(default_factory=dict)


class SMTPConfig(_Base):
    addr: str = ":25"
    submission_addr: str = ":587"
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_recipients: int = 50
    allow_insecure: bool = False


class DovecotConfig(_Base):
    """How Lightr reaches Dovecot.

    Four seams: LMTP for delivery, IMAP for mailbox reads, doveadm for
    admin, and a Maildir root that both processes agree on.
    """

    # Delivery. A unix socket is preferred; host/port is the fallback.
    lmtp_socket: Path | None = Path("/run/dovecot/lmtp")
    lmtp_host: str = "127.0.0.1"
    lmtp_port: int = 24

    # Mailbox reads.
    imap_host: str = "127.0.0.1"
    imap_port: int = 143
    imap_use_tls: bool = False
    imap_pool_size: int = 8
    imap_idle_timeout_seconds: int = 60

    # Dovecot master user. Lets Lightr open any mailbox for the API and
    # the CLI without holding users' own passwords -- authenticating as
    # "user*master_user" with the master password. Configure the
    # matching passdb entry in Dovecot; without it, mailbox reads are
    # unavailable and Lightr says so rather than failing obscurely.
    master_user: str = ""
    master_password: str = ""

    # Shared secret Dovecot's passdb/userdb Lua script presents to
    # Lightr's internal auth endpoints. Not an API key: Dovecot is a
    # service, not an operator, and these routes must never be
    # reachable with an ordinary key.
    internal_key: str = ""

    @property
    def has_master_user(self) -> bool:
        return bool(self.master_user and self.master_password)

    # Admin.
    doveadm_url: str = "http://127.0.0.1:8080/doveadm/v1"
    doveadm_api_key: str = ""

    # Storage. Maildir, deliberately -- see docs/PYTHON-REWRITE.md section 3.
    maildir_root: Path = Path("/var/mail/lightr")
    sieve_dir: Path = Path("/var/lib/lightr/sieve")

    @property
    def uses_lmtp_socket(self) -> bool:
        return self.lmtp_socket is not None


class DKIMConfig(_Base):
    selector: str = "default"
    key_bits: int = 2048
    private_key_path: Path | None = None


class WebhookConfig(_Base):
    url: str = ""
    enabled: bool = False


class LoggingConfig(_Base):
    level: str = "info"
    file: Path | None = DEFAULT_LOG_FILE


class SpamConfig(_Base):
    enabled: bool = True
    suspicious_threshold: float = 2.0
    junk_threshold: float = 4.0
    dnsbl_zones: list[str] = Field(default_factory=list)
    rspamd_url: str = ""
    rspamd_password: str = ""
    timeout_seconds: int = 5


class SecurityConfig(_Base):
    require_tls_for_auth: bool = True


class Config(_Base):
    data_dir: Path = DEFAULT_DATA_DIR
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    smtp: SMTPConfig = Field(default_factory=SMTPConfig)
    dovecot: DovecotConfig = Field(default_factory=DovecotConfig)
    dkim: DKIMConfig = Field(default_factory=DKIMConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    tls: TLSConfig = Field(default_factory=TLSConfig)
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    spam: SpamConfig = Field(default_factory=SpamConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    @model_validator(mode="after")
    def _normalise(self) -> Self:
        """Fill in paths that derive from data_dir, and validate the pairs."""
        if self.database.path is None and self.database.driver is DatabaseDriver.SQLITE:
            self.database.path = self.data_dir / "lightr.db"

        tls_dir = self.data_dir / "tls"
        if self.tls.cert_file is None:
            self.tls.cert_file = tls_dir / "server.crt"
        if self.tls.key_file is None:
            self.tls.key_file = tls_dir / "server.key"

        if not self.server.hostname:
            self.server.hostname = "localhost"

        if self.database.driver is DatabaseDriver.POSTGRES and not self.database.dsn:
            raise ValueError("database.dsn is required when driver is 'postgres'")

        if self.smtp.max_recipients < 1:
            raise ValueError("smtp.max_recipients must be at least 1")
        if self.smtp.max_message_bytes < 1024:
            raise ValueError("smtp.max_message_bytes must be at least 1024")

        return self

    @property
    def database_url(self) -> str:
        return self.database.url(self.data_dir)

    # -- loading and saving --------------------------------------------

    @classmethod
    def load(cls, path: Path | str | None = None) -> Config:
        """Load config from YAML, falling back to defaults if absent.

        A missing file is not an error -- it yields the default config,
        matching the Go engine's behaviour.
        """
        resolved = Path(path) if path else cls.default_path()
        if not resolved.exists():
            return cls()
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"{resolved}: expected a YAML mapping at the top level")
        return cls.model_validate(_drop_retired_keys(raw))

    def save(self, path: Path | str) -> None:
        """Write config to YAML with owner-only permissions."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_yaml(), encoding="utf-8")
        target.chmod(0o600)

    def to_yaml(self) -> str:
        # mode="python", not "json": JSON mode stringifies Paths with
        # Pydantic's own str(), which on Windows yields backslashes
        # before _stringify ever sees them.
        #
        # Nulls are written, not excluded. Dropping them means an
        # explicit "lmtp_socket: null" -- which is how an operator says
        # "use TCP, not a unix socket" -- disappears on the next save
        # and silently reverts to the default on the next load.
        return yaml.safe_dump(
            _stringify(self.model_dump(mode="python")),
            sort_keys=False,
            default_flow_style=False,
        )

    @staticmethod
    def default_path() -> Path:
        if env := os.environ.get("LIGHTR_CONFIG"):
            return Path(env)
        return DEFAULT_CONFIG_PATH


# Keys the Go engine understood that no longer apply. Dropping them
# rather than erroring lets an existing config file load unchanged.
RETIRED_KEYS: dict[str, str] = {
    "imap": "IMAP is served by Dovecot; use the 'dovecot' block instead",
}


def _drop_retired_keys(raw: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in raw.items() if k not in RETIRED_KEYS}


def _stringify(value: Any) -> Any:
    """Render Paths and enums as plain strings for YAML output.

    Paths are always written POSIX-style. Lightr runs on Linux, so a
    config written while developing on Windows would otherwise contain
    ``\\var\\lib\\lightr`` -- a literal filename, not a path, anywhere
    it was actually used.
    """
    if isinstance(value, dict):
        return {k: _stringify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stringify(v) for v in value]
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, StrEnum):
        return str(value)
    return value
