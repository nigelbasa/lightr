"""Create the Postgres role and database Lightr needs.

An operator moving off SQLite otherwise has to invent a role name, a
password and a set of grants, get them into a DSN by hand, and get the
same database reachable from Dovecot's userdb -- which is four places
to make one mistake and a password typed into a shell history.

This does it with the escalation the machine already grants: `psql` as
the `postgres` system user, which is how every Debian-family Postgres
install is administered locally. Nothing here reaches the network, and
nothing asks for a superuser password.

The generated password is written into /etc/lightr/config.yaml (0640
root:lightr) and printed nowhere. Nobody has to see it, so nobody has
to be careful with it.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from lightr.auth import generate_password

#: The system user local Postgres administration runs as.
SUPERUSER = "postgres"

#: Long, and never typed by a human -- it goes into a config file and
#: a Dovecot conf, both machine-written.
PASSWORD_LENGTH = 40


class ProvisionError(RuntimeError):
    """The role or database could not be created."""


@dataclass(slots=True)
class Provisioned:
    role: str
    database: str
    dsn: str
    created_role: bool
    created_database: bool
    reset_password: bool


def psql(sql: str, *, database: str = "postgres") -> str:
    """Run one statement as the Postgres superuser.

    ``sudo -u postgres`` rather than a connection string: it is the
    path that works on a stock install with no password set, and it
    fails immediately and legibly when this is not being run as root.
    """
    if not shutil.which("psql"):
        raise ProvisionError(
            "psql is not installed, so the role cannot be created. "
            "apt install postgresql-client -- or create the role yourself "
            "and put its DSN in database.dsn."
        )

    command = ["psql", "--no-psqlrc", "-tAX", "-d", database, "-c", sql]
    if shutil.which("sudo"):
        command = ["sudo", "-n", "-u", SUPERUSER, *command]

    try:
        result = subprocess.run(
            command, capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvisionError(f"could not run psql: {exc}") from exc

    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ProvisionError(_explain(detail))
    return result.stdout.decode("utf-8", "replace").strip()


def _explain(detail: str) -> str:
    """Turn psql's error into the thing to do about it."""
    lowered = detail.lower()
    if "sudo" in lowered and "password" in lowered:
        return (
            "this needs to run as root, so it can administer Postgres as the "
            f"{SUPERUSER} user. Try: sudo lightr db provision"
        )
    if "could not connect" in lowered or "connection refused" in lowered:
        return (
            "Postgres is not running or not listening locally. "
            "systemctl status postgresql"
        )
    if "role" in lowered and "does not exist" in lowered:
        return (
            f"there is no {SUPERUSER} role on this server, so Lightr cannot "
            "administer it. Create the role and database yourself, then put "
            "the DSN in database.dsn."
        )
    return detail or "psql failed without saying why"


def quote_literal(value: str) -> str:
    """A single-quoted SQL string.

    The password is generated here, not supplied, so this is belt and
    braces -- but a provisioning path that builds SQL by concatenation
    and has no quoting is one refactor away from being a real problem.
    """
    return "'" + value.replace("'", "''") + "'"


def quote_identifier(value: str) -> str:
    if not value.replace("_", "").isalnum():
        raise ProvisionError(
            f"{value!r} is not a usable Postgres name -- letters, digits and "
            "underscores only"
        )
    return '"' + value + '"'


def exists(what: str, name: str) -> bool:
    table = {"role": "pg_roles WHERE rolname", "database": "pg_database WHERE datname"}
    return psql(f"SELECT 1 FROM {table[what]} = {quote_literal(name)}") == "1"


def provision(
    *,
    role: str = "lightr",
    database: str = "lightr",
    host: str = "127.0.0.1",
    port: int = 5432,
    known_password: str | None = None,
) -> Provisioned:
    """Create the role and database if they are not there.

    Idempotent, because the package runs setup on every upgrade. The
    one thing it will not do quietly is reset the password of a role
    that already works: that would break Dovecot's userdb until it was
    regenerated, and something else may be using the role too.
    """
    role_name = quote_identifier(role)
    database_name = quote_identifier(database)

    created_role = False
    reset_password = False
    password = known_password

    if not exists("role", role):
        password = generate_password(PASSWORD_LENGTH)
        psql(
            f"CREATE ROLE {role_name} LOGIN PASSWORD {quote_literal(password)}"
        )
        created_role = True
    elif password is None:
        # The role is there and we do not have its password -- which
        # means nothing here can connect as it. Resetting is the only
        # way forward, and it is announced rather than done silently.
        password = generate_password(PASSWORD_LENGTH)
        psql(f"ALTER ROLE {role_name} WITH LOGIN PASSWORD {quote_literal(password)}")
        reset_password = True

    created_database = False
    if not exists("database", database):
        # CREATE DATABASE cannot run inside a transaction block, which
        # is why each statement here is its own psql invocation.
        psql(f"CREATE DATABASE {database_name} OWNER {role_name}")
        created_database = True

    # Owning the database is not enough on Postgres 15+, where PUBLIC
    # lost CREATE on the public schema. Without this the first
    # migration fails with "permission denied for schema public",
    # which reads like a bug in Lightr.
    psql(
        f"GRANT ALL ON SCHEMA public TO {role_name}",
        database=database,
    )
    psql(
        f"ALTER DATABASE {database_name} OWNER TO {role_name}",
    )

    assert password is not None
    return Provisioned(
        role=role,
        database=database,
        dsn=f"postgresql://{role}:{password}@{host}:{port}/{database}",
        created_role=created_role,
        created_database=created_database,
        reset_password=reset_password,
    )


def existing_password(dsn: str) -> str | None:
    """The password already in a DSN, if there is one."""
    from urllib.parse import urlsplit

    if not dsn:
        return None
    try:
        return urlsplit(dsn).password
    except ValueError:  # pragma: no cover - malformed DSN
        return None


def write_dsn(config_path: Path, dsn: str) -> None:
    """Put the DSN in the config, without disturbing anything else."""
    from lightr import configtemplate

    configtemplate.set_values(
        config_path,
        {("database", "driver"): "postgres", ("database", "dsn"): dsn},
    )


__all__ = [
    "PASSWORD_LENGTH",
    "ProvisionError",
    "Provisioned",
    "existing_password",
    "provision",
    "psql",
    "quote_identifier",
    "quote_literal",
    "write_dsn",
]
