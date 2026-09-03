"""Can this machine actually run Lightr?

Written after a deployment where ten separate things were wrong and
every one of them was found by a mail client failing to log in. The
engine started, reported itself healthy, and could not deliver a
message. Each of these checks corresponds to something that actually
happened.

The distinction that matters is **fatal versus degraded**. A missing
`dovecot-auth-lua` package is not a warning: nobody can log in, and
saying so quietly is how an install looks fine for an hour. A missing
PTR record is a warning: mail flows, some receivers refuse it.

The failure this was written for was a warning that should have been
fatal, so anything that means "cannot work" fails the run.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from lightr.config import Config, DatabaseDriver

#: Below this, the code does not import: StrEnum, datetime.UTC and
#: typing.Self are all 3.11.
MINIMUM_PYTHON = (3, 11)

#: Dovecot's Lua passdb needs 2.4 for `dovecot.http`. Lightr no longer
#: uses it -- checkpassword works everywhere -- but the version is
#: still worth reporting, because it decides what is even possible.
LUA_HTTP_DOVECOT = (2, 4)


class Level(StrEnum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass(slots=True)
class Check:
    name: str
    level: Level
    detail: str
    fix: str | None = None

    @property
    def fatal(self) -> bool:
        return self.level is Level.FAIL


@dataclass(slots=True)
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(
        self, name: str, level: Level, detail: str, fix: str | None = None
    ) -> None:
        self.checks.append(Check(name, level, detail, fix))

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.level is Level.FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.level is Level.WARN]

    @property
    def ok(self) -> bool:
        return not self.failures


# --------------------------------------------------------------------
# The checks
# --------------------------------------------------------------------


def check_python(report: Report) -> None:
    current = sys.version_info[:2]
    if current < MINIMUM_PYTHON:
        report.add(
            "python",
            Level.FAIL,
            f"Python {current[0]}.{current[1]}; Lightr needs "
            f"{MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]} or newer",
            "Ubuntu 22.04 ships 3.10. Add deadsnakes and build the venv with "
            "python3.12: add-apt-repository ppa:deadsnakes/ppa",
        )
        return
    report.add("python", Level.OK, f"Python {current[0]}.{current[1]}")


def check_platform(report: Report) -> None:
    if platform.system() != "Linux":
        report.add(
            "platform",
            Level.FAIL,
            f"{platform.system()} is not supported",
            "Lightr targets Linux. Dovecot, Maildir permissions and the "
            "systemd unit all assume it.",
        )
        return
    report.add("platform", Level.OK, _distribution())


def _distribution() -> str:
    try:
        fields = dict(
            line.split("=", 1)
            for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
            if "=" in line
        )
        return fields.get("PRETTY_NAME", "Linux").strip('"')
    except OSError:  # pragma: no cover - not Linux
        return "Linux"


def dovecot_version() -> tuple[int, ...] | None:
    """Dovecot's version, or None if it is not installed."""
    if not shutil.which("dovecot"):
        return None
    try:
        out = subprocess.run(
            ["dovecot", "--version"], capture_output=True, timeout=10, check=False
        ).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return None
    parts = out.strip().split()[0].split(".") if out.strip() else []
    numbers = []
    for part in parts:
        if not part.isdigit():
            break
        numbers.append(int(part))
    return tuple(numbers) or None


def check_dovecot(report: Report) -> None:
    version = dovecot_version()
    if version is None:
        report.add(
            "dovecot",
            Level.FAIL,
            "Dovecot is not installed; there are no mailboxes without it",
            "apt install dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve",
        )
        return

    shown = ".".join(str(n) for n in version)
    note = "" if version >= LUA_HTTP_DOVECOT else " (2.3: Lua has no HTTP support)"
    report.add("dovecot", Level.OK, f"Dovecot {shown}{note}")


#: Probed by file, not by asking apt: a package can be installed and
#: its module absent, and the module is what Dovecot loads.
DOVECOT_MODULES: tuple[tuple[str, str, str, bool], ...] = (
    (
        "lmtp",
        "/usr/lib/dovecot/lmtp",
        "dovecot-lmtpd",
        True,
    ),
    (
        "sieve",
        "/usr/lib/dovecot/modules/lib90_sieve_plugin.so",
        "dovecot-sieve",
        False,
    ),
)


def check_dovecot_modules(report: Report, cfg: Config) -> None:
    if dovecot_version() is None:
        return

    for name, path, package, required in DOVECOT_MODULES:
        if Path(path).exists():
            report.add(f"dovecot-{name}", Level.OK, package)
            continue
        report.add(
            f"dovecot-{name}",
            Level.FAIL if required else Level.WARN,
            f"{package} is missing"
            + ("" if required else "; filter rules will not run"),
            f"apt install {package}",
        )

    _check_userdb_driver(report, cfg)


def _check_userdb_driver(report: Report, cfg: Config) -> None:
    """Dovecot needs its own driver for Lightr's database.

    A missing one fails at delivery time with "Unknown database
    driver", which points at nothing.
    """
    from lightr.dovecot import userdb

    package = userdb.package_name(cfg)
    driver = userdb.driver_name(cfg)
    candidates = (
        Path(f"/usr/lib/dovecot/modules/auth/libdriver_{driver}.so"),
        Path(f"/usr/lib/dovecot/modules/libdriver_{driver}.so"),
    )
    if any(p.exists() for p in candidates):
        report.add("dovecot-sql", Level.OK, package)
        return

    report.add(
        "dovecot-sql",
        Level.FAIL,
        f"{package} is missing, so Dovecot cannot look up where mailboxes live",
        f"apt install {package}",
    )


def check_database_driver(report: Report, cfg: Config) -> None:
    driver = cfg.database.driver
    module, extra = (
        ("aiosqlite", "sqlite")
        if driver is DatabaseDriver.SQLITE
        else ("asyncpg", "postgres")
    )
    try:
        __import__(module)
    except ImportError:
        report.add(
            "database-driver",
            Level.FAIL,
            f"{module} is not installed, and database.driver is {driver}",
            f"pip install 'lightr[{extra}]'",
        )
        return
    report.add("database-driver", Level.OK, f"{module} for {driver}")


def check_config_readable(report: Report, path: Path) -> None:
    if not path.exists():
        report.add(
            "config",
            Level.WARN,
            f"{path} does not exist yet; defaults are in use",
            "It is written when the package is installed.",
        )
        return

    info = path.stat()
    mode = info.st_mode & 0o777
    if mode & 0o007:
        report.add(
            "config",
            Level.WARN,
            f"{path} is world-readable ({mode:o}) and holds credentials",
            f"chmod 640 {path}",
        )
        return

    if not _readable_by_service(path, info.st_uid, info.st_gid, mode):
        # Fatal, not a warning. The service starts, cannot read its own
        # config, and falls back to defaults -- so it looks healthy
        # while pointing at the wrong database.
        report.add(
            "config",
            Level.FAIL,
            f"{path} ({mode:o}) cannot be read by the {SERVICE_USER} user, "
            "which is who the service runs as",
            f"chown root:{SERVICE_GROUP} {path} && chmod 640 {path}",
        )
        return

    report.add("config", Level.OK, f"{path} ({mode:o})")


#: Who the systemd unit runs as.
SERVICE_USER = "lightr"
SERVICE_GROUP = "lightr"


def _readable_by_service(path: Path, uid: int, gid: int, mode: int) -> bool:
    """Whether the service user could open this file.

    Answers "yes" whenever it cannot tell -- no such user on this
    machine, or no POSIX users at all. A check that guesses wrong in
    the other direction fails an install that is fine.
    """
    try:
        import grp
        import pwd
    except ImportError:  # pragma: no cover - not POSIX
        return True

    try:
        service = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        return True  # a pip install, run as whoever ran it

    if service.pw_uid == uid:
        return bool(mode & 0o400)
    if service.pw_gid == gid:
        return bool(mode & 0o040)
    try:
        group = grp.getgrgid(gid)
    except KeyError:
        return bool(mode & 0o004)
    if SERVICE_USER in group.gr_mem:
        return bool(mode & 0o040)
    return bool(mode & 0o004)


def check_doveconf(report: Report) -> None:
    """Dovecot's own parser on Dovecot's own configuration."""
    if not shutil.which("doveconf"):
        return
    try:
        result = subprocess.run(
            ["doveconf", "-n"], capture_output=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return

    if result.returncode:
        report.add(
            "dovecot-config",
            Level.FAIL,
            "Dovecot's configuration does not parse: "
            + result.stderr.decode("utf-8", "replace").strip().splitlines()[-1][:160],
            "lightr dovecot install",
        )
        return
    report.add("dovecot-config", Level.OK, "doveconf accepts the configuration")


def run(cfg: Config, config_path: Path | None = None) -> Report:
    """Every check, in the order a failure would matter."""
    report = Report()
    check_platform(report)
    check_python(report)
    check_config_readable(report, config_path or Config.default_path())
    check_database_driver(report, cfg)
    check_dovecot(report)
    check_dovecot_modules(report, cfg)
    check_doveconf(report)
    return report


__all__ = [
    "DOVECOT_MODULES",
    "LUA_HTTP_DOVECOT",
    "MINIMUM_PYTHON",
    "SERVICE_GROUP",
    "SERVICE_USER",
    "Check",
    "Level",
    "Report",
    "dovecot_version",
    "run",
]
