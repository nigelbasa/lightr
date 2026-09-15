"""Managing Dovecot as an internal component.

Lightr owns Dovecot's configuration and lifecycle. An operator runs
``lightr``; they do not edit ``dovecot.conf``, hash a master password
by hand, or remember to reload the service afterwards.

That means Lightr writes files outside its own tree and restarts
another daemon, so every step here is deliberate about failure:

* configuration is written atomically, and the previous version is
  kept, so a bad generation can be rolled back
* Dovecot's own ``doveconf`` checks the result **before** the service
  is reloaded -- a config that does not parse would otherwise take
  the mail server down
* nothing is destructive: existing files are backed up, never replaced
  in the dark
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from lightr.config import Config
from lightr.dovecot import config as dovecot_config
from lightr.dovecot.doveadm import Doveadm, DoveadmError

log = logging.getLogger("lightr.dovecot")

#: Where Dovecot's own config lives on a Debian install.
DOVECOT_CONF_DIR = Path("/etc/dovecot")
MASTER_USERS_FILE = DOVECOT_CONF_DIR / "master-users"

#: Lightr's master user. Named so it is obvious in Dovecot's logs which
#: connections are the engine's rather than a person's.
DEFAULT_MASTER_USER = "lightr-master"


class DovecotManagementError(RuntimeError):
    """Dovecot could not be configured."""


@dataclass
class Change:
    """One file Lightr wrote."""

    path: Path
    action: str  # written | unchanged | backed-up
    backup: Path | None = None


@dataclass
class InstallReport:
    changes: list[Change] = field(default_factory=list)
    reloaded: bool = False
    warnings: list[str] = field(default_factory=list)
    generated: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return any(c.action == "written" for c in self.changes)


def write_atomic(
    path: Path, content: str, *, mode: int = 0o644, group: str | None = None
) -> Change:
    """Write a file atomically, backing up anything already there.

    Dovecot may read any of these at any moment, so the new content is
    written beside the old and renamed into place.
    """
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return Change(path, "unchanged")

    backup: Path | None = None
    if path.exists():
        stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        backup = path.with_suffix(path.suffix + f".lightr-{stamp}.bak")
        shutil.copy2(path, backup)

    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".lightr-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        Path(temporary).replace(path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    path.chmod(mode)
    if group:
        _set_group(path, group)

    return Change(path, "written", backup)


def _set_group(path: Path, group: str) -> None:
    """Give a file to a group, if that group exists here.

    A missing group is not fatal: it means Dovecot is not installed on
    this machine, and the caller has already been told that. Failing
    the whole write would turn a warning into an outage.
    """
    try:
        shutil.chown(path, group=group)
    except (LookupError, PermissionError, OSError, AttributeError) as exc:
        log.warning("could not give %s to group %s: %s", path, group, exc)


class DovecotManager:
    """Installs and maintains Dovecot's configuration."""

    def __init__(
        self,
        cfg: Config,
        *,
        doveadm: Doveadm | None = None,
        conf_dir: Path = DOVECOT_CONF_DIR,
    ) -> None:
        self.cfg = cfg
        self.conf_dir = conf_dir
        self.doveadm = doveadm if doveadm is not None else Doveadm()
        #: How to precompile a Sieve script. A list so tests can run
        #: something other than Pigeonhole's sievec.
        sievec = shutil.which("sievec")
        self.sievec_command: list[str] | None = [sievec] if sievec else None

    # -- the whole job ----------------------------------------------------

    async def reconcile(self, *, save_config: Path | None = None) -> InstallReport:
        """Make Dovecot match Lightr's configuration. Safe to call always.

        This is the automatic path: ``lightr setup`` calls it, and the
        package runs that on install and upgrade, so an install that
        has drifted -- a hand-edited conf, a package upgrade that
        replaced a file, a config change nobody re-applied -- converges
        without an operator knowing it happened. ``serve`` only reports
        drift; see ``drift``.

        Never raises. Dovecot being misconfigured is worth a loud
        warning, but it must not stop Lightr from starting: the API,
        the queue, and SMTP receive are all still useful while
        mailboxes are down, and refusing to boot would turn a mailbox
        problem into a total outage.
        """
        report = InstallReport()

        missing = self.fill_in_gaps()
        if missing and save_config is not None:
            # Surgical, not load-modify-dump. Dumping the model back
            # over the config file writes away every comment in it --
            # and, on a live server once, a hand-edited Postgres DSN.
            from lightr import configtemplate

            try:
                configtemplate.set_values(
                    save_config,
                    {
                        ("dovecot", "internal_key"): self.cfg.dovecot.internal_key,
                        ("dovecot", "master_user"): self.cfg.dovecot.master_user,
                        ("dovecot", "master_password"): (
                            self.cfg.dovecot.master_password
                        ),
                    },
                )
                report.generated = missing
            except OSError as exc:
                report.warnings.append(
                    f"generated {', '.join(missing)} but could not save "
                    f"{save_config}: {exc}"
                )

        if not self.doveadm.available:
            report.warnings.append(
                "doveadm was not found, so Dovecot was not configured. "
                "Mailboxes will not work until it is installed: "
                "apt install dovecot-core"
            )
            return report

        try:
            return await self.install(reload=True, report=report)
        except (DovecotManagementError, OSError) as exc:
            report.warnings.append(f"could not configure Dovecot: {exc}")
            return report

    def fill_in_gaps(self) -> list[str]:
        """Generate any secret Dovecot needs that is not set yet.

        An operator should never have to invent, hash, or type these.
        Returns what was created, for reporting.
        """
        from lightr.auth import generate_password

        created: list[str] = []
        if not self.cfg.dovecot.internal_key:
            self.cfg.dovecot.internal_key = dovecot_config.generate_internal_key()
            created.append("internal auth key")
        if not self.cfg.dovecot.has_master_user:
            self.cfg.dovecot.master_user = DEFAULT_MASTER_USER
            self.cfg.dovecot.master_password = generate_password(32)
            created.append("master user")
        return created

    async def install(
        self, *, reload: bool = True, report: InstallReport | None = None
    ) -> InstallReport:
        """Generate, verify, and install everything Dovecot needs."""
        report = report if report is not None else InstallReport()

        # Everything from here is rolled back together. A half-written
        # configuration -- the Lua auth script present but the conf
        # missing, say -- is worse than none, because Dovecot may still
        # start and behave in a way nobody configured.
        try:
            for generated in dovecot_config.generate(self.cfg):
                target = self._retarget(generated.path)
                report.changes.append(
                    write_atomic(
                        target,
                        generated.content,
                        mode=generated.mode,
                        group=generated.group,
                    )
                )

            master = await self.write_master_user()
            if master is not None:
                report.changes.append(master)

            report.changes.extend(self.remove_retired())
        except BaseException:
            self.rollback(report)
            raise

        if not report.changed:
            log.info("Dovecot configuration is already current")
            return report

        # Verify before reloading. A config that does not parse would
        # otherwise take the mail server down on the next restart.
        problem = await self.verify()
        if problem is not None:
            self.rollback(report)
            raise DovecotManagementError(
                f"Dovecot rejected the generated configuration, so nothing was "
                f"changed:\n{problem}"
            )

        if (warning := await self.compile_spam_script()) is not None:
            report.warnings.append(warning)

        if reload:
            try:
                await self.doveadm.reload()
                report.reloaded = True
            except DoveadmError as exc:
                report.warnings.append(
                    f"configuration written, but Dovecot did not reload: {exc}. "
                    f"Run: systemctl reload dovecot"
                )

        return report

    async def compile_spam_script(self) -> str | None:
        """Precompile the server-wide spam script. A warning, or None.

        LMTP runs as the mail user and would compile the script on
        delivery, but it cannot save the compiled form into a directory
        root created here -- so it would recompile, and log that it
        could not save, on every message. Compiling at install time
        also catches a script Dovecot would refuse, while someone is
        watching.

        Not fatal: a script that does not compile means spam reaches
        the inbox, which is how things were before it existed.
        """
        import asyncio

        if self.sievec_command is None:
            # The .deb depends on dovecot-sieve, which ships sievec; a
            # pip install does not. Without it Sieve does not run at all,
            # so spam reaches the inbox -- say so while someone is looking.
            return (
                "sievec was not found, so spam will not be filed into Junk: "
                "install dovecot-sieve"
            )
        path = self._retarget(dovecot_config.spam_script_path(self.cfg))
        try:
            process = await asyncio.create_subprocess_exec(
                *self.sievec_command, str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        except TimeoutError:
            process.kill()
            return "sievec did not finish compiling the spam filing script"
        except OSError as exc:
            return f"could not run sievec on the spam filing script: {exc}"

        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace").strip()
            return (
                f"the spam filing script at {path} did not compile, so spam will "
                f"be delivered to the inbox: {detail or 'no output'}"
            )
        return None

    def drift(self) -> list[str]:
        """Names of generated files that no longer match this config.

        Read-only on purpose. ``serve`` used to reconcile on every
        start, which meant the service needed write access to
        /etc/dovecot -- so either the unit granted the mail engine
        runtime write access to Dovecot's configuration, or
        ``ProtectSystem=strict`` made it warn on every start. Neither
        is worth it. Configuration happens at install time; a running
        service reports drift and leaves it alone.
        """
        stale: list[str] = []
        try:
            generated = dovecot_config.generate(self.cfg)
        except dovecot_config.DovecotConfigError:
            # Cannot even work out what the files should say -- usually
            # no internal key yet. Reporting that as "no drift" would
            # be the reassuring answer rather than the true one.
            return ["(Dovecot has never been configured)"]

        for item in generated:
            target = self._retarget(item.path)
            try:
                current = target.read_text(encoding="utf-8")
            except OSError:
                stale.append(target.name)
                continue
            if current != item.content:
                stale.append(target.name)
        return stale

    #: Files earlier versions generated that nothing reads now. The
    #: Lua script is not merely unused -- it holds the internal auth
    #: key, so leaving it behind leaves a credential in a file no
    #: upgrade would ever touch again.
    RETIRED = ("lightr-auth.lua",)

    def remove_retired(self) -> list[Change]:
        """Delete files a previous version wrote and this one does not."""
        removed: list[Change] = []
        for name in self.RETIRED:
            path = self.conf_dir / name
            if not path.exists():
                continue
            try:
                path.unlink()
            except OSError as exc:  # pragma: no cover - read-only /etc
                log.warning("could not remove %s: %s", path, exc)
                continue
            log.info("removed %s, which nothing reads any more", path)
            removed.append(Change(path, "removed"))
        return removed

    def _retarget(self, path: Path) -> Path:
        """Point a generated path at this manager's conf directory."""
        if self.conf_dir == DOVECOT_CONF_DIR:
            return path
        try:
            relative = path.relative_to(DOVECOT_CONF_DIR)
        except ValueError:
            relative = Path(path.name)
        return self.conf_dir / relative

    # -- master user ------------------------------------------------------

    async def write_master_user(self) -> Change | None:
        """Write Dovecot's master-user file.

        The master user is how Lightr opens any mailbox for the API and
        the CLI without holding users' own passwords. Hashing goes
        through ``doveadm pw`` so the format is whatever this Dovecot
        actually accepts, rather than whatever we guessed.
        """
        dovecot = self.cfg.dovecot
        if not dovecot.has_master_user:
            return None

        try:
            digest = await self.doveadm.pw(dovecot.master_password)
        except DoveadmError as exc:
            raise DovecotManagementError(
                f"could not hash the master password: {exc}"
            ) from exc

        content = f"{dovecot.master_user}:{digest}\n"
        # A credential that opens every mailbox -- but Dovecot's auth
        # process has to read it, and that runs as the dovecot user.
        # Owner-and-group is the tightest setting that works: 0600
        # root:root leaves the auth process unable to start at all.
        return write_atomic(
            self.conf_dir / "master-users",
            content,
            mode=0o640,
            group=dovecot_config.DOVECOT_GROUP,
        )

    async def ensure_master_user(self) -> str:
        """Create the master user if there is not one, returning its name.

        Generates the password too. An operator should never have to
        invent, hash, or type this -- it exists only for Lightr.
        """
        from lightr.auth import generate_password

        if self.cfg.dovecot.has_master_user:
            return self.cfg.dovecot.master_user

        self.cfg.dovecot.master_user = DEFAULT_MASTER_USER
        self.cfg.dovecot.master_password = generate_password(32)
        return self.cfg.dovecot.master_user

    # -- verification and rollback ----------------------------------------

    async def verify(self) -> str | None:
        """Check the configuration parses. Returns the problem, or None."""
        if not shutil.which("doveconf"):
            log.warning("doveconf is unavailable; the configuration was not checked")
            return None

        import asyncio

        try:
            process = await asyncio.create_subprocess_exec(
                "doveconf", "-n",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, err = await asyncio.wait_for(process.communicate(), timeout=15)
        except (OSError, TimeoutError) as exc:
            return f"could not run doveconf: {exc}"

        if process.returncode:
            return err.decode("utf-8", "replace").strip()
        return None

    def rollback(self, report: InstallReport) -> None:
        """Undo an install, restoring whatever was there before."""
        for change in reversed(report.changes):
            if change.action != "written":
                continue
            if change.backup and change.backup.exists():
                shutil.copy2(change.backup, change.path)
                log.info("restored %s", change.path)
            else:
                # Nothing was there before; remove what we added.
                change.path.unlink(missing_ok=True)
                log.info("removed %s", change.path)

    # -- status -----------------------------------------------------------

    async def status(self) -> dict[str, object]:
        """What Lightr can see of Dovecot right now."""
        info: dict[str, object] = {
            "doveadm_available": self.doveadm.available,
            "conf_dir": str(self.conf_dir),
            "master_user": self.cfg.dovecot.master_user or None,
            "internal_key_set": bool(self.cfg.dovecot.internal_key),
        }

        if not self.doveadm.available:
            info["version"] = None
            return info

        try:
            info["version"] = (await self.doveadm.version()).splitlines()[0]
        except DoveadmError as exc:
            info["version"] = f"unavailable: {exc}"

        try:
            info["connected_users"] = len(await self.doveadm.who())
        except DoveadmError:
            info["connected_users"] = None

        return info

    async def provision_account(self, email: str, quota_bytes: int | None = None) -> None:
        """Set up a new mailbox in Dovecot.

        Dovecot creates a Maildir on first delivery, so this is not
        strictly required -- but doing it now means the account is
        selectable in a mail client immediately rather than looking
        broken until its first message.
        """
        from lightr.dovecot.maildir import DEFAULT_FOLDERS

        try:
            await self.doveadm.mailbox_create(email, *DEFAULT_FOLDERS)
        except DoveadmError as exc:
            # Not fatal: Dovecot will create them itself on delivery.
            log.warning("could not pre-create folders for %s: %s", email, exc)

        if quota_bytes:
            try:
                await self.doveadm.quota_recalc(email)
            except DoveadmError as exc:
                log.debug("quota recalc for %s failed: %s", email, exc)


__all__ = [
    "DEFAULT_MASTER_USER",
    "DOVECOT_CONF_DIR",
    "MASTER_USERS_FILE",
    "Change",
    "DovecotManagementError",
    "DovecotManager",
    "InstallReport",
    "write_atomic",
]
