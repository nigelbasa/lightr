"""Maildir layout.

Maildir, with single-instance attachment storage OFF -- see
docs/PYTHON-REWRITE.md section 3. One file per message, never modified
after write, every operation atomic. Attachments live inside the
message file, so there is no separate object whose loss would corrupt
a mail.

Lightr does not write into Maildir during normal delivery -- Dovecot's
LMTP server does. This module computes the paths both sides must agree
on, and is used by provisioning and by recovery tooling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Dovecot's standard Maildir++ folder prefix.
FOLDER_PREFIX = "."

# Folders Dovecot is configured to auto-create. INBOX is the Maildir
# root itself, not a subdirectory.
DEFAULT_FOLDERS = ("Sent", "Drafts", "Trash", "Junk", "Archive")

# A Maildir path component must not escape the root or confuse Dovecot.
_UNSAFE = re.compile(r"[/\\\x00]|\.\.")


class MaildirError(ValueError):
    """A Maildir path could not be built safely."""


@dataclass(frozen=True, slots=True)
class MaildirLayout:
    """Where one account's mail lives on disk."""

    root: Path

    @property
    def inbox(self) -> Path:
        return self.root

    @property
    def posix(self) -> str:
        """The root as a POSIX path.

        Whatever platform Lightr runs on while developing, the value
        handed to Dovecot -- and stored in accounts.maildir_path --
        describes a Linux filesystem, so it must never carry Windows
        separators.
        """
        return self.root.as_posix()

    def folder(self, name: str) -> Path:
        """The Maildir++ directory for a named folder.

        INBOX is the root; everything else is a dot-prefixed sibling,
        with '/' in the name mapping to '.' as Dovecot expects.
        """
        if name.upper() == "INBOX":
            return self.root
        parts = [p for p in name.split("/") if p]
        if not parts:
            raise MaildirError("folder name cannot be empty")
        for part in parts:
            _reject_unsafe(part)
        return self.root / (FOLDER_PREFIX + ".".join(parts))

    @property
    def subdirs(self) -> tuple[Path, ...]:
        """The cur/new/tmp triplet every Maildir needs."""
        return tuple(self.root / d for d in ("cur", "new", "tmp"))

    def exists(self) -> bool:
        return all(d.is_dir() for d in self.subdirs)

    def create(self, folders: tuple[str, ...] = DEFAULT_FOLDERS) -> None:
        """Provision the Maildir tree.

        Dovecot creates these itself on first delivery, but doing it at
        account-creation time means `lightr account create` leaves a
        mailbox an IMAP client can select immediately.
        """
        for directory in self.subdirs:
            directory.mkdir(parents=True, exist_ok=True)
        for name in folders:
            for sub in ("cur", "new", "tmp"):
                (self.folder(name) / sub).mkdir(parents=True, exist_ok=True)
        # Dovecot treats a folder as subscribed if it is listed here.
        subscriptions = self.root / "subscriptions"
        if not subscriptions.exists():
            subscriptions.write_text("\n".join(folders) + "\n", encoding="utf-8")

    def message_count(self, folder: str = "INBOX") -> int:
        """Messages in a folder, counted off disk.

        A fallback for diagnostics when Dovecot is down; the mailbox
        API reads through IMAP instead.
        """
        target = self.folder(folder)
        return sum(
            1
            for sub in ("cur", "new")
            if (target / sub).is_dir()
            for entry in (target / sub).iterdir()
            if entry.is_file()
        )


def _reject_unsafe(component: str) -> None:
    if not component or _UNSAFE.search(component):
        raise MaildirError(f"unsafe Maildir path component: {component!r}")


def layout_for(maildir_root: Path, email: str) -> MaildirLayout:
    """The Maildir for an address, under the configured root.

    Laid out as ``<root>/<domain>/<local_part>/`` -- domain-first so an
    operator can move or back up a whole domain as one directory, and
    so two domains can hold the same local part.
    """
    if "@" not in email:
        raise MaildirError(f"{email!r} is not an email address")
    local, _, domain = email.partition("@")
    local, domain = local.lower(), domain.lower()
    _reject_unsafe(local)
    _reject_unsafe(domain)
    return MaildirLayout(root=maildir_root / domain / local)


__all__ = [
    "DEFAULT_FOLDERS",
    "MaildirError",
    "MaildirLayout",
    "layout_for",
]
