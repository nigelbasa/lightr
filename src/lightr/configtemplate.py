"""The commented ``/etc/lightr/config.yaml`` an install starts from.

Written by hand rather than dumped from the model, because the point of
it is the comments: an operator opening this file should be able to see
what each setting is for and what happens if they change it, the way
they can in ``sshd_config`` or ``dovecot.conf``.

Two rules keep it honest:

* **Only operator settings appear here.** ``dovecot.internal_key``,
  ``master_user`` and ``master_password`` are generated on first setup
  and written back into the file. Listing them as blanks invites
  someone to fill them in by hand, and a hand-typed internal key that
  disagrees with Dovecot's copy fails as "wrong password" for every
  user.

* **Everything commented out is a real default.** The commented lines
  are what Lightr does anyway, so uncommenting one and leaving it
  unchanged is a no-op. A comment that lies about a default is worse
  than no comment.

``Config`` forbids unknown keys, so a stale key here would stop a fresh
install from loading its own config file. ``tests/test_config_template``
loads this text through the model to keep the two from drifting.
"""

from __future__ import annotations

import os
from pathlib import Path

#: 0640 root:lightr. The service runs as ``lightr`` and has to read it;
#: it holds a database password, so nobody else should.
CONFIG_MODE = 0o640
CONFIG_GROUP = "lightr"

TEMPLATE = """\
# Lightr configuration.
#
# Everything commented out below is already the default -- the lines
# are here to show what can be changed, not to be uncommented.
#
# Secrets Lightr generates for itself -- the Dovecot internal key, the
# master user and its password -- are written into this file the first
# time `lightr setup` runs. Do not type them in by hand: they have to
# match what Dovecot was given, and a key that does not fails as "wrong
# password" for every user.
#
# After editing:  systemctl restart lightr

server:
  # The name this server calls itself in SMTP, and the name its
  # certificate should match. Set this: the default is wrong for
  # every real deployment, and receivers check it.
  hostname: localhost

  # Address the SMTP listeners bind to. 0.0.0.0 is every interface.
  # bind_address: 0.0.0.0

database:
  # sqlite is fine for a single server. Use postgres when you want
  # backups, replication, or more than one Lightr talking to one
  # database.
  driver: sqlite

  # For postgres, set driver: postgres and put the DSN here. Dovecot
  # reads this database too, so the role needs SELECT on it.
  # dsn: postgresql://lightr:password@127.0.0.1:5432/lightr

  # Where the sqlite file lives. Defaults to data_dir/lightr.db.
  # path: /var/lib/lightr/lightr.db

# smtp:
#   addr: ":25"              # inbound mail from other servers
#   submission_addr: ":587"  # mail from your own users, authenticated
#   max_message_bytes: 26214400
#   max_recipients: 50

# http:
#   # The operator API and the endpoints Dovecot authenticates against.
#   # Loopback-only unless you put a reverse proxy in front of it: this
#   # is plain HTTP and sees plaintext passwords. See docs/DEPLOY.md.
#   addr: ":8080"

# tls:
#   # Used for SMTP STARTTLS. Point these at your certificate; without
#   # one, submission refuses to accept a password.
#   cert_file: /etc/letsencrypt/live/mail.example.com/fullchain.pem
#   key_file: /etc/letsencrypt/live/mail.example.com/privkey.pem

# dkim:
#   # The selector published in DNS as <selector>._domainkey.<domain>.
#   selector: default
#   key_bits: 2048

# spam:
#   enabled: true
#   # Score at which a message is filed as Junk rather than delivered.
#   junk_threshold: 4.0
#   # rspamd_url: http://127.0.0.1:11333

# webhook:
#   # Delivery events are POSTed here, signed with a shared secret.
#   url: https://example.com/lightr/events
#   enabled: false

# limits:
#   # Rate limiting, not DDoS protection: these refuse more work than a
#   # caller is entitled to before it reaches the database or Dovecot.
#   # A flood big enough to fill the link is answered upstream. Counted
#   # in this process, so a second Lightr enforces its own copy. Zero
#   # means unlimited.
#   auth_failures_per_minute: 20    # per address, guessing an API key
#   api_requests_per_minute: 600    # per address; keys carry their own
#   smtp_sessions_per_minute: 30    # per address, inbound only
#   smtp_messages_per_hour: 300     # per address, inbound only

# logging:
#   level: info
#   file: /var/log/lightr/lightr.log
"""


def write(path: Path) -> None:
    """Write the template, with the ownership the service needs.

    Never overwrites: this runs on every package upgrade, and the file
    it would replace holds the keys the running install authenticates
    with.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    path.write_text(TEMPLATE, encoding="utf-8")
    restrict(path)


def restrict(path: Path) -> None:
    """0640 root:lightr, as far as this process is allowed to go.

    Chowning needs root, and the group only exists once the package has
    created it, so both are best-effort -- but the mode is not. A
    config file this process cannot chown is still a config file that
    must not be world-readable.
    """
    try:
        path.chmod(CONFIG_MODE)
    except OSError:  # pragma: no cover - unwritable file
        return
    try:
        import grp  # POSIX only; on Windows there is nothing to chown to.

        gid = grp.getgrnam(CONFIG_GROUP).gr_gid
    except (ImportError, KeyError):  # pragma: no cover - group absent
        return
    try:
        os.chown(path, -1, gid)
    except (OSError, AttributeError):  # pragma: no cover - not root
        pass


def set_values(path: Path, values: dict[tuple[str, str], object]) -> list[str]:
    """Write settings into an existing config, leaving the rest alone.

    Line-oriented rather than load-modify-dump, because a dump throws
    away every comment in the file -- and, on a real server once, a
    hand-edited Postgres DSN with it. Lightr writes back only the
    handful of secrets it generates for itself, so the surgical version
    is small and the destructive one has no reason to exist.

    ``values`` is keyed by ``(block, setting)``. A setting already
    present is rewritten in place; one whose block exists is inserted
    under that block's header; one whose block does not exist appends
    the block. Inserting under an existing header matters: appending a
    second ``dovecot:`` mapping would leave YAML with a duplicate key,
    and PyYAML silently keeps the last one -- so the operator's
    settings in the first block would vanish.

    Returns the settings it changed, and is a no-op when they all
    already hold the value asked for. The package runs this on every
    upgrade.
    """
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    changed: list[str] = []

    for (block, setting), value in values.items():
        rendered = _render(value)

        if not setting:
            # A top-level scalar such as ``data_dir``, written as
            # ("data_dir", "").
            index = _find_scalar(lines, block)
            wanted = f"{block}: {rendered}"
            if index is None:
                lines.insert(0, wanted)
            elif lines[index] == wanted:
                continue
            else:
                lines[index] = wanted
            changed.append(block)
            continue

        index = _find_setting(lines, block, setting)
        if index is not None:
            wanted = f"  {setting}: {rendered}"
            if lines[index] == wanted:
                continue
            lines[index] = wanted
        else:
            header = _find_block(lines, block)
            if header is None:
                if lines and lines[-1].strip():
                    lines.append("")
                lines.append(f"{block}:")
                lines.append(f"  {setting}: {rendered}")
            else:
                lines.insert(header + 1, f"  {setting}: {rendered}")
        changed.append(f"{block}.{setting}")

    if not changed:
        return []

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    restrict(path)
    return changed


def _render(value: object) -> str:
    import yaml

    return yaml.safe_dump(value, default_flow_style=True).strip().removesuffix("...").strip()


def _find_scalar(lines: list[str], name: str) -> int | None:
    """The index of an uncommented top-level ``name: value`` line."""
    for index, line in enumerate(lines):
        if line.startswith(f"{name}:") and line.rstrip() != f"{name}:":
            return index
    return None


def _find_block(lines: list[str], block: str) -> int | None:
    """The index of an uncommented ``block:`` header."""
    for index, line in enumerate(lines):
        if line.rstrip() == f"{block}:":
            return index
    return None


def _find_setting(lines: list[str], block: str, setting: str) -> int | None:
    header = _find_block(lines, block)
    if header is None:
        return None
    for index in range(header + 1, len(lines)):
        line = lines[index]
        if line and not line[0].isspace() and not line.startswith("#"):
            return None  # the next top-level block started
        if line.strip().startswith(f"{setting}:") and line.startswith("  "):
            return index
    return None


__all__ = [
    "CONFIG_GROUP",
    "CONFIG_MODE",
    "TEMPLATE",
    "restrict",
    "set_values",
    "write",
]
