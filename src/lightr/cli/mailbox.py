"""Mailbox commands.

This group did not exist in the Go CLI -- mail was reachable only as a
side effect of `lightr data export`. Reads go through the same IMAP
adapter the REST API uses, so the two cannot disagree about what is in
a mailbox.
"""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from lightr.dovecot.mailbox import (
    MessageDetail,
    MessageSummary,
    build_search_criteria,
)

from . import output
from .context import confirm, fail, run
from .imap_client import open_mailbox
from .output import Format

app = typer.Typer(no_args_is_help=True, help="Read and manage mail in a mailbox.")

LIST_COLUMNS = [
    ("uid", "UID"),
    ("date", "DATE"),
    ("from_", "FROM"),
    ("subject", "SUBJECT"),
    ("seen", "READ"),
]

FOLDER_COLUMNS = [
    ("name", "FOLDER"),
    ("messages", "MESSAGES"),
    ("unseen", "UNSEEN"),
]

_ACCOUNT_ARG = typer.Argument(help="Account whose mailbox to read, e.g. ops@acme.test")
_FOLDER_OPT = typer.Option("--folder", help="Folder to read.")


@app.command("folders")
def folders(
    account: Annotated[str, _ACCOUNT_ARG],
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """List the folders in a mailbox."""

    async def _run() -> list:
        async with open_mailbox(account) as mailbox:
            return await mailbox.folders()

    output.render(run(_run), FOLDER_COLUMNS, fmt=fmt, empty="No folders.")


@app.command("list")
def list_messages(
    account: Annotated[str, _ACCOUNT_ARG],
    folder: Annotated[str, _FOLDER_OPT] = "INBOX",
    limit: Annotated[int, typer.Option("--limit", "-n", help="How many to show.")] = 20,
    offset: Annotated[int, typer.Option(help="Skip this many first.")] = 0,
    unread: Annotated[bool, typer.Option("--unread", help="Only unread messages.")] = False,
    flagged: Annotated[bool, typer.Option("--flagged", help="Only flagged messages.")] = False,
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """List messages, newest first."""

    async def _run() -> list[MessageSummary]:
        criteria = build_search_criteria(unread=unread, flagged=flagged)
        async with open_mailbox(account) as mailbox:
            return await mailbox.list(folder, limit=limit, offset=offset, criteria=criteria)

    output.render(
        run(_run),
        LIST_COLUMNS,
        fmt=fmt,
        empty=f"No messages in {folder}.",
    )


@app.command("search")
def search_messages(
    account: Annotated[str, _ACCOUNT_ARG],
    folder: Annotated[str, _FOLDER_OPT] = "INBOX",
    sender: Annotated[str | None, typer.Option("--from", help="Match the From header.")] = None,
    recipient: Annotated[str | None, typer.Option("--to", help="Match the To header.")] = None,
    subject: Annotated[str | None, typer.Option("--subject")] = None,
    text: Annotated[
        str | None, typer.Option("--text", help="Match anywhere in the message.")
    ] = None,
    since: Annotated[str | None, typer.Option("--since", help="On or after YYYY-MM-DD.")] = None,
    before: Annotated[str | None, typer.Option("--before", help="Before YYYY-MM-DD.")] = None,
    unread: Annotated[bool, typer.Option("--unread")] = False,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 50,
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Search a folder.

    Unlike the Go engine's IMAP SEARCH, which ignored its criteria and
    returned everything, this is evaluated by Dovecot.
    """

    async def _run() -> list[MessageSummary]:
        criteria = build_search_criteria(
            unread=unread,
            sender=sender,
            recipient=recipient,
            subject=subject,
            text=text,
            since=since,
            before=before,
        )
        async with open_mailbox(account) as mailbox:
            return await mailbox.list(folder, limit=limit, criteria=criteria)

    output.render(run(_run), LIST_COLUMNS, fmt=fmt, empty="No matches.")


@app.command("read")
def read_message(
    account: Annotated[str, _ACCOUNT_ARG],
    uid: Annotated[int, typer.Argument(help="Message UID, from `mailbox list`.")],
    folder: Annotated[str, _FOLDER_OPT] = "INBOX",
    raw: Annotated[bool, typer.Option("--raw", help="Print the original RFC 822 source.")] = False,
    headers_only: Annotated[bool, typer.Option("--headers", help="Headers only.")] = False,
    html: Annotated[bool, typer.Option("--html", help="Prefer the HTML part.")] = False,
    mark_read: Annotated[
        bool, typer.Option("--mark-read/--no-mark-read", help="Mark it seen after reading.")
    ] = False,
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """Read one message."""

    async def _run() -> MessageDetail:
        async with open_mailbox(account) as mailbox:
            message = await mailbox.get(folder, uid)
            if mark_read:
                await mailbox.mark(folder, uid, seen=True)
            return message

    message = run(_run)

    if raw:
        output.raw(message.raw.decode("utf-8", "replace"))
        return

    if fmt is not None and fmt is not Format.TABLE:
        payload = {
            "uid": message.uid,
            "folder": message.folder,
            "subject": message.subject,
            "from": message.from_,
            "to": message.to,
            "date": message.date,
            "size": message.size,
            "seen": message.seen,
            "attachments": [a.__dict__ for a in message.attachments],
            "text": message.text,
            "html": message.html,
        }
        output.detail(payload, fmt=fmt)
        return

    output.detail(
        {
            "From": message.from_,
            "To": message.to,
            "Subject": message.subject,
            "Date": message.date,
            "Size": output.human_size(message.size),
            "Read": message.seen,
        },
        fmt=Format.TABLE,
    )
    if message.attachments:
        output.stdout.print()
        output.render(
            message.attachments,
            [("index", "#"), ("filename", "FILENAME"), ("content_type", "TYPE"),
             ("size", "BYTES")],
            fmt=Format.TABLE,
            title="Attachments",
        )
    if not headers_only:
        body = message.html if (html and message.html) else message.text
        output.stdout.print()
        if body:
            output.raw(body)
        else:
            output.stderr.print("[dim](no text body)[/dim]")


@app.command("attachments")
def list_attachments(
    account: Annotated[str, _ACCOUNT_ARG],
    uid: Annotated[int, typer.Argument(help="Message UID.")],
    folder: Annotated[str, _FOLDER_OPT] = "INBOX",
    fmt: Annotated[Format | None, typer.Option("--format", "-f")] = None,
) -> None:
    """List a message's attachments."""

    async def _run() -> list:
        async with open_mailbox(account) as mailbox:
            return (await mailbox.get(folder, uid)).attachments

    output.render(
        run(_run),
        [("index", "#"), ("filename", "FILENAME"), ("content_type", "TYPE"), ("size", "BYTES")],
        fmt=fmt,
        empty="This message has no attachments.",
    )


@app.command("download")
def download_attachment(
    account: Annotated[str, _ACCOUNT_ARG],
    uid: Annotated[int, typer.Argument(help="Message UID.")],
    index: Annotated[int, typer.Option("--attachment", "-a", help="Index from `attachments`.")],
    folder: Annotated[str, _FOLDER_OPT] = "INBOX",
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Where to write it. Defaults to its own name."),
    ] = None,
) -> None:
    """Download one attachment to a file."""

    async def _run() -> tuple[str, str, bytes]:
        async with open_mailbox(account) as mailbox:
            return await mailbox.attachment(folder, uid, index)

    filename, content_type, payload = run(_run)
    target = out or Path(filename)
    if target.is_dir():
        target = target / filename
    if target.exists():
        confirm(f"Overwrite {target}?", yes=False)
    target.write_bytes(payload)
    output.success(f"Wrote {target} ({output.human_size(len(payload))}, {content_type})")


@app.command("mark")
def mark_message(
    account: Annotated[str, _ACCOUNT_ARG],
    uid: Annotated[int, typer.Argument(help="Message UID.")],
    folder: Annotated[str, _FOLDER_OPT] = "INBOX",
    read: Annotated[bool | None, typer.Option("--read/--unread")] = None,
    flag: Annotated[bool | None, typer.Option("--flag/--unflag")] = None,
) -> None:
    """Mark a message read, unread, flagged, or unflagged."""
    if read is None and flag is None:
        raise typer.BadParameter("give at least one of --read/--unread or --flag/--unflag")

    async def _run() -> None:
        async with open_mailbox(account) as mailbox:
            await mailbox.mark(folder, uid, seen=read, flagged=flag)

    run(_run)
    output.success(f"Updated message {uid} in {folder}")


@app.command("move")
def move_message(
    account: Annotated[str, _ACCOUNT_ARG],
    uid: Annotated[int, typer.Argument(help="Message UID.")],
    destination: Annotated[str, typer.Argument(help="Destination folder.")],
    folder: Annotated[str, _FOLDER_OPT] = "INBOX",
) -> None:
    """Move a message to another folder."""

    async def _run() -> None:
        async with open_mailbox(account) as mailbox:
            await mailbox.move(folder, uid, destination)

    run(_run)
    output.success(f"Moved message {uid} to {destination}")


@app.command("delete")
def delete_message(
    account: Annotated[str, _ACCOUNT_ARG],
    uid: Annotated[int, typer.Argument(help="Message UID.")],
    folder: Annotated[str, _FOLDER_OPT] = "INBOX",
    purge: Annotated[
        bool, typer.Option("--purge", help="Expunge immediately instead of moving to Trash.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Delete a message. Moves it to Trash unless --purge."""
    if purge:
        confirm(
            f"Permanently delete message {uid} from {folder}?",
            yes=yes,
            detail="[yellow]--purge is irreversible; the message is not recoverable.[/yellow]",
        )

    async def _run() -> None:
        async with open_mailbox(account) as mailbox:
            await mailbox.delete(folder, uid, expunge=purge)

    run(_run)
    output.success(
        f"Message {uid} {'purged' if purge else 'moved to Trash'}"
    )


# --------------------------------------------------------------------
# Import and export
# --------------------------------------------------------------------


class _Source(StrEnum):
    AUTO = "auto"
    MBOX = "mbox"
    MAILDIR = "maildir"
    EML = "eml"


def _detect(path: Path) -> _Source:
    """Work out what a path holds, so --format is rarely needed."""
    if path.is_dir():
        return _Source.MAILDIR if (path / "cur").is_dir() else _Source.EML
    if path.suffix.lower() in (".eml", ".msg", ".mail"):
        return _Source.EML
    return _Source.MBOX


@app.command("import")
def import_mail(
    account: Annotated[str, _ACCOUNT_ARG],
    path: Annotated[Path, typer.Argument(help="An mbox file, a Maildir, or .eml file(s).")],
    source: Annotated[
        _Source, typer.Option("--format", help="Override what the path is taken to be.")
    ] = _Source.AUTO,
    folder: Annotated[
        str | None,
        typer.Option("--folder", help="Put everything here. A Maildir keeps its own by default."),
    ] = None,
    limit: Annotated[
        int | None, typer.Option("--limit", help="Stop after this many messages.")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Count what would be imported, and import nothing.")
    ] = False,
) -> None:
    """Import mail into a mailbox.

    Messages are appended through IMAP, so Dovecot indexes them as it
    would any delivery -- flags and original dates included. Nothing
    already in the mailbox is touched; re-running an import duplicates
    the messages rather than replacing them.
    """
    from lightr.mailtransfer import (
        TransferError,
        read_eml,
        read_maildir,
        read_mbox,
    )
    from lightr.mailtransfer import import_messages as _import

    kind = _detect(path) if source is _Source.AUTO else source

    def _messages():
        if kind is _Source.MAILDIR:
            return read_maildir(path, folder)
        if kind is _Source.EML:
            return read_eml(path, folder or "INBOX")
        return read_mbox(path, folder or "INBOX")

    async def _run():
        if dry_run:
            return await _import(_NoMailbox(), _messages(), dry_run=True, limit=limit)
        async with open_mailbox(account) as mailbox:
            return await _import(mailbox, _messages(), limit=limit)

    try:
        report = run(_run)
    except TransferError as exc:
        fail(str(exc))

    verb = "Would import" if dry_run else "Imported"
    output.success(
        f"{verb} {report.messages} message(s), {output.human_size(report.bytes_moved)}, "
        f"from {kind} at {path}"
    )
    for name, count in sorted(report.folders.items()):
        output.info(f"  {name}: {count}")
    for failure in report.failures[:10]:
        output.warn(failure)
    if len(report.failures) > 10:
        output.warn(f"...and {len(report.failures) - 10} more failures")


class _NoMailbox:
    """A destination that accepts nothing, for --dry-run."""

    async def append(self, folder, raw, *, flags=(), date=None) -> None:
        raise AssertionError("dry run must not append")  # pragma: no cover


@app.command("export")
def export_mail(
    account: Annotated[str, _ACCOUNT_ARG],
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Write here instead of stdout."),
    ] = None,
    folder: Annotated[
        str | None,
        typer.Option("--folder", help="One folder. Every folder is exported by default."),
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", help="Messages per folder.")
    ] = 100_000,
) -> None:
    """Export a mailbox as mbox.

    mbox because it is what every other mail tool reads. The messages
    come out byte-for-byte as they were delivered, with mboxrd quoting
    applied to the From_ lines and nothing else changed.
    """
    from lightr.mailtransfer import Message, to_mbox

    async def _run() -> list[bytes]:
        chunks: list[bytes] = []
        async with open_mailbox(account) as mailbox:
            names = (
                [folder]
                if folder
                else [f.name for f in await mailbox.folders()]
            )
            for name in names:
                for summary in await mailbox.list(name, limit=limit):
                    raw = await mailbox.raw(name, summary.uid)
                    chunks.extend(
                        to_mbox([Message(raw=raw, folder=name, date=summary.date)])
                    )
        return chunks

    chunks = run(_run)
    payload = b"".join(chunks)

    if out is None:
        # Bytes straight to the buffer: Rich would wrap and corrupt it.
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        output.success(f"Exported {len(chunks)} message(s)")
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(payload)
    output.success(
        f"Exported {len(chunks)} message(s) to {out} ({output.human_size(len(payload))})"
    )
