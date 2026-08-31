"""Uniform CLI output.

Every list and get command renders through here, so no group invents
its own format. Tables when a human is watching, JSON when the output
is piped -- which means `lightr account list | jq` works without the
caller having to remember a flag.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml
from rich.console import Console
from rich.table import Table

stdout = Console()
stderr = Console(stderr=True)


class Format(StrEnum):
    TABLE = "table"
    JSON = "json"
    YAML = "yaml"

    @classmethod
    def resolve(cls, requested: Format | None) -> Format:
        """Pick a format when the caller did not.

        A TTY gets a table; a pipe gets JSON. Explicit always wins.
        """
        if requested is not None:
            return requested
        return cls.TABLE if sys.stdout.isatty() else cls.JSON


def plain(value: Any) -> Any:
    """Make a value safe for JSON and YAML.

    Handles the four record shapes the engine passes around: Pydantic
    models, dataclasses (the Dovecot adapters use those), enums, and
    the scalar types JSON has no encoder for.
    """
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, list | tuple | set | frozenset):
        return [plain(v) for v in value]
    if isinstance(value, UUID | Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "model_dump"):
        return plain(value.model_dump())
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value)}
    return value


#: A column is (attribute, heading) or (attribute, heading, formatter).
Column = tuple[str, str] | tuple[str, str, Any]


def render(
    rows: Sequence[Any],
    columns: Sequence[Column],
    *,
    fmt: Format | None = None,
    title: str | None = None,
    empty: str = "Nothing to show.",
) -> None:
    """Render a list of records.

    ``columns`` is a sequence of ``(attribute, heading)`` pairs, with an
    optional third element to format the value for display. The table
    shows only those columns; JSON and YAML carry the whole record,
    since a machine reader usually wants everything.
    """
    resolved = Format.resolve(fmt)
    records = [plain(r) for r in rows]

    if resolved is Format.JSON:
        stdout.print_json(json.dumps(records, default=str))
        return
    if resolved is Format.YAML:
        stdout.print(yaml.safe_dump(records, sort_keys=False, default_flow_style=False), end="")
        return

    if not records:
        stderr.print(f"[dim]{empty}[/dim]")
        return

    table = Table(title=title, header_style="bold", box=None, pad_edge=False)
    for column in columns:
        table.add_column(column[1], overflow="fold")
    for record in records:
        cells = []
        for column in columns:
            value = record.get(column[0])
            formatter = column[2] if len(column) > 2 else None
            cells.append(_cell(formatter(value) if formatter else value))
        table.add_row(*cells)
    stdout.print(table)


def detail(record: Any, *, fmt: Format | None = None, title: str | None = None) -> None:
    """Render one record as a field/value table, or as JSON/YAML."""
    resolved = Format.resolve(fmt)
    data = plain(record)

    if resolved is Format.JSON:
        stdout.print_json(json.dumps(data, default=str))
        return
    if resolved is Format.YAML:
        stdout.print(yaml.safe_dump(data, sort_keys=False, default_flow_style=False), end="")
        return

    table = Table(title=title, box=None, show_header=False, pad_edge=False)
    table.add_column("field", style="dim")
    table.add_column("value", overflow="fold")
    for key, value in data.items():
        if value is None or value == [] or value == "":
            continue
        table.add_row(key, _cell(value))
    stdout.print(table)


def _cell(value: Any) -> str:
    if value is None:
        return "[dim]-[/dim]"
    if isinstance(value, bool):
        return "[green]yes[/green]" if value else "[dim]no[/dim]"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else "[dim]-[/dim]"
    return str(value)


def raw(content: str) -> None:
    """Write content to stdout byte-for-byte.

    Rich wraps to the terminal width -- and to a default width when
    piped -- which silently corrupts anything meant to be a file. Every
    generated config, Sieve script, and raw message source goes through
    here instead, so `lightr dovecot config > 99-lightr.conf` produces
    a file Dovecot can actually parse.
    """
    sys.stdout.write(content)
    if content and not content.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


def success(message: str) -> None:
    stderr.print(f"[green]OK[/green] {message}")


def warn(message: str) -> None:
    stderr.print(f"[yellow]warning[/yellow] {message}")


def info(message: str) -> None:
    stderr.print(f"[dim]{message}[/dim]")


def secret(label: str, value: str) -> None:
    """Print a secret once, to stdout, with the caveat on stderr.

    stdout so it can be captured; the warning on stderr so capturing it
    does not swallow the caveat.
    """
    stderr.print(f"[yellow]{label} -- shown once, not recoverable:[/yellow]")
    stdout.print(value)


def human_size(num_bytes: int | None) -> str:
    if num_bytes is None:
        return "-"
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


__all__ = [
    "Format",
    "detail",
    "human_size",
    "info",
    "plain",
    "raw",
    "render",
    "secret",
    "stderr",
    "stdout",
    "success",
    "warn",
]
