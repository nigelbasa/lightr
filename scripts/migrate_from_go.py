#!/usr/bin/env python3
"""Move an early Go-engine SQLite database into a fresh Lightr install.

This is for databases older than ``v0.1.0-go-final`` -- the ones with
seven tables and no ``aliases``, ``api_keys``, or ``webhooks``. Running
``lightr migrate`` against one of those does **not** work: migration
0001 creates tables with ``checkfirst``, so it skips the tables that
already exist and leaves ``domains`` without ``mail_hostname``,
``spam_policy``, and the relay columns. Nothing errors; the engine
just fails on the first query that touches one.

So this does not migrate the old database in place. It reads it and
writes into a **new, already-migrated** one, which is also how you get
from SQLite to Postgres. The mapping is explicit here so you can read
it and disagree with it, rather than implicit in a migration chain
that was written for a different schema.

Three things the old schema does that the new one will not accept:

``organizations.billing_tier``
    Has no home in the new schema. Dropped.
``auth_mode = 'offloaded'``
    The value is ``external`` now. Accounts carrying it need an auth
    provider configured or they cannot log in -- this reports them.
a domain whose ``org_id`` names no organization
    SQLite does not enforce foreign keys by default and Postgres does,
    so this has to be resolved rather than carried. ``--adopt-orphans``
    puts them in a named organization.

And one that is not a schema difference at all: early builds wrote DKIM
private keys to ``<data_dir>/keys/<domain>.<selector>.pem`` and left
``domains.dkim_private_key`` as an empty string. The new engine signs
from the column. Carrying the row alone therefore produces an install
that looks configured and signs nothing, which no test catches and
every receiver notices -- so ``--dkim-keys`` reads the directory.

Mail is not carried in the database at all: ``messages`` holds metadata
and the bytes live in the blob store. ``--export-mail`` lays them out
as one directory per folder so ``lightr mailbox import`` can take them.

A long-lived install accumulates mail nobody wants to carry: bounce
reports, backscatter from someone spoofing the domain, and years of
test sends. ``--skip-bounces``, ``--skip-tests`` and ``--mail-since``
leave those behind. They only affect what is *exported* -- the old blob
store is never modified, so a filter set too aggressively costs another
export, not the mail.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from lightr.config import Config
from lightr.db.engine import create_engine
from lightr.models import Account, AuthMode, Domain, Organization
from lightr.repo import AccountRepo, DomainRepo, OrganizationRepo

#: Old value -> new value. The Go engine called it "offloaded".
AUTH_MODES = {
    "native": AuthMode.NATIVE,
    "offloaded": AuthMode.EXTERNAL,
    "external": AuthMode.EXTERNAL,
    "disabled": AuthMode.DISABLED,
}


def open_old(path: Path) -> sqlite3.Connection:
    """Open the old database read-only, so a mistake here cannot hurt it."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def rows(conn: sqlite3.Connection, sql: str, *args: object) -> list[sqlite3.Row]:
    return list(conn.execute(sql, args))


def parse_hostnames(pairs: list[str] | None) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for pair in pairs or []:
        domain, sep, host = pair.partition("=")
        if not sep:
            raise SystemExit(f"--hostname expects domain=host, got {pair!r}")
        mapping[domain.strip().lower()] = host.strip()
    return mapping


async def transfer(args: argparse.Namespace) -> int:
    old = open_old(args.sqlite)
    cfg = Config.load(args.config)
    hostnames = parse_hostnames(args.hostname)

    engine = create_engine(cfg)
    try:
        async with engine.begin() as conn:
            orgs, domains, accounts = (
                OrganizationRepo(conn), DomainRepo(conn), AccountRepo(conn)
            )

            existing = await orgs.count()
            if existing and not args.force:
                raise SystemExit(
                    f"the target database already holds {existing} organization(s). "
                    f"This writes into an empty install; pass --force only if you "
                    f"know what is already there."
                )

            # -- organizations -------------------------------------------
            org_ids: dict[str, UUID] = {}
            for row in rows(old, "select id, name from organizations"):
                org = Organization(id=UUID(row["id"]), name=row["name"])
                if not args.dry_run:
                    await orgs.create(org)
                org_ids[row["id"]] = org.id
                print(f"  org      {org.name}")

            # A domain whose org does not exist cannot be carried as-is:
            # Postgres enforces the foreign key SQLite ignored.
            orphan_org: UUID | None = None
            orphans = [
                r for r in rows(old, "select id, name, org_id from domains")
                if r["org_id"] not in org_ids
            ]
            if orphans:
                names = ", ".join(r["name"] for r in orphans)
                if not args.adopt_orphans:
                    raise SystemExit(
                        f"these domains reference an organization that does not "
                        f"exist: {names}\n"
                        f"Pass --adopt-orphans NAME to put them in one, or fix the "
                        f"old database first. They are not dropped silently."
                    )
                org = Organization(name=args.adopt_orphans)
                if not args.dry_run:
                    await orgs.create(org)
                orphan_org = org.id
                print(f"  org      {org.name}  (created for: {names})")

            # -- domains --------------------------------------------------
            domain_ids: dict[str, UUID] = {}
            unsigned: list[str] = []
            for row in rows(old, "select * from domains"):
                keys = row.keys()
                name = row["name"]
                pem = _dkim_key(args.dkim_keys, name, row["dkim_selector"] or "default")
                domain = Domain(
                    id=UUID(row["id"]),
                    org_id=org_ids.get(row["org_id"]) or orphan_org,  # type: ignore[arg-type]
                    name=name,
                    mail_hostname=hostnames.get(name.lower()),
                    dkim_private_key=pem or row["dkim_private_key"] or None,
                    dkim_selector=row["dkim_selector"] or "default",
                    webhook_url=row["webhook_url"],
                    auth_webhook_url=(
                        row["auth_webhook_url"] if "auth_webhook_url" in keys else None
                    ),
                    is_verified=bool(row["is_verified"]),
                )
                if not args.dry_run:
                    await domains.create(domain)
                domain_ids[row["id"]] = domain.id
                host = domain.mail_hostname or f"(defaults to {name})"
                signing = (
                    "dkim from file" if pem
                    else "dkim in db" if domain.dkim_private_key
                    else "NO DKIM KEY"
                )
                print(f"  domain   {name}  ->  {host}  [{signing}]")
                if not domain.dkim_private_key:
                    unsigned.append(name)

            # -- accounts -------------------------------------------------
            needs_provider: list[str] = []
            for row in rows(old, "select * from accounts"):
                mode = AUTH_MODES.get(row["auth_mode"] or "native")
                if mode is None:
                    raise SystemExit(
                        f"account {row['local_part']} has auth_mode "
                        f"{row['auth_mode']!r}, which this does not know how to map"
                    )
                account = Account(
                    id=UUID(row["id"]),
                    domain_id=domain_ids[row["domain_id"]],
                    local_part=row["local_part"],
                    display_name=row["display_name"],
                    auth_mode=mode,
                    password_hash=row["password_hash"],
                    external_id=row["external_id"],
                    quota_bytes=row["quota_bytes"] or None,
                    # Left unset on purpose: layout_for computes it, and
                    # backup and restore then agree about where mail lives.
                    maildir_path=None,
                )
                if not args.dry_run:
                    await accounts.create(account)

                email = f"{row['local_part']}@{_domain_name(old, row['domain_id'])}"
                note = ""
                if mode is AuthMode.EXTERNAL:
                    note = "  [external -- needs an auth provider]"
                    needs_provider.append(email)
                print(f"  account  {email}{note}")
    finally:
        await engine.dispose()

    if unsigned:
        print("\nThese domains have no DKIM key and will send unsigned mail.")
        print("Generate one and publish the record before sending from them:")
        for name in unsigned:
            print(f"  lightr domain dkim {name} --generate && lightr domain dns {name}")

    if needs_provider:
        print("\nThese authenticate externally and cannot log in until a provider")
        print("covers their domain (`lightr auth add ...`, then `lightr auth test`):")
        for email in needs_provider:
            print(f"  {email}")

    if args.export_mail:
        export_mail(
            old, args.blobs, args.export_mail,
            skip_bounces=args.skip_bounces,
            skip_tests=args.skip_tests,
            since=args.mail_since,
        )

    old.close()
    return 0


def _dkim_key(keys_dir: Path | None, domain: str, selector: str) -> str | None:
    """Read a DKIM key the old engine left on disk, if it is there."""
    if keys_dir is None:
        return None
    path = keys_dir / f"{domain}.{selector}.pem"
    if not path.is_file():
        return None
    pem = path.read_text(encoding="utf-8").strip()
    if "PRIVATE KEY" not in pem:
        print(f"  ! {path} does not look like a private key; ignoring it")
        return None
    return pem


def _domain_name(conn: sqlite3.Connection, domain_id: str) -> str:
    row = conn.execute("select name from domains where id=?", (domain_id,)).fetchone()
    return row["name"] if row else "?"


#: A delivery report rather than mail a person wrote.
BOUNCE_SQL = """(
    lower(coalesce(m."from",'')) like '%mailer-daemon%'
    or lower(coalesce(m."from",'')) like '%postmaster@%'
    or lower(coalesce(m.subject,'')) like 'undeliverable%'
    or lower(coalesce(m.subject,'')) like '%delivery status notification%'
    or lower(coalesce(m.subject,'')) like '%returned mail%'
    or lower(coalesce(m.subject,'')) like '%delivery has failed%'
)"""

#: An empty subject, "test" in it, or under a kilobyte. In practice
#: that is someone checking the server works.
TEST_SQL = """(
    lower(coalesce(m.subject,'')) like '%test%'
    or coalesce(m.subject,'') = ''
    or coalesce(m.size_bytes,0) < 1000
)"""


def export_mail(
    conn: sqlite3.Connection,
    blobs: Path,
    out: Path,
    *,
    skip_bounces: bool = False,
    skip_tests: bool = False,
    since: str | None = None,
) -> None:
    """Lay the blob store out as one directory per mailbox folder.

    Driven from the database rows, not from what is on disk: the store
    holds orphans that no message references, and deleted mail must not
    come back.

    Filters affect only what is *written here*. The old blob store is
    never touched, so a filter set too aggressively costs another
    export rather than the mail.
    """
    print(f"\nExporting mail from {blobs} to {out}")
    counts: dict[tuple[str, str], int] = defaultdict(int)
    missing: list[str] = []

    where = ["m.deleted_at is null"]
    if skip_bounces:
        where.append(f"not {BOUNCE_SQL}")
    if skip_tests:
        where.append(f"not {TEST_SQL}")
    if since:
        where.append("m.received_at >= :since")

    query = f"""
        select m.storage_path, m.folder, m.read_at,
               a.local_part || '@' || d.name as email
        from messages m
        join accounts a on m.account_id = a.id
        join domains d on a.domain_id = d.id
        where {" and ".join(where)}
    """.replace(":since", f"'{since}'" if since else "''")

    total = conn.execute(
        "select count(*) from messages m where m.deleted_at is null"
    ).fetchone()[0]

    for row in conn.execute(query):
        source = blobs / row["storage_path"]
        if not source.is_file():
            missing.append(row["storage_path"])
            continue

        folder = row["folder"] or "INBOX"
        target = out / row["email"] / folder
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target / (source.name if source.suffix else f"{source.name}.eml"))
        counts[(row["email"], folder)] += 1

    manifest = out / "import-plan.json"
    plan = [
        {
            "account": email,
            "folder": folder,
            "messages": n,
            "command": (
                f"lightr mailbox import {email} "
                f"{(out / email / folder).as_posix()} --folder {folder}"
            ),
        }
        for (email, folder), n in sorted(counts.items())
    ]
    manifest.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    for entry in plan:
        print(f"  {entry['account']:<32} {entry['folder']:<8} {entry['messages']:>5}")
    exported = sum(counts.values())
    print(f"\n  {exported} of {total} live message(s); plan written to {manifest}")
    if exported < total:
        print(f"  {total - exported} left behind by the filters")
    if missing:
        print(f"  {len(missing)} referenced blob(s) were missing and were skipped")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sqlite", type=Path, required=True, help="Old lightr.db.")
    parser.add_argument("--config", type=Path, required=True, help="New config.yaml.")
    parser.add_argument(
        "--hostname", action="append",
        help="Set a domain's mail hostname, as domain=host. Repeatable.",
    )
    parser.add_argument(
        "--adopt-orphans", metavar="NAME",
        help="Organization to put domains in whose own organization is missing.",
    )
    parser.add_argument(
        "--dkim-keys", type=Path,
        help="Directory of <domain>.<selector>.pem files the old engine wrote.",
    )
    parser.add_argument("--blobs", type=Path, help="Blob store root.")
    parser.add_argument("--export-mail", type=Path, help="Where to lay out the mail.")
    parser.add_argument(
        "--skip-bounces", action="store_true",
        help="Leave delivery reports and backscatter behind.",
    )
    parser.add_argument(
        "--skip-tests", action="store_true",
        help="Leave test sends behind: no subject, 'test' in it, or under 1KB.",
    )
    parser.add_argument(
        "--mail-since", metavar="YYYY-MM-DD",
        help="Only export mail received on or after this date.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report, write nothing.")
    parser.add_argument("--force", action="store_true", help="Write into a non-empty database.")
    args = parser.parse_args()

    if args.export_mail and not args.blobs:
        raise SystemExit("--export-mail needs --blobs")

    import asyncio

    if args.dry_run:
        print("DRY RUN -- nothing is written\n")
    return asyncio.run(transfer(args))


if __name__ == "__main__":
    raise SystemExit(main())
