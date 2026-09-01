# Changing over from the Go engine

For an install running an **early** Go build — the seven-table schema
with no `aliases`, `api_keys`, or `webhooks`. Written against a real
one, so the hazards below are things that were actually found rather
than things that might happen.

`lightr migrate` **does not work on these databases.** Migration 0001
creates tables with `checkfirst`, so it skips the ones that already
exist and leaves `domains` without `mail_hostname`, `spam_policy`, and
the relay columns. Nothing errors. The engine fails later, on the first
query that touches one.

So this does not upgrade the old database. It builds a new one and
copies the data across, which is also how you get to Postgres.

---

## What bites, and why

| | |
| --- | --- |
| `auth_mode = 'offloaded'` | The value is `external` now. Pydantic rejects the old one, so those accounts do not load at all. |
| a domain whose `org_id` names no organization | SQLite does not enforce foreign keys; Postgres does. Ours had one. |
| `organizations.billing_tier` | No home in the new schema. Dropped. |
| **DKIM keys on disk, not in the database** | Early builds wrote `<data_dir>/keys/<domain>.<selector>.pem` and left the column an *empty string* — not NULL, which is why a `IS NULL` check says everything is fine. The new engine signs from the column. Miss this and three domains send unsigned mail that no test catches and every receiver notices. |
| mail in `messages` | Metadata only; the bytes are in the blob store. Dovecot owns mail now, so it has to be imported. |
| IMAP moves to Dovecot | The old engine served :143/:993 itself. Every mail client resyncs from scratch — **tell the mailbox owners first.** |

---

## 1. Back up, before stopping anything

The blob store is the only copy of the mail, and the import reads from
it. Verify the copy landed before the old service goes down.

```bash
ssh root@HOST 'sqlite3 /var/lib/lightr/lightr.db ".backup /tmp/snap.db"'
ssh root@HOST 'cd /var/lib/lightr && tar czf /tmp/blobs.tar.gz blobs'
scp root@HOST:/tmp/snap.db          ./lightr.db
scp root@HOST:/tmp/blobs.tar.gz     ./blobs.tar.gz
scp root@HOST:/usr/bin/lightr       ./lightr-go-binary
scp root@HOST:'/var/lib/lightr/keys/*.pem' ./keys/
scp root@HOST:/etc/lightr/config.yaml ./config.yaml.old
```

Compare `sha256sum` on both ends. A backup you have not verified is a
file.

## 2. Postgres

An isolated role and database, owned by that role, reachable only on
localhost.

```bash
sudo -u postgres createuser --pwprompt lightr
```

```bash
sudo -u postgres createdb --owner=lightr --encoding=UTF8 lightr
```

Confirm it connects and that the role is *not* a superuser:

```bash
psql "postgresql://lightr:PASSWORD@127.0.0.1:5432/lightr" -c "select current_user, current_database();"
```

## 3. Stop the old engine, keep it recoverable

```bash
systemctl stop lightr && systemctl disable lightr
cp /usr/bin/lightr /usr/bin/lightr-go.backup
```

Do **not** delete `/var/lib/lightr/lightr.db` or `blobs/`. They are the
rollback, and they stay the rollback long after it looks fine.

## 4. Install, and point at Postgres

```bash
pip install 'lightr[postgres,imap]'
lightr init --hostname mail.example.com
```

Then set in `/etc/lightr/config.yaml`:

```yaml
database:
  driver: postgres
  dsn: "postgresql://lightr:PASSWORD@127.0.0.1:5432/lightr"
```

```bash
lightr migrate && lightr status
```

`init` configures Dovecot as part of its job. If it warns, stop and
read the warning — mailboxes will not work until it is resolved, and
the import in step 6 goes through IMAP.

## 5. Copy the data across

```bash
python scripts/migrate_from_go.py \
  --sqlite /var/lib/lightr/lightr.db \
  --config /etc/lightr/config.yaml \
  --dkim-keys /var/lib/lightr/keys \
  --adopt-orphans "ORG NAME" \
  --hostname example.com=mail.example.com \
  --blobs /var/lib/lightr/blobs \
  --export-mail /var/tmp/mailout \
  --dry-run
```

Read what it prints, then run it again without `--dry-run`. It refuses
rather than guessing: an unknown `auth_mode`, an orphaned domain, or a
non-empty target all stop it.

`--hostname` matters more than it looks. It sets what the domain uses
for outbound HELO and DKIM; getting it wrong does not error, it just
costs deliverability. Take the values from the old config's SNI certs.

Check before going on:

```bash
lightr domain list && lightr account list
```

## 6. Import the mail

Dovecot must be running and the mailboxes provisioned first:

```bash
systemctl enable --now dovecot
lightr dovecot status          # must report a version
```

### Leave behind what you do not want

A long-lived install accumulates mail nobody needs to carry. On the one
this was written against, 918 live messages were 298 MB — of which 688
were bounce reports and backscatter, and 68 were old test sends. The
mail an actual person wrote was 162 messages and 54 MB.

```bash
python scripts/migrate_from_go.py ... \
  --export-mail /var/tmp/mailout \
  --skip-bounces --skip-tests --mail-since 2026-01-01
```

Filters affect only what is written to the export directory. The old
blob store is never modified, so a filter set too aggressively costs
another export, not the mail. `--skip-tests` is the blunter of the two
— it drops anything under 1 KB or with "test" in the subject, which
catches short real mail too. Run without it first and compare counts if
that matters.

### Then import

`--export-mail` wrote `import-plan.json` with one command per mailbox
folder. Run them **one at a time**, `--dry-run` first, and record what
completed — import is not idempotent, so a retry after a partial run
duplicates messages.

```bash
lightr mailbox import you@example.com /var/tmp/mailout/you@example.com/INBOX --folder INBOX
```

On a small VPS, do these serially and watch `free -m`.

## 7. Start, and prove it works

```bash
systemctl enable --now lightr
lightr status && lightr dovecot status
lightr mailbox folders you@example.com
lightr mailbox list you@example.com
```

Then real mail, in and out, and <https://mail-tester.com> for the
SPF/DKIM/DMARC verdict. Any domain the script reported as having no
DKIM key needs one before it sends:

```bash
lightr domain dkim example.com --generate && lightr domain dns example.com
```

Accounts reported as `external` cannot log in until a provider covers
their domain — see the offloaded-authentication section of
[DEPLOY.md](DEPLOY.md), then `lightr auth test`.

Finally, snapshot the finished install:

```bash
lightr backup create /var/backups/lightr/
```

## Rollback

```bash
systemctl stop lightr
systemctl enable --now lightr   # after restoring the old unit + binary
```

The old SQLite file and blob store are untouched throughout, so the Go
engine starts against exactly what it had. That is why step 3 says not
to delete them.
