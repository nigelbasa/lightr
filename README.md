# Lightr

A lightweight mail engine. Lightr owns SMTP, identity, policy, and the
operator surface; **Dovecot** serves mailboxes over IMAP.

That split is deliberate. Implementing IMAP well is a multi-year job
that Dovecot has already done — UIDs, flags, BODYSTRUCTURE, partial
fetch, IDLE, and the client quirks that come with them. Lightr does the
part that is actually its own: getting mail in and out, deciding who
may do what, and giving an operator a CLI and an API that answer
questions without a database client.

```
   :25 / :587  ──►  ┌──────────────┐  ── LMTP ─────────────►  ┌─────────┐
   REST :8080  ──►  │              │                          │         │ ──► Maildir
   CLI         ──►  │    Lightr    │  ◄─ passdb Lua / HTTP ───│ Dovecot │
                    │   (Python)   │                          │         │
                    │              │  ── IMAP client ────────►│         │ ◄── :143 / :993
                    └──────┬───────┘  ── doveadm ────────────►└─────────┘     mail clients
                           │
                    SQLite / Postgres
```

## What Lightr owns

- SMTP receive (:25), submission (:587), and outbound relay
- DKIM signing, SPF, DMARC, spam scoring
- Outbound queue with retries, bounce handling, suppression
- Organizations, domains, accounts, aliases, API keys, permissions
- Webhooks, the REST API, and the CLI
- **Dovecot itself** — configuration, master user, Sieve installation,
  quota reads, and reloads. Lightr drives it via `doveadm`.

## What Dovecot owns

IMAP, message storage, flags, UIDs, folders, Sieve execution, quota
enforcement, and encryption at rest.

## Install

Linux only. Requires Python 3.11+, and Dovecot for mailboxes.

```bash
pipx install lightr
```

Or from a Debian package, which pulls Dovecot in as a dependency:

```bash
sudo apt install ./lightr_0.2.0_all.deb
```

## Quick start

```bash
lightr init --hostname mail.example.com

lightr domain create example.com
lightr domain dkim example.com --generate
lightr domain dns example.com           # records to publish
lightr domain verify example.com        # check what you published

lightr account create ops@example.com   # prompts for a password
lightr serve
```

There is no step for Dovecot. `lightr init` generates its auth key and
master user, writes its configuration, verifies that configuration with
Dovecot's own parser, and reloads the service. `lightr serve` does the
same check on every start, so an install that drifts — a hand-edited
file, a package upgrade that replaced one — comes back into line on its
own. Creating an account provisions its mailbox.

You never edit `dovecot.conf`, hash a master password, or restart
Dovecot. If Dovecot is missing or broken, Lightr says so and keeps
running: the API, the queue, and SMTP receive still work while
mailboxes do not.

## The CLI

Every object is addressable by its human name — an email address, a
domain, an organization name. No command requires a UUID.

```bash
lightr account list --domain example.com
lightr account get ops@example.com
lightr account passwd ops@example.com          # prompts; never a flag

lightr mailbox folders ops@example.com
lightr mailbox list ops@example.com --unread
lightr mailbox read ops@example.com 4821
lightr mailbox search ops@example.com --from billing@ --since 2026-08-01
lightr mailbox download ops@example.com 4821 --attachment 2 -o invoice.pdf

lightr backup create /var/backups/lightr/      # everything Lightr owns
lightr mailbox import ops@example.com old.mbox # mbox, Maildir, or .eml
lightr mailbox export ops@example.com -o ops.mbox

lightr status
lightr dovecot status                          # what Lightr sees of Dovecot
lightr dovecot quota                           # real usage, as Dovecot measures it
lightr queue stats
lightr suppression check someone@example.com   # why did mail stop?
```

`--format table|json|yaml` works on every list and get. Output defaults
to a table on a terminal and JSON when piped, so `lightr account list |
jq` works without a flag.

Passwords are never accepted as command-line arguments — that would put
them in shell history and in `ps` output for every user on the machine.
Use the prompt, `--stdin`, or `--generate`.

## The API

```bash
curl -H "X-API-Key: $KEY" https://mail.example.com/v1/domains
```

Keys are scoped to an organization, a domain, or a single account, and
a scoped key cannot read another tenant's data. `Authorization: Bearer`
works too.

## Configuration

`/etc/lightr/config.yaml`. `lightr init` writes a working one.

An existing config from the Go engine loads unchanged — the retired
`imap` block is ignored, replaced by a `dovecot` block describing how
to reach Dovecot.

## Storage

Maildir, with single-instance attachment storage **off**. One file per
message, never modified after write, every operation atomic — so
corruption is confined to a single message, and attachments live inside
the message file rather than in a shared store whose loss would break
many mails at once.

## Upgrading from the Go engine

The Go implementation is preserved on the `archive/go-engine` branch,
tagged `v0.1.0-go-final`.

```bash
lightr migrate    # adopts an existing database in place
```

The schema is shared, so `lightr migrate` adds only what is missing.

Migration 0003 **drops** the old `messages`, `encryption_keys`, and
`encrypted_messages` tables — Dovecot owns the message store now, and
mail encrypted by the Go engine is not carried over. Migration 0002
still preserves them, so stop there and take a backup first if any of
it matters:

```bash
lightr migrate --revision 0002
```

Note that IMAP clients will resync from scratch on first connect. The
Go engine's IMAP server used positional UIDs that shifted on every
delete, so every existing client cache is already stale.

## Deploying

Publishing to PyPI and installing on a server are both covered in
[docs/DEPLOY.md](docs/DEPLOY.md), including the two things that must be
sorted before anything else works: a PTR record for your IP, and an
unblocked port 25.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,sqlite,postgres]"
pytest
ruff check src tests
```

## Scope

Lightr is a mail engine, not a mail product. It does not own templates,
open/click tracking, unsubscribe flows, campaign analytics, mailing
lists, autoresponders, or groupware. Those belong in applications built
on top of it. See [docs/CORE.md](docs/CORE.md).

## License

MIT
