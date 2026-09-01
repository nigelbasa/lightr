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
- **Dovecot's configuration** — `lightr dovecot config` generates it

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
lightr dovecot setup                    # generate the internal auth key
lightr dovecot config --write           # write Dovecot's configuration
systemctl restart dovecot

lightr domain create example.com
lightr domain dns example.com           # records to publish
lightr account create ops@example.com   # prompts for a password

lightr serve
```

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

lightr status
lightr dovecot check
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

The schema is shared, so `lightr migrate` adds only what is missing. It
does **not** drop the old `messages`, `encryption_keys`, or
`encrypted_messages` tables — those may hold the only copy of data that
still needs migrating into Dovecot.

Note that IMAP clients will resync from scratch on first connect. The
Go engine's IMAP server used positional UIDs that shifted on every
delete, so every existing client cache is already stale.

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
