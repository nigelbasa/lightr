# Lightr — Python Rewrite Map

## Status

All nine phases are built. 864 tests pass; ruff clean.

| Phase | State | Notes |
|---|---|---|
| 0 Archive | **done** | Go on `archive/go-engine`, tagged `v0.1.0-go-final` |
| 1 Foundation | **done** | Config, SQLAlchemy Core schema, Alembic, async engine |
| 2 Domain & identity | **done** | Models, repositories, bcrypt auth, API keys |
| 3 Dovecot | **done** | Maildir, LMTP, Sieve generation + installation, IMAP client, config generation |
| 4 REST API | **done** | Operator routes, mailbox routes, Dovecot passdb/userdb |
| 5 CLI | **done** | Resources, `mailbox`, `account passwd`, `dovecot`, `apikey`, `queue`, `suppression` |
| 6 Inbound SMTP | **done** | Receive, submission, routing, SPF/DKIM/DMARC, spam scoring, bounce ingestion |
| 7 Outbound | **done** | DKIM signing, queue with retries, sender, relay + direct MX |
| 8 Integrations | **done** | Webhooks with SSRF protection and emission; bounces and suppression |
| 9 Packaging | **done** | PyPI wheel, `.deb` via nfpm, systemd unit, CI |

### What is deliberately not built

* **A permissions engine.** API keys carry scopes and those are
  enforced, which is what multi-tenant isolation rests on; the
  `permission_policies` / `sudo_sessions` tables are modelled but
  unused. They would buy finer-grained operator policy, which no
  install has yet needed.
* **RADIUS.** The `auth_providers.provider` column's comment lists it
  alongside the four that are built. It is vanishingly rare for mail,
  and a row naming it is **refused** rather than accepted and silently
  ignored.

### Offloaded authentication, as built

Three providers: LDAP (bind, not hash comparison), an HTTP webhook, and
OAuth2/OIDC token validation. One contract underneath all three:

| the provider says | Lightr reports | Dovecot sees |
| --- | --- | --- |
| these credentials are good | success | `PASSDB_RESULT_OK` |
| no | `bad_password` (401) | `PASSWORD_MISMATCH` |
| nothing — it could not answer | `provider_unavailable` (503) | `INTERNAL_FAILURE` |

The third row is the one that matters. Told a password is wrong, users
change it; a ten-minute directory outage reported as a wrong password
becomes a week of support. Same reasoning as a DMARC `temperror`: a
lookup that did not happen is not evidence.

There is no browser on the IMAP login path, so the OIDC provider
**validates a bearer token** rather than running a redirect flow — and
checks that the token's claim names *this* account. A valid token
belonging to someone else must not open this mailbox, and an answer
carrying no identifying claim at all fails closed.

Every provider is bounded by a timeout it cannot exceed, and Dovecot's
own `auth_cache` sits in front of the whole path, so a reconnecting
mail client does not cost a round trip to the directory.
`lightr account passwd` flushes the cache entry it changed.

The Go engine's per-domain `domains.auth_webhook_url` still answers,
but only when `auth_webhook_verified` is set, and an explicit
`auth_providers` row always wins over it.

### Decisions, now settled

* **Old encrypted mail is not migrated.** Migration 0003 drops
  `encryption_keys`, `encrypted_messages`, and `messages`. 0002 still
  preserves them, so an operator can stop there and take a backup
  before going on.
* **`messages` is gone.** The mailbox routes and CLI read through IMAP.
* **Sieve installs via doveadm**, which compiles the script and rejects
  a broken one up front.
* **Lightr manages Dovecot fully.** `lightr dovecot install` generates
  the internal key and master user, writes the configuration and the
  hashed master-users file, verifies it with `doveconf` before
  reloading, and rolls back on failure. An operator never edits
  `dovecot.conf`, hashes a master password, or reloads the service.

---

Decisions locked; see the status table above for what is built.

Source of truth for scope: [CORE.md](CORE.md).

## Locked decisions

| # | Decision | Choice |
|---|---|---|
| 1 | IMAP | **Dovecot** — Lightr does not implement IMAP |
| 2 | Mail storage | **Maildir**, SIS/`mail_attachment_dir` **off** |
| 3 | Web framework | **Starlette** |
| 4 | DB layer | **SQLAlchemy Core**, SQLite + Postgres |
| 5 | Distribution | **PyPI** wheel + `.deb`; **Linux only** |
| 6 | Repo | Archive Go to a branch, rebuild on `main` |

---

## 0. Phase zero — archive the Go engine

The working tree is dirty with a large uncommitted scope-cut on `main`
(16 deleted packages, plus untracked `docs/`, `integration/`, and new API
handlers). **Commit that first** — the archive branch is worthless without it,
and the scope-cut is the thing that defines what gets ported.

```bash
git add -A
git commit -m "Scope cut: remove non-engine packages per CORE.md"
git checkout -b archive/go-engine
git push -u origin archive/go-engine
git tag v0.1.0-go-final && git push --tags
git checkout main
```

`main` is then cleared for the Python tree. Keep `integration/e2e_test.go` and
`docs/` out of the wipe — the e2e suite is the rewrite's acceptance baseline
(§8) and must be ported before engine code exists.

---

## 1. Architecture after Dovecot

Lightr becomes the mail *engine and control plane*. Dovecot becomes the
*mailbox server*. The seam is four well-defined interfaces.

```
   :25 / :587  ──►  ┌──────────────┐  ── LMTP :24 ────────►  ┌─────────┐
   REST :8080  ──►  │              │                         │         │ ──► Maildir
   CLI         ──►  │    Lightr    │  ◄─ passdb Lua / HTTP ──│ Dovecot │     ~/Maildir
                    │   (Python)   │                         │         │
                    │              │  ── IMAP client ───────►│         │  ◄── :143 / :993
                    └──────┬───────┘  ── doveadm HTTP ──────►└─────────┘      mail clients
                           │
                    SQLite / Postgres
              orgs · domains · accounts · aliases
              api_keys · queue · bounces · webhooks
```

### Who owns what

| Concern | Owner |
|---|---|
| SMTP receive, submission, relay | Lightr |
| DKIM signing, SPF, DMARC, spam scoring | Lightr |
| Outbound queue, retries, bounces, suppression | Lightr |
| Orgs, domains, accounts, aliases, API keys, permissions | Lightr |
| Webhooks, REST API, CLI | Lightr |
| **IMAP protocol (:143, :993)** | **Dovecot** |
| **Message storage, flags, UIDs, folders** | **Dovecot** |
| **Sieve execution, quota enforcement** | **Dovecot** |
| **Encryption at rest** | **Dovecot** (`mail_crypt`) |

### The four seams

1. **LMTP (delivery).** Lightr accepts on :25/:587, does SPF/DKIM/DMARC/spam,
   resolves aliases, injects `X-Spam-*` and auth-result headers, then hands the
   message to Dovecot's LMTP socket. Dovecot writes it and runs Sieve.
2. **passdb Lua over HTTP (auth).** Dovecot calls a Lightr endpoint to
   authenticate IMAP logins. This is the only option that also covers offloaded
   auth (LDAP / OAuth2 / OIDC / webhook) — an SQL passdb against
   `accounts.password_hash` would only work for local bcrypt accounts.
   `checkpassword` is documented as unsuitable for heavy traffic; don't use it.
3. **IMAP client (mailbox reads).** The REST `/v1/mailbox/*` routes and the new
   mailbox CLI both read through an IMAP client (`aioimaplib`) against Dovecot.
   Format-agnostic, uses Dovecot's own flag/UID semantics, no filesystem
   coupling. Build this path once; API and CLI share it.
4. **doveadm HTTP API (admin).** Quota queries, mailbox create/delete,
   force-resync, expunge — operator actions that don't fit an IMAP session.

---

## 2. What the Dovecot choice deletes, changes, and adds

### Deleted outright (~3,200 lines never ported)

| Package | Lines | Why |
|---|---|---|
| `internal/imap` | 1,454 | Dovecot owns the protocol |
| `internal/encryption` | 1,098 | Lightr no longer owns the store — see below |
| `internal/filter` (engine) | 624 | Becomes a Sieve generator, not a runtime |
| `IdleNotifier` (in `imap`) | — | Dovecot handles IDLE natively |

### Encryption at rest — the largest consequence

`internal/encryption` (1,098 lines, plus `encryption_keys` and
`encrypted_messages` tables) cannot survive: Lightr does not write the message
files any more. Dovecot's `mail_crypt` plugin replaces it, with per-user or
global keys managed on Dovecot's side.

**This needs a migration answer before cutover.** Any mail already encrypted by
the Go engine is readable only by the Go engine's key handling. Either decrypt
it during the Maildir import (§7) and re-encrypt via `mail_crypt`, or accept
that encrypted historical mail stays with the archived engine. Decide early —
it constrains the import path.

### Filters split in two

The `Rule` model has conditions Dovecot can evaluate and conditions it cannot:

- **Sieve-expressible** — `from`, `to`, `cc`, `subject`, `header`, `size`.
  Lightr generates a Sieve script per account and installs it; Dovecot runs it.
- **Lightr-only** — `spam_score`, `spf_result`, `dkim_result`, `dmarc_result`,
  `attachment`. These depend on analysis only Lightr performs. Evaluate them
  pre-LMTP and encode the outcome as headers (`X-Spam-Score`,
  `Authentication-Results`) that the generated Sieve script can then test.

Net effect: Lightr stops running a filter engine and starts emitting Sieve.

### Quota — pick one authority

`accounts.quota_bytes` / `used_bytes` in Lightr vs Dovecot's quota plugin.
Recommendation: **Dovecot enforces, Lightr configures.** Lightr writes the
limit into the userdb response and reads current usage via doveadm; drop
`used_bytes` as a Lightr-maintained column.

### Config surface shrinks

`imap.addr`, `imap.tls_addr`, and `imap.allow_insecure` disappear. They're
replaced by a `dovecot:` block — LMTP socket path, IMAP host/port for the
client path, doveadm URL and API key, Maildir root.

### The old IMAP bug list is now migration history

The Go IMAP backend had positional UIDs, a hardcoded `UIDVALIDITY` of 1, a
`SEARCH` that ignored its criteria, and only `\Seen` persisted. Dovecot gets
all of this right by construction, so those stop being work items.

They matter in exactly one way: **every existing client's cache is already
garbage**, because positional UIDs shifted on every delete. A clean
`UIDVALIDITY` on the new Dovecot store is correct and expected — clients will
resync from scratch on first connect. Say so in the upgrade notes.

### New work the choice adds

- LMTP client and delivery path
- passdb/userdb Lua script + the Lightr auth endpoint it calls
- Sieve script generator + installer (via doveadm or ManageSieve)
- doveadm HTTP client
- IMAP-client mailbox adapter (shared by REST and CLI)
- Dovecot config templating + a packaging dependency (§9)

---

## 3. Storage format: Maildir, no SIS

**Use Maildir. Do not enable `mail_attachment_dir` / single-instance storage.**

Reasoning, in order of weight:

- **Maildir is one file per message, never modified after write, and every
  operation is atomic.** Corruption is confined to a single message by
  construction. That's the right trade for an engine whose main promise is not
  losing mail.
- **SIS is deprecated** and has a track record of missing-attachment errors —
  logs filling with references to attachment files that no longer exist. It
  buys disk savings you do not need at this scale, at the cost of the exact
  failure mode that is hardest to recover from.
- **sdbox** is faster and keeps filenames stable, but flags and keywords live
  *only* in Dovecot's index files. **mdbox** is faster still and loses mail
  outright if indexes are damaged, since multiple messages share a file.
- Maildir keeps a **filesystem escape hatch**: backup, grep, and manual
  recovery all work with ordinary tools, and the archived Go engine's importer
  can still read the tree.

So: attachments are safe, provided SIS stays off. Each message — headers, body,
and attachments — is one self-contained file on disk. Revisit sdbox only if
mailbox sizes make Maildir I/O the measured bottleneck.

---

## 4. Storage layer

Keep the existing schema for everything Lightr still owns. That preserves the
ability to point the Python engine at a Go-written database and diff behaviour
(§8), which is the cheapest verification available.

### Schema changes from the Dovecot decision

```sql
-- messages: no longer the store. Keep as a lightweight index only if
-- the API needs list/search without an IMAP round-trip; otherwise drop.
--   storage_path  -> obsolete (Dovecot owns the file)
--   read_at       -> obsolete (Dovecot owns flags)
--   deleted_at    -> obsolete (Dovecot owns expunge)

DROP TABLE encryption_keys;      -- mail_crypt replaces it
DROP TABLE encrypted_messages;

ALTER TABLE accounts DROP COLUMN used_bytes;   -- doveadm is authoritative
ALTER TABLE accounts ADD COLUMN maildir_path TEXT;
ALTER TABLE filter_rules ADD COLUMN sieve_generated_at TIMESTAMP;
```

**Open question:** does `messages` survive as a metadata cache, or get dropped?
Dropping it is cleaner and removes a whole class of drift between Lightr's view
and Dovecot's. Keeping it makes `/v1/accounts/{id}/messages` cheap and
searchable without an IMAP session. Recommendation: **drop it**, back the
message routes with the IMAP client, and revisit only if list latency proves
unacceptable.

### Structural changes

- **Centralize DDL with Alembic.** Eleven packages currently run their own
  `CREATE TABLE` in a repository constructor. One versioned migration
  directory replaces all of it.
- **SQLAlchemy Core** — not the ORM. It handles the SQLite/Postgres dialect
  split (the thing Go does by hand with a `bind()` helper rewriting `?` to
  `$n`), keeps queries greppable against the archived Go source during the
  port, and doesn't impose an identity map the engine has no use for.

### Tables Lightr keeps

`organizations` → `domains` → `accounts`, plus `aliases`,
`alias_reply_routes`, `api_keys`, `api_key_usage`, `auth_providers`,
`bounces`, `suppression_list`, `email_queue`, `filter_rules`,
`permission_policies`, `sudo_sessions`, `permission_audit`, `user_privileges`,
`known_organizations`, `sender_contacts`, `spam_feedback`, `webhooks`,
`webhook_events`.

---

## 5. Library mapping

Runtime: Python 3.12+ on Linux, asyncio throughout.

| Concern | Go today | Python target |
|---|---|---|
| Inbound SMTP + submission | `emersion/go-smtp` | `aiosmtpd` |
| Outbound relay | `go-smtp` client | `aiosmtplib` |
| LMTP delivery to Dovecot | — (new) | `aiosmtplib` (LMTP mode) |
| Mailbox reads | `internal/imap` | `aioimaplib` against Dovecot |
| Dovecot admin | — (new) | `httpx` → doveadm HTTP API |
| MIME parse / build | `go-message` | stdlib `email.policy.SMTP` |
| DKIM sign / verify | `go-msgauth/dkim` | `dkimpy` |
| SPF / DMARC | hand-rolled | `pyspf` + `authres` |
| SQLite / Postgres | `modernc.org/sqlite`, `pgx` | SQLAlchemy Core + `aiosqlite` / `asyncpg` |
| Migrations | ad-hoc `ALTER TABLE` | Alembic |
| HTTP API | stdlib `ServeMux` | **Starlette** |
| LDAP offload | `go-ldap/ldap/v3` | `ldap3` (sync — wrap in `to_thread`) |
| Password hashing | `x/crypto/bcrypt` | `bcrypt` — must stay bcrypt for hash compat |
| CLI | hand-rolled dispatch | Typer + Rich |
| Config | `yaml.v3` + `normalize()` | PyYAML + Pydantic v2 |

---

## 6. The CLI

The complaint is that data wasn't reachable — orgs, domains, emails — and that
there was no password reset. The audit is narrower and more specific than that:

**Already fine.** `org`, `domain`, and `account` all have
`list / create / get / update / delete`, and `resolveOrg` / `resolveDomain` /
`resolveAccount` already accept **either a name/email or a UUID**. The resource
CLI works better than it feels.

**Genuinely missing:**

1. **No message or mailbox command exists at all.** Mail is reachable only as a
   side effect of `lightr data export`. This is the real gap.
2. **No password reset subcommand.** Passwords are set only via
   `account create --password` and `account update --password`, which puts the
   plaintext into shell history *and* into `ps` output for any user on the box.
3. **Inconsistent output.** `--format yaml|json` on some groups, a hardcoded
   table on others, nothing machine-friendly across the board.

### What to build

```bash
# the missing group — reads through the shared IMAP-client path
lightr mailbox folders      ops@acme.test
lightr mailbox list         ops@acme.test --folder INBOX --limit 20 --unread
lightr mailbox read         ops@acme.test 4821 [--raw | --headers]
lightr mailbox attachments  ops@acme.test 4821
lightr mailbox download     ops@acme.test 4821 --attachment 2 --out ./file.pdf
lightr mailbox search       ops@acme.test --from billing@ --since 2026-08-01
lightr mailbox delete       ops@acme.test 4821

# password handling that doesn't leak
lightr account passwd ops@acme.test            # prompts, no echo, confirms
lightr account passwd ops@acme.test --stdin    # for scripts and config mgmt
lightr account passwd ops@acme.test --generate # prints once, stores hash
```

### CLI principles for the rewrite

- **Every object addressable by its human name.** `ops@acme.test`,
  `acme.test`, `"Acme Ltd"` — never require a UUID. Extend the existing
  resolver pattern to every group, including `queue`, `webhook`, and `apikey`.
- **`--format table|json|yaml` on every list and get**, table by default when
  attached to a TTY, JSON when piped. No group gets a bespoke output.
- **Secrets never come from argv.** Prompt, `--stdin`, or a file path. This
  applies to `--password`, `--relay-password`, `--auth-value`, and webhook
  secrets — all of which currently take plaintext flags.
- **Destructive commands confirm** unless `--yes`. `account delete` removes a
  mailbox; it should say what it's about to destroy first.
- **Errors say what to do next.** "domain acme.test is not verified — run
  `lightr domain verify acme.test`" beats a wrapped SQL error.
- **The CLI must not import the server stack.** A Typer app that pulls in
  Starlette and aiosmtpd pays ~1s of import time on every invocation.

---

## 7. REST API

~50 routes, ported to Starlette. Two distinct auth surfaces that must not
collapse into one dependency: operator routes scoped by org/domain/account on
an API key, and `/v1/mailbox/*` which is account-session scoped — a different
principal entirely.

**Changed by Dovecot:** the eight message and mailbox routes
(`/v1/accounts/{id}/messages`, `/v1/messages/{id}`, and the six
`/v1/mailbox/*` reads) are re-backed onto the IMAP-client path. Response
shapes stay identical; only the data source changes. `/v1/mailbox/send` still
goes through Lightr's own submission path, not Dovecot.

**New:** an internal auth endpoint for the Dovecot passdb Lua script. It must
be bound to localhost or a unix socket, never exposed publicly, and it is the
one route that sees plaintext passwords — rate-limit it and never log the body.

Route inventory is unchanged from the Go build:

```
GET    /health

# operator — X-API-Key / Authorization
GET    /v1/orgs                              POST   /v1/orgs
GET    /v1/orgs/{id}
GET    /v1/apikeys                           POST   /v1/apikeys
POST   /v1/apikeys/{id}/rotate               POST   /v1/apikeys/{id}/revoke
DELETE /v1/apikeys/{id}
GET    /v1/domains                           POST   /v1/domains
GET    /v1/orgs/{org_id}/domains
GET    /v1/domains/{id}                      PATCH  /v1/domains/{id}
DELETE /v1/domains/{id}                      GET    /v1/domains/{id}/dns
POST   /v1/domains/{id}/verify
POST   /v1/domains/{id}/auth-webhook/verify
POST   /v1/domains/{id}/auth-webhook/rotate-secret
GET    /v1/accounts                          POST   /v1/accounts
GET    /v1/accounts/{id}                     PATCH  /v1/accounts/{id}
DELETE /v1/accounts/{id}
GET    /v1/aliases                           POST   /v1/aliases
PATCH  /v1/aliases/{id}                      DELETE /v1/aliases/{id}
GET    /v1/accounts/{account_id}/messages    GET    /v1/messages/{id}
GET    /v1/webhooks                          POST   /v1/webhooks
GET    /v1/webhooks/{id}                     PATCH  /v1/webhooks/{id}
DELETE /v1/webhooks/{id}                     POST   /v1/webhooks/{id}/verify
GET    /v1/webhooks/{id}/events              GET    /v1/webhooks/{id}/stats
POST   /v1/send

# mailbox — account-session scoped, now IMAP-backed
GET    /v1/mailbox                           GET    /v1/mailbox/messages
GET    /v1/mailbox/messages/{id}             PATCH  /v1/mailbox/messages/{id}
GET    /v1/mailbox/messages/{id}/attachments/{att_id}
GET    /v1/mailbox/folders                   POST   /v1/mailbox/send
GET    /v1/mailbox/contacts                  PATCH  /v1/mailbox/account

# internal — localhost only, never public
POST   /internal/auth/verify                 (Dovecot passdb)
GET    /internal/auth/user                   (Dovecot userdb)
```

Starlette gives no free OpenAPI. Either hand-write the spec or add
`starlette-apispec` — worth doing, since the Go build has none.

---

## 8. Concurrency

asyncio throughout. Three explicit decisions:

- **Queue sender:** in-process asyncio task for phase-1 parity with Go. If it
  later moves to a separate worker, `email_queue` needs a claim/lease column to
  prevent double-send.
- **Blocking calls:** `bcrypt`, `ldap3`, and DNS are synchronous. Wrap in
  `asyncio.to_thread`. Never block the loop on an SMTP DATA path or on the
  passdb endpoint — Dovecot has an auth timeout.
- **IMAP client pooling:** one connection per request is too slow for the
  mailbox API. Pool connections per account with an idle timeout, and make sure
  a stale Dovecot connection surfaces as a retry, not a 500.

`IdleNotifier` is deleted — Dovecot handles IDLE.

---

## 9. Verification

`integration/e2e_test.go` (963 lines) is the most valuable asset in the repo.
Port it to pytest **before any engine code**, run it against the Go binary to
establish the baseline, then gate every Python phase on it.

| Layer | Method |
|---|---|
| API parity | Record Go responses for all ~50 routes, replay against Python, diff JSON |
| Shared-DB A/B | Both engines on one SQLite file, compare reads — possible because §4 keeps the schema |
| SMTP conformance | swaks / `smtplib` through both |
| LMTP delivery | Message in on :25 → assert the file lands in Maildir with the right headers |
| Dovecot auth | passdb Lua against a live Lightr endpoint, local + each offload provider |
| Sieve generation | Golden-file the generated scripts; run them through `sieve-test` |
| IMAP client compat | Thunderbird, Apple Mail, Outlook, K-9 — now testing *Dovecot*, so this is a config check, not a protocol one |

That last row is the biggest win from the Dovecot decision: client
compatibility stops being a correctness problem and becomes a configuration
problem.

---

## 10. Phase order

Dovecot integration moves **early** — the mailbox API and CLI can't be built
until it's known what backs them.

| Phase | Content | Gate |
|---|---|---|
| 0 | Commit the scope-cut, archive Go to `archive/go-engine`, tag, clear `main`. Port e2e suite to pytest, baseline against the Go binary. | Suite green vs Go |
| 1 | Skeleton, Pydantic config, logging, metrics, Alembic migrations, SQLAlchemy Core storage across both drivers. | Round-trips a Go-written DB |
| 2 | Domain model, org/domain/account/alias repos, bcrypt auth, API keys, permissions. | Unit tests |
| 3 | **Dovecot integration** — Maildir layout, LMTP delivery, passdb/userdb Lua + internal auth endpoint, doveadm client, IMAP mailbox adapter, Sieve generator. | Mail delivered via LMTP is readable over IMAP by a real client |
| 4 | REST API — all ~50 routes on Starlette, mailbox routes on the IMAP adapter. | API parity diff clean |
| 5 | CLI on Typer — full resource groups, **new `mailbox` group**, **`account passwd`**, uniform `--format`, no secrets in argv. | CLI test port green + the §6 gaps closed |
| 6 | SMTP receive + submission on aiosmtpd, alias/bridge/reply routing, spam, SPF/DMARC, header injection for Sieve. | SMTP conformance + LMTP handoff |
| 7 | Outbound: relay, DKIM signing, queue + retry, bounce parsing, suppression. | Round-trip send/receive |
| 8 | Webhooks + SSRF guard, backup/export, mbox/maildir/eml import (incl. the encryption migration answer), auth offload (LDAP/OAuth2/OIDC/webhook). | Feature tests |
| 9 | Packaging: PyPI wheel, `.deb` with a Dovecot dependency, systemd units, Dovecot config templating, installer rework, docs. | Clean install on a fresh Debian box |

Phases 4–5 and 6–7 can interleave. Phase 3 blocks 4, 5, and 6.

---

## 11. Packaging notes

Linux only, so the Windows privilege-dropping path in the Go build is dropped
outright — `os.setuid` / `os.setgid` after binding :25 and :587 covers it.

Two artifacts:

- **PyPI wheel** — `pip install lightr` / `pipx install lightr`, for people who
  already run Dovecot and want the engine alongside it.
- **`.deb`** — depends on `dovecot-core`, `dovecot-imapd`, `dovecot-lmtpd`,
  `dovecot-sieve`, and `dovecot-lua` (for passdb). Ships systemd units and a
  templated Dovecot config drop-in.

The `.deb` is now the harder artifact: `lightr init` must generate a working
Dovecot configuration, not just its own. Treat Dovecot config templating as a
first-class deliverable in phase 9, with the generated files reviewed as
carefully as the Python.

---

## 12. Remaining open questions

1. **Does `messages` survive as a cache, or get dropped?** Recommendation: drop
   it, back the routes with IMAP. (§4)
2. **What happens to mail already encrypted by the Go engine?** Decrypt during
   import and re-encrypt with `mail_crypt`, or leave it with the archived
   engine. This constrains the phase-8 importer. (§2)
3. **Sieve installation route:** doveadm, or ManageSieve on :4190? doveadm
   avoids opening another port; ManageSieve lets users edit their own rules.
4. **Does Lightr manage Dovecot's config, or just document it?** Full
   templating is better UX and much more surface area to own.
