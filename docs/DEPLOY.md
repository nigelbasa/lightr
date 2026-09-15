# Deploying Lightr

Two halves: publishing the package, then installing it on a server.
Publishing needs your PyPI credentials, so those steps are yours to run
— nothing here does it for you.

---

## 1. Publish to PyPI

### One-time setup

Create accounts and an API token:

1. Register at <https://pypi.org/account/register/> (and
   <https://test.pypi.org/account/register/> — separate account, worth
   having).
2. Enable 2FA. PyPI requires it for publishing.
3. Create a token at <https://pypi.org/manage/account/token/>. Scope it
   to "Entire account" for the first upload — you can't scope a token
   to a project that doesn't exist yet. After the first release, delete
   it and make a project-scoped one.

Put the token in `~/.pypirc`, owner-readable only:

```ini
[pypi]
  username = __token__
  password = pypi-AgEIcHlwaS5vcmc...

[testpypi]
  username = __token__
  password = pypi-AgENdGVzdC5weXBpLm9yZw...
```

```bash
chmod 600 ~/.pypirc
```

**Check the name is free before you build.** Use the JSON API, not the
project page: `pypi.org/project/<name>/` answers 200 for names that do
not exist, so it will tell you every name is taken.

```powershell
try { Invoke-WebRequest "https://pypi.org/pypi/lightr/json" -UseBasicParsing -EA Stop; "taken" }
catch { "available ($($_.Exception.Response.StatusCode.value__))" }
```

404 means it is yours to claim. If it is taken, change `name` in
`pyproject.toml` (`lightr-mail` is the obvious fallback) — the import
name stays `lightr` either way, so only the install command changes.

### Every release

### From Windows

`twine` reads credentials from the environment, so the token never has
to go in a file:

```powershell
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = "pypi-AgEIcHlwaS5vcmc..."   # paste yours

# The venv's Python: twine is a dev dependency, not a global one.
.venv\Scripts\python.exe -m twine upload `
  --repository-url https://test.pypi.org/legacy/ `
  dist\lightr-0.3.5-py3-none-any.whl dist\lightr-0.3.5.tar.gz

.venv\Scripts\python.exe -m twine upload `
  dist\lightr-0.3.5-py3-none-any.whl dist\lightr-0.3.5.tar.gz
```

Name the files rather than writing `dist\*`: PowerShell does not expand
wildcards for external commands, so the glob is passed through and only
works because twine expands it itself.

The variables live only in that shell session. Close it when you are
done, and revoke the token if it has been anywhere it should not.

### From a Unix shell

```bash
# 1. Version. It must not already exist on PyPI; a version can never
#    be re-uploaded, only yanked.
#    Edit pyproject.toml and src/lightr/__init__.py — both.

# 2. Build clean. A stale dist/ will happily upload last week's code.
rm -rf dist build
python -m build

# 3. Validate what PyPI will validate.
python -m twine check dist/*

# 4. Rehearse on TestPyPI first.
python -m twine upload --repository testpypi dist/*

python -m venv /tmp/verify
/tmp/verify/bin/pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  'lightr[sqlite,imap]'
/tmp/verify/bin/lightr --version

# 5. The real thing.
python -m twine upload dist/*
```

`--extra-index-url` in step 4 is not optional: TestPyPI does not mirror
real dependencies, so without it the install fails on `sqlalchemy`
rather than on anything about Lightr.

### After publishing

```bash
git push && git push --tags
```

The tag `v0.3.5` already exists locally.

---

## 2. Install on the VPS

Assumes Debian 12 or Ubuntu 22.04+. Run as root or under `sudo`.

### Before you touch the server

Two things must be true, and both take time to propagate, so start
them first:

- **A hostname that resolves.** `mail.example.com` with an A record
  pointing at the VPS.
- **A PTR record** for the VPS IP, pointing back at that hostname. This
  is set in your provider's control panel, not in DNS — and without it
  a large share of receivers will refuse your mail outright.

Check port 25 is not blocked. Many providers block it by default and
will unblock on request:

```bash
nc -zv gmail-smtp-in.l.google.com 25
```

If that times out, everything else will work and no mail will leave the
box. Sort it before going further.

### Install

```bash
apt update
# Python 3.11+ is required. Ubuntu 22.04 ships 3.10, so add the PPA
# there first: add-apt-repository ppa:deadsnakes/ppa
apt install -y python3.12 python3.12-venv \
  dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve

adduser --system --group --home /var/lib/lightr --shell /usr/sbin/nologin lightr
adduser dovecot lightr          # Dovecot reads the Sieve scripts Lightr writes

python3.12 -m venv /opt/lightr
/opt/lightr/bin/pip install --upgrade pip
/opt/lightr/bin/pip install 'lightr[sqlite,imap]'
ln -sf /opt/lightr/bin/lightr /usr/local/bin/lightr

lightr --version
```

Use `'lightr[postgres,sqlite,imap]'` for Postgres — keep `sqlite` in
the list either way. `lightr setup` writes a SQLite config first and you
point it at Postgres afterwards, so it needs that driver even on an
install that will never use it.

Dovecot needs its own driver for whichever database Lightr uses:
**`dovecot-sqlite`** or **`dovecot-pgsql`**. Without it Dovecot cannot
answer "where does this mailbox live", and delivery fails with "Unknown
database driver", which points at nothing. `lightr preflight` names the
package you are missing.

### Configure

```bash
mkdir -p /etc/lightr /var/mail/lightr /var/log/lightr
chown lightr:lightr /var/mail/lightr /var/log/lightr
chmod 2770 /var/mail/lightr

lightr setup --hostname mail.example.com
chown root:lightr /etc/lightr/config.yaml
chmod 640 /etc/lightr/config.yaml
```

`setup` configures Dovecot as part of its job — it generates the auth
key and master user, writes Dovecot's configuration, verifies it with
`doveconf`, and reloads. There is no separate Dovecot step. If it
warns, read the warning; mailboxes will not work until it is resolved.

It also edits one stock Dovecot file. Debian's and Ubuntu's
`/etc/dovecot/conf.d/10-auth.conf` ends with
`!include auth-system.conf.ext`, which declares a PAM passdb. Dovecot
tries passdbs in the order they appear, and `10-auth.conf` loads before
Lightr's `99-lightr.conf`, so every IMAP login went to PAM first. That
logged a PAM failure for each login and added PAM's failure delay before
Lightr was asked. Dovecot 2.3 cannot remove a passdb declared earlier,
so `setup` (and `lightr dovecot install`) comments that line out:

```
# Disabled by Lightr, which authenticates every login itself.
# PAM was being tried first on each one. See docs/DEPLOY.md.
#!include auth-system.conf.ext
```

The original is saved next to it as
`10-auth.conf.lightr-<timestamp>.bak`, and the edit is rolled back with
everything else if `doveconf` rejects the result. To undo it, remove the
`#` and run `systemctl reload dovecot`.

Because `10-auth.conf` is a dpkg conffile, an upgrade of `dovecot-core`
that changes it asks whether to keep your version. Keep it (`N`). If the
stock file comes back anyway, `lightr preflight` and `lightr serve` warn
about `dovecot-pam`, and `lightr dovecot install` fixes it again. You
can also do it by hand: comment out `!include auth-system.conf.ext` in
`/etc/dovecot/conf.d/10-auth.conf`, then run `systemctl reload dovecot`.

### Postgres

SQLite is what a fresh install uses, and it is fine for one server. Move
to Postgres when you want backups you can take while it runs,
replication, or more than one Lightr on one database.

```bash
apt install -y postgresql postgresql-client dovecot-pgsql
sudo lightr db provision
```

That creates the role and the database, grants what the migrations
need, writes the connection string into `/etc/lightr/config.yaml`, and
brings the schema up. It administers Postgres as the `postgres` system
user -- the way a Debian-family install is administered locally -- so it
needs root and no superuser password.

The generated password is written into the config and printed nowhere.
Nobody has to see it, so nobody has to be careful with it.

It does **not** copy what is already in SQLite. On an install with data
in it:

```bash
lightr backup create /var/backups/lightr/before-postgres.tar.gz
sudo lightr db provision
lightr backup restore /var/backups/lightr/before-postgres.tar.gz --yes
lightr dovecot install     # Dovecot reads this database too
```

Run it again any time -- an existing role and database are left alone.
The one thing it will not do quietly is reset the password of a role
whose password is not already in your config; it says so when it has to.

### Your first domain

```bash
lightr domain create example.com --mail-hostname mail.example.com
lightr domain dkim example.com --generate
lightr domain dns example.com          # publish these records
```

Publish what it prints, wait for propagation, then:

```bash
lightr domain verify example.com
```

It will not report verified until MX, SPF, DKIM, and DMARC are all
live. That is deliberate — a domain that passes here is one that other
servers will accept mail from.

### Accounts and running

```bash
lightr account create you@example.com   # prompts for a password

# Port 25 needs a capability, not root.
setcap 'cap_net_bind_service=+ep' /opt/lightr/bin/python3

cp /opt/lightr/lib/python3*/site-packages/../../../packaging/systemd/lightr.service \
   /lib/systemd/system/lightr.service 2>/dev/null || \
  curl -fsSL https://raw.githubusercontent.com/nigelbasa/lightr/main/packaging/systemd/lightr.service \
    -o /lib/systemd/system/lightr.service

systemctl daemon-reload
systemctl enable --now lightr
systemctl status lightr
```

### TLS

Get a certificate before letting anyone connect — Lightr refuses
plaintext authentication by default, which is correct and which means
submission will not work until TLS is in place:

```bash
apt install -y certbot
certbot certonly --standalone -d mail.example.com

# Point Dovecot and Lightr at it, then:
systemctl reload lightr
```

### Where encryption terminates

Worth stating plainly, because "we support TLS" without saying where it
terminates is how people end up serving plaintext on a public
interface.

| Surface | Encrypted by | Notes |
| --- | --- | --- |
| SMTP receive (:25) | Lightr, STARTTLS | Opportunistic. It has to be: a sending server that will not do TLS is still delivering you mail. |
| Submission (:587) | Lightr, STARTTLS | Required. `security.require_tls_for_auth` is on by default and refuses a password in the clear. |
| IMAP (:143, :993) | Dovecot | Dovecot's own certificate, configured where its certificate always was. |
| Outbound, direct to MX | Lightr, opportunistic | Encrypted where the receiver offers it. |
| Outbound, through a relay | Lightr, STARTTLS or TLS | Required whenever a relay password is set; `lightr domain relay` refuses otherwise. See **Sending through a relay**. |
| **HTTP API (:8080)** | **nothing — put a proxy in front** | Plain HTTP. |
| Dovecot → Lightr auth | nothing, and it does not cross a network | Loopback only. |

The API is the one that needs a decision. Lightr does not terminate TLS
for it, deliberately: a mail engine is a bad place to keep a web
server's certificate rotation working, and every deployment already has
something that does it well. Put nginx or Caddy in front, and keep
Lightr on loopback:

```yaml
# /etc/lightr/config.yaml
http:
  addr: "127.0.0.1:8080"
```

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;
    ssl_certificate     /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        # Lightr trusts the *last* entry, so a client cannot forge it.
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

The default `addr: ":8080"` binds every interface. That is fine behind
a firewall and wrong on a public host, so decide which you have.

The endpoints Dovecot uses to check passwords are on that same port and
see plaintext passwords, which is the reason they are refused unless
the caller presents the internal key — and the reason to keep the
listener on loopback rather than relying on that alone.

### Rate limits

Set in the `limits` block, and enforced in one process — two Lightrs
behind a load balancer each enforce their own copy, so the effective
limit is doubled. Defaults are in `/etc/lightr/config.yaml`.

This is rate limiting, not DDoS protection. It refuses more work than a
caller is entitled to before that work reaches the database or Dovecot.
It does nothing about a flood large enough to fill the link or exhaust
the accept queue; that is answered upstream, by your provider or by
something in front of the host.

Per-key limits come from the key itself (`rate_limit` per minute and
`daily_limit`), so a tenant that needs more can be given more without
raising it for everyone. Zero means unlimited, everywhere.

### Spam checking

Every inbound message gets a score. The score goes into `X-Spam-Score`
and the reasons into `X-Lightr-Spam-Reasons`. At `junk_threshold`
(default 4.0), `X-Spam-Flag: YES` is set and the message is filed into
Junk. Filing follows the domain's spam policy:

| `--spam-policy` | Flagged mail |
| --- | --- |
| `junk` (default) | Filed into Junk. |
| `tag` | Stays in the inbox; only the headers are set. |
| `reject` | Filed into Junk, for now. Refusing at SMTP time is not implemented: it would turn every false positive into a bounce the recipient never sees. |

Filing is done by a server-wide Sieve script that `lightr setup` installs
into `sieve_dir` and Dovecot runs before each mailbox's own filters.
For mail it files, the mailbox's filters do not run. Nothing is refused
because of its score.

There are three layers. Each one is optional and adds to the one before:

| | What it does | Turned on by |
| --- | --- | --- |
| Lightr's own scorer | SPF, DKIM and DMARC results, executable attachments, malformed headers. | Always on. |
| DNS blocklists | Checks the connecting address, the sender's domain, and linked domains against Spamhaus, SpamCop, Barracuda and similar lists. | `dnsbl_zones`, `domain_blocklist_zones` |
| rspamd | A full filter: Bayes learning, fuzzy hashes, its own blocklists, phishing checks. When it answers, its verdict replaces the two layers above. | `rspamd_url` |

#### A local DNS resolver comes first

Blocklists refuse queries that arrive through big public resolvers,
such as 8.8.8.8, 1.1.1.1 and most cloud providers' defaults. They also
refuse through anything else sending them heavy traffic. Refused
queries are not counted as listings, so a server stuck behind one of
those resolvers simply gets no blocklist protection. Run your own
resolver:

```bash
apt install -y unbound
```

```bash
systemctl enable --now unbound
```

Then point the host at it. On Ubuntu that means setting `DNS=127.0.0.1`
in `/etc/systemd/resolved.conf`, followed by `systemctl restart
systemd-resolved`. Confirm the change with `resolvectl status`.

#### Blocklists

```yaml
# /etc/lightr/config.yaml
spam:
  dnsbl_zones: [zen.spamhaus.org, bl.spamcop.net]
  domain_blocklist_zones: [dbl.spamhaus.org]
```

Before relying on them, check each list actually answers:

```bash
lightr spam lists
```

The command asks every list for its fixed test entries. A list shows
`refused` when queries are reaching it through a public resolver, and
`lists everything` when the resolver is rewriting answers. In either
case the command exits non-zero.

Read each list's terms before adding it. Spamhaus is free only for low
volume and non-commercial use; commercial senders need its Data Query
Service. One listing adds 3 points (2.5 for a domain), so a listing
alone does not flag mail as spam, but a listing plus a failed check
does.

#### rspamd

Install it from rspamd's own package repository. Distribution packages
lag well behind; the instructions are at <https://rspamd.com/downloads.html>.
Once it is installed:

```bash
systemctl enable --now rspamd
```

```yaml
spam:
  rspamd_url: http://127.0.0.1:11333
```

Lightr posts each message to the normal worker on port 11333, which
needs no password. Keep that port on loopback. rspamd does its own
blocklist lookups, so it needs the local resolver too. Bayes learning
needs Redis (`apt install redis-server`); see rspamd's documentation on
the statistics module.

If rspamd is down or slow, Lightr logs it and scores the message
itself, blocklists included. A broken spam filter never means mail
goes through unchecked.

### Sending through a relay

A server on a small or residential IP, or one whose reverse DNS you
cannot set, reaches the inbox more reliably by handing its outgoing mail
to a provider with a good sending reputation (a "smarthost"). Lightr does
this per domain. Receiving does not change: MX still points here and
Dovecot still holds the mail. And the message is DKIM-signed here, as the
domain, before it is handed over, so the recipient sees the domain's own
signature whatever the provider adds.

```bash
# The password comes from a prompt (or --password-stdin), never a flag.
lightr domain relay example.com --host smtp.provider.example --port 587 \
    --username apikey --password

# Log in without sending anything, and say exactly what the server said.
lightr domain relay example.com --test

lightr domain relay example.com              # show the settings
lightr domain relay example.com --disable    # back to direct delivery, settings kept
lightr domain relay example.com --clear      # forget them
```

TLS is on by default when a host is set. Port 465 is spoken to with TLS
from the first byte; other ports negotiate STARTTLS. A relay password is
never sent without one or the other: the command refuses. An
organization or admin API key can do the same with
`PATCH /v1/domains/{id}` and the `relay_*` fields; a key confined to one
domain or account cannot, because the relay receives everything the
domain sends.

Then, in the domain's DNS:

- **SPF:** add the provider's include, keeping the server's own address
  for anything still sent directly, e.g.
  `v=spf1 ip4:203.0.113.10 include:spf.provider.example ~all`.
- **The provider's own records.** Most want a DKIM record or a
  verification TXT of their own. Publish them alongside the domain's
  Lightr DKIM record, not instead of it.

DMARC passes on the domain's own DKIM signature even when the provider
rewrites the envelope sender to its own bounce domain.

---

## 3. Check it works

```bash
lightr status                    # database, revision, counts
lightr dovecot status            # what Lightr can see of Dovecot
lightr domain verify example.com # DNS
lightr queue stats               # outbound
```

Then send yourself mail from an outside address and read it back:

```bash
lightr mailbox list you@example.com
lightr mailbox read you@example.com <uid>
```

And send one out, checking it arrives unmarked. <https://mail-tester.com>
scores SPF, DKIM, DMARC, and reputation in one go and is the fastest
way to find what is still wrong.

### When something is not working

```bash
journalctl -u lightr -f                  # what Lightr is doing
journalctl -u dovecot -f                 # what Dovecot is doing
lightr suppression check them@example.com # why did mail to them stop?
lightr queue list --status failed        # what failed to send, and why
```

If Dovecot's log shows `pam_unix(dovecot:auth): check pass; user unknown`
on every IMAP login, the stock PAM passdb is still active and runs
before Lightr's. See **Configure** above. The fix is
`lightr dovecot install`.

A current install can have files `serve` cannot read, because they hold
the internal key and the database DSN (`lightr-checkpassword`,
`lightr-userdb.conf.ext`, readable only by root and Dovecot). `serve`
does not call those out of date. It logs that they were not checked. To
check them, run `lightr dovecot install` as root; if they are already
current, it changes nothing.

### Offloaded authentication

Accounts authenticate against a local password by default. To point
them at a directory instead:

```bash
lightr auth add ldap corp --domain example.com   --set uri=ldaps://dc.corp.example.com   --set base_dn=ou=people,dc=corp,dc=example,dc=com   --set bind_dn='cn=lightr,ou=services,dc=corp,dc=example,dc=com'   --set bind_password='...'   --set 'user_filter=(mail={username})'

lightr auth enable ops@example.com     # its local password stops working
lightr auth test ops@example.com       # try a real login
```

`lightr auth test` runs the same path SMTP, the API, and Dovecot's
passdb all run, and says which provider answered. Use it before telling
anyone their mail client will work.

An HTTP endpoint instead of a directory:

```bash
lightr auth add webhook app --domain example.com   --set url=https://app.example.com/auth --set secret='...'
```

It receives `{"username", "password"}` signed with `X-Lightr-Signature`
exactly as event webhooks are, and should answer `{"ok": true}` or
401/403. **Answer 5xx if you cannot check** — a 200 saying `ok: false`
means "wrong password", and every user will be told to change one that
is fine.

OAuth2/OIDC validates a bearer token, because there is no browser on an
IMAP login:

```bash
lightr auth add oidc sso --domain example.com   --set introspection_url=https://idp.example.com/oauth2/introspect   --set client_id=lightr --set client_secret='...'   --set username_claim=email
```

The claim must name the account being logged into. A valid token
belonging to someone else is refused.

LDAP needs the extra: `pip install 'lightr[ldap]'`.

### Webhooks

```bash
lightr webhook events                       # what you can subscribe to
lightr webhook create billing https://api.example.com/hooks/lightr   --event mail.delivered --event mail.bounced
lightr webhook test billing                 # fire a ping, report what came back
lightr webhook deliveries billing           # recent attempts, newest first
```

Every payload is signed: `X-Lightr-Signature` is
`sha256=HMAC(secret, timestamp + "." + body)`, with the timestamp in
`X-Lightr-Timestamp`. Signing both together is what stops a captured
request being replayed; reject anything more than five minutes old.
`lightr webhook secret <name>` prints the secret, and
`lightr.webhooks.delivery.verify` is the reference implementation to
test a receiver against.

A webhook URL is chosen by a tenant and fetched by the server, so
private and link-local addresses are refused — otherwise it is a way to
make Lightr read the cloud metadata endpoint on someone's behalf. If
your receiver genuinely is on this network, set:

```yaml
webhook:
  allow_private: true
```

---

## 4. Backups

```bash
lightr backup create /var/backups/lightr/          # database only
lightr backup create /var/backups/ --include-mail  # and the Maildirs
lightr backup inspect /var/backups/lightr-backup-20260901-120000.tar.gz
```

The archive holds every row Lightr owns, unredacted: password hashes,
DKIM private keys, relay credentials. That is what makes it a working
backup rather than a decorative one, and it is why the file is written
`0600`. Treat it as you would the private keys inside it.

Mail is left out unless you ask for it — the database is kilobytes and
the mail is not. Both halves are worth having, on different schedules.

A nightly database backup, kept for a fortnight:

```bash
cat >/etc/cron.daily/lightr-backup <<'SH'
#!/bin/sh
install -d -m 700 /var/backups/lightr
lightr backup create /var/backups/lightr/
find /var/backups/lightr -name 'lightr-backup-*.tar.gz' -mtime +14 -delete
SH
chmod +x /etc/cron.daily/lightr-backup
```

Restoring replaces everything, and asks before it does:

```bash
lightr backup restore /var/backups/lightr/lightr-backup-20260901-120000.tar.gz
```

It refuses an archive taken at a different schema revision rather than
loading half of it. `lightr backup inspect` tells you the revision
before you try.

**Test a restore before you need one.** A backup nobody has restored
is a file, not a backup:

```bash
lightr --config /tmp/test.yaml setup --data-dir /tmp/test-restore
lightr --config /tmp/test.yaml backup restore /var/backups/lightr/<file> --yes
lightr --config /tmp/test.yaml account list
```

### Moving mail in from another server

```bash
lightr mailbox import ops@example.com /var/mail/old/ops.mbox
lightr mailbox import ops@example.com /home/ops/Maildir      # folders and flags kept
lightr mailbox import ops@example.com ./exported/ --dry-run  # count first
```

Messages are appended through IMAP, so Dovecot indexes them as it would
any delivery. Re-running an import adds the messages again rather than
replacing them — use `--dry-run` first.

Out again, as mbox, which every other mail tool reads:

```bash
lightr mailbox export ops@example.com -o ops.mbox
```

---

## 5. Upgrading

```bash
/opt/lightr/bin/pip install --upgrade lightr
lightr migrate
systemctl restart lightr
```

`serve` checks Dovecot's configuration on every start, but only reports
what is out of date. It never rewrites it, because that would need write
access to `/etc/dovecot` for as long as it runs. The package runs
`lightr setup` on upgrade, which applies changes. After a pip upgrade,
apply them yourself:

```bash
lightr dovecot install
```

**Coming from the Go engine:** migration `0003` drops the old
`messages`, `encryption_keys`, and `encrypted_messages` tables. If any
of that data matters, stop at `0002` and back up first:

```bash
lightr migrate --revision 0002
lightr backup create /root/before-0003.tar.gz
lightr migrate
```

IMAP clients will resync from scratch on first connect. The Go engine
used positional UIDs that shifted on every delete, so every existing
client cache is already stale.
