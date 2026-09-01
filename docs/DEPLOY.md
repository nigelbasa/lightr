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

**The name `lightr` may already be taken.** Check
<https://pypi.org/project/lightr/> before you build. If it is, change
`name` in `pyproject.toml` (`lightr-mail` is the obvious fallback) —
the import name stays `lightr` either way, so only the install command
changes.

### Every release

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

The tag `v0.3.0` already exists locally.

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
apt install -y python3 python3-venv python3-pip \
  dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-lua

adduser --system --group --home /var/lib/lightr --shell /usr/sbin/nologin lightr
adduser dovecot lightr          # Dovecot reads the Sieve scripts Lightr writes

python3 -m venv /opt/lightr
/opt/lightr/bin/pip install --upgrade pip
/opt/lightr/bin/pip install 'lightr[sqlite,imap]'
ln -sf /opt/lightr/bin/lightr /usr/local/bin/lightr

lightr --version
```

Use `'lightr[postgres,imap]'` instead if you want Postgres.

### Configure

```bash
mkdir -p /etc/lightr /var/mail/lightr /var/log/lightr
chown lightr:lightr /var/mail/lightr /var/log/lightr
chmod 2770 /var/mail/lightr

lightr init --hostname mail.example.com
chown root:lightr /etc/lightr/config.yaml
chmod 640 /etc/lightr/config.yaml
```

`init` configures Dovecot as part of its job — it generates the auth
key and master user, writes Dovecot's configuration, verifies it with
`doveconf`, and reloads. There is no separate Dovecot step. If it
warns, read the warning; mailboxes will not work until it is resolved.

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
lightr --config /tmp/test.yaml init --data-dir /tmp/test-restore
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

`serve` re-checks Dovecot's configuration on every start, so an upgrade
that changes what Dovecot needs applies itself.

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
