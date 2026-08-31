# Deployment Runbook

This runbook covers a production-minded Lightr deployment on a single node with either SQLite or PostgreSQL.

## 1. Choose a profile

- SQLite:
  - Best for single-node installs
  - Lowest operational overhead
  - Good default if you do not need external database infrastructure
- PostgreSQL:
  - Better for larger installs and managed database environments
  - Recommended when you want easier backup, failover, and external observability

Sample configs are available at:

- [config/production.sqlite.yaml](C:/Users/User/mydev/lightr/config/production.sqlite.yaml)
- [config/production.postgres.yaml](C:/Users/User/mydev/lightr/config/production.postgres.yaml)

You can also generate one directly:

```bash
lightr config sample --profile sqlite --prod --output /etc/lightr/config.yaml
lightr config sample --profile postgres --prod --output /etc/lightr/config.yaml
```

## 2. Initialize directories

Recommended paths:

- config: `/etc/lightr/config.yaml`
- data: `/var/lib/lightr`
- logs: `/var/log/lightr/lightr.log`

Create them before first start:

```bash
sudo mkdir -p /etc/lightr /var/lib/lightr /var/log/lightr
sudo chown -R lightr:lightr /etc/lightr /var/lib/lightr /var/log/lightr
sudo chmod 750 /etc/lightr /var/lib/lightr /var/log/lightr
```

## 3. Configure TLS

Set node-wide fallback TLS paths in `lightr.yaml`:

```yaml
tls:
  cert_file: /etc/letsencrypt/live/mail.example.com/fullchain.pem
  key_file: /etc/letsencrypt/live/mail.example.com/privkey.pem
```

Per-domain TLS bindings should be stored on the domain records, not in the runtime config.

## 4. Configure spam handling

Recommended production baseline:

```yaml
spam:
  enabled: true
  suspicious_threshold: 2
  junk_threshold: 4
  timeout_seconds: 5
  dnsbl_zones:
    - zen.spamhaus.org
    - bl.spamcop.net
  rspamd_url: http://127.0.0.1:11334
```

Recommended domain spam policy:

- `junk` for most installs
- `quarantine` if operators need manual review before mailbox exposure
- `reject` only when you are confident your DNSBL/content filters are tuned

Set it per domain with:

```bash
lightr domain update example.com --spam-policy junk
```

Useful operations commands:

```bash
lightr spam feedback list
lightr spam feedback reset --sender sender@example.net
lightr spam scan --file ./sample.eml --ip 203.0.113.4 --helo mx.example.net --from bounce@example.net
```

## 5. Configure DNS

For each sending domain:

- MX record to the receiving host
- SPF record authorizing your outbound path
- DKIM public key for the selector you use
- DMARC policy
- PTR/reverse DNS for the public sending IP

At minimum, make sure SPF, DKIM, and DMARC align for every outbound path, including any external relay you configure per domain.

Useful domain DNS commands:

```bash
lightr domain dns example.com
lightr domain verify example.com
```

Notes:

- `domain dns` prints the recommended `MX`, `SPF`, `DKIM`, and `DMARC` records for that specific domain, plus `PTR` guidance.
- Lightr does not update your DNS provider directly; you publish the records yourself.
- `domain verify` requires live `MX`, `SPF`, `DKIM`, and `DMARC` to pass before the domain is marked verified.
- `PTR` is checked and reported, but it is not currently required for verification.

## 6. Bootstrap the service

Initialize config:

```bash
lightr init --hostname mail.example.com
chown -R lightr:lightr /var/lib/lightr
chown root:lightr /etc/lightr/config.yaml
chmod 640 /etc/lightr/config.yaml
```

Validate it:

```bash
lightr config validate
```

Bring up the first mailbox surface:

```bash
lightr domain create --name example.com --mail-hostname mail.example.com --spam-policy junk
lightr domain dns example.com
lightr account create --domain example.com --email ops@example.com --password CHANGE_ME
```

## 7. Health checks

Before exposing ports publicly, confirm:

```bash
lightr health check
lightr health stats
lightr domain list --format yaml
```

Useful native log commands during rollout:

```bash
lightr logs show --since 1h --tail 200
lightr logs show --domain example.com
lightr logs show --level error --component smtp
lightr logs clear --older-than 7d
```

Notes:

- Native logs are written to `/var/log/lightr/lightr.log` by default.
- This is separate from `journalctl -u lightr`; both can be useful.
- Domain filtering is available directly in the CLI, so operators do not need to grep the log file manually.

Keep the separation explicit during rollout:

- `server.hostname` is the node-wide runtime identity used during init.
- `domain.mail_hostname` is the public mail host that should line up with MX, SPF, DKIM-facing docs, TLS naming, and PTR where applicable.
- In many single-domain installs they are the same value, but the operator model now keeps them distinct on purpose.

## 8. Suggested systemd unit

```ini
[Unit]
Description=Lightr Mail Server
After=network-online.target
Wants=network-online.target

[Service]
User=lightr
Group=lightr
WorkingDirectory=/var/lib/lightr
ExecStart=/usr/local/bin/lightr --config /etc/lightr/config.yaml serve
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

## 9. Pre-flight checklist

- `config validate` passes
- TLS cert files readable by the `lightr` user
- database reachable
- ports 25, 587, 143, and 993 opened as intended
- reverse DNS set
- SPF, DKIM, and DMARC in place
- spam policy set per domain
- relay settings verified if using external relays
- backup/export path tested

## 10. Recommended first production checks

- Send local-to-local mail
- Send outbound mail to Gmail and Outlook
- Verify SPF/DKIM/DMARC in received headers
- Confirm spam lands in the intended folder/policy path
- Move a message to `Junk` and back to `INBOX` to confirm feedback learning works
- Run:

```bash
lightr spam feedback list
lightr logs show --since 1h
```
