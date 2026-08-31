# Lightr

A lightweight, embeddable email server written in Go. Lightr provides SMTP (inbound/outbound), IMAP, and a REST API for managing email domains, accounts, and operator controls.

## Features

- **SMTP Server** - Receive and store incoming emails with MIME parsing
- **SMTP Relay** - Send outbound emails with DKIM signing
- **IMAP Server** - Allow email clients to access mailboxes
- **REST API** - Manage domains, accounts, and advanced tenancy controls
- **DKIM Signing** - Generate keys and sign outbound emails
- **TLS Support** - HTTPS, SMTP STARTTLS, and IMAPS
- **Email Queue** - Persistent queue with exponential backoff retries
- **Webhooks** - Notify external services on email events
- **SQLite Storage** - Lightweight, file-based storage
- **Systemd Integration** - Run as a system service

## Core Contract

Lightr is a mail engine, not a mail product.

Lightr owns:

- SMTP, IMAP, relay, queueing, storage, and DKIM
- domains, accounts, aliases, auth, API keys, permissions, and operator APIs
- DNS/TLS guidance, spam handling, and webhooks as integration primitives

Lightr does not own:

- templates and rendering
- open/click tracking
- unsubscribe UX
- campaigns, marketing automation, mailing lists, autoresponders
- CalDAV, CardDAV, or other app-layer product features

The detailed scope contract lives in [docs/CORE.md](C:/Users/User/mydev/lightr/docs/CORE.md).

## Installation

### Installer Script

```bash
curl -fsSL https://lightr.nigelbasa.tech/install.sh | sudo bash -s -- example.com
```

The installer downloads the latest Linux release binary, creates the `lightr`
service account, installs a systemd unit, runs `lightr init`, and leaves the
instance ready for config review at `/etc/lightr/config.yaml`. Add `--start`
if you want it to bring the service up immediately after install. If your
public mail host should differ from the simple default, pass
`--mail-hostname mail.example.com` during install and reuse that value when you
create the first domain.

### From Package (Debian/Ubuntu)

```bash
# Download the latest release
wget https://github.com/nigelbasa/lightr/releases/download/v0.1.0/lightr_0.1.0_amd64.deb

# Install
sudo dpkg -i lightr_0.1.0_amd64.deb

# Initialize (generates API key)
sudo lightr init --hostname mail.example.com
sudo chown -R lightr:lightr /var/lib/lightr
sudo chown root:lightr /etc/lightr/config.yaml
sudo chmod 640 /etc/lightr/config.yaml

# Start the service
sudo systemctl start lightr
sudo systemctl enable lightr
```

### From Source

```bash
# Clone
git clone https://github.com/nigelbasa/lightr.git
cd lightr

# Build
go build -o lightr ./cmd/lightr

# Build release targets
make build-linux
make build-windows

# Initialize
./lightr init

# Run
./lightr serve
```

### Windows Binary

```powershell
Invoke-WebRequest -Uri https://github.com/nigelbasa/lightr/releases/latest/download/lightr-windows-amd64.exe -OutFile lightr.exe
.\lightr.exe version
```

### Using Docker

```bash
docker pull ghcr.io/nigelbasa/lightr:latest
docker run -p 8080:8080 -p 2525:2525 -p 1143:1143 -v lightr-data:/app/data ghcr.io/nigelbasa/lightr
```

## Quick Start (CLI)

```bash
# 1. Initialize installation
lightr init --hostname mail.example.com

# 2. Add the email domain and its public mail host
lightr domain create --name example.com --mail-hostname mail.example.com --spam-policy junk

# 3. Create an email account
lightr account create --domain example.com --email user@example.com --password secret123

# 4. Start the server
lightr serve
```

## Domain DNS

Lightr provides recommended DNS records per domain, including `MX`, `SPF`, `DKIM`, and `DMARC`, plus `PTR` guidance.

```bash
lightr domain dns example.com
lightr domain verify example.com
```

Important:

- Lightr generates and verifies the records, but it does not publish them to your DNS provider for you.
- Domain verification requires `MX`, `SPF`, `DKIM`, and `DMARC`.
- `PTR` is shown and checked, but it is not currently required for domain verification.

The generated DMARC recommendation is domain-specific. Today the default recommendation is:

```txt
_dmarc.example.com IN TXT "v=DMARC1; p=quarantine; adkim=s; aspf=s"
```

## Default Ports

| Service | Port | Notes |
|---------|------|-------|
| HTTP API | 8080 | REST API for management |
| SMTP | 2525 | Use 25 in production (requires root) |
| IMAP | 1143 | Use 143/993 in production |

## Configuration

Config file at `/etc/lightr/config.yaml` (system) or `./lightr.yaml` (local). The active schema is also reflected in [lightr.yaml.example](C:/Users/User/mydev/lightr/lightr.yaml.example), [config/config.minimal.yaml](C:/Users/User/mydev/lightr/config/config.minimal.yaml), [config/production.sqlite.yaml](C:/Users/User/mydev/lightr/config/production.sqlite.yaml), and [config/production.postgres.yaml](C:/Users/User/mydev/lightr/config/production.postgres.yaml).

You can generate a production sample directly:

```bash
lightr config sample --profile sqlite --prod --output /etc/lightr/config.yaml
lightr config sample --profile postgres --prod --output /etc/lightr/config.yaml
```

`server.hostname` is now the canonical SMTP banner/EHLO identity. Domain-specific public mail identity belongs on each domain’s `mail_hostname`.

```yaml
data_dir: ./data

database:
  driver: sqlite
  path: ./data/lightr.db

http:
  addr: ":8080"

api:
  admin_key: "CHANGE_ME"

smtp:
  addr: ":2525"
  submission_addr: ":587"
  allow_insecure: false  # Set to false in production

imap:
  addr: ":1143"
  allow_insecure: false  # Set to false in production

dkim:
  selector: "default"
  key_bits: 2048
```

## Native Logs

Lightr writes native structured logs to `logging.file` in addition to whatever your service manager captures.

Common commands:

```bash
lightr logs show
lightr logs show --since 1h --tail 200
lightr logs show --domain example.com
lightr logs show --level error --component smtp
lightr logs clear --older-than 7d
lightr logs clear --domain example.com
lightr logs clear --all
```

Notes:

- `logs show` reads the native log file, not the systemd journal.
- On Linux, if the native file is missing, Lightr will point you at `journalctl -u lightr`.
- Domain filtering is substring-based against the structured log lines, which works well for domain names and email addresses already present in the log stream.

## API Endpoints

### Domains

```bash
# Create a domain
curl -X POST http://localhost:8080/v1/domains \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "mail_hostname": "mail.example.com"}'
```

### Accounts

```bash
# Create an account
curl -X POST http://localhost:8080/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "email": "user@example.com",
    "auth_mode": "native",
    "password": "secret",
    "quota_bytes": 1073741824
  }'

# Get account
curl http://localhost:8080/v1/accounts/{id}
```

### Send Email

```bash
curl -X POST http://localhost:8080/v1/send \
  -H "Content-Type: application/json" \
  -d '{
    "from": "user@yourdomain.com",
    "to": "recipient@example.com",
    "subject": "Hello",
    "body": "Hello World!"
  }'
```

## DKIM Setup

1. Generate DKIM keys:

```go
keyPair, err := smtp.GenerateDKIMKey(2048, "default")
// keyPair.PrivateKeyPEM - Save this securely
// keyPair.PublicKeyDNS - Add this as a TXT record
```

2. Add DNS TXT record:
   - Name: `default._domainkey.yourdomain.com`
   - Value: `v=DKIM1; k=rsa; p=<public key>`

3. Configure the relay with the private key:

```go
relay.AddDKIMSigner("yourdomain.com", "default", privateKeyPEM)
```

## Architecture

```
cmd/lightr/          - Main entry point
internal/
  api/               - REST API handlers
  auth/              - Authentication service
  config/            - YAML configuration
  domain/            - Domain models and interfaces
  imap/              - IMAP server implementation
  smtp/              - SMTP server, relay, and DKIM
  storage/           - SQLite storage implementation
  webhook/           - Webhook notification service
```

## Database Schema

Lightr uses SQLite with the following tables:

- `organizations` - Internal tenancy boundary for advanced multi-tenant scoping
- `domains` - Email domains with DKIM configuration
- `accounts` - Email accounts with auth settings
- `messages` - Email metadata and storage paths

## Auth Modes

- **native** - Password stored as bcrypt hash in database
- **offloaded** - Authentication delegated to external HTTP service

## Production Considerations

1. **TLS** - Configure TLS certificates for SMTP/IMAP
2. **Ports** - Use standard ports (25, 143, 993) with proper permissions
3. **Mail hostname** - Keep the runtime hostname and each domain `mail_hostname` aligned with the public MX/TLS identity you actually publish
4. **SPF/DMARC** - Configure DNS records for email deliverability
5. **Reverse DNS** - Set up PTR record for your mail server IP
5. **Spam** - Configure `spam_policy` per domain and wire DNSBL/Rspamd if used
6. **Rate Limiting** - Implement rate limiting for outbound emails
7. **Monitoring** - Add metrics and logging for production monitoring

For the full deployment checklist and systemd example, see [docs/DEPLOYMENT.md](C:/Users/User/mydev/lightr/docs/DEPLOYMENT.md).

## Documentation Site

The repository includes a separate Next.js docs app in [`docs-site`](C:/Users/User/mydev/lightr/docs-site).

- Run it locally with `cd docs-site && npm install && npm run dev`
- The public installer is published from `docs-site/public/install.sh`
- That file is synced automatically from the repo-root [`quickstart.sh`](C:/Users/User/mydev/lightr/quickstart.sh) before `dev` and `build`

## License

MIT License
