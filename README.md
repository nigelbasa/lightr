# Lightr

A lightweight, embeddable email server written in Go. Lightr provides SMTP (inbound/outbound), IMAP, and a REST API for managing email domains, accounts, and templates.

## Features

- **SMTP Server** - Receive and store incoming emails with MIME parsing
- **SMTP Relay** - Send outbound emails with DKIM signing
- **IMAP Server** - Allow email clients to access mailboxes
- **REST API** - Manage organizations, domains, accounts, and templates
- **DKIM Signing** - Generate keys and sign outbound emails
- **TLS Support** - HTTPS, SMTP STARTTLS, and IMAPS
- **Email Queue** - Persistent queue with exponential backoff retries
- **Webhooks** - Notify external services on email events
- **Email Tracking** - Track opens and clicks with pixel/redirect tracking
- **SQLite Storage** - Lightweight, file-based storage
- **Systemd Integration** - Run as a system service

## Installation

### From Package (Debian/Ubuntu)

```bash
# Download the latest release
wget https://github.com/nigelbasa/lightr/releases/download/v0.1.0/lightr_0.1.0_amd64.deb

# Install
sudo dpkg -i lightr_0.1.0_amd64.deb

# Initialize (generates API key)
sudo -u lightr lightr init --config /etc/lightr/lightr.yaml --data-dir /var/lib/lightr

# Start the service
sudo systemctl start lightr
sudo systemctl enable lightr
```

### From Source

```bash
# Build
go build -o lightr ./cmd/lightr

# Initialize
./lightr init

# Run
./lightr serve
```

### Using Docker

```bash
docker pull ghcr.io/nigelbasa/lightr:latest
docker run -p 8080:8080 -p 2525:2525 -p 1143:1143 -v lightr-data:/app/data ghcr.io/nigelbasa/lightr
```

## Quick Start (CLI)

```bash
# 1. Initialize installation
lightr init

# 2. Create an organization
lightr add-org --name "My Company"
# Output: Created organization: 6b20632d-571e-43c6-ab7c-bbd6934ae5b8

# 3. Add a domain
lightr add-domain --org 6b20632d-571e-43c6-ab7c-bbd6934ae5b8 --name mail.example.com
# Output: Created domain: 3120d2e0-dba8-4335-ab5d-6485696090a1

# 4. Generate DKIM keys
lightr dkim-gen --domain mail.example.com
# Output: Add this TXT record to DNS: default._domainkey.mail.example.com

# 5. Generate TLS certificate (dev only)
lightr tls-gen --domain mail.example.com

# 6. Create an email account
lightr add-account --domain 3120d2e0-dba8-4335-ab5d-6485696090a1 --email user@mail.example.com

# 7. Start the server
lightr serve
```

## Default Ports

| Service | Port | Notes |
|---------|------|-------|
| HTTP API | 8080 | REST API for management |
| SMTP | 2525 | Use 25 in production (requires root) |
| IMAP | 1143 | Use 143/993 in production |

## Configuration

Config file at `/etc/lightr/lightr.yaml` (system) or `./lightr.yaml` (local):

```yaml
data_dir: ./data

http:
  addr: ":8080"

smtp:
  addr: ":2525"
  domain: "mail.yourdomain.com"
  allow_insecure: false  # Set to false in production

imap:
  addr: ":1143"
  allow_insecure: false  # Set to false in production

dkim:
  selector: "default"
  key_bits: 2048
```

## API Endpoints

### Domains

```bash
# Create a domain
curl -X POST http://localhost:8080/domains \
  -H "Content-Type: application/json" \
  -d '{"org_id": "uuid", "name": "example.com"}'
```

### Accounts

```bash
# Create an account
curl -X POST http://localhost:8080/accounts \
  -H "Content-Type: application/json" \
  -d '{
    "domain_id": "uuid",
    "local_part": "user",
    "auth_mode": "native",
    "password": "secret",
    "quota_bytes": 1073741824
  }'

# Get account
curl http://localhost:8080/accounts/{id}
```

### Send Email

```bash
curl -X POST http://localhost:8080/send \
  -H "Content-Type: application/json" \
  -d '{
    "from": "user@yourdomain.com",
    "to": "recipient@example.com",
    "subject": "Hello",
    "body": "Hello World!"
  }'
```

### Tracking

- **Open tracking**: `GET /track/open/{msg_id}` - Returns 1x1 transparent GIF
- **Click tracking**: `GET /track/click/{msg_id}?url=https://...` - Redirects to URL

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
  tracking/          - Email open/click tracking
  webhook/           - Webhook notification service
```

## Database Schema

Lightr uses SQLite with the following tables:

- `organizations` - Multi-tenant organization support
- `domains` - Email domains with DKIM configuration
- `accounts` - Email accounts with auth settings
- `messages` - Email metadata and storage paths
- `templates` - Email templates for rendering
- `tracking_events` - Open and click tracking data

## Auth Modes

- **native** - Password stored as bcrypt hash in database
- **offloaded** - Authentication delegated to external HTTP service

## Production Considerations

1. **TLS** - Configure TLS certificates for SMTP/IMAP
2. **Ports** - Use standard ports (25, 143, 993) with proper permissions
3. **SPF/DMARC** - Configure DNS records for email deliverability
4. **Reverse DNS** - Set up PTR record for your mail server IP
5. **Rate Limiting** - Implement rate limiting for outbound emails
6. **Monitoring** - Add metrics and logging for production monitoring

## License

MIT License
