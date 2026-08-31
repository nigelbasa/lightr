# Core Contract

Lightr is a mail engine and operator surface.

## What Lightr Owns

- SMTP receive, SMTP submission, outbound relay, and DKIM signing
- IMAP mailbox access
- Domains, accounts, aliases, org/domain/account scoping
- Queueing, retries, storage, and backup/export basics
- Authentication, API keys, permissions, and offloaded-auth plumbing
- DNS/TLS/mail identity guidance for operators
- Spam handling and mailbox-side classification feedback
- Webhooks as an integration primitive
- CLI and HTTP API for operator control

## What Lightr Does Not Own

- Email templates and rendering
- Open/click tracking
- Unsubscribe UX and one-click unsubscribe flows
- Campaign analytics and marketing automation
- Mailing lists, autoresponders, groupware, CalDAV, or CardDAV
- App-specific end-user features built on top of mail transport and storage

Those belong in applications built on top of Lightr, not in the engine itself.

## Domain DNS Contract

Lightr generates recommended DNS records per domain and verifies what you publish:

- MX
- SPF
- DKIM
- DMARC
- PTR guidance

CLI:

```bash
lightr domain dns example.com
lightr domain verify example.com
```

HTTP API:

- `GET /v1/domains/{id}/dns`
- `POST /v1/domains/{id}/verify`

Important:

- Lightr does not push records into your DNS provider.
- Lightr shows you the records to publish and verifies the live DNS state afterward.
- Domain verification currently requires `MX`, `SPF`, `DKIM`, and `DMARC` to be present and valid.
- `PTR` is reported as guidance, but it is not currently required to mark a domain verified.

## DMARC

Yes, DMARC is part of the per-domain DNS flow.

Today Lightr generates a recommended DMARC record like:

```txt
_dmarc.example.com IN TXT "v=DMARC1; p=quarantine; adkim=s; aspf=s"
```

That recommendation is domain-specific and is available through `lightr domain dns <domain>` and the domain DNS API response.

If you want a different DMARC policy such as `p=none` or `p=reject`, that is still an operator DNS decision today rather than a persisted per-domain policy setting inside Lightr.
