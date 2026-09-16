# Building a mail client on Lightr

Two ways in, and a client can use either or both:

- **IMAP and SMTP**, served by Dovecot and Lightr. Any existing mail
  app works with these unchanged.
- **The mailbox API**, `/v1/mailbox/*`. For a web or mobile client that
  would rather speak JSON than IMAP.

They are the same mailbox. The API reads and writes through Dovecot
over IMAP, so a flag set in one shows up in the other straight away.

---

## Standard mail apps

| | Server | Port | Security | Login |
| --- | --- | --- | --- | --- |
| Incoming (IMAP) | `mail.example.com` | 993 | TLS | full address + password |
| Incoming (IMAP) | `mail.example.com` | 143 | STARTTLS | full address + password |
| Outgoing (SMTP) | `mail.example.com` | 587 | STARTTLS | full address + password |

Port 25 is for other servers delivering mail, not for clients.
Submission refuses a password sent without TLS. Where each connection
is encrypted is covered in [DEPLOY.md](DEPLOY.md#where-encryption-terminates).

What a client gets over IMAP:

| | |
| --- | --- |
| Folders | Sent, Drafts, Trash, Junk and Archive exist in every mailbox and are subscribed, with the special-use flags clients use to find them. |
| Quota | `GETQUOTAROOT` works, so a client can show how full the mailbox is. |
| Trash and Junk | Emptied automatically after 30 days. |
| Flags | Seen, Flagged, Answered, Draft, Deleted, and custom keywords. |
| Push | `IDLE`. |
| Connections | Up to 20 per user per address. |

When a client sends through port 587, it saves its own copy to Sent
over IMAP, as with any server. The server does not.

### Configuring itself

A mail app can find all of the above from the address alone, once the
domain publishes the records for it:

```bash
lightr domain dns example.com --optional
```

That adds `autoconfig` and `autodiscover` CNAMEs and the two SRV
records to the ones a domain already needs. Lightr then serves the XML
each client asks for — Mozilla `config-v1.1.xml` for Thunderbird,
Autodiscover for Outlook — over HTTPS, without a key, because a client
has none until it knows where to connect.

These records are optional. Mail is delivered without them, and
`lightr domain verify` does not require them; without them, a client
is set up by typing the table above in by hand.

## The mailbox API

### Signing in

A client signs in with the mailbox's own address and password, checked
the same way IMAP and SMTP check them:

```http
POST /v1/auth/session
{"email": "you@example.com", "password": "..."}

201 {"token": "...", "token_type": "Bearer", "expires_at": "2026-10-16T...Z",
     "session_id": "...", "account": {"email": "you@example.com", "display_name": "You"}}
```

Send the token as `Authorization: Bearer <token>`. It lasts 30 days,
reaches this one mailbox and nothing else, and is sent with nothing to
choose between mailboxes, so it cannot be pointed at another.

| | |
| --- | --- |
| `401` | Wrong address or password. The same answer for a mailbox that does not exist or is disabled. |
| `429` | Too many attempts, from this address or at this mailbox. Honour `Retry-After`. A successful sign-in resets the count. |
| `503` | The organization's identity provider did not answer. Not a wrong password: try again. |

| Endpoint | |
| --- | --- |
| `DELETE /v1/mailbox/session` | Sign out: this token stops working. |
| `GET /v1/mailbox/sessions` | Devices signed in: created, last used, address, user agent, and which one is `current`. |
| `DELETE /v1/mailbox/sessions/{id}` | Sign another device out. |
| `POST /v1/mailbox/password` | `{"current_password", "new_password"}`. Signs every other device out and clears Dovecot's cached login, so the old password stops working over IMAP too. `409` for a mailbox whose password lives with an identity provider. |

An operator can still make a long-lived key for a script or an
integration, and the mailbox API accepts it the same way:

```bash
lightr apikey create --type account --account you@example.com
```

Org and admin keys are refused here. Put the API behind a TLS proxy
([DEPLOY.md](DEPLOY.md#where-encryption-terminates)).

Errors come back as `{"error": "..."}`. A `400` is the request's fault
(including a folder Dovecot will not accept), a `404` is a missing
message or rule, a `429` carries `Retry-After`, and a `502` means the
mail store could not be reached.

### Reading

| | |
| --- | --- |
| `GET /v1/mailbox` | Address, display name, quota, and inbox counts. |
| `GET /v1/mailbox/folders` | Every folder with message, unseen and UIDVALIDITY counts. |
| `GET /v1/mailbox/messages?folder=&limit=&offset=` | Newest first. Filters: `unread`, `flagged`, `from`, `to`, `subject`, `text`, `since`, `before` (dates as `YYYY-MM-DD`). `limit` is capped at 200. |
| `GET /v1/mailbox/threads?folder=&limit=&offset=` | The same messages grouped into conversations, most recently active first. Takes the same filters. `limit` counts threads, capped at 100. |
| `GET /v1/mailbox/messages/{uid}?folder=` | Headers, text, HTML and attachment list. |
| `GET /v1/mailbox/messages/{uid}/attachments/{index}?folder=` | The attachment's bytes. |

Messages are identified by IMAP UID within a folder. A UID stays valid
while the folder's `uidvalidity` is unchanged, so a client that caches
should store both.

A thread looks like this, and carries its messages so a conversation
list needs one request:

```json
{
  "uid": 41, "uids": [41, 44, 47], "count": 3,
  "folder": "INBOX", "subject": "Invoice 42",
  "participants": ["Billing <billing@example.com>", "You <you@example.com>"],
  "date": "2026-09-14T11:02:00+00:00",
  "unseen": 1, "flagged": false, "size": 18422,
  "messages": [ ... ]
}
```

Dovecot does the grouping, by `References` and `In-Reply-To`, so the
threads match what a desktop mail app shows for the same mailbox.
`uid` is the conversation's oldest message, and identifies it. Paging
counts threads, never messages, so a conversation is never split
across two pages.

### Changing messages

| | |
| --- | --- |
| `PATCH /v1/mailbox/messages/{uid}?folder=` | `{"read", "flagged", "answered", "draft": true/false, "folder": "Archive"}`. Any combination; `folder` moves the message. Flags must be real booleans. |
| `DELETE /v1/mailbox/messages/{uid}?folder=` | Moves to Trash. `?purge=1`, or deleting something already in Trash, removes it for good. |
| `POST /v1/mailbox/messages/bulk` | `{"folder": "INBOX", "uids": [...], "read": true, "move_to": "Archive"}` or `{"uids": [...], "delete": true}` or `{"uids": [...], "purge": true}`. Up to 1000 UIDs. Flags are applied before a move or delete. |

### Folders

| | |
| --- | --- |
| `POST /v1/mailbox/folders` | `{"name": "Receipts/2026"}`. `/` makes a subfolder. |
| `PATCH /v1/mailbox/folders/{name}` | `{"name": "new name"}`. |
| `DELETE /v1/mailbox/folders/{name}` | |
| `POST /v1/mailbox/folders/Trash/empty` | Also `Junk`. Returns `{"removed": n}`. No other folder can be emptied this way; use bulk `purge`. |

INBOX, Sent, Drafts, Trash, Junk and Archive cannot be renamed or
deleted. Lightr files mail into them by name.

### Live updates

`wss://mail.example.com/v1/mailbox/events` pushes what IMAP's `IDLE`
pushes, as JSON. One socket watches one folder, INBOX until told
otherwise, and a mailbox may hold five at once.

Authenticate with `Authorization: Bearer <token>` where the client can
set headers. A browser cannot, so the first message may carry the token
instead -- within ten seconds, and never in the query string, which ends
up in the proxy's access log:

```json
{"token": "..."}
```

The server then sends:

```json
{"type": "ready", "mailbox": "you@example.com", "folder": "INBOX",
 "folders": [{"name": "INBOX", "messages": 12, "unseen": 3, "uidvalidity": 1}]}

{"type": "update", "folder": "INBOX",
 "new": [{"uid": 41, "subject": "...", "from": "...", "seen": false}],
 "changed": [{"uid": 38, "seen": true}],
 "removed": [37],
 "status": {"name": "INBOX", "messages": 13, "unseen": 4, "uidvalidity": 1}}

{"type": "heartbeat"}
```

`changed` carries a message whose flags changed; `removed` carries UIDs
that left the watched window of the newest 50 messages. Send
`{"type": "watch", "folder": "Sent"}` to follow another folder (a fresh
`ready` follows), `{"type": "refresh"}` to ask for the current state, and
`{"type": "ping"}` for a `{"type": "pong"}`.

Close codes: `4401` the token was missing, wrong or expired, `4403` the
key does not open a mailbox, `4429` too many sockets for this mailbox.

### Writing and sending

Both endpoints below take a message as JSON:

```json
{
  "to": ["friend@example.net"],
  "cc": [], "bcc": [],
  "subject": "Hello",
  "text": "Plain body",
  "html": "<p>Optional HTML body</p>",
  "in_reply_to": "<original@message.id>",
  "references": "<original@message.id>"
}
```

Or they take a whole message as `{"raw": "<RFC 5322 text>"}` when the
client builds its own MIME, for example to attach files. With `raw`,
`POST /send` addresses whoever is in To, Cc and Bcc, unless a
`recipients` list is given. The limit is 25 MB.

| | |
| --- | --- |
| `POST /v1/mailbox/drafts` | Saves to Drafts. Pass `"replace": <uid>` to swap out the previous save, which is stored before the old copy is removed. |
| `POST /v1/mailbox/send` | Sends and files a copy in Sent. Pass `"reply_to": {"folder": "INBOX", "uid": 42}` to mark the original answered. `"from"` may be an alias that delivers to this mailbox. Returns `202` with `queued`, `rejected` and `saved_to_sent`. |

Sending takes the same path as port 587: the same check on who may send
as which address, the same queue, and the same DKIM signing. It is
refused (`403`) when the account has been blocked from sending, or when
`from` is not an address this mailbox owns. Bcc recipients get the
mail, but the Bcc header is stripped from what goes out; it stays in
the Sent copy. If the mail went out but could not be filed in Sent, the
response still says `202`, with `saved_to_sent: false`. Do not retry
it: the mail has already been sent.

### Forwarding

| | |
| --- | --- |
| `GET /v1/mailbox/forwarding` | `{"enabled", "destinations", "keeps_copy", "replies_routed"}` |
| `PUT /v1/mailbox/forwarding` | `{"destinations": ["me@gmail.com"]}`. Up to 10. |
| `DELETE /v1/mailbox/forwarding` | Stops forwarding. |

A copy is always kept in the mailbox. Forwarded mail is sent from this
server's domain so it passes SPF at the other end. Spam is not
forwarded. A reply written from a destination goes back to the
original sender from this mailbox's address, with nothing in it showing
where it was forwarded.

### Filters

Rules run on delivery, compiled to Sieve.

| | |
| --- | --- |
| `GET /v1/mailbox/filters` | All rules, by priority. |
| `POST /v1/mailbox/filters` | Create; see the shape below. |
| `GET` / `PATCH` / `DELETE /v1/mailbox/filters/{id}` | `PATCH` changes only the fields given. |
| `GET /v1/mailbox/filters/script` | The compiled Sieve, as text. |

```json
{
  "name": "Receipts",
  "priority": 10,
  "match_type": "all",
  "conditions": [
    {"field": "from", "operator": "contains", "value": "bank.example"}
  ],
  "actions": [
    {"type": "file_into", "value": "Receipts"},
    {"type": "mark_read"}
  ],
  "stop_on_match": true,
  "is_active": true
}
```

| | |
| --- | --- |
| Fields | `from`, `to`, `cc`, `subject`, `body`, `header` (with `"header": "X-Name"`), `attachment`, `size`, `spam_score`, `spf_result`, `dkim_result`, `dmarc_result` |
| Operators | `equals`, `contains`, `starts_with`, `ends_with`, `matches` (glob), `gt`, `lt` |
| Actions | `file_into`, `mark_read`, `flag`, `discard`, `reject`, `stop` |

Rules are compiled before they are stored, so a rule that will not
compile is refused with a `400`. Each change is installed before the
response comes back. If Dovecot will not accept the result, the change
is undone. `redirect` is not available; use forwarding.

---

## Not provided

Worth knowing before designing around any of these:

| | |
| --- | --- |
| ManageSieve (:4190) | Filters are managed through the API. A script uploaded some other way is overwritten the next time the rules change. |
| JMAP, CalDAV, CardDAV | Mail only. |
| SRV-only discovery | The SRV records are published, but a client that reads *only* SRV still asks the user for a username. Autoconfig and Autodiscover carry that. |
| Server-side Sent copies | A client saves its own copy over IMAP, as with any server. |
