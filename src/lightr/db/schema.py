"""Database schema, as SQLAlchemy Core tables.

Column names and types deliberately match the Go engine's schema so an
existing database opens unchanged. Where the Dovecot migration changes
ownership of a field, the column is kept but annotated -- dropping it
would break reading a database written by ``v0.1.0-go-final``.

Three tables from the Go schema are intentionally absent:

``messages``
    Dovecot owns the message store. Mailbox reads go through IMAP.
``encryption_keys`` / ``encrypted_messages``
    Replaced by Dovecot's ``mail_crypt`` plugin.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)

metadata = MetaData()

# The Go engine stores UUIDs as their string form in TEXT columns.
UUID = String(36)


def _created_at(name: str = "created_at", *, nullable: bool = False) -> Column:
    return Column(name, DateTime, nullable=nullable, server_default=func.current_timestamp())


# --------------------------------------------------------------------
# Tenancy: organizations -> domains -> accounts
# --------------------------------------------------------------------

organizations = Table(
    "organizations",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("name", Text, nullable=False),
    _created_at(),
)

domains = Table(
    "domains",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("org_id", UUID, ForeignKey("organizations.id"), nullable=False),
    Column("name", Text, nullable=False, unique=True),
    Column("mail_hostname", Text),
    Column("dkim_private_key", Text),
    Column("dkim_selector", Text),
    Column("webhook_url", Text),
    Column("auth_webhook_url", Text),
    Column("auth_webhook_secret", Text),
    Column("auth_webhook_verified", Boolean, server_default="0"),
    Column("auth_webhook_verified_at", DateTime),
    Column("tls_cert_file", Text),
    Column("tls_key_file", Text),
    Column("relay_enabled", Boolean, server_default="0"),
    Column("relay_host", Text),
    Column("relay_port", Integer),
    Column("relay_username", Text),
    Column("relay_password", Text),
    Column("relay_use_tls", Boolean, server_default="0"),
    Column("relay_tls_skip_verify", Boolean, server_default="0"),
    Column("spam_policy", Text, server_default="junk"),
    Column("is_verified", Boolean, server_default="0"),
    _created_at(),
)

accounts = Table(
    "accounts",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("domain_id", UUID, ForeignKey("domains.id"), nullable=False),
    Column("local_part", Text, nullable=False),
    Column("display_name", Text),
    Column("auth_mode", Text, nullable=False),
    Column("password_hash", Text),
    Column("external_id", Text),
    # BigInteger, not Integer: a 2 GB quota is 2147483648, one past the
    # top of a signed 32-bit column. SQLite stores it anyway because its
    # typing is dynamic; Postgres refuses the insert outright, so the
    # narrower type only ever fails on a real deployment.
    Column("quota_bytes", BigInteger),
    # Dovecot's quota plugin is authoritative for usage; this column is
    # retained for compatibility with Go-written databases and is no
    # longer maintained by Lightr.
    Column("used_bytes", BigInteger, server_default="0"),
    # Added by the Dovecot migration: where this account's Maildir lives.
    Column("maildir_path", Text),
    # Independent of auth_mode, which says *how* an account logs in. A
    # compromised account needs to stop sending while its owner can
    # still log in and read what arrived; a departed employee's mailbox
    # stops receiving while someone reads the backlog. `disabled` does
    # neither -- it blocks everything at once.
    Column("can_send", Boolean, nullable=False, server_default="1"),
    Column("can_receive", Boolean, nullable=False, server_default="1"),
    _created_at(),
    UniqueConstraint("domain_id", "local_part"),
    Index("idx_accounts_email", "domain_id", "local_part"),
)

# --------------------------------------------------------------------
# Aliases and bridge reply routing
# --------------------------------------------------------------------

aliases = Table(
    "aliases",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("domain_id", UUID, nullable=False),
    Column("source", Text, nullable=False),
    Column("destinations", Text, nullable=False),  # JSON array
    Column("type", Text, nullable=False, server_default="forward"),
    Column("is_active", Boolean, nullable=False, server_default="1"),
    _created_at(),
    _created_at("updated_at"),
    UniqueConstraint("domain_id", "source"),
)

alias_reply_routes = Table(
    "alias_reply_routes",
    metadata,
    Column("token", Text, primary_key=True),
    Column("alias_id", UUID, nullable=False),
    # Nullable: a plain forward has no mailbox of its own, and its token
    # exists only so the forward's envelope sender is on our domain.
    Column("account_id", UUID),
    Column("domain_id", UUID),
    Column("local_address", Text, nullable=False),
    Column("bridge_destinations", Text, nullable=False),
    Column("original_from", Text, nullable=False),
    Column("original_to", Text),
    Column("original_cc", Text),
    # bridge: replies are relayed. forward: only bounces come back.
    Column("kind", Text, nullable=False, server_default="bridge"),
    _created_at(),
    Index("idx_alias_reply_routes_created", "created_at"),
)

# --------------------------------------------------------------------
# API keys
# --------------------------------------------------------------------

api_keys = Table(
    "api_keys",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("name", Text, nullable=False),
    Column("description", Text),
    Column("prefix", Text, nullable=False),
    Column("key_hash", Text, nullable=False, unique=True),
    Column("organization_id", UUID),
    Column("domain_id", UUID),
    Column("account_id", UUID),
    Column("user_id", UUID),
    Column("type", Text, nullable=False),
    Column("permissions", Text, nullable=False),  # JSON array
    Column("allowed_ips", Text),
    Column("allowed_domains", Text),
    Column("rate_limit", Integer, server_default="1000"),
    Column("daily_limit", Integer, server_default="100000"),
    Column("active", Boolean, server_default="1"),
    Column("expires_at", DateTime),
    Column("last_used_at", DateTime),
    Column("last_used_ip", Text),
    Column("usage_count", Integer, server_default="0"),
    Column("usage_today", Integer, server_default="0"),
    Column("metadata", Text),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
    Index("idx_api_keys_hash", "key_hash"),
    Index("idx_api_keys_prefix", "prefix"),
    Index("idx_api_keys_org", "organization_id"),
    Index("idx_api_keys_domain", "domain_id"),
    Index("idx_api_keys_account", "account_id"),
)

api_key_usage = Table(
    "api_key_usage",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("key_id", UUID, ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False),
    Column("endpoint", Text, nullable=False),
    Column("method", Text, nullable=False),
    Column("status", Integer, nullable=False),
    Column("ip", Text),
    Column("user_agent", Text),
    Column("duration_ms", Integer),
    Column("timestamp", DateTime, nullable=False),
    Index("idx_api_key_usage_key", "key_id"),
    Index("idx_api_key_usage_time", "timestamp"),
)

# --------------------------------------------------------------------
# Offloaded authentication
# --------------------------------------------------------------------

auth_providers = Table(
    "auth_providers",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("org_id", UUID, nullable=False),
    Column("name", Text, nullable=False),
    Column("provider", Text, nullable=False),  # ldap | oauth2 | oidc | webhook | radius
    Column("enabled", Boolean, server_default="1"),
    Column("priority", Integer, server_default="100"),
    Column("config", Text, nullable=False),  # JSON
    Column("domains", Text),
    Column("is_default", Boolean, server_default="0"),
    Column("auto_provision", Boolean, server_default="0"),
    Column("sync_groups", Boolean, server_default="0"),
    Column("sync_profile", Boolean, server_default="0"),
    _created_at(),
    _created_at("updated_at"),
    UniqueConstraint("org_id", "name"),
)

# --------------------------------------------------------------------
# Outbound: queue, bounces, suppression
# --------------------------------------------------------------------

email_queue = Table(
    "email_queue",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("org_id", UUID, nullable=False),
    Column("domain_id", UUID, nullable=False),
    Column("from_addr", Text, nullable=False),
    Column("to_addrs", Text, nullable=False),  # JSON array
    Column("subject", Text, nullable=False),
    Column("body", Text, nullable=False),
    Column("html_body", Text),
    Column("headers", Text),
    # The message exactly as it should leave, when there is one. Mail
    # submitted by a client or forwarded from outside already has its
    # MIME structure, attachments and headers; rebuilding it from
    # subject and body threw all of that away. Null for messages that
    # really are just a subject and a body, which still compose.
    Column("raw", LargeBinary),
    # The SMTP envelope sender, when it differs from the From header --
    # a forward rewritten with SRS, so the destination's SPF check sees
    # a domain that authorises this server.
    Column("envelope_from", Text),
    Column("status", Text, nullable=False, server_default="pending"),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("max_attempts", Integer, nullable=False, server_default="5"),
    Column("last_error", Text),
    Column("next_retry", DateTime, nullable=False),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
    Column("delivered_at", DateTime),
    Index("idx_email_queue_status_retry", "status", "next_retry"),
)

bounces = Table(
    "bounces",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("org_id", UUID, nullable=False),
    Column("domain_id", UUID, nullable=False),
    Column("original_msg_id", Text),
    Column("recipient_email", Text, nullable=False),
    Column("bounce_type", Text, nullable=False),  # hard | soft | complaint
    Column("diagnostic_code", Text),
    Column("remote_mta", Text),
    _created_at(),
    Index("idx_bounces_recipient", "recipient_email"),
)

suppression_list = Table(
    "suppression_list",
    metadata,
    Column("email", Text, primary_key=True),
    Column("reason", Text, nullable=False),
    Column("org_id", UUID),
    _created_at(),
)

# --------------------------------------------------------------------
# Filters -> Sieve
# --------------------------------------------------------------------

filter_rules = Table(
    "filter_rules",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("org_id", UUID, nullable=False),
    Column("account_id", UUID),
    Column("name", Text, nullable=False),
    Column("description", Text),
    Column("priority", Integer, server_default="100"),
    Column("conditions", Text, nullable=False),  # JSON
    Column("match_type", Text, server_default="all"),
    Column("actions", Text, nullable=False),  # JSON
    Column("is_active", Boolean, server_default="1"),
    Column("stop_on_match", Boolean, server_default="0"),
    # Added by the Dovecot migration: when this rule was last compiled
    # into the account's Sieve script.
    Column("sieve_generated_at", DateTime),
    _created_at(),
    _created_at("updated_at"),
    Index("idx_filter_rules_account", "account_id"),
)

# --------------------------------------------------------------------
# Permissions
# --------------------------------------------------------------------

permission_policies = Table(
    "permission_policies",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("name", Text, nullable=False),
    Column("description", Text),
    Column("user_id", UUID),
    Column("role_id", UUID),
    Column("group_id", UUID),
    Column("operations", Text, nullable=False),  # JSON array
    Column("effect", Text, nullable=False),  # allow | deny
    Column("conditions", Text),
    Column("priority", Integer, server_default="0"),
    Column("active", Boolean, server_default="1"),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
)

sudo_sessions = Table(
    "sudo_sessions",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("user_id", UUID, nullable=False),
    Column("level", Integer, nullable=False),
    Column("mfa_verified", Boolean, server_default="0"),
    Column("remote_ip", Text),
    Column("reason", Text),
    Column("created_at", DateTime, nullable=False),
    Column("expires_at", DateTime, nullable=False),
    Column("last_used_at", DateTime, nullable=False),
    Column("operations", Text),
    Index("idx_sudo_sessions_user", "user_id"),
)

permission_audit = Table(
    "permission_audit",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("user_id", UUID, nullable=False),
    Column("session_id", UUID),
    Column("operation", Text, nullable=False),
    Column("target", Text),
    Column("result", Text, nullable=False),
    Column("reason", Text),
    Column("details", Text),
    Column("remote_ip", Text),
    Column("user_agent", Text),
    Column("timestamp", DateTime, nullable=False),
    Index("idx_permission_audit_time", "timestamp"),
)

user_privileges = Table(
    "user_privileges",
    metadata,
    Column("user_id", UUID, primary_key=True),
    Column("level", Integer, nullable=False, server_default="0"),
    Column("updated_at", DateTime, nullable=False),
)

# --------------------------------------------------------------------
# Sender reputation and spam feedback
# --------------------------------------------------------------------

known_organizations = Table(
    "known_organizations",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("name", Text, nullable=False),
    Column("domains", Text, nullable=False),  # JSON array
    Column("trust_level", Text, server_default="external"),
    Column("logo_url", Text),
    Column("verified_at", DateTime),
    _created_at(),
    _created_at("updated_at"),
)

sender_contacts = Table(
    "sender_contacts",
    metadata,
    Column("sender_email", Text, primary_key=True),
    Column("recipient_email", Text, primary_key=True),
    _created_at("first_contact"),
    _created_at("last_contact"),
    Column("contact_count", Integer, server_default="1"),
)

spam_feedback = Table(
    "spam_feedback",
    metadata,
    Column("key_type", Text, primary_key=True),
    Column("key_value", Text, primary_key=True),
    Column("spam_votes", Integer, server_default="0"),
    Column("ham_votes", Integer, server_default="0"),
    _created_at("updated_at"),
    Index("idx_spam_feedback_updated", "updated_at"),
)

# --------------------------------------------------------------------
# Webhooks
# --------------------------------------------------------------------

webhooks = Table(
    "webhooks",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("name", Text, nullable=False),
    Column("description", Text),
    Column("url", Text, nullable=False),
    Column("method", Text, server_default="POST"),
    Column("secret", Text),
    Column("auth_type", Text, server_default="none"),
    Column("auth_value", Text),
    Column("events", Text, nullable=False),  # JSON array
    Column("organization_id", UUID),
    Column("domain_filter", Text),
    Column("headers", Text),
    Column("max_retries", Integer, server_default="5"),
    Column("retry_delay", Integer, server_default="60"),
    Column("timeout", Integer, server_default="30"),
    Column("active", Boolean, server_default="1"),
    Column("verified", Boolean, server_default="0"),
    Column("last_success", DateTime),
    Column("last_failure", DateTime),
    Column("failure_count", Integer, server_default="0"),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
    Index("idx_webhooks_org", "organization_id"),
)

webhook_events = Table(
    "webhook_events",
    metadata,
    Column("id", UUID, primary_key=True),
    Column("webhook_id", UUID, ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False),
    Column("event_type", Text, nullable=False),
    Column("payload", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("attempts", Integer, server_default="0"),
    Column("next_retry", DateTime),
    Column("response_code", Integer),
    Column("response_body", Text),
    Column("error", Text),
    Column("created_at", DateTime, nullable=False),
    Column("delivered_at", DateTime),
    Column("duration_ms", Integer),
    Index("idx_webhook_events_webhook", "webhook_id"),
    Index("idx_webhook_events_status", "status"),
)

__all__ = [
    "accounts",
    "alias_reply_routes",
    "aliases",
    "api_key_usage",
    "api_keys",
    "auth_providers",
    "bounces",
    "domains",
    "email_queue",
    "filter_rules",
    "known_organizations",
    "metadata",
    "organizations",
    "permission_audit",
    "permission_policies",
    "sender_contacts",
    "spam_feedback",
    "sudo_sessions",
    "suppression_list",
    "user_privileges",
    "webhook_events",
    "webhooks",
]
