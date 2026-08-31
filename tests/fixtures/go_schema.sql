-- Verbatim DDL from the Go engine at v0.1.0-go-final.
--
-- Extracted from internal/{storage,alias,apikeys,auth,bounce,queue,
-- filter,permissions,security,webhooks}. Used to prove the Python
-- schema opens a database the Go engine wrote.
--
-- Includes the three tables Lightr no longer models (messages,
-- encryption_keys, encrypted_messages) so the test also proves we
-- tolerate their presence rather than tripping over them.

CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domains (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    name TEXT UNIQUE NOT NULL,
    mail_hostname TEXT,
    dkim_private_key TEXT,
    dkim_selector TEXT,
    webhook_url TEXT,
    auth_webhook_url TEXT,
    auth_webhook_secret TEXT,
    auth_webhook_verified BOOLEAN DEFAULT FALSE,
    auth_webhook_verified_at TIMESTAMP,
    tls_cert_file TEXT,
    tls_key_file TEXT,
    relay_enabled BOOLEAN DEFAULT FALSE,
    relay_host TEXT,
    relay_port INTEGER,
    relay_username TEXT,
    relay_password TEXT,
    relay_use_tls BOOLEAN DEFAULT FALSE,
    relay_tls_skip_verify BOOLEAN DEFAULT FALSE,
    spam_policy TEXT DEFAULT 'junk',
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(org_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    domain_id TEXT NOT NULL,
    local_part TEXT NOT NULL,
    display_name TEXT,
    auth_mode TEXT NOT NULL,
    password_hash TEXT,
    external_id TEXT,
    quota_bytes INTEGER,
    used_bytes INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, local_part),
    FOREIGN KEY(domain_id) REFERENCES domains(id)
);

-- Retired: Dovecot owns the message store.
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    folder TEXT,
    size_bytes INTEGER,
    storage_path TEXT,
    subject TEXT,
    "from" TEXT,
    "to" TEXT,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP,
    deleted_at TIMESTAMP,
    FOREIGN KEY(account_id) REFERENCES accounts(id)
);

CREATE TABLE IF NOT EXISTS spam_feedback (
    key_type TEXT NOT NULL,
    key_value TEXT NOT NULL,
    spam_votes INTEGER DEFAULT 0,
    ham_votes INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (key_type, key_value)
);

CREATE TABLE IF NOT EXISTS aliases (
    id TEXT PRIMARY KEY,
    domain_id TEXT NOT NULL,
    source TEXT NOT NULL,
    destinations TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'forward',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, source)
);

CREATE TABLE IF NOT EXISTS alias_reply_routes (
    token TEXT PRIMARY KEY,
    alias_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    local_address TEXT NOT NULL,
    bridge_destinations TEXT NOT NULL,
    original_from TEXT NOT NULL,
    original_to TEXT,
    original_cc TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    prefix TEXT NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    organization_id TEXT,
    domain_id TEXT,
    account_id TEXT,
    user_id TEXT,
    type TEXT NOT NULL,
    permissions TEXT NOT NULL,
    allowed_ips TEXT,
    allowed_domains TEXT,
    rate_limit INTEGER DEFAULT 1000,
    daily_limit INTEGER DEFAULT 100000,
    active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    last_used_ip TEXT,
    usage_count INTEGER DEFAULT 0,
    usage_today INTEGER DEFAULT 0,
    metadata TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS api_key_usage (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT,
    duration_ms INTEGER,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_providers (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    priority INTEGER DEFAULT 100,
    config TEXT NOT NULL,
    domains TEXT,
    is_default INTEGER DEFAULT 0,
    auto_provision INTEGER DEFAULT 0,
    sync_groups INTEGER DEFAULT 0,
    sync_profile INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

CREATE TABLE IF NOT EXISTS bounces (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    original_msg_id TEXT,
    recipient_email TEXT NOT NULL,
    bounce_type TEXT NOT NULL,
    diagnostic_code TEXT,
    remote_mta TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS suppression_list (
    email TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    org_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS email_queue (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    from_addr TEXT NOT NULL,
    to_addrs TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    html_body TEXT,
    headers TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    last_error TEXT,
    next_retry DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    delivered_at DATETIME
);

CREATE TABLE IF NOT EXISTS filter_rules (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    account_id TEXT,
    name TEXT NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 100,
    conditions TEXT NOT NULL,
    match_type TEXT DEFAULT 'all',
    actions TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    stop_on_match INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permission_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    user_id TEXT,
    role_id TEXT,
    group_id TEXT,
    operations TEXT NOT NULL,
    effect TEXT NOT NULL,
    conditions TEXT,
    priority INTEGER DEFAULT 0,
    active INTEGER DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS sudo_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    level INTEGER NOT NULL,
    mfa_verified INTEGER DEFAULT 0,
    remote_ip TEXT,
    reason TEXT,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    last_used_at DATETIME NOT NULL,
    operations TEXT
);

CREATE TABLE IF NOT EXISTS permission_audit (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_id TEXT,
    operation TEXT NOT NULL,
    target TEXT,
    result TEXT NOT NULL,
    reason TEXT,
    details TEXT,
    remote_ip TEXT,
    user_agent TEXT,
    timestamp DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS user_privileges (
    user_id TEXT PRIMARY KEY,
    level INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS known_organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domains TEXT NOT NULL,
    trust_level TEXT DEFAULT 'external',
    logo_url TEXT,
    verified_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sender_contacts (
    sender_email TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    first_contact DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_contact DATETIME DEFAULT CURRENT_TIMESTAMP,
    contact_count INTEGER DEFAULT 1,
    PRIMARY KEY (sender_email, recipient_email)
);

CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'POST',
    secret TEXT,
    auth_type TEXT DEFAULT 'none',
    auth_value TEXT,
    events TEXT NOT NULL,
    organization_id TEXT,
    domain_filter TEXT,
    headers TEXT,
    max_retries INTEGER DEFAULT 5,
    retry_delay INTEGER DEFAULT 60,
    timeout INTEGER DEFAULT 30,
    active INTEGER DEFAULT 1,
    verified INTEGER DEFAULT 0,
    last_success DATETIME,
    last_failure DATETIME,
    failure_count INTEGER DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_events (
    id TEXT PRIMARY KEY,
    webhook_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    next_retry DATETIME,
    response_code INTEGER,
    response_body TEXT,
    error TEXT,
    created_at DATETIME NOT NULL,
    delivered_at DATETIME,
    duration_ms INTEGER,
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);

-- Retired: replaced by Dovecot's mail_crypt plugin.
CREATE TABLE IF NOT EXISTS encryption_keys (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    type TEXT NOT NULL,
    usage TEXT NOT NULL,
    key_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    name TEXT,
    public_key TEXT NOT NULL,
    private_key TEXT,
    certificate TEXT,
    issuer TEXT,
    subject TEXT,
    serial_number TEXT,
    algorithm TEXT,
    key_size INTEGER,
    subkeys TEXT,
    created_date DATETIME NOT NULL,
    expiry_date DATETIME,
    is_revoked INTEGER DEFAULT 0,
    revoked_at DATETIME,
    revoked_by TEXT,
    trust_level TEXT DEFAULT 'unknown',
    is_verified INTEGER DEFAULT 0,
    verified_at DATETIME,
    verified_by TEXT,
    is_default INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    imported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_messages_account_folder ON messages(account_id, folder);
CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(domain_id, local_part);
CREATE INDEX IF NOT EXISTS idx_spam_feedback_updated ON spam_feedback(updated_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(organization_id);
