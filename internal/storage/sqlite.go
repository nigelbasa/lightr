package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nigelbasa/lightr/internal/domain"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db     *sql.DB
	driver string
}

type SpamFeedbackEntry struct {
	KeyType   string
	KeyValue  string
	SpamVotes int64
	HamVotes  int64
	UpdatedAt string
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		_ = db.Close()
		return nil, err
	}

	s := &SQLiteStore{db: db, driver: "sqlite"}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return s, nil
}

func NewPostgresStore(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	s := &SQLiteStore{db: db, driver: "postgres"}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// DB returns the underlying database connection
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

func (s *SQLiteStore) Driver() string {
	return s.driver
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) init() error {
	schema := `
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

	CREATE INDEX IF NOT EXISTS idx_messages_account_folder ON messages(account_id, folder);
	CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(domain_id, local_part);
	CREATE INDEX IF NOT EXISTS idx_spam_feedback_updated ON spam_feedback(updated_at);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	for _, stmt := range []string{
		`ALTER TABLE domains ADD COLUMN mail_hostname TEXT`,
		`ALTER TABLE domains ADD COLUMN tls_cert_file TEXT`,
		`ALTER TABLE domains ADD COLUMN tls_key_file TEXT`,
		`ALTER TABLE domains ADD COLUMN relay_enabled BOOLEAN DEFAULT FALSE`,
		`ALTER TABLE domains ADD COLUMN relay_host TEXT`,
		`ALTER TABLE domains ADD COLUMN relay_port INTEGER`,
		`ALTER TABLE domains ADD COLUMN relay_username TEXT`,
		`ALTER TABLE domains ADD COLUMN relay_password TEXT`,
		`ALTER TABLE domains ADD COLUMN relay_use_tls BOOLEAN DEFAULT FALSE`,
		`ALTER TABLE domains ADD COLUMN relay_tls_skip_verify BOOLEAN DEFAULT FALSE`,
		`ALTER TABLE domains ADD COLUMN spam_policy TEXT DEFAULT 'junk'`,
		`ALTER TABLE domains ADD COLUMN auth_webhook_secret TEXT`,
		`ALTER TABLE domains ADD COLUMN auth_webhook_verified BOOLEAN DEFAULT FALSE`,
		`ALTER TABLE domains ADD COLUMN auth_webhook_verified_at TIMESTAMP`,
	} {
		if _, err := s.db.Exec(s.bind(stmt)); err != nil && !isIgnorableAlterError(err) {
			return err
		}
	}

	return nil
}

func (s *SQLiteStore) exec(query string, args ...interface{}) (sql.Result, error) {
	return s.db.Exec(s.bind(query), args...)
}

func (s *SQLiteStore) query(query string, args ...interface{}) (*sql.Rows, error) {
	return s.db.Query(s.bind(query), args...)
}

func (s *SQLiteStore) queryRow(query string, args ...interface{}) *sql.Row {
	return s.db.QueryRow(s.bind(query), args...)
}

func (s *SQLiteStore) bind(query string) string {
	if s.driver != "postgres" {
		return query
	}
	var b strings.Builder
	arg := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			b.WriteString(fmt.Sprintf("$%d", arg))
			arg++
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

// DomainRepository implementation
func (s *SQLiteStore) CreateDomain(dom *domain.Domain) error {
	_, err := s.exec(`INSERT INTO domains (id, org_id, name, mail_hostname, dkim_private_key, dkim_selector, webhook_url, auth_webhook_url, auth_webhook_secret, auth_webhook_verified, auth_webhook_verified_at, tls_cert_file, tls_key_file, relay_enabled, relay_host, relay_port, relay_username, relay_password, relay_use_tls, relay_tls_skip_verify, spam_policy, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dom.ID.String(), dom.OrgID.String(), dom.Name, dom.MailHostname, dom.DKIMPrivateKey, dom.DKIMSelector, dom.WebhookURL, dom.AuthWebhookURL, dom.AuthWebhookSecret, dom.AuthWebhookVerified, dom.AuthWebhookVerifiedAt, dom.TLSCertFile, dom.TLSKeyFile, dom.RelayEnabled, dom.RelayHost, nullableInt(dom.RelayPort), dom.RelayUsername, dom.RelayPassword, dom.RelayUseTLS, dom.RelayTLSSkipVerify, firstNonEmpty(dom.SpamPolicy, "junk"), dom.IsVerified)
	return err
}

func (s *SQLiteStore) GetDomainByName(name string) (*domain.Domain, error) {
	row := s.queryRow(`SELECT id, org_id, name, COALESCE(mail_hostname, ''), dkim_private_key, dkim_selector, webhook_url, auth_webhook_url, auth_webhook_secret, auth_webhook_verified, auth_webhook_verified_at, tls_cert_file, tls_key_file, relay_enabled, relay_host, relay_port, relay_username, relay_password, relay_use_tls, relay_tls_skip_verify, COALESCE(spam_policy, 'junk'), is_verified FROM domains WHERE name = ?`, name)
	d := &domain.Domain{}
	var id, orgID string
	var authWebhookURL, authWebhookSecret, tlsCertFile, tlsKeyFile, relayHost, relayUsername, relayPassword sql.NullString
	var relayPort sql.NullInt64
	err := row.Scan(&id, &orgID, &d.Name, &d.MailHostname, &d.DKIMPrivateKey, &d.DKIMSelector, &d.WebhookURL, &authWebhookURL, &authWebhookSecret, &d.AuthWebhookVerified, &d.AuthWebhookVerifiedAt, &tlsCertFile, &tlsKeyFile, &d.RelayEnabled, &relayHost, &relayPort, &relayUsername, &relayPassword, &d.RelayUseTLS, &d.RelayTLSSkipVerify, &d.SpamPolicy, &d.IsVerified)
	if err != nil {
		return nil, err
	}
	d.ID, _ = uuid.Parse(id)
	d.OrgID, _ = uuid.Parse(orgID)
	d.AuthWebhookURL = authWebhookURL.String
	d.AuthWebhookSecret = authWebhookSecret.String
	d.TLSCertFile = tlsCertFile.String
	d.TLSKeyFile = tlsKeyFile.String
	d.RelayHost = relayHost.String
	d.RelayUsername = relayUsername.String
	d.RelayPassword = relayPassword.String
	if relayPort.Valid {
		d.RelayPort = int(relayPort.Int64)
	}
	return d, nil
}

func (s *SQLiteStore) GetDomainByID(id uuid.UUID) (*domain.Domain, error) {
	row := s.queryRow(`SELECT id, org_id, name, COALESCE(mail_hostname, ''), dkim_private_key, dkim_selector, webhook_url, auth_webhook_url, auth_webhook_secret, auth_webhook_verified, auth_webhook_verified_at, tls_cert_file, tls_key_file, relay_enabled, relay_host, relay_port, relay_username, relay_password, relay_use_tls, relay_tls_skip_verify, COALESCE(spam_policy, 'junk'), is_verified FROM domains WHERE id = ?`, id.String())
	d := &domain.Domain{}
	var domID, orgID string
	var authWebhookURL, authWebhookSecret, tlsCertFile, tlsKeyFile, relayHost, relayUsername, relayPassword sql.NullString
	var relayPort sql.NullInt64
	err := row.Scan(&domID, &orgID, &d.Name, &d.MailHostname, &d.DKIMPrivateKey, &d.DKIMSelector, &d.WebhookURL, &authWebhookURL, &authWebhookSecret, &d.AuthWebhookVerified, &d.AuthWebhookVerifiedAt, &tlsCertFile, &tlsKeyFile, &d.RelayEnabled, &relayHost, &relayPort, &relayUsername, &relayPassword, &d.RelayUseTLS, &d.RelayTLSSkipVerify, &d.SpamPolicy, &d.IsVerified)
	if err != nil {
		return nil, err
	}
	d.ID, _ = uuid.Parse(domID)
	d.OrgID, _ = uuid.Parse(orgID)
	d.AuthWebhookURL = authWebhookURL.String
	d.AuthWebhookSecret = authWebhookSecret.String
	d.TLSCertFile = tlsCertFile.String
	d.TLSKeyFile = tlsKeyFile.String
	d.RelayHost = relayHost.String
	d.RelayUsername = relayUsername.String
	d.RelayPassword = relayPassword.String
	if relayPort.Valid {
		d.RelayPort = int(relayPort.Int64)
	}
	return d, nil
}

func (s *SQLiteStore) ListDomainsByOrg(orgID uuid.UUID) ([]*domain.Domain, error) {
	rows, err := s.query(`SELECT id, org_id, name, COALESCE(mail_hostname, ''), dkim_private_key, dkim_selector, webhook_url, auth_webhook_url, auth_webhook_secret, auth_webhook_verified, auth_webhook_verified_at, tls_cert_file, tls_key_file, relay_enabled, relay_host, relay_port, relay_username, relay_password, relay_use_tls, relay_tls_skip_verify, COALESCE(spam_policy, 'junk'), is_verified FROM domains WHERE org_id = ?`, orgID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []*domain.Domain
	for rows.Next() {
		d := &domain.Domain{}
		var id, oid string
		var authWebhookURL, authWebhookSecret, tlsCertFile, tlsKeyFile, relayHost, relayUsername, relayPassword sql.NullString
		var relayPort sql.NullInt64
		if err := rows.Scan(&id, &oid, &d.Name, &d.MailHostname, &d.DKIMPrivateKey, &d.DKIMSelector, &d.WebhookURL, &authWebhookURL, &authWebhookSecret, &d.AuthWebhookVerified, &d.AuthWebhookVerifiedAt, &tlsCertFile, &tlsKeyFile, &d.RelayEnabled, &relayHost, &relayPort, &relayUsername, &relayPassword, &d.RelayUseTLS, &d.RelayTLSSkipVerify, &d.SpamPolicy, &d.IsVerified); err != nil {
			return nil, err
		}
		d.ID, _ = uuid.Parse(id)
		d.OrgID, _ = uuid.Parse(oid)
		d.AuthWebhookURL = authWebhookURL.String
		d.AuthWebhookSecret = authWebhookSecret.String
		d.TLSCertFile = tlsCertFile.String
		d.TLSKeyFile = tlsKeyFile.String
		d.RelayHost = relayHost.String
		d.RelayUsername = relayUsername.String
		d.RelayPassword = relayPassword.String
		if relayPort.Valid {
			d.RelayPort = int(relayPort.Int64)
		}
		domains = append(domains, d)
	}
	return domains, nil
}

func (s *SQLiteStore) UpdateDomain(dom *domain.Domain) error {
	_, err := s.exec(`UPDATE domains SET name = ?, mail_hostname = ?, dkim_private_key = ?, dkim_selector = ?, webhook_url = ?, auth_webhook_url = ?, auth_webhook_secret = ?, auth_webhook_verified = ?, auth_webhook_verified_at = ?, tls_cert_file = ?, tls_key_file = ?, relay_enabled = ?, relay_host = ?, relay_port = ?, relay_username = ?, relay_password = ?, relay_use_tls = ?, relay_tls_skip_verify = ?, spam_policy = ?, is_verified = ? WHERE id = ?`,
		dom.Name, dom.MailHostname, dom.DKIMPrivateKey, dom.DKIMSelector, dom.WebhookURL, dom.AuthWebhookURL, dom.AuthWebhookSecret, dom.AuthWebhookVerified, dom.AuthWebhookVerifiedAt, dom.TLSCertFile, dom.TLSKeyFile, dom.RelayEnabled, dom.RelayHost, nullableInt(dom.RelayPort), dom.RelayUsername, dom.RelayPassword, dom.RelayUseTLS, dom.RelayTLSSkipVerify, firstNonEmpty(dom.SpamPolicy, "junk"), dom.IsVerified, dom.ID.String())
	return err
}

func (s *SQLiteStore) DeleteDomain(id uuid.UUID) error {
	_, err := s.exec(`DELETE FROM domains WHERE id = ?`, id.String())
	return err
}

// AccountRepository implementation
func (s *SQLiteStore) CreateAccount(acc *domain.Account) error {
	_, err := s.exec(`INSERT INTO accounts (id, domain_id, local_part, display_name, auth_mode, password_hash, external_id, quota_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		acc.ID.String(), acc.DomainID.String(), acc.LocalPart, acc.DisplayName, string(acc.AuthMode), acc.PasswordHash, acc.ExternalID, acc.QuotaBytes)
	return err
}

func (s *SQLiteStore) GetAccountByID(id uuid.UUID) (*domain.Account, error) {
	row := s.queryRow(`SELECT id, domain_id, local_part, COALESCE(display_name, ''), auth_mode, password_hash, external_id, quota_bytes, used_bytes FROM accounts WHERE id = ?`, id.String())
	acc := &domain.Account{}
	var accID, domID, authMode string
	err := row.Scan(&accID, &domID, &acc.LocalPart, &acc.DisplayName, &authMode, &acc.PasswordHash, &acc.ExternalID, &acc.QuotaBytes, &acc.UsedBytes)
	if err != nil {
		return nil, err
	}
	acc.ID, _ = uuid.Parse(accID)
	acc.DomainID, _ = uuid.Parse(domID)
	acc.AuthMode = domain.AuthMode(authMode)
	return acc, nil
}

func (s *SQLiteStore) GetAccountByEmail(email string) (*domain.Account, error) {
	row := s.queryRow(`
		SELECT a.id, a.domain_id, a.local_part, COALESCE(a.display_name, ''), a.auth_mode, a.password_hash, a.external_id, a.quota_bytes, a.used_bytes 
		FROM accounts a
		JOIN domains d ON a.domain_id = d.id
		WHERE (a.local_part || '@' || d.name) = ?`, email)

	acc := &domain.Account{}
	var accID, domID, authMode string
	var passwordHash, externalID sql.NullString
	var quotaBytes, usedBytes sql.NullInt64
	err := row.Scan(&accID, &domID, &acc.LocalPart, &acc.DisplayName, &authMode, &passwordHash, &externalID, &quotaBytes, &usedBytes)
	if err != nil {
		return nil, err
	}
	acc.ID, _ = uuid.Parse(accID)
	acc.DomainID, _ = uuid.Parse(domID)
	acc.AuthMode = domain.AuthMode(authMode)
	acc.PasswordHash = passwordHash.String
	acc.ExternalID = externalID.String
	if quotaBytes.Valid {
		acc.QuotaBytes = quotaBytes.Int64
	}
	if usedBytes.Valid {
		acc.UsedBytes = usedBytes.Int64
	}
	return acc, nil
}

func (s *SQLiteStore) GetAccountByLocalPart(domainID uuid.UUID, localPart string) (*domain.Account, error) {
	row := s.queryRow(`
		SELECT id, domain_id, local_part, COALESCE(display_name, ''), auth_mode, password_hash, external_id, quota_bytes, used_bytes 
		FROM accounts 
		WHERE domain_id = ? AND local_part = ?`, domainID.String(), localPart)

	acc := &domain.Account{}
	var accID, domID, authMode string
	var passwordHash, externalID sql.NullString
	var quotaBytes, usedBytes sql.NullInt64
	err := row.Scan(&accID, &domID, &acc.LocalPart, &acc.DisplayName, &authMode, &passwordHash, &externalID, &quotaBytes, &usedBytes)
	if err != nil {
		return nil, err
	}
	acc.ID, _ = uuid.Parse(accID)
	acc.DomainID, _ = uuid.Parse(domID)
	acc.AuthMode = domain.AuthMode(authMode)
	acc.PasswordHash = passwordHash.String
	acc.ExternalID = externalID.String
	acc.QuotaBytes = quotaBytes.Int64
	acc.UsedBytes = usedBytes.Int64
	return acc, nil
}

func (s *SQLiteStore) UpdateAccount(acc *domain.Account) error {
	_, err := s.exec(`UPDATE accounts SET password_hash = ?, used_bytes = ?, display_name = ?, auth_mode = ?, external_id = ?, quota_bytes = ? WHERE id = ?`,
		acc.PasswordHash, acc.UsedBytes, acc.DisplayName, string(acc.AuthMode), acc.ExternalID, acc.QuotaBytes, acc.ID.String())
	return err
}

func (s *SQLiteStore) DeleteAccount(id uuid.UUID) error {
	_, err := s.exec(`DELETE FROM accounts WHERE id = ?`, id.String())
	return err
}

// SearchByDomain searches for accounts in a domain matching a query
func (s *SQLiteStore) SearchByDomain(domainName, query string, limit int) ([]*domain.Account, error) {
	if limit <= 0 {
		limit = 10
	}

	rows, err := s.query(`
		SELECT a.id, a.domain_id, a.local_part, COALESCE(a.display_name, ''), a.auth_mode 
		FROM accounts a
		JOIN domains d ON a.domain_id = d.id
		WHERE d.name = ? AND (a.local_part LIKE ? OR a.display_name LIKE ?)
		LIMIT ?
	`, domainName, "%"+query+"%", "%"+query+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*domain.Account
	for rows.Next() {
		acc := &domain.Account{}
		var accID, domID, authMode string
		if err := rows.Scan(&accID, &domID, &acc.LocalPart, &acc.DisplayName, &authMode); err != nil {
			return nil, err
		}
		acc.ID, _ = uuid.Parse(accID)
		acc.DomainID, _ = uuid.Parse(domID)
		acc.AuthMode = domain.AuthMode(authMode)

		// Build email from local_part and domain
		acc.Email = acc.LocalPart + "@" + domainName
		accounts = append(accounts, acc)
	}
	return accounts, nil
}

func (s *SQLiteStore) ListAccountsByDomain(domainID uuid.UUID) ([]*domain.Account, error) {
	rows, err := s.query(`
		SELECT id, domain_id, local_part, COALESCE(display_name, ''), auth_mode, password_hash, external_id, quota_bytes, used_bytes
		FROM accounts
		WHERE domain_id = ?
		ORDER BY local_part
	`, domainID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*domain.Account
	for rows.Next() {
		acc := &domain.Account{}
		var accID, domID, authMode string
		var passwordHash, externalID sql.NullString
		var quotaBytes, usedBytes sql.NullInt64
		if err := rows.Scan(&accID, &domID, &acc.LocalPart, &acc.DisplayName, &authMode, &passwordHash, &externalID, &quotaBytes, &usedBytes); err != nil {
			return nil, err
		}
		acc.ID, _ = uuid.Parse(accID)
		acc.DomainID, _ = uuid.Parse(domID)
		acc.AuthMode = domain.AuthMode(authMode)
		acc.PasswordHash = passwordHash.String
		acc.ExternalID = externalID.String
		if quotaBytes.Valid {
			acc.QuotaBytes = quotaBytes.Int64
		}
		if usedBytes.Valid {
			acc.UsedBytes = usedBytes.Int64
		}
		accounts = append(accounts, acc)
	}
	return accounts, nil
}

// MessageRepository implementation. CreateMessage and UpdateMessage also
// adjust the account's used_bytes quota counter so it stays in sync without
// a separate maintenance pass.
func (s *SQLiteStore) CreateMessage(msg *domain.Message) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(s.bind(`INSERT INTO messages (id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		msg.ID.String(), msg.AccountID.String(), msg.Folder, msg.SizeBytes, msg.StoragePath, msg.Subject, msg.From, msg.To, msg.ReceivedAt, msg.ReadAt); err != nil {
		return err
	}
	if msg.SizeBytes > 0 && msg.DeletedAt == nil {
		if _, err := tx.Exec(s.bind(`UPDATE accounts SET used_bytes = used_bytes + ? WHERE id = ?`),
			msg.SizeBytes, msg.AccountID.String()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetMessageByID(id uuid.UUID) (*domain.Message, error) {
	row := s.queryRow(`SELECT id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at, deleted_at FROM messages WHERE id = ?`, id.String())
	m := &domain.Message{}
	var msgID, accID string
	err := row.Scan(&msgID, &accID, &m.Folder, &m.SizeBytes, &m.StoragePath, &m.Subject, &m.From, &m.To, &m.ReceivedAt, &m.ReadAt, &m.DeletedAt)
	if err != nil {
		return nil, err
	}
	m.ID, _ = uuid.Parse(msgID)
	m.AccountID, _ = uuid.Parse(accID)
	return m, nil
}

func (s *SQLiteStore) ListByAccount(accountID uuid.UUID, folder string) ([]*domain.Message, error) {
	rows, err := s.query(`SELECT id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at, deleted_at FROM messages WHERE account_id = ? AND folder = ?`,
		accountID.String(), folder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []*domain.Message
	for rows.Next() {
		m := &domain.Message{}
		var id, accID string
		if err := rows.Scan(&id, &accID, &m.Folder, &m.SizeBytes, &m.StoragePath, &m.Subject, &m.From, &m.To, &m.ReceivedAt, &m.ReadAt, &m.DeletedAt); err != nil {
			return nil, err
		}
		m.ID, _ = uuid.Parse(id)
		m.AccountID, _ = uuid.Parse(accID)
		msgs = append(msgs, m)
	}
	return msgs, nil
}

func (s *SQLiteStore) UpdateMessage(msg *domain.Message) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Detect delete/undelete transition so we can keep used_bytes in sync.
	var prevDeletedAt sql.NullTime
	var prevSize int64
	if err := tx.QueryRow(s.bind(`SELECT deleted_at, size_bytes FROM messages WHERE id = ?`),
		msg.ID.String()).Scan(&prevDeletedAt, &prevSize); err != nil {
		return err
	}
	wasDeleted := prevDeletedAt.Valid
	isDeleted := msg.DeletedAt != nil

	if _, err := tx.Exec(s.bind(`UPDATE messages SET folder = ?, read_at = ?, deleted_at = ? WHERE id = ?`),
		msg.Folder, msg.ReadAt, msg.DeletedAt, msg.ID.String()); err != nil {
		return err
	}

	if prevSize > 0 {
		switch {
		case !wasDeleted && isDeleted:
			if _, err := tx.Exec(s.bind(`UPDATE accounts SET used_bytes = used_bytes - ? WHERE id = ?`),
				prevSize, msg.AccountID.String()); err != nil {
				return err
			}
		case wasDeleted && !isDeleted:
			if _, err := tx.Exec(s.bind(`UPDATE accounts SET used_bytes = used_bytes + ? WHERE id = ?`),
				prevSize, msg.AccountID.String()); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) RecordFeedback(ctx context.Context, senderEmail, senderDomain string, isSpam bool) error {
	_ = ctx
	if senderEmail != "" {
		if err := s.recordFeedbackKey("sender_email", strings.ToLower(strings.TrimSpace(senderEmail)), isSpam); err != nil {
			return err
		}
	}
	if senderDomain != "" {
		if err := s.recordFeedbackKey("sender_domain", strings.ToLower(strings.TrimSpace(senderDomain)), isSpam); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) recordFeedbackKey(keyType, keyValue string, isSpam bool) error {
	if keyValue == "" {
		return nil
	}
	if isSpam {
		_, err := s.exec(`INSERT INTO spam_feedback (key_type, key_value, spam_votes, ham_votes, updated_at) VALUES (?, ?, 1, 0, CURRENT_TIMESTAMP)
			ON CONFLICT(key_type, key_value) DO UPDATE SET spam_votes = spam_feedback.spam_votes + 1, updated_at = CURRENT_TIMESTAMP`,
			keyType, keyValue)
		return err
	}
	_, err := s.exec(`INSERT INTO spam_feedback (key_type, key_value, spam_votes, ham_votes, updated_at) VALUES (?, ?, 0, 1, CURRENT_TIMESTAMP)
		ON CONFLICT(key_type, key_value) DO UPDATE SET ham_votes = spam_feedback.ham_votes + 1, updated_at = CURRENT_TIMESTAMP`,
		keyType, keyValue)
	return err
}

func (s *SQLiteStore) FeedbackScore(ctx context.Context, senderEmail, senderDomain string) (float64, []string, error) {
	_ = ctx
	score := 0.0
	var reasons []string
	if senderEmail != "" {
		spamVotes, hamVotes, err := s.feedbackVotes("sender_email", strings.ToLower(strings.TrimSpace(senderEmail)))
		if err != nil {
			return 0, nil, err
		}
		if spamVotes != 0 || hamVotes != 0 {
			score += (float64(spamVotes) * 3.0) - (float64(hamVotes) * 3.0)
			reasons = append(reasons, fmt.Sprintf("user feedback on sender %s: spam=%d ham=%d", senderEmail, spamVotes, hamVotes))
		}
	}
	if senderDomain != "" {
		spamVotes, hamVotes, err := s.feedbackVotes("sender_domain", strings.ToLower(strings.TrimSpace(senderDomain)))
		if err != nil {
			return 0, nil, err
		}
		if spamVotes != 0 || hamVotes != 0 {
			score += (float64(spamVotes) * 1.5) - (float64(hamVotes) * 1.5)
			reasons = append(reasons, fmt.Sprintf("user feedback on domain %s: spam=%d ham=%d", senderDomain, spamVotes, hamVotes))
		}
	}
	return score, reasons, nil
}

func (s *SQLiteStore) feedbackVotes(keyType, keyValue string) (int64, int64, error) {
	row := s.queryRow(`SELECT spam_votes, ham_votes FROM spam_feedback WHERE key_type = ? AND key_value = ?`, keyType, keyValue)
	var spamVotes, hamVotes int64
	if err := row.Scan(&spamVotes, &hamVotes); err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	return spamVotes, hamVotes, nil
}

func (s *SQLiteStore) ListSpamFeedback(keyType string) ([]SpamFeedbackEntry, error) {
	query := `SELECT key_type, key_value, spam_votes, ham_votes, updated_at FROM spam_feedback`
	args := []interface{}{}
	if strings.TrimSpace(keyType) != "" {
		query += ` WHERE key_type = ?`
		args = append(args, keyType)
	}
	query += ` ORDER BY updated_at DESC, key_type, key_value`
	rows, err := s.query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []SpamFeedbackEntry
	for rows.Next() {
		var entry SpamFeedbackEntry
		if err := rows.Scan(&entry.KeyType, &entry.KeyValue, &entry.SpamVotes, &entry.HamVotes, &entry.UpdatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *SQLiteStore) ResetSpamFeedback(keyType, keyValue string) error {
	if strings.TrimSpace(keyType) == "" || strings.TrimSpace(keyValue) == "" {
		return fmt.Errorf("key type and key value are required")
	}
	_, err := s.exec(`DELETE FROM spam_feedback WHERE key_type = ? AND key_value = ?`, strings.TrimSpace(keyType), strings.ToLower(strings.TrimSpace(keyValue)))
	return err
}

func (s *SQLiteStore) ResetAllSpamFeedback() error {
	_, err := s.exec(`DELETE FROM spam_feedback`)
	return err
}

func (s *SQLiteStore) ListMessagesByAccount(accountID uuid.UUID) ([]*domain.Message, error) {
	rows, err := s.query(`SELECT id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at, deleted_at FROM messages WHERE account_id = ? ORDER BY received_at`,
		accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []*domain.Message
	for rows.Next() {
		m := &domain.Message{}
		var id, accID string
		if err := rows.Scan(&id, &accID, &m.Folder, &m.SizeBytes, &m.StoragePath, &m.Subject, &m.From, &m.To, &m.ReceivedAt, &m.ReadAt, &m.DeletedAt); err != nil {
			return nil, err
		}
		m.ID, _ = uuid.Parse(id)
		m.AccountID, _ = uuid.Parse(accID)
		msgs = append(msgs, m)
	}
	return msgs, nil
}

// OrganizationRepository implementation
func (s *SQLiteStore) CreateOrg(org *domain.Organization) error {
	_, err := s.exec(`INSERT INTO organizations (id, name) VALUES (?, ?)`,
		org.ID.String(), org.Name)
	return err
}

func (s *SQLiteStore) GetOrgByID(id uuid.UUID) (*domain.Organization, error) {
	row := s.queryRow(`SELECT id, name, created_at FROM organizations WHERE id = ?`, id.String())
	org := &domain.Organization{}
	var orgID string
	err := row.Scan(&orgID, &org.Name, &org.CreatedAt)
	if err != nil {
		return nil, err
	}
	org.ID, _ = uuid.Parse(orgID)
	return org, nil
}

func (s *SQLiteStore) GetOrgByName(name string) (*domain.Organization, error) {
	row := s.queryRow(`SELECT id, name, created_at FROM organizations WHERE name = ?`, name)
	org := &domain.Organization{}
	var orgID string
	err := row.Scan(&orgID, &org.Name, &org.CreatedAt)
	if err != nil {
		return nil, err
	}
	org.ID, _ = uuid.Parse(orgID)
	return org, nil
}

func (s *SQLiteStore) ListOrgs() ([]*domain.Organization, error) {
	rows, err := s.query(`SELECT id, name, created_at FROM organizations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []*domain.Organization
	for rows.Next() {
		org := &domain.Organization{}
		var id string
		if err := rows.Scan(&id, &org.Name, &org.CreatedAt); err != nil {
			return nil, err
		}
		org.ID, _ = uuid.Parse(id)
		orgs = append(orgs, org)
	}
	return orgs, nil
}

func (s *SQLiteStore) UpdateOrg(org *domain.Organization) error {
	_, err := s.exec(`UPDATE organizations SET name = ? WHERE id = ?`,
		org.Name, org.ID.String())
	return err
}

func (s *SQLiteStore) DeleteOrg(id uuid.UUID) error {
	_, err := s.exec(`DELETE FROM organizations WHERE id = ?`, id.String())
	return err
}

// LocalBlobStorage implementation
type LocalBlobStorage struct {
	baseDir string
}

func NewLocalBlobStorage(baseDir string) *LocalBlobStorage {
	return &LocalBlobStorage{baseDir: baseDir}
}

func (l *LocalBlobStorage) Put(path string, data []byte) error {
	fullPath, err := l.resolve(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(fullPath, data, 0644)
}

func (l *LocalBlobStorage) Get(path string) ([]byte, error) {
	fullPath, err := l.resolve(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(fullPath)
}

func (l *LocalBlobStorage) Delete(path string) error {
	fullPath, err := l.resolve(path)
	if err != nil {
		return err
	}
	return os.Remove(fullPath)
}

// resolve joins path against baseDir and confirms the result stays inside it.
// This is the last line of defense against path traversal in blob keys —
// callers are also expected to validate untrusted segments upstream.
func (l *LocalBlobStorage) resolve(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("blob path is required")
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("invalid blob path")
	}
	full := filepath.Join(l.baseDir, path)
	absRoot, err := filepath.Abs(l.baseDir)
	if err != nil {
		return "", err
	}
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if absFull != absRoot && !strings.HasPrefix(absFull, absRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("blob path escapes base directory")
	}
	return full, nil
}

func isIgnorableAlterError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists")
}

func nullableInt(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
