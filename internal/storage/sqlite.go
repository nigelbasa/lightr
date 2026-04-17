package storage

import (
	"database/sql"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	s := &SQLiteStore{db: db}
	if err := s.init(); err != nil {
		return nil, err
	}

	return s, nil
}

// DB returns the underlying database connection
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

func (s *SQLiteStore) init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS organizations (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		billing_tier TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS domains (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		name TEXT UNIQUE NOT NULL,
		dkim_private_key TEXT,
		dkim_selector TEXT,
		webhook_url TEXT,
		auth_webhook_url TEXT,
		is_verified BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
		received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		read_at DATETIME,
		deleted_at DATETIME,
		FOREIGN KEY(account_id) REFERENCES accounts(id)
	);

	CREATE TABLE IF NOT EXISTS templates (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		name TEXT NOT NULL,
		subject TEXT,
		content TEXT,
		UNIQUE(org_id, name),
		FOREIGN KEY(org_id) REFERENCES organizations(id)
	);

	CREATE TABLE IF NOT EXISTS tracking_events (
		id TEXT PRIMARY KEY,
		message_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		link_url TEXT,
		ip_address TEXT,
		user_agent TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(message_id) REFERENCES messages(id)
	);

	CREATE INDEX IF NOT EXISTS idx_messages_account_folder ON messages(account_id, folder);
	CREATE INDEX IF NOT EXISTS idx_tracking_message ON tracking_events(message_id);
	CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(domain_id, local_part);
	`
	_, err := s.db.Exec(schema)
	return err
}

// DomainRepository implementation
func (s *SQLiteStore) CreateDomain(dom *domain.Domain) error {
	_, err := s.db.Exec(`INSERT INTO domains (id, org_id, name, dkim_private_key, dkim_selector, webhook_url, auth_webhook_url, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		dom.ID.String(), dom.OrgID.String(), dom.Name, dom.DKIMPrivateKey, dom.DKIMSelector, dom.WebhookURL, dom.AuthWebhookURL, dom.IsVerified)
	return err
}

func (s *SQLiteStore) GetDomainByName(name string) (*domain.Domain, error) {
	row := s.db.QueryRow(`SELECT id, org_id, name, dkim_selector, webhook_url, auth_webhook_url, is_verified FROM domains WHERE name = ?`, name)
	d := &domain.Domain{}
	var id, orgID string
	var authWebhookURL sql.NullString
	err := row.Scan(&id, &orgID, &d.Name, &d.DKIMSelector, &d.WebhookURL, &authWebhookURL, &d.IsVerified)
	if err != nil {
		return nil, err
	}
	d.ID, _ = uuid.Parse(id)
	d.OrgID, _ = uuid.Parse(orgID)
	d.AuthWebhookURL = authWebhookURL.String
	return d, nil
}

func (s *SQLiteStore) GetDomainByID(id uuid.UUID) (*domain.Domain, error) {
	row := s.db.QueryRow(`SELECT id, org_id, name, dkim_selector, webhook_url, auth_webhook_url, is_verified FROM domains WHERE id = ?`, id.String())
	d := &domain.Domain{}
	var domID, orgID string
	var authWebhookURL sql.NullString
	err := row.Scan(&domID, &orgID, &d.Name, &d.DKIMSelector, &d.WebhookURL, &authWebhookURL, &d.IsVerified)
	if err != nil {
		return nil, err
	}
	d.ID, _ = uuid.Parse(domID)
	d.OrgID, _ = uuid.Parse(orgID)
	d.AuthWebhookURL = authWebhookURL.String
	return d, nil
}

func (s *SQLiteStore) ListDomainsByOrg(orgID uuid.UUID) ([]*domain.Domain, error) {
	rows, err := s.db.Query(`SELECT id, org_id, name, dkim_selector, webhook_url, auth_webhook_url, is_verified FROM domains WHERE org_id = ?`, orgID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []*domain.Domain
	for rows.Next() {
		d := &domain.Domain{}
		var id, oid string
		var authWebhookURL sql.NullString
		if err := rows.Scan(&id, &oid, &d.Name, &d.DKIMSelector, &d.WebhookURL, &authWebhookURL, &d.IsVerified); err != nil {
			return nil, err
		}
		d.ID, _ = uuid.Parse(id)
		d.OrgID, _ = uuid.Parse(oid)
		d.AuthWebhookURL = authWebhookURL.String
		domains = append(domains, d)
	}
	return domains, nil
}

// AccountRepository implementation
func (s *SQLiteStore) CreateAccount(acc *domain.Account) error {
	_, err := s.db.Exec(`INSERT INTO accounts (id, domain_id, local_part, auth_mode, password_hash, external_id, quota_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		acc.ID.String(), acc.DomainID.String(), acc.LocalPart, string(acc.AuthMode), acc.PasswordHash, acc.ExternalID, acc.QuotaBytes)
	return err
}

func (s *SQLiteStore) GetAccountByID(id uuid.UUID) (*domain.Account, error) {
	row := s.db.QueryRow(`SELECT id, domain_id, local_part, COALESCE(display_name, ''), auth_mode, password_hash, external_id, quota_bytes, used_bytes FROM accounts WHERE id = ?`, id.String())
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
	row := s.db.QueryRow(`
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
	row := s.db.QueryRow(`
		SELECT id, domain_id, local_part, auth_mode, password_hash, external_id, quota_bytes, used_bytes 
		FROM accounts 
		WHERE domain_id = ? AND local_part = ?`, domainID.String(), localPart)

	acc := &domain.Account{}
	var accID, domID, authMode string
	var passwordHash, externalID sql.NullString
	var quotaBytes, usedBytes sql.NullInt64
	err := row.Scan(&accID, &domID, &acc.LocalPart, &authMode, &passwordHash, &externalID, &quotaBytes, &usedBytes)
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
	_, err := s.db.Exec(`UPDATE accounts SET password_hash = ?, used_bytes = ?, display_name = ? WHERE id = ?`,
		acc.PasswordHash, acc.UsedBytes, acc.DisplayName, acc.ID.String())
	return err
}

func (s *SQLiteStore) DeleteAccount(id uuid.UUID) error {
	_, err := s.db.Exec(`DELETE FROM accounts WHERE id = ?`, id.String())
	return err
}

// SearchByDomain searches for accounts in a domain matching a query
func (s *SQLiteStore) SearchByDomain(domainName, query string, limit int) ([]*domain.Account, error) {
	if limit <= 0 {
		limit = 10
	}
	
	rows, err := s.db.Query(`
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

// MessageRepository implementation
func (s *SQLiteStore) CreateMessage(msg *domain.Message) error {
	_, err := s.db.Exec(`INSERT INTO messages (id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		msg.ID.String(), msg.AccountID.String(), msg.Folder, msg.SizeBytes, msg.StoragePath, msg.Subject, msg.From, msg.To, msg.ReceivedAt, msg.ReadAt)
	return err
}

func (s *SQLiteStore) GetMessageByID(id uuid.UUID) (*domain.Message, error) {
	row := s.db.QueryRow(`SELECT id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at, deleted_at FROM messages WHERE id = ?`, id.String())
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
	rows, err := s.db.Query(`SELECT id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at, deleted_at FROM messages WHERE account_id = ? AND folder = ?`,
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
	_, err := s.db.Exec(`UPDATE messages SET folder = ?, read_at = ?, deleted_at = ? WHERE id = ?`,
		msg.Folder, msg.ReadAt, msg.DeletedAt, msg.ID.String())
	return err
}

// TemplateRepository implementation
func (s *SQLiteStore) CreateTemplate(t *domain.Template) error {
	_, err := s.db.Exec(`INSERT INTO templates (id, org_id, name, subject, content) VALUES (?, ?, ?, ?, ?)`,
		t.ID.String(), t.OrgID.String(), t.Name, t.Subject, t.Content)
	return err
}

func (s *SQLiteStore) GetTemplateByName(orgID uuid.UUID, name string) (*domain.Template, error) {
	row := s.db.QueryRow(`SELECT id, org_id, name, subject, content FROM templates WHERE org_id = ? AND name = ?`, orgID.String(), name)
	t := &domain.Template{}
	var id, oid string
	err := row.Scan(&id, &oid, &t.Name, &t.Subject, &t.Content)
	if err != nil {
		return nil, err
	}
	t.ID, _ = uuid.Parse(id)
	t.OrgID, _ = uuid.Parse(oid)
	return t, nil
}

func (s *SQLiteStore) ListTemplatesByOrg(orgID uuid.UUID) ([]*domain.Template, error) {
	rows, err := s.db.Query(`SELECT id, org_id, name, subject, content FROM templates WHERE org_id = ?`, orgID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*domain.Template
	for rows.Next() {
		t := &domain.Template{}
		var id, oid string
		if err := rows.Scan(&id, &oid, &t.Name, &t.Subject, &t.Content); err != nil {
			return nil, err
		}
		t.ID, _ = uuid.Parse(id)
		t.OrgID, _ = uuid.Parse(oid)
		templates = append(templates, t)
	}
	return templates, nil
}

func (s *SQLiteStore) GetTemplateByID(id uuid.UUID) (*domain.Template, error) {
	row := s.db.QueryRow(`SELECT id, org_id, name, subject, content FROM templates WHERE id = ?`, id.String())
	t := &domain.Template{}
	var tid, oid string
	err := row.Scan(&tid, &oid, &t.Name, &t.Subject, &t.Content)
	if err != nil {
		return nil, err
	}
	t.ID, _ = uuid.Parse(tid)
	t.OrgID, _ = uuid.Parse(oid)
	return t, nil
}

func (s *SQLiteStore) DeleteTemplate(id uuid.UUID) error {
	_, err := s.db.Exec(`DELETE FROM templates WHERE id = ?`, id.String())
	return err
}

// TrackingEventRepository implementation
func (s *SQLiteStore) CreateTrackingEvent(event *domain.TrackingEvent) error {
	_, err := s.db.Exec(`INSERT INTO tracking_events (id, message_id, event_type, link_url, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)`,
		event.ID.String(), event.MessageID.String(), event.EventType, event.LinkURL, event.IPAddress, event.UserAgent)
	return err
}

func (s *SQLiteStore) GetTrackingEventsByMessage(messageID uuid.UUID) ([]*domain.TrackingEvent, error) {
	rows, err := s.db.Query(`SELECT id, message_id, event_type, link_url, ip_address, user_agent, created_at FROM tracking_events WHERE message_id = ?`, messageID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*domain.TrackingEvent
	for rows.Next() {
		e := &domain.TrackingEvent{}
		var id, msgID string
		if err := rows.Scan(&id, &msgID, &e.EventType, &e.LinkURL, &e.IPAddress, &e.UserAgent, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.ID, _ = uuid.Parse(id)
		e.MessageID, _ = uuid.Parse(msgID)
		events = append(events, e)
	}
	return events, nil
}

// OrganizationRepository implementation
func (s *SQLiteStore) CreateOrg(org *domain.Organization) error {
	_, err := s.db.Exec(`INSERT INTO organizations (id, name, billing_tier) VALUES (?, ?, ?)`,
		org.ID.String(), org.Name, org.BillingTier)
	return err
}

func (s *SQLiteStore) GetOrgByID(id uuid.UUID) (*domain.Organization, error) {
	row := s.db.QueryRow(`SELECT id, name, billing_tier, created_at FROM organizations WHERE id = ?`, id.String())
	org := &domain.Organization{}
	var orgID string
	err := row.Scan(&orgID, &org.Name, &org.BillingTier, &org.CreatedAt)
	if err != nil {
		return nil, err
	}
	org.ID, _ = uuid.Parse(orgID)
	return org, nil
}

func (s *SQLiteStore) ListOrgs() ([]*domain.Organization, error) {
	rows, err := s.db.Query(`SELECT id, name, billing_tier, created_at FROM organizations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []*domain.Organization
	for rows.Next() {
		org := &domain.Organization{}
		var id string
		if err := rows.Scan(&id, &org.Name, &org.BillingTier, &org.CreatedAt); err != nil {
			return nil, err
		}
		org.ID, _ = uuid.Parse(id)
		orgs = append(orgs, org)
	}
	return orgs, nil
}

// LocalBlobStorage implementation
type LocalBlobStorage struct {
	baseDir string
}

func NewLocalBlobStorage(baseDir string) *LocalBlobStorage {
	return &LocalBlobStorage{baseDir: baseDir}
}

func (l *LocalBlobStorage) Put(path string, data []byte) error {
	fullPath := filepath.Join(l.baseDir, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(fullPath, data, 0644)
}

func (l *LocalBlobStorage) Get(path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(l.baseDir, path))
}

func (l *LocalBlobStorage) Delete(path string) error {
	return os.Remove(filepath.Join(l.baseDir, path))
}
