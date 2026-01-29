package autoresponder

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ResponderType defines the type of auto-responder
type ResponderType string

const (
	TypeOutOfOffice  ResponderType = "out_of_office"
	TypeVacation     ResponderType = "vacation"
	TypeAway         ResponderType = "away"
	TypeCustom       ResponderType = "custom"
	TypeWelcome      ResponderType = "welcome"       // For new contacts
	TypeAcknowledge  ResponderType = "acknowledge"   // Receipt acknowledgment
)

// ResponderStatus represents the status of an auto-responder
type ResponderStatus string

const (
	StatusActive   ResponderStatus = "active"
	StatusInactive ResponderStatus = "inactive"
	StatusScheduled ResponderStatus = "scheduled"
)

// AutoResponder represents an automatic email reply configuration
type AutoResponder struct {
	ID              uuid.UUID       `json:"id"`
	OrgID           uuid.UUID       `json:"org_id"`
	AccountID       uuid.UUID       `json:"account_id"`
	Type            ResponderType   `json:"type"`
	Status          ResponderStatus `json:"status"`
	
	// Content
	Subject         string          `json:"subject"`
	Body            string          `json:"body"`
	BodyHTML        string          `json:"body_html,omitempty"`
	
	// Scheduling
	StartDate       *time.Time      `json:"start_date,omitempty"`
	EndDate         *time.Time      `json:"end_date,omitempty"`
	ActiveDays      []int           `json:"active_days,omitempty"`    // 0=Sun, 6=Sat
	ActiveStartTime string          `json:"active_start_time,omitempty"` // HH:MM
	ActiveEndTime   string          `json:"active_end_time,omitempty"`   // HH:MM
	Timezone        string          `json:"timezone"`
	
	// Filters
	OnlyContacts    bool            `json:"only_contacts"`     // Only reply to known contacts
	OnlyFirstTime   bool            `json:"only_first_time"`   // Only reply once per sender
	ExcludeDomains  []string        `json:"exclude_domains,omitempty"`
	ExcludeAddresses []string       `json:"exclude_addresses,omitempty"`
	IncludeOnly     []string        `json:"include_only,omitempty"` // Only reply to these
	ExcludeMailingLists bool        `json:"exclude_mailing_lists"`
	ExcludeNoReply  bool            `json:"exclude_no_reply"`
	MinInterval     int             `json:"min_interval_hours"` // Min hours between replies to same sender
	
	// Tracking
	ReplyCount      int             `json:"reply_count"`
	LastTriggeredAt *time.Time      `json:"last_triggered_at,omitempty"`
	
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// ReplyLog tracks auto-replies sent
type ReplyLog struct {
	ID            uuid.UUID `json:"id"`
	ResponderID   uuid.UUID `json:"responder_id"`
	AccountID     uuid.UUID `json:"account_id"`
	OriginalFrom  string    `json:"original_from"`
	OriginalMsgID string    `json:"original_msg_id"`
	SentAt        time.Time `json:"sent_at"`
}

// Service manages auto-responders
type Service struct {
	mu        sync.RWMutex
	repo      Repository
	sender    EmailSender
	contacts  ContactChecker
	logger    Logger
	cache     map[uuid.UUID]*AutoResponder // accountID -> active responder
}

// EmailSender interface for sending replies
type EmailSender interface {
	SendReply(ctx context.Context, to, subject, body, bodyHTML, inReplyTo, references string) error
}

// ContactChecker interface for checking if sender is a known contact
type ContactChecker interface {
	IsContact(ctx context.Context, accountID uuid.UUID, email string) (bool, error)
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// Repository interface
type Repository interface {
	CreateAutoResponder(ctx context.Context, ar *AutoResponder) error
	GetAutoResponder(ctx context.Context, id uuid.UUID) (*AutoResponder, error)
	GetActiveResponder(ctx context.Context, accountID uuid.UUID) (*AutoResponder, error)
	UpdateAutoResponder(ctx context.Context, ar *AutoResponder) error
	DeleteAutoResponder(ctx context.Context, id uuid.UUID) error
	ListByAccount(ctx context.Context, accountID uuid.UUID) ([]*AutoResponder, error)
	
	// Reply log
	LogReply(ctx context.Context, log *ReplyLog) error
	GetLastReply(ctx context.Context, responderID uuid.UUID, fromEmail string) (*ReplyLog, error)
	GetReplyCount(ctx context.Context, responderID uuid.UUID) (int, error)
}

// NewService creates a new auto-responder service
func NewService(repo Repository, sender EmailSender, contacts ContactChecker, logger Logger) *Service {
	return &Service{
		repo:     repo,
		sender:   sender,
		contacts: contacts,
		logger:   logger,
		cache:    make(map[uuid.UUID]*AutoResponder),
	}
}

// IncomingEmail represents an incoming email to check for auto-reply
type IncomingEmail struct {
	From       string
	To         string
	Subject    string
	MessageID  string
	References string
	Headers    map[string]string
	IsMailingList bool
}

// ShouldReply checks if an auto-reply should be sent and returns the response if so
func (s *Service) ShouldReply(ctx context.Context, accountID uuid.UUID, email *IncomingEmail) (*AutoResponder, error) {
	// Get active responder
	responder, err := s.getActiveResponder(ctx, accountID)
	if err != nil || responder == nil {
		return nil, err
	}

	// Check if responder is currently active
	if !s.isCurrentlyActive(responder) {
		return nil, nil
	}

	// Apply filters
	if !s.passesFilters(ctx, accountID, responder, email) {
		return nil, nil
	}

	// Check minimum interval
	if responder.MinInterval > 0 {
		lastReply, err := s.repo.GetLastReply(ctx, responder.ID, email.From)
		if err == nil && lastReply != nil {
			minTime := lastReply.SentAt.Add(time.Duration(responder.MinInterval) * time.Hour)
			if time.Now().Before(minTime) {
				s.logger.Debug("skipping reply due to min interval", "from", email.From)
				return nil, nil
			}
		}
	}

	return responder, nil
}

// SendAutoReply sends an auto-reply for an incoming email
func (s *Service) SendAutoReply(ctx context.Context, accountID uuid.UUID, email *IncomingEmail) error {
	responder, err := s.ShouldReply(ctx, accountID, email)
	if err != nil || responder == nil {
		return err
	}

	// Build reply subject
	subject := responder.Subject
	if subject == "" {
		subject = "Re: " + email.Subject
	} else if !strings.HasPrefix(strings.ToLower(email.Subject), "re:") {
		subject = "Re: " + email.Subject + " - " + responder.Subject
	}

	// Build references header
	references := email.MessageID
	if email.References != "" {
		references = email.References + " " + email.MessageID
	}

	// Send the reply
	err = s.sender.SendReply(ctx, email.From, subject, responder.Body, responder.BodyHTML, email.MessageID, references)
	if err != nil {
		s.logger.Error("failed to send auto-reply", "to", email.From, "error", err)
		return err
	}

	// Log the reply
	log := &ReplyLog{
		ID:            uuid.New(),
		ResponderID:   responder.ID,
		AccountID:     accountID,
		OriginalFrom:  email.From,
		OriginalMsgID: email.MessageID,
		SentAt:        time.Now(),
	}
	if err := s.repo.LogReply(ctx, log); err != nil {
		s.logger.Error("failed to log auto-reply", "error", err)
	}

	// Update responder stats
	responder.ReplyCount++
	now := time.Now()
	responder.LastTriggeredAt = &now
	s.repo.UpdateAutoResponder(ctx, responder)

	s.logger.Info("sent auto-reply", "to", email.From, "responder", responder.ID)
	return nil
}

func (s *Service) getActiveResponder(ctx context.Context, accountID uuid.UUID) (*AutoResponder, error) {
	// Check cache first
	s.mu.RLock()
	if cached, ok := s.cache[accountID]; ok {
		s.mu.RUnlock()
		return cached, nil
	}
	s.mu.RUnlock()

	// Get from repo
	responder, err := s.repo.GetActiveResponder(ctx, accountID)
	if err != nil || responder == nil {
		return nil, err
	}

	// Cache it
	s.mu.Lock()
	s.cache[accountID] = responder
	s.mu.Unlock()

	return responder, nil
}

func (s *Service) isCurrentlyActive(ar *AutoResponder) bool {
	now := time.Now()

	// Check date range
	if ar.StartDate != nil && now.Before(*ar.StartDate) {
		return false
	}
	if ar.EndDate != nil && now.After(*ar.EndDate) {
		return false
	}

	// Check day of week
	if len(ar.ActiveDays) > 0 {
		today := int(now.Weekday())
		found := false
		for _, day := range ar.ActiveDays {
			if day == today {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check time of day
	if ar.ActiveStartTime != "" && ar.ActiveEndTime != "" {
		currentTime := now.Format("15:04")
		if currentTime < ar.ActiveStartTime || currentTime > ar.ActiveEndTime {
			return false
		}
	}

	return true
}

func (s *Service) passesFilters(ctx context.Context, accountID uuid.UUID, ar *AutoResponder, email *IncomingEmail) bool {
	from := strings.ToLower(email.From)
	fromDomain := extractDomain(from)

	// Check exclude no-reply addresses
	if ar.ExcludeNoReply {
		noReplyPatterns := []string{"noreply", "no-reply", "donotreply", "do-not-reply", "mailer-daemon", "postmaster"}
		for _, pattern := range noReplyPatterns {
			if strings.Contains(from, pattern) {
				return false
			}
		}
	}

	// Check exclude mailing lists
	if ar.ExcludeMailingLists && email.IsMailingList {
		return false
	}

	// Check mailing list headers
	if ar.ExcludeMailingLists {
		listHeaders := []string{"List-Unsubscribe", "List-Id", "Mailing-List", "X-Mailing-List"}
		for _, h := range listHeaders {
			if _, ok := email.Headers[h]; ok {
				return false
			}
		}
	}

	// Check excluded domains
	for _, domain := range ar.ExcludeDomains {
		if strings.EqualFold(fromDomain, domain) {
			return false
		}
	}

	// Check excluded addresses
	for _, addr := range ar.ExcludeAddresses {
		if strings.EqualFold(from, addr) {
			return false
		}
	}

	// Check include-only list
	if len(ar.IncludeOnly) > 0 {
		found := false
		for _, addr := range ar.IncludeOnly {
			if strings.EqualFold(from, addr) || strings.EqualFold(fromDomain, addr) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check contacts-only filter
	if ar.OnlyContacts && s.contacts != nil {
		isContact, err := s.contacts.IsContact(ctx, accountID, from)
		if err != nil || !isContact {
			return false
		}
	}

	// Check first-time-only filter
	if ar.OnlyFirstTime {
		lastReply, err := s.repo.GetLastReply(ctx, ar.ID, from)
		if err == nil && lastReply != nil {
			return false
		}
	}

	return true
}

// InvalidateCache removes an account's responder from cache
func (s *Service) InvalidateCache(accountID uuid.UUID) {
	s.mu.Lock()
	delete(s.cache, accountID)
	s.mu.Unlock()
}

// Create creates a new auto-responder
func (s *Service) Create(ctx context.Context, ar *AutoResponder) error {
	if ar.ID == uuid.Nil {
		ar.ID = uuid.New()
	}
	if ar.Status == "" {
		ar.Status = StatusInactive
	}
	if ar.Timezone == "" {
		ar.Timezone = "UTC"
	}
	ar.CreatedAt = time.Now()
	ar.UpdatedAt = time.Now()

	err := s.repo.CreateAutoResponder(ctx, ar)
	if err == nil {
		s.InvalidateCache(ar.AccountID)
	}
	return err
}

// Update updates an auto-responder
func (s *Service) Update(ctx context.Context, ar *AutoResponder) error {
	ar.UpdatedAt = time.Now()
	err := s.repo.UpdateAutoResponder(ctx, ar)
	if err == nil {
		s.InvalidateCache(ar.AccountID)
	}
	return err
}

// Delete deletes an auto-responder
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	ar, err := s.repo.GetAutoResponder(ctx, id)
	if err != nil {
		return err
	}

	err = s.repo.DeleteAutoResponder(ctx, id)
	if err == nil && ar != nil {
		s.InvalidateCache(ar.AccountID)
	}
	return err
}

// Activate activates an auto-responder (deactivates any other active ones)
func (s *Service) Activate(ctx context.Context, id uuid.UUID) error {
	ar, err := s.repo.GetAutoResponder(ctx, id)
	if err != nil {
		return err
	}

	// Deactivate current active responder if any
	current, err := s.repo.GetActiveResponder(ctx, ar.AccountID)
	if err == nil && current != nil && current.ID != id {
		current.Status = StatusInactive
		s.repo.UpdateAutoResponder(ctx, current)
	}

	ar.Status = StatusActive
	ar.UpdatedAt = time.Now()
	err = s.repo.UpdateAutoResponder(ctx, ar)
	if err == nil {
		s.InvalidateCache(ar.AccountID)
	}
	return err
}

// Deactivate deactivates an auto-responder
func (s *Service) Deactivate(ctx context.Context, id uuid.UUID) error {
	ar, err := s.repo.GetAutoResponder(ctx, id)
	if err != nil {
		return err
	}

	ar.Status = StatusInactive
	ar.UpdatedAt = time.Now()
	err = s.repo.UpdateAutoResponder(ctx, ar)
	if err == nil {
		s.InvalidateCache(ar.AccountID)
	}
	return err
}

func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// SQLiteRepository implements Repository for SQLite
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new SQLite repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS auto_responders (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'out_of_office',
			status TEXT NOT NULL DEFAULT 'inactive',
			subject TEXT NOT NULL,
			body TEXT NOT NULL,
			body_html TEXT,
			start_date DATETIME,
			end_date DATETIME,
			active_days TEXT,
			active_start_time TEXT,
			active_end_time TEXT,
			timezone TEXT DEFAULT 'UTC',
			only_contacts INTEGER DEFAULT 0,
			only_first_time INTEGER DEFAULT 0,
			exclude_domains TEXT,
			exclude_addresses TEXT,
			include_only TEXT,
			exclude_mailing_lists INTEGER DEFAULT 1,
			exclude_no_reply INTEGER DEFAULT 1,
			min_interval_hours INTEGER DEFAULT 4,
			reply_count INTEGER DEFAULT 0,
			last_triggered_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auto_responders_account ON auto_responders(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_auto_responders_status ON auto_responders(account_id, status)`,
		
		`CREATE TABLE IF NOT EXISTS auto_responder_logs (
			id TEXT PRIMARY KEY,
			responder_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			original_from TEXT NOT NULL,
			original_msg_id TEXT,
			sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (responder_id) REFERENCES auto_responders(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auto_responder_logs_lookup ON auto_responder_logs(responder_id, original_from)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) CreateAutoResponder(ctx context.Context, ar *AutoResponder) error {
	daysJSON, _ := json.Marshal(ar.ActiveDays)
	excludeDomainsJSON, _ := json.Marshal(ar.ExcludeDomains)
	excludeAddrsJSON, _ := json.Marshal(ar.ExcludeAddresses)
	includeOnlyJSON, _ := json.Marshal(ar.IncludeOnly)

	query := `
	INSERT INTO auto_responders (
		id, org_id, account_id, type, status, subject, body, body_html,
		start_date, end_date, active_days, active_start_time, active_end_time, timezone,
		only_contacts, only_first_time, exclude_domains, exclude_addresses, include_only,
		exclude_mailing_lists, exclude_no_reply, min_interval_hours, reply_count,
		last_triggered_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		ar.ID.String(), ar.OrgID.String(), ar.AccountID.String(), ar.Type, ar.Status,
		ar.Subject, ar.Body, ar.BodyHTML, ar.StartDate, ar.EndDate,
		string(daysJSON), ar.ActiveStartTime, ar.ActiveEndTime, ar.Timezone,
		ar.OnlyContacts, ar.OnlyFirstTime, string(excludeDomainsJSON),
		string(excludeAddrsJSON), string(includeOnlyJSON), ar.ExcludeMailingLists,
		ar.ExcludeNoReply, ar.MinInterval, ar.ReplyCount, ar.LastTriggeredAt,
		ar.CreatedAt, ar.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetAutoResponder(ctx context.Context, id uuid.UUID) (*AutoResponder, error) {
	query := `
	SELECT id, org_id, account_id, type, status, subject, body, body_html,
		start_date, end_date, active_days, active_start_time, active_end_time, timezone,
		only_contacts, only_first_time, exclude_domains, exclude_addresses, include_only,
		exclude_mailing_lists, exclude_no_reply, min_interval_hours, reply_count,
		last_triggered_at, created_at, updated_at
	FROM auto_responders WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanAutoResponder(row)
}

func (r *SQLiteRepository) GetActiveResponder(ctx context.Context, accountID uuid.UUID) (*AutoResponder, error) {
	query := `
	SELECT id, org_id, account_id, type, status, subject, body, body_html,
		start_date, end_date, active_days, active_start_time, active_end_time, timezone,
		only_contacts, only_first_time, exclude_domains, exclude_addresses, include_only,
		exclude_mailing_lists, exclude_no_reply, min_interval_hours, reply_count,
		last_triggered_at, created_at, updated_at
	FROM auto_responders WHERE account_id = ? AND status = 'active' LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, accountID.String())
	return r.scanAutoResponder(row)
}

func (r *SQLiteRepository) UpdateAutoResponder(ctx context.Context, ar *AutoResponder) error {
	daysJSON, _ := json.Marshal(ar.ActiveDays)
	excludeDomainsJSON, _ := json.Marshal(ar.ExcludeDomains)
	excludeAddrsJSON, _ := json.Marshal(ar.ExcludeAddresses)
	includeOnlyJSON, _ := json.Marshal(ar.IncludeOnly)

	query := `
	UPDATE auto_responders SET
		type = ?, status = ?, subject = ?, body = ?, body_html = ?,
		start_date = ?, end_date = ?, active_days = ?, active_start_time = ?, active_end_time = ?,
		timezone = ?, only_contacts = ?, only_first_time = ?, exclude_domains = ?,
		exclude_addresses = ?, include_only = ?, exclude_mailing_lists = ?, exclude_no_reply = ?,
		min_interval_hours = ?, reply_count = ?, last_triggered_at = ?, updated_at = ?
	WHERE id = ?
	`

	_, err := r.db.ExecContext(ctx, query,
		ar.Type, ar.Status, ar.Subject, ar.Body, ar.BodyHTML,
		ar.StartDate, ar.EndDate, string(daysJSON), ar.ActiveStartTime, ar.ActiveEndTime,
		ar.Timezone, ar.OnlyContacts, ar.OnlyFirstTime, string(excludeDomainsJSON),
		string(excludeAddrsJSON), string(includeOnlyJSON), ar.ExcludeMailingLists,
		ar.ExcludeNoReply, ar.MinInterval, ar.ReplyCount, ar.LastTriggeredAt,
		time.Now(), ar.ID.String())

	return err
}

func (r *SQLiteRepository) DeleteAutoResponder(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM auto_responders WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) ListByAccount(ctx context.Context, accountID uuid.UUID) ([]*AutoResponder, error) {
	query := `
	SELECT id, org_id, account_id, type, status, subject, body, body_html,
		start_date, end_date, active_days, active_start_time, active_end_time, timezone,
		only_contacts, only_first_time, exclude_domains, exclude_addresses, include_only,
		exclude_mailing_lists, exclude_no_reply, min_interval_hours, reply_count,
		last_triggered_at, created_at, updated_at
	FROM auto_responders WHERE account_id = ? ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var responders []*AutoResponder
	for rows.Next() {
		ar, err := r.scanAutoResponderRow(rows)
		if err != nil {
			return nil, err
		}
		responders = append(responders, ar)
	}
	return responders, rows.Err()
}

func (r *SQLiteRepository) LogReply(ctx context.Context, log *ReplyLog) error {
	query := `
	INSERT INTO auto_responder_logs (id, responder_id, account_id, original_from, original_msg_id, sent_at)
	VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query,
		log.ID.String(), log.ResponderID.String(), log.AccountID.String(),
		log.OriginalFrom, log.OriginalMsgID, log.SentAt)
	return err
}

func (r *SQLiteRepository) GetLastReply(ctx context.Context, responderID uuid.UUID, fromEmail string) (*ReplyLog, error) {
	query := `
	SELECT id, responder_id, account_id, original_from, original_msg_id, sent_at
	FROM auto_responder_logs 
	WHERE responder_id = ? AND original_from = ?
	ORDER BY sent_at DESC LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, responderID.String(), fromEmail)

	var log ReplyLog
	var idStr, responderIDStr, accountIDStr string
	err := row.Scan(&idStr, &responderIDStr, &accountIDStr, &log.OriginalFrom, &log.OriginalMsgID, &log.SentAt)
	if err != nil {
		return nil, err
	}

	log.ID, _ = uuid.Parse(idStr)
	log.ResponderID, _ = uuid.Parse(responderIDStr)
	log.AccountID, _ = uuid.Parse(accountIDStr)

	return &log, nil
}

func (r *SQLiteRepository) GetReplyCount(ctx context.Context, responderID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM auto_responder_logs WHERE responder_id = ?", responderID.String()).Scan(&count)
	return count, err
}

func (r *SQLiteRepository) scanAutoResponder(row *sql.Row) (*AutoResponder, error) {
	var ar AutoResponder
	var idStr, orgIDStr, accountIDStr string
	var daysJSON, excludeDomainsJSON, excludeAddrsJSON, includeOnlyJSON string

	err := row.Scan(
		&idStr, &orgIDStr, &accountIDStr, &ar.Type, &ar.Status,
		&ar.Subject, &ar.Body, &ar.BodyHTML, &ar.StartDate, &ar.EndDate,
		&daysJSON, &ar.ActiveStartTime, &ar.ActiveEndTime, &ar.Timezone,
		&ar.OnlyContacts, &ar.OnlyFirstTime, &excludeDomainsJSON,
		&excludeAddrsJSON, &includeOnlyJSON, &ar.ExcludeMailingLists,
		&ar.ExcludeNoReply, &ar.MinInterval, &ar.ReplyCount, &ar.LastTriggeredAt,
		&ar.CreatedAt, &ar.UpdatedAt)
	if err != nil {
		return nil, err
	}

	ar.ID, _ = uuid.Parse(idStr)
	ar.OrgID, _ = uuid.Parse(orgIDStr)
	ar.AccountID, _ = uuid.Parse(accountIDStr)
	_ = json.Unmarshal([]byte(daysJSON), &ar.ActiveDays)
	_ = json.Unmarshal([]byte(excludeDomainsJSON), &ar.ExcludeDomains)
	_ = json.Unmarshal([]byte(excludeAddrsJSON), &ar.ExcludeAddresses)
	_ = json.Unmarshal([]byte(includeOnlyJSON), &ar.IncludeOnly)

	return &ar, nil
}

func (r *SQLiteRepository) scanAutoResponderRow(rows *sql.Rows) (*AutoResponder, error) {
	var ar AutoResponder
	var idStr, orgIDStr, accountIDStr string
	var daysJSON, excludeDomainsJSON, excludeAddrsJSON, includeOnlyJSON string

	err := rows.Scan(
		&idStr, &orgIDStr, &accountIDStr, &ar.Type, &ar.Status,
		&ar.Subject, &ar.Body, &ar.BodyHTML, &ar.StartDate, &ar.EndDate,
		&daysJSON, &ar.ActiveStartTime, &ar.ActiveEndTime, &ar.Timezone,
		&ar.OnlyContacts, &ar.OnlyFirstTime, &excludeDomainsJSON,
		&excludeAddrsJSON, &includeOnlyJSON, &ar.ExcludeMailingLists,
		&ar.ExcludeNoReply, &ar.MinInterval, &ar.ReplyCount, &ar.LastTriggeredAt,
		&ar.CreatedAt, &ar.UpdatedAt)
	if err != nil {
		return nil, err
	}

	ar.ID, _ = uuid.Parse(idStr)
	ar.OrgID, _ = uuid.Parse(orgIDStr)
	ar.AccountID, _ = uuid.Parse(accountIDStr)
	_ = json.Unmarshal([]byte(daysJSON), &ar.ActiveDays)
	_ = json.Unmarshal([]byte(excludeDomainsJSON), &ar.ExcludeDomains)
	_ = json.Unmarshal([]byte(excludeAddrsJSON), &ar.ExcludeAddresses)
	_ = json.Unmarshal([]byte(includeOnlyJSON), &ar.IncludeOnly)

	return &ar, nil
}
