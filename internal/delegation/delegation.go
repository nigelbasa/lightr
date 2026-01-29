package delegation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Permission types for mailbox delegation
type Permission string

const (
	PermissionRead       Permission = "read"        // Read emails
	PermissionWrite      Permission = "write"       // Compose drafts
	PermissionSend       Permission = "send"        // Send emails
	PermissionSendAs     Permission = "send_as"     // Send as mailbox owner
	PermissionSendOnBehalf Permission = "send_on_behalf" // Send on behalf of owner
	PermissionDelete     Permission = "delete"      // Delete emails
	PermissionManage     Permission = "manage"      // Manage folders, rules
	PermissionFullAccess Permission = "full_access" // All permissions
)

// DelegationType represents the type of delegation
type DelegationType string

const (
	TypePersonal   DelegationType = "personal"   // Personal delegation by user
	TypeShared     DelegationType = "shared"     // Shared mailbox (no owner)
	TypeResource   DelegationType = "resource"   // Resource mailbox (room, equipment)
	TypeDistribution DelegationType = "distribution" // Distribution group
)

// Mailbox represents a mailbox that can be delegated
type Mailbox struct {
	ID          uuid.UUID      `json:"id"`
	OrgID       uuid.UUID      `json:"org_id"`
	Email       string         `json:"email"`
	DisplayName string         `json:"display_name"`
	Type        DelegationType `json:"type"`
	OwnerID     *uuid.UUID     `json:"owner_id,omitempty"` // nil for shared mailboxes
	
	// Settings
	AutoAccept      bool          `json:"auto_accept,omitempty"`       // For resource mailboxes
	BookingPolicy   *BookingPolicy `json:"booking_policy,omitempty"`   // For resource mailboxes
	ForwardingEmail string        `json:"forwarding_email,omitempty"`
	
	// Metadata
	Description string    `json:"description,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BookingPolicy for resource mailboxes
type BookingPolicy struct {
	AllowConflicts       bool     `json:"allow_conflicts"`
	MaxDurationMinutes   int      `json:"max_duration_minutes"`
	MinLeadTimeMinutes   int      `json:"min_lead_time_minutes"`
	MaxLeadTimeDays      int      `json:"max_lead_time_days"`
	AllowRecurring       bool     `json:"allow_recurring"`
	RequireApproval      bool     `json:"require_approval"`
	ApproverIDs          []uuid.UUID `json:"approver_ids,omitempty"`
	AllowedBookerDomains []string `json:"allowed_booker_domains,omitempty"`
}

// Delegation represents access granted to a mailbox
type Delegation struct {
	ID          uuid.UUID    `json:"id"`
	MailboxID   uuid.UUID    `json:"mailbox_id"`
	DelegateID  uuid.UUID    `json:"delegate_id"` // User or group who has access
	DelegateType string      `json:"delegate_type"` // "user" or "group"
	
	Permissions []Permission `json:"permissions"`
	
	// Scope restrictions
	FolderIDs   []uuid.UUID  `json:"folder_ids,omitempty"` // Limit to specific folders
	ReadOnly    bool         `json:"read_only"`
	
	// Time restrictions
	StartDate   *time.Time   `json:"start_date,omitempty"`
	EndDate     *time.Time   `json:"end_date,omitempty"`
	
	// Metadata
	GrantedBy   uuid.UUID    `json:"granted_by"`
	Reason      string       `json:"reason,omitempty"`
	IsActive    bool         `json:"is_active"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// SendAsConfig configures send-as permissions
type SendAsConfig struct {
	ID           uuid.UUID `json:"id"`
	MailboxID    uuid.UUID `json:"mailbox_id"`    // Mailbox to send as
	DelegateID   uuid.UUID `json:"delegate_id"`   // User who can send as
	
	// Send identity
	DisplayName  string    `json:"display_name,omitempty"` // Override display name
	ReplyTo      string    `json:"reply_to,omitempty"`     // Override reply-to
	
	// Options
	AddSignature bool      `json:"add_signature"`    // Add mailbox signature
	CopyToSent   bool      `json:"copy_to_sent"`     // Copy to mailbox's Sent folder
	
	// Approval
	RequireApproval bool   `json:"require_approval"`
	ApproverIDs    []uuid.UUID `json:"approver_ids,omitempty"`
	
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AccessLog records mailbox access
type AccessLog struct {
	ID          uuid.UUID `json:"id"`
	MailboxID   uuid.UUID `json:"mailbox_id"`
	AccessedBy  uuid.UUID `json:"accessed_by"`
	AccessType  string    `json:"access_type"` // "read", "send", "delete", etc.
	MessageID   *uuid.UUID `json:"message_id,omitempty"`
	FolderID    *uuid.UUID `json:"folder_id,omitempty"`
	Details     string    `json:"details,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// Service manages mailbox delegation
type Service struct {
	mu     sync.RWMutex
	repo   Repository
	cache  *delegationCache
	logger Logger
}

type delegationCache struct {
	mu          sync.RWMutex
	delegations map[uuid.UUID][]*Delegation // mailboxID -> delegations
	userAccess  map[uuid.UUID][]uuid.UUID   // userID -> mailboxIDs they can access
	expiry      time.Time
	ttl         time.Duration
}

// Repository interface
type Repository interface {
	// Mailboxes
	SaveMailbox(ctx context.Context, mailbox *Mailbox) error
	GetMailbox(ctx context.Context, id uuid.UUID) (*Mailbox, error)
	GetMailboxByEmail(ctx context.Context, email string) (*Mailbox, error)
	GetMailboxesByOwner(ctx context.Context, ownerID uuid.UUID) ([]*Mailbox, error)
	GetSharedMailboxes(ctx context.Context, orgID uuid.UUID) ([]*Mailbox, error)
	DeleteMailbox(ctx context.Context, id uuid.UUID) error
	
	// Delegations
	SaveDelegation(ctx context.Context, delegation *Delegation) error
	GetDelegation(ctx context.Context, id uuid.UUID) (*Delegation, error)
	GetDelegationsForMailbox(ctx context.Context, mailboxID uuid.UUID) ([]*Delegation, error)
	GetDelegationsForUser(ctx context.Context, userID uuid.UUID) ([]*Delegation, error)
	GetActiveDelegation(ctx context.Context, mailboxID, delegateID uuid.UUID) (*Delegation, error)
	DeleteDelegation(ctx context.Context, id uuid.UUID) error
	
	// Send-as configs
	SaveSendAsConfig(ctx context.Context, config *SendAsConfig) error
	GetSendAsConfig(ctx context.Context, id uuid.UUID) (*SendAsConfig, error)
	GetSendAsConfigsForUser(ctx context.Context, userID uuid.UUID) ([]*SendAsConfig, error)
	DeleteSendAsConfig(ctx context.Context, id uuid.UUID) error
	
	// Access logs
	SaveAccessLog(ctx context.Context, log *AccessLog) error
	GetAccessLogs(ctx context.Context, query *AccessLogQuery) ([]*AccessLog, error)
}

// AccessLogQuery for querying access logs
type AccessLogQuery struct {
	MailboxID  *uuid.UUID
	AccessedBy *uuid.UUID
	AccessType string
	DateFrom   *time.Time
	DateTo     *time.Time
	Limit      int
	Offset     int
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewService creates a new delegation service
func NewService(repo Repository, logger Logger) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
		cache: &delegationCache{
			delegations: make(map[uuid.UUID][]*Delegation),
			userAccess:  make(map[uuid.UUID][]uuid.UUID),
			ttl:         5 * time.Minute,
		},
	}
}

// Mailbox Management

// CreateMailbox creates a new mailbox
func (s *Service) CreateMailbox(ctx context.Context, mailbox *Mailbox) error {
	mailbox.ID = uuid.New()
	mailbox.IsActive = true
	mailbox.CreatedAt = time.Now()
	mailbox.UpdatedAt = time.Now()

	if err := s.repo.SaveMailbox(ctx, mailbox); err != nil {
		return err
	}

	s.logger.Info("created mailbox", "id", mailbox.ID, "email", mailbox.Email, "type", mailbox.Type)
	return nil
}

// GetMailbox retrieves a mailbox by ID
func (s *Service) GetMailbox(ctx context.Context, id uuid.UUID) (*Mailbox, error) {
	return s.repo.GetMailbox(ctx, id)
}

// GetAccessibleMailboxes returns all mailboxes a user can access
func (s *Service) GetAccessibleMailboxes(ctx context.Context, userID uuid.UUID) ([]*Mailbox, error) {
	// Get user's own mailboxes
	ownMailboxes, err := s.repo.GetMailboxesByOwner(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get delegated mailboxes
	delegations, err := s.repo.GetDelegationsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	mailboxMap := make(map[uuid.UUID]*Mailbox)
	for _, m := range ownMailboxes {
		mailboxMap[m.ID] = m
	}

	for _, d := range delegations {
		if !d.IsActive {
			continue
		}
		if d.EndDate != nil && time.Now().After(*d.EndDate) {
			continue
		}
		if d.StartDate != nil && time.Now().Before(*d.StartDate) {
			continue
		}

		if _, exists := mailboxMap[d.MailboxID]; !exists {
			m, err := s.repo.GetMailbox(ctx, d.MailboxID)
			if err == nil && m.IsActive {
				mailboxMap[m.ID] = m
			}
		}
	}

	result := make([]*Mailbox, 0, len(mailboxMap))
	for _, m := range mailboxMap {
		result = append(result, m)
	}

	return result, nil
}

// Delegation Management

// GrantDelegation grants access to a mailbox
func (s *Service) GrantDelegation(ctx context.Context, delegation *Delegation) error {
	// Validate mailbox exists
	mailbox, err := s.repo.GetMailbox(ctx, delegation.MailboxID)
	if err != nil {
		return fmt.Errorf("mailbox not found: %w", err)
	}

	// Check if delegation already exists
	existing, err := s.repo.GetActiveDelegation(ctx, delegation.MailboxID, delegation.DelegateID)
	if err == nil && existing != nil {
		// Update existing delegation
		existing.Permissions = delegation.Permissions
		existing.FolderIDs = delegation.FolderIDs
		existing.ReadOnly = delegation.ReadOnly
		existing.StartDate = delegation.StartDate
		existing.EndDate = delegation.EndDate
		existing.UpdatedAt = time.Now()
		return s.repo.SaveDelegation(ctx, existing)
	}

	delegation.ID = uuid.New()
	delegation.IsActive = true
	delegation.CreatedAt = time.Now()
	delegation.UpdatedAt = time.Now()

	if err := s.repo.SaveDelegation(ctx, delegation); err != nil {
		return err
	}

	// Invalidate cache
	s.invalidateCache(delegation.MailboxID, delegation.DelegateID)

	s.logger.Info("granted delegation",
		"mailbox", mailbox.Email,
		"delegate", delegation.DelegateID,
		"permissions", delegation.Permissions)

	return nil
}

// RevokeDelegation revokes access to a mailbox
func (s *Service) RevokeDelegation(ctx context.Context, delegationID uuid.UUID, revokedBy uuid.UUID) error {
	delegation, err := s.repo.GetDelegation(ctx, delegationID)
	if err != nil {
		return err
	}

	delegation.IsActive = false
	delegation.UpdatedAt = time.Now()

	if err := s.repo.SaveDelegation(ctx, delegation); err != nil {
		return err
	}

	// Invalidate cache
	s.invalidateCache(delegation.MailboxID, delegation.DelegateID)

	s.logger.Info("revoked delegation", "id", delegationID, "revoked_by", revokedBy)
	return nil
}

// GetDelegationsForMailbox returns all delegations for a mailbox
func (s *Service) GetDelegationsForMailbox(ctx context.Context, mailboxID uuid.UUID) ([]*Delegation, error) {
	return s.repo.GetDelegationsForMailbox(ctx, mailboxID)
}

// Permission Checking

// HasPermission checks if a user has a specific permission on a mailbox
func (s *Service) HasPermission(ctx context.Context, userID, mailboxID uuid.UUID, permission Permission) (bool, error) {
	// Check cache first
	if cached := s.getCachedPermissions(userID, mailboxID); cached != nil {
		return containsPermission(cached, permission), nil
	}

	// Check if user owns the mailbox
	mailbox, err := s.repo.GetMailbox(ctx, mailboxID)
	if err != nil {
		return false, err
	}
	if mailbox.OwnerID != nil && *mailbox.OwnerID == userID {
		return true, nil // Owner has all permissions
	}

	// Check delegations
	delegation, err := s.repo.GetActiveDelegation(ctx, mailboxID, userID)
	if err != nil {
		return false, nil // No delegation found
	}

	if !delegation.IsActive {
		return false, nil
	}

	// Check time restrictions
	now := time.Now()
	if delegation.StartDate != nil && now.Before(*delegation.StartDate) {
		return false, nil
	}
	if delegation.EndDate != nil && now.After(*delegation.EndDate) {
		return false, nil
	}

	// Check permission
	hasPermission := containsPermission(delegation.Permissions, permission)

	// Cache the result
	s.cachePermissions(userID, mailboxID, delegation.Permissions)

	return hasPermission, nil
}

// GetEffectivePermissions returns all permissions a user has on a mailbox
func (s *Service) GetEffectivePermissions(ctx context.Context, userID, mailboxID uuid.UUID) ([]Permission, error) {
	// Check if user owns the mailbox
	mailbox, err := s.repo.GetMailbox(ctx, mailboxID)
	if err != nil {
		return nil, err
	}
	if mailbox.OwnerID != nil && *mailbox.OwnerID == userID {
		return []Permission{PermissionFullAccess}, nil
	}

	// Get delegation
	delegation, err := s.repo.GetActiveDelegation(ctx, mailboxID, userID)
	if err != nil {
		return nil, nil
	}

	if !delegation.IsActive {
		return nil, nil
	}

	// Check time restrictions
	now := time.Now()
	if delegation.StartDate != nil && now.Before(*delegation.StartDate) {
		return nil, nil
	}
	if delegation.EndDate != nil && now.After(*delegation.EndDate) {
		return nil, nil
	}

	return delegation.Permissions, nil
}

// Send-As Management

// ConfigureSendAs sets up send-as permission
func (s *Service) ConfigureSendAs(ctx context.Context, config *SendAsConfig) error {
	// Verify user has send_as permission
	hasPermission, err := s.HasPermission(ctx, config.DelegateID, config.MailboxID, PermissionSendAs)
	if err != nil {
		return err
	}
	if !hasPermission {
		return fmt.Errorf("user does not have send_as permission")
	}

	config.ID = uuid.New()
	config.IsActive = true
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	return s.repo.SaveSendAsConfig(ctx, config)
}

// GetSendAsIdentities returns all identities a user can send as
func (s *Service) GetSendAsIdentities(ctx context.Context, userID uuid.UUID) ([]*SendAsIdentity, error) {
	configs, err := s.repo.GetSendAsConfigsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	var identities []*SendAsIdentity
	for _, config := range configs {
		if !config.IsActive {
			continue
		}

		mailbox, err := s.repo.GetMailbox(ctx, config.MailboxID)
		if err != nil || !mailbox.IsActive {
			continue
		}

		identity := &SendAsIdentity{
			Email:       mailbox.Email,
			DisplayName: config.DisplayName,
			ReplyTo:     config.ReplyTo,
			MailboxID:   mailbox.ID,
		}
		if identity.DisplayName == "" {
			identity.DisplayName = mailbox.DisplayName
		}

		identities = append(identities, identity)
	}

	return identities, nil
}

// SendAsIdentity represents an identity a user can send as
type SendAsIdentity struct {
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	ReplyTo     string    `json:"reply_to,omitempty"`
	MailboxID   uuid.UUID `json:"mailbox_id"`
}

// Access Logging

// LogAccess records an access event
func (s *Service) LogAccess(ctx context.Context, log *AccessLog) error {
	log.ID = uuid.New()
	log.Timestamp = time.Now()
	return s.repo.SaveAccessLog(ctx, log)
}

// GetAccessLogs retrieves access logs
func (s *Service) GetAccessLogs(ctx context.Context, query *AccessLogQuery) ([]*AccessLog, error) {
	if query.Limit == 0 {
		query.Limit = 100
	}
	return s.repo.GetAccessLogs(ctx, query)
}

// Shared Mailbox Management

// CreateSharedMailbox creates a shared mailbox
func (s *Service) CreateSharedMailbox(ctx context.Context, orgID uuid.UUID, email, displayName string, memberIDs []uuid.UUID, grantedBy uuid.UUID) (*Mailbox, error) {
	mailbox := &Mailbox{
		ID:          uuid.New(),
		OrgID:       orgID,
		Email:       email,
		DisplayName: displayName,
		Type:        TypeShared,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.repo.SaveMailbox(ctx, mailbox); err != nil {
		return nil, err
	}

	// Grant access to members
	for _, memberID := range memberIDs {
		delegation := &Delegation{
			ID:          uuid.New(),
			MailboxID:   mailbox.ID,
			DelegateID:  memberID,
			DelegateType: "user",
			Permissions: []Permission{PermissionRead, PermissionWrite, PermissionSend},
			GrantedBy:   grantedBy,
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		if err := s.repo.SaveDelegation(ctx, delegation); err != nil {
			s.logger.Error("failed to grant delegation", "member", memberID, "error", err)
		}
	}

	s.logger.Info("created shared mailbox", "id", mailbox.ID, "email", email, "members", len(memberIDs))
	return mailbox, nil
}

// CreateResourceMailbox creates a resource mailbox (room, equipment)
func (s *Service) CreateResourceMailbox(ctx context.Context, orgID uuid.UUID, email, displayName, description string, policy *BookingPolicy) (*Mailbox, error) {
	mailbox := &Mailbox{
		ID:            uuid.New(),
		OrgID:         orgID,
		Email:         email,
		DisplayName:   displayName,
		Type:          TypeResource,
		Description:   description,
		AutoAccept:    !policy.RequireApproval,
		BookingPolicy: policy,
		IsActive:      true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := s.repo.SaveMailbox(ctx, mailbox); err != nil {
		return nil, err
	}

	s.logger.Info("created resource mailbox", "id", mailbox.ID, "email", email)
	return mailbox, nil
}

// Cache helpers

func (s *Service) invalidateCache(mailboxID, userID uuid.UUID) {
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()

	delete(s.cache.delegations, mailboxID)
	delete(s.cache.userAccess, userID)
}

func (s *Service) getCachedPermissions(userID, mailboxID uuid.UUID) []Permission {
	s.cache.mu.RLock()
	defer s.cache.mu.RUnlock()

	if time.Now().After(s.cache.expiry) {
		return nil
	}

	delegations, ok := s.cache.delegations[mailboxID]
	if !ok {
		return nil
	}

	for _, d := range delegations {
		if d.DelegateID == userID {
			return d.Permissions
		}
	}
	return nil
}

func (s *Service) cachePermissions(userID, mailboxID uuid.UUID, permissions []Permission) {
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()

	// Create fake delegation for cache
	d := &Delegation{
		MailboxID:   mailboxID,
		DelegateID:  userID,
		Permissions: permissions,
	}

	s.cache.delegations[mailboxID] = append(s.cache.delegations[mailboxID], d)
	s.cache.userAccess[userID] = append(s.cache.userAccess[userID], mailboxID)
	s.cache.expiry = time.Now().Add(s.cache.ttl)
}

// Helpers

func containsPermission(permissions []Permission, target Permission) bool {
	for _, p := range permissions {
		if p == target || p == PermissionFullAccess {
			return true
		}
	}
	return false
}

// SQLiteRepository implements Repository
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS delegate_mailboxes (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			email TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL,
			type TEXT NOT NULL,
			owner_id TEXT,
			auto_accept INTEGER DEFAULT 0,
			booking_policy TEXT,
			forwarding_email TEXT,
			description TEXT,
			is_active INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS delegations (
			id TEXT PRIMARY KEY,
			mailbox_id TEXT NOT NULL,
			delegate_id TEXT NOT NULL,
			delegate_type TEXT NOT NULL DEFAULT 'user',
			permissions TEXT NOT NULL,
			folder_ids TEXT,
			read_only INTEGER DEFAULT 0,
			start_date DATETIME,
			end_date DATETIME,
			granted_by TEXT NOT NULL,
			reason TEXT,
			is_active INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(mailbox_id, delegate_id)
		)`,
		
		`CREATE TABLE IF NOT EXISTS send_as_configs (
			id TEXT PRIMARY KEY,
			mailbox_id TEXT NOT NULL,
			delegate_id TEXT NOT NULL,
			display_name TEXT,
			reply_to TEXT,
			add_signature INTEGER DEFAULT 1,
			copy_to_sent INTEGER DEFAULT 1,
			require_approval INTEGER DEFAULT 0,
			approver_ids TEXT,
			is_active INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(mailbox_id, delegate_id)
		)`,
		
		`CREATE TABLE IF NOT EXISTS delegation_access_logs (
			id TEXT PRIMARY KEY,
			mailbox_id TEXT NOT NULL,
			accessed_by TEXT NOT NULL,
			access_type TEXT NOT NULL,
			message_id TEXT,
			folder_id TEXT,
			details TEXT,
			ip_address TEXT,
			user_agent TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_mailbox_org ON delegate_mailboxes(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_mailbox_owner ON delegate_mailboxes(owner_id)`,
		`CREATE INDEX IF NOT EXISTS idx_delegation_mailbox ON delegations(mailbox_id)`,
		`CREATE INDEX IF NOT EXISTS idx_delegation_delegate ON delegations(delegate_id)`,
		`CREATE INDEX IF NOT EXISTS idx_access_log_mailbox ON delegation_access_logs(mailbox_id)`,
		`CREATE INDEX IF NOT EXISTS idx_access_log_timestamp ON delegation_access_logs(timestamp)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// Mailbox methods
func (r *SQLiteRepository) SaveMailbox(ctx context.Context, mailbox *Mailbox) error {
	var ownerID *string
	if mailbox.OwnerID != nil {
		s := mailbox.OwnerID.String()
		ownerID = &s
	}

	policyJSON, _ := json.Marshal(mailbox.BookingPolicy)

	query := `
	INSERT INTO delegate_mailboxes (
		id, org_id, email, display_name, type, owner_id, auto_accept,
		booking_policy, forwarding_email, description, is_active, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		display_name = excluded.display_name,
		auto_accept = excluded.auto_accept,
		booking_policy = excluded.booking_policy,
		forwarding_email = excluded.forwarding_email,
		description = excluded.description,
		is_active = excluded.is_active,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		mailbox.ID.String(), mailbox.OrgID.String(), mailbox.Email, mailbox.DisplayName,
		mailbox.Type, ownerID, mailbox.AutoAccept, string(policyJSON),
		mailbox.ForwardingEmail, mailbox.Description, mailbox.IsActive,
		mailbox.CreatedAt, mailbox.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetMailbox(ctx context.Context, id uuid.UUID) (*Mailbox, error) {
	query := `
	SELECT id, org_id, email, display_name, type, owner_id, auto_accept,
		booking_policy, forwarding_email, description, is_active, created_at, updated_at
	FROM delegate_mailboxes WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanMailbox(row)
}

func (r *SQLiteRepository) GetMailboxByEmail(ctx context.Context, email string) (*Mailbox, error) {
	query := `
	SELECT id, org_id, email, display_name, type, owner_id, auto_accept,
		booking_policy, forwarding_email, description, is_active, created_at, updated_at
	FROM delegate_mailboxes WHERE email = ?
	`
	row := r.db.QueryRowContext(ctx, query, email)
	return r.scanMailbox(row)
}

func (r *SQLiteRepository) GetMailboxesByOwner(ctx context.Context, ownerID uuid.UUID) ([]*Mailbox, error) {
	query := `
	SELECT id, org_id, email, display_name, type, owner_id, auto_accept,
		booking_policy, forwarding_email, description, is_active, created_at, updated_at
	FROM delegate_mailboxes WHERE owner_id = ? AND is_active = 1
	`
	rows, err := r.db.QueryContext(ctx, query, ownerID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanMailboxes(rows)
}

func (r *SQLiteRepository) GetSharedMailboxes(ctx context.Context, orgID uuid.UUID) ([]*Mailbox, error) {
	query := `
	SELECT id, org_id, email, display_name, type, owner_id, auto_accept,
		booking_policy, forwarding_email, description, is_active, created_at, updated_at
	FROM delegate_mailboxes WHERE org_id = ? AND type = 'shared' AND is_active = 1
	`
	rows, err := r.db.QueryContext(ctx, query, orgID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanMailboxes(rows)
}

func (r *SQLiteRepository) DeleteMailbox(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "UPDATE delegate_mailboxes SET is_active = 0 WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) scanMailbox(row *sql.Row) (*Mailbox, error) {
	var m Mailbox
	var idStr, orgIDStr string
	var ownerIDStr *string
	var policyJSON string

	err := row.Scan(&idStr, &orgIDStr, &m.Email, &m.DisplayName, &m.Type,
		&ownerIDStr, &m.AutoAccept, &policyJSON, &m.ForwardingEmail,
		&m.Description, &m.IsActive, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}

	m.ID, _ = uuid.Parse(idStr)
	m.OrgID, _ = uuid.Parse(orgIDStr)
	if ownerIDStr != nil {
		id, _ := uuid.Parse(*ownerIDStr)
		m.OwnerID = &id
	}
	if policyJSON != "" {
		var policy BookingPolicy
		_ = json.Unmarshal([]byte(policyJSON), &policy)
		m.BookingPolicy = &policy
	}

	return &m, nil
}

func (r *SQLiteRepository) scanMailboxes(rows *sql.Rows) ([]*Mailbox, error) {
	var mailboxes []*Mailbox
	for rows.Next() {
		var m Mailbox
		var idStr, orgIDStr string
		var ownerIDStr *string
		var policyJSON string

		err := rows.Scan(&idStr, &orgIDStr, &m.Email, &m.DisplayName, &m.Type,
			&ownerIDStr, &m.AutoAccept, &policyJSON, &m.ForwardingEmail,
			&m.Description, &m.IsActive, &m.CreatedAt, &m.UpdatedAt)
		if err != nil {
			return nil, err
		}

		m.ID, _ = uuid.Parse(idStr)
		m.OrgID, _ = uuid.Parse(orgIDStr)
		if ownerIDStr != nil {
			id, _ := uuid.Parse(*ownerIDStr)
			m.OwnerID = &id
		}
		if policyJSON != "" {
			var policy BookingPolicy
			_ = json.Unmarshal([]byte(policyJSON), &policy)
			m.BookingPolicy = &policy
		}

		mailboxes = append(mailboxes, &m)
	}
	return mailboxes, rows.Err()
}

// Delegation methods
func (r *SQLiteRepository) SaveDelegation(ctx context.Context, d *Delegation) error {
	permissionsJSON, _ := json.Marshal(d.Permissions)
	foldersJSON, _ := json.Marshal(d.FolderIDs)

	query := `
	INSERT INTO delegations (
		id, mailbox_id, delegate_id, delegate_type, permissions, folder_ids,
		read_only, start_date, end_date, granted_by, reason, is_active, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(mailbox_id, delegate_id) DO UPDATE SET
		permissions = excluded.permissions,
		folder_ids = excluded.folder_ids,
		read_only = excluded.read_only,
		start_date = excluded.start_date,
		end_date = excluded.end_date,
		is_active = excluded.is_active,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		d.ID.String(), d.MailboxID.String(), d.DelegateID.String(), d.DelegateType,
		string(permissionsJSON), string(foldersJSON), d.ReadOnly, d.StartDate, d.EndDate,
		d.GrantedBy.String(), d.Reason, d.IsActive, d.CreatedAt, d.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetDelegation(ctx context.Context, id uuid.UUID) (*Delegation, error) {
	query := `
	SELECT id, mailbox_id, delegate_id, delegate_type, permissions, folder_ids,
		read_only, start_date, end_date, granted_by, reason, is_active, created_at, updated_at
	FROM delegations WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanDelegation(row)
}

func (r *SQLiteRepository) GetDelegationsForMailbox(ctx context.Context, mailboxID uuid.UUID) ([]*Delegation, error) {
	query := `
	SELECT id, mailbox_id, delegate_id, delegate_type, permissions, folder_ids,
		read_only, start_date, end_date, granted_by, reason, is_active, created_at, updated_at
	FROM delegations WHERE mailbox_id = ? AND is_active = 1
	`
	rows, err := r.db.QueryContext(ctx, query, mailboxID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanDelegations(rows)
}

func (r *SQLiteRepository) GetDelegationsForUser(ctx context.Context, userID uuid.UUID) ([]*Delegation, error) {
	query := `
	SELECT id, mailbox_id, delegate_id, delegate_type, permissions, folder_ids,
		read_only, start_date, end_date, granted_by, reason, is_active, created_at, updated_at
	FROM delegations WHERE delegate_id = ? AND is_active = 1
	`
	rows, err := r.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanDelegations(rows)
}

func (r *SQLiteRepository) GetActiveDelegation(ctx context.Context, mailboxID, delegateID uuid.UUID) (*Delegation, error) {
	query := `
	SELECT id, mailbox_id, delegate_id, delegate_type, permissions, folder_ids,
		read_only, start_date, end_date, granted_by, reason, is_active, created_at, updated_at
	FROM delegations WHERE mailbox_id = ? AND delegate_id = ? AND is_active = 1
	`
	row := r.db.QueryRowContext(ctx, query, mailboxID.String(), delegateID.String())
	return r.scanDelegation(row)
}

func (r *SQLiteRepository) DeleteDelegation(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "UPDATE delegations SET is_active = 0 WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) scanDelegation(row *sql.Row) (*Delegation, error) {
	var d Delegation
	var idStr, mailboxIDStr, delegateIDStr, grantedByStr string
	var permissionsJSON, foldersJSON string

	err := row.Scan(&idStr, &mailboxIDStr, &delegateIDStr, &d.DelegateType,
		&permissionsJSON, &foldersJSON, &d.ReadOnly, &d.StartDate, &d.EndDate,
		&grantedByStr, &d.Reason, &d.IsActive, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}

	d.ID, _ = uuid.Parse(idStr)
	d.MailboxID, _ = uuid.Parse(mailboxIDStr)
	d.DelegateID, _ = uuid.Parse(delegateIDStr)
	d.GrantedBy, _ = uuid.Parse(grantedByStr)
	_ = json.Unmarshal([]byte(permissionsJSON), &d.Permissions)
	_ = json.Unmarshal([]byte(foldersJSON), &d.FolderIDs)

	return &d, nil
}

func (r *SQLiteRepository) scanDelegations(rows *sql.Rows) ([]*Delegation, error) {
	var delegations []*Delegation
	for rows.Next() {
		var d Delegation
		var idStr, mailboxIDStr, delegateIDStr, grantedByStr string
		var permissionsJSON, foldersJSON string

		err := rows.Scan(&idStr, &mailboxIDStr, &delegateIDStr, &d.DelegateType,
			&permissionsJSON, &foldersJSON, &d.ReadOnly, &d.StartDate, &d.EndDate,
			&grantedByStr, &d.Reason, &d.IsActive, &d.CreatedAt, &d.UpdatedAt)
		if err != nil {
			return nil, err
		}

		d.ID, _ = uuid.Parse(idStr)
		d.MailboxID, _ = uuid.Parse(mailboxIDStr)
		d.DelegateID, _ = uuid.Parse(delegateIDStr)
		d.GrantedBy, _ = uuid.Parse(grantedByStr)
		_ = json.Unmarshal([]byte(permissionsJSON), &d.Permissions)
		_ = json.Unmarshal([]byte(foldersJSON), &d.FolderIDs)

		delegations = append(delegations, &d)
	}
	return delegations, rows.Err()
}

// Send-as config methods
func (r *SQLiteRepository) SaveSendAsConfig(ctx context.Context, c *SendAsConfig) error {
	approversJSON, _ := json.Marshal(c.ApproverIDs)

	query := `
	INSERT INTO send_as_configs (
		id, mailbox_id, delegate_id, display_name, reply_to, add_signature,
		copy_to_sent, require_approval, approver_ids, is_active, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(mailbox_id, delegate_id) DO UPDATE SET
		display_name = excluded.display_name,
		reply_to = excluded.reply_to,
		add_signature = excluded.add_signature,
		copy_to_sent = excluded.copy_to_sent,
		require_approval = excluded.require_approval,
		approver_ids = excluded.approver_ids,
		is_active = excluded.is_active,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		c.ID.String(), c.MailboxID.String(), c.DelegateID.String(), c.DisplayName,
		c.ReplyTo, c.AddSignature, c.CopyToSent, c.RequireApproval,
		string(approversJSON), c.IsActive, c.CreatedAt, c.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetSendAsConfig(ctx context.Context, id uuid.UUID) (*SendAsConfig, error) {
	query := `
	SELECT id, mailbox_id, delegate_id, display_name, reply_to, add_signature,
		copy_to_sent, require_approval, approver_ids, is_active, created_at, updated_at
	FROM send_as_configs WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())

	var c SendAsConfig
	var idStr, mailboxIDStr, delegateIDStr string
	var approversJSON string

	err := row.Scan(&idStr, &mailboxIDStr, &delegateIDStr, &c.DisplayName,
		&c.ReplyTo, &c.AddSignature, &c.CopyToSent, &c.RequireApproval,
		&approversJSON, &c.IsActive, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}

	c.ID, _ = uuid.Parse(idStr)
	c.MailboxID, _ = uuid.Parse(mailboxIDStr)
	c.DelegateID, _ = uuid.Parse(delegateIDStr)
	_ = json.Unmarshal([]byte(approversJSON), &c.ApproverIDs)

	return &c, nil
}

func (r *SQLiteRepository) GetSendAsConfigsForUser(ctx context.Context, userID uuid.UUID) ([]*SendAsConfig, error) {
	query := `
	SELECT id, mailbox_id, delegate_id, display_name, reply_to, add_signature,
		copy_to_sent, require_approval, approver_ids, is_active, created_at, updated_at
	FROM send_as_configs WHERE delegate_id = ? AND is_active = 1
	`
	rows, err := r.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []*SendAsConfig
	for rows.Next() {
		var c SendAsConfig
		var idStr, mailboxIDStr, delegateIDStr string
		var approversJSON string

		err := rows.Scan(&idStr, &mailboxIDStr, &delegateIDStr, &c.DisplayName,
			&c.ReplyTo, &c.AddSignature, &c.CopyToSent, &c.RequireApproval,
			&approversJSON, &c.IsActive, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			return nil, err
		}

		c.ID, _ = uuid.Parse(idStr)
		c.MailboxID, _ = uuid.Parse(mailboxIDStr)
		c.DelegateID, _ = uuid.Parse(delegateIDStr)
		_ = json.Unmarshal([]byte(approversJSON), &c.ApproverIDs)

		configs = append(configs, &c)
	}
	return configs, rows.Err()
}

func (r *SQLiteRepository) DeleteSendAsConfig(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "UPDATE send_as_configs SET is_active = 0 WHERE id = ?", id.String())
	return err
}

// Access log methods
func (r *SQLiteRepository) SaveAccessLog(ctx context.Context, log *AccessLog) error {
	var messageID, folderID *string
	if log.MessageID != nil {
		s := log.MessageID.String()
		messageID = &s
	}
	if log.FolderID != nil {
		s := log.FolderID.String()
		folderID = &s
	}

	query := `
	INSERT INTO delegation_access_logs (
		id, mailbox_id, accessed_by, access_type, message_id, folder_id,
		details, ip_address, user_agent, timestamp
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		log.ID.String(), log.MailboxID.String(), log.AccessedBy.String(),
		log.AccessType, messageID, folderID, log.Details, log.IPAddress,
		log.UserAgent, log.Timestamp)

	return err
}

func (r *SQLiteRepository) GetAccessLogs(ctx context.Context, query *AccessLogQuery) ([]*AccessLog, error) {
	var conditions []string
	var args []interface{}

	if query.MailboxID != nil {
		conditions = append(conditions, "mailbox_id = ?")
		args = append(args, query.MailboxID.String())
	}
	if query.AccessedBy != nil {
		conditions = append(conditions, "accessed_by = ?")
		args = append(args, query.AccessedBy.String())
	}
	if query.AccessType != "" {
		conditions = append(conditions, "access_type = ?")
		args = append(args, query.AccessType)
	}
	if query.DateFrom != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, *query.DateFrom)
	}
	if query.DateTo != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, *query.DateTo)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + joinConditions(conditions)
	}

	if query.Limit == 0 {
		query.Limit = 100
	}

	selectQuery := fmt.Sprintf(`
	SELECT id, mailbox_id, accessed_by, access_type, message_id, folder_id,
		details, ip_address, user_agent, timestamp
	FROM delegation_access_logs %s
	ORDER BY timestamp DESC
	LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, query.Limit, query.Offset)
	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AccessLog
	for rows.Next() {
		var log AccessLog
		var idStr, mailboxIDStr, accessedByStr string
		var messageIDStr, folderIDStr *string

		err := rows.Scan(&idStr, &mailboxIDStr, &accessedByStr, &log.AccessType,
			&messageIDStr, &folderIDStr, &log.Details, &log.IPAddress,
			&log.UserAgent, &log.Timestamp)
		if err != nil {
			return nil, err
		}

		log.ID, _ = uuid.Parse(idStr)
		log.MailboxID, _ = uuid.Parse(mailboxIDStr)
		log.AccessedBy, _ = uuid.Parse(accessedByStr)
		if messageIDStr != nil {
			id, _ := uuid.Parse(*messageIDStr)
			log.MessageID = &id
		}
		if folderIDStr != nil {
			id, _ := uuid.Parse(*folderIDStr)
			log.FolderID = &id
		}

		logs = append(logs, &log)
	}
	return logs, rows.Err()
}

func joinConditions(conditions []string) string {
	if len(conditions) == 0 {
		return ""
	}
	result := conditions[0]
	for i := 1; i < len(conditions); i++ {
		result += " AND " + conditions[i]
	}
	return result
}
