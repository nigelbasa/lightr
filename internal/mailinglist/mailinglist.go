package mailinglist

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ListType defines the type of mailing list
type ListType string

const (
	TypeAnnouncement ListType = "announcement" // One-way, only admins can post
	TypeDiscussion   ListType = "discussion"   // Two-way, members can post
	TypeModerated    ListType = "moderated"    // Posts require approval
	TypePrivate      ListType = "private"      // Invite only, hidden
)

// SubscriptionStatus represents a member's subscription status
type SubscriptionStatus string

const (
	SubPending      SubscriptionStatus = "pending"     // Awaiting confirmation
	SubActive       SubscriptionStatus = "active"      // Active subscription
	SubUnsubscribed SubscriptionStatus = "unsubscribed"
	SubBounced      SubscriptionStatus = "bounced"     // Too many bounces
	SubBlocked      SubscriptionStatus = "blocked"     // Blocked by admin
)

// DeliveryMode defines how a member receives list mail
type DeliveryMode string

const (
	DeliveryImmediate DeliveryMode = "immediate" // Each message as it arrives
	DeliveryDigest    DeliveryMode = "digest"    // Daily/weekly digest
	DeliveryNone      DeliveryMode = "none"      // Web only, no delivery
)

// MemberRole defines a member's role in the list
type MemberRole string

const (
	RoleMember    MemberRole = "member"
	RoleModerator MemberRole = "moderator"
	RoleOwner     MemberRole = "owner"
)

// MailingList represents a mailing list
type MailingList struct {
	ID              uuid.UUID         `json:"id"`
	OrgID           uuid.UUID         `json:"org_id"`
	Address         string            `json:"address"`           // list@domain.com
	Name            string            `json:"name"`
	Description     string            `json:"description,omitempty"`
	Type            ListType          `json:"type"`
	
	// Settings
	SubjectPrefix   string            `json:"subject_prefix,omitempty"` // e.g., "[list-name]"
	ReplyTo         ReplyToSetting    `json:"reply_to"`
	CustomReplyTo   string            `json:"custom_reply_to,omitempty"`
	FooterText      string            `json:"footer_text,omitempty"`
	FooterHTML      string            `json:"footer_html,omitempty"`
	WelcomeMessage  string            `json:"welcome_message,omitempty"`
	GoodbyeMessage  string            `json:"goodbye_message,omitempty"`
	
	// Subscription settings
	RequireApproval bool              `json:"require_approval"`    // Require admin approval
	RequireConfirm  bool              `json:"require_confirmation"` // Double opt-in
	AllowSelfUnsub  bool              `json:"allow_self_unsub"`
	
	// Posting settings
	MembersCanPost  bool              `json:"members_can_post"`
	NonMemberAction PostAction        `json:"non_member_action"`   // What to do with non-member posts
	ModerateFirst   int               `json:"moderate_first_n"`    // Moderate first N posts from new members
	MaxMessageSize  int64             `json:"max_message_size"`    // Max size in bytes
	AllowAttachments bool             `json:"allow_attachments"`
	
	// Digest settings
	DigestEnabled   bool              `json:"digest_enabled"`
	DigestFrequency DigestFrequency   `json:"digest_frequency"`
	DigestDay       int               `json:"digest_day"`          // Day of week (0=Sun) or month
	DigestTime      string            `json:"digest_time"`         // HH:MM
	
	// Archive settings
	ArchiveEnabled  bool              `json:"archive_enabled"`
	ArchivePublic   bool              `json:"archive_public"`
	
	// Stats
	MemberCount     int               `json:"member_count"`
	MessageCount    int               `json:"message_count"`
	LastPostAt      *time.Time        `json:"last_post_at,omitempty"`
	
	// Status
	IsActive        bool              `json:"is_active"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// ReplyToSetting defines where replies go
type ReplyToSetting string

const (
	ReplyToSender ReplyToSetting = "sender" // Reply to original sender
	ReplyToList   ReplyToSetting = "list"   // Reply to list
	ReplyToBoth   ReplyToSetting = "both"   // Reply to both
	ReplyToCustom ReplyToSetting = "custom" // Custom reply-to address
)

// PostAction defines what to do with posts
type PostAction string

const (
	ActionReject   PostAction = "reject"   // Reject with message
	ActionModerate PostAction = "moderate" // Hold for moderation
	ActionDiscard  PostAction = "discard"  // Silently discard
	ActionAccept   PostAction = "accept"   // Accept (for open lists)
)

// DigestFrequency defines digest frequency
type DigestFrequency string

const (
	DigestDaily   DigestFrequency = "daily"
	DigestWeekly  DigestFrequency = "weekly"
	DigestMonthly DigestFrequency = "monthly"
)

// Member represents a mailing list member
type Member struct {
	ID              uuid.UUID          `json:"id"`
	ListID          uuid.UUID          `json:"list_id"`
	Email           string             `json:"email"`
	Name            string             `json:"name,omitempty"`
	Status          SubscriptionStatus `json:"status"`
	Role            MemberRole         `json:"role"`
	DeliveryMode    DeliveryMode       `json:"delivery_mode"`
	
	// Confirmation
	ConfirmToken    string             `json:"-"`
	ConfirmExpires  *time.Time         `json:"-"`
	
	// Moderation
	PostCount       int                `json:"post_count"`
	ModeratedUntil  int                `json:"moderated_until"` // Moderate until this many posts
	
	// Bounce tracking
	BounceCount     int                `json:"bounce_count"`
	LastBounceAt    *time.Time         `json:"last_bounce_at,omitempty"`
	
	// Unsubscribe
	UnsubToken      string             `json:"-"`
	UnsubscribedAt  *time.Time         `json:"unsubscribed_at,omitempty"`
	
	SubscribedAt    time.Time          `json:"subscribed_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}

// PendingMessage represents a message awaiting moderation
type PendingMessage struct {
	ID           uuid.UUID  `json:"id"`
	ListID       uuid.UUID  `json:"list_id"`
	From         string     `json:"from"`
	Subject      string     `json:"subject"`
	Body         string     `json:"body"`
	BodyHTML     string     `json:"body_html,omitempty"`
	Headers      string     `json:"headers"`
	Reason       string     `json:"reason"`        // Why it's pending
	ReceivedAt   time.Time  `json:"received_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	HandledAt    *time.Time `json:"handled_at,omitempty"`
	HandledBy    *uuid.UUID `json:"handled_by,omitempty"`
	Decision     string     `json:"decision,omitempty"` // approve, reject, discard
}

// Service manages mailing lists
type Service struct {
	mu       sync.RWMutex
	repo     Repository
	sender   EmailSender
	logger   Logger
	lists    map[string]*MailingList // address -> list cache
}

// EmailSender interface for sending list mail
type EmailSender interface {
	SendToList(ctx context.Context, list *MailingList, from, subject, body, bodyHTML string, members []*Member) error
	SendConfirmation(ctx context.Context, list *MailingList, member *Member) error
	SendWelcome(ctx context.Context, list *MailingList, member *Member) error
	SendGoodbye(ctx context.Context, list *MailingList, member *Member) error
	SendModerationNotice(ctx context.Context, list *MailingList, msg *PendingMessage) error
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// Repository interface
type Repository interface {
	// Lists
	CreateList(ctx context.Context, list *MailingList) error
	GetList(ctx context.Context, id uuid.UUID) (*MailingList, error)
	GetListByAddress(ctx context.Context, address string) (*MailingList, error)
	UpdateList(ctx context.Context, list *MailingList) error
	DeleteList(ctx context.Context, id uuid.UUID) error
	ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*MailingList, error)
	
	// Members
	AddMember(ctx context.Context, member *Member) error
	GetMember(ctx context.Context, listID uuid.UUID, email string) (*Member, error)
	GetMemberByID(ctx context.Context, id uuid.UUID) (*Member, error)
	GetMemberByToken(ctx context.Context, token string) (*Member, error)
	GetMemberByUnsubToken(ctx context.Context, token string) (*Member, error)
	UpdateMember(ctx context.Context, member *Member) error
	RemoveMember(ctx context.Context, listID uuid.UUID, email string) error
	ListMembers(ctx context.Context, listID uuid.UUID, status SubscriptionStatus) ([]*Member, error)
	GetActiveMembers(ctx context.Context, listID uuid.UUID) ([]*Member, error)
	GetDigestMembers(ctx context.Context, listID uuid.UUID) ([]*Member, error)
	
	// Pending messages
	CreatePendingMessage(ctx context.Context, msg *PendingMessage) error
	GetPendingMessage(ctx context.Context, id uuid.UUID) (*PendingMessage, error)
	ListPendingMessages(ctx context.Context, listID uuid.UUID) ([]*PendingMessage, error)
	UpdatePendingMessage(ctx context.Context, msg *PendingMessage) error
	DeletePendingMessage(ctx context.Context, id uuid.UUID) error
}

// NewService creates a new mailing list service
func NewService(repo Repository, sender EmailSender, logger Logger) *Service {
	return &Service{
		repo:   repo,
		sender: sender,
		logger: logger,
		lists:  make(map[string]*MailingList),
	}
}

// CreateList creates a new mailing list
func (s *Service) CreateList(ctx context.Context, list *MailingList) error {
	if list.ID == uuid.Nil {
		list.ID = uuid.New()
	}
	
	// Set defaults
	if list.Type == "" {
		list.Type = TypeDiscussion
	}
	if list.ReplyTo == "" {
		list.ReplyTo = ReplyToList
	}
	if list.NonMemberAction == "" {
		list.NonMemberAction = ActionModerate
	}
	if list.MaxMessageSize == 0 {
		list.MaxMessageSize = 10 * 1024 * 1024 // 10MB
	}
	
	list.RequireConfirm = true
	list.AllowSelfUnsub = true
	list.MembersCanPost = true
	list.IsActive = true
	list.CreatedAt = time.Now()
	list.UpdatedAt = time.Now()

	err := s.repo.CreateList(ctx, list)
	if err == nil {
		s.mu.Lock()
		s.lists[strings.ToLower(list.Address)] = list
		s.mu.Unlock()
	}
	return err
}

// Subscribe subscribes an email to a list
func (s *Service) Subscribe(ctx context.Context, listID uuid.UUID, email, name string) (*Member, error) {
	list, err := s.repo.GetList(ctx, listID)
	if err != nil {
		return nil, err
	}
	if !list.IsActive {
		return nil, errors.New("list is not active")
	}

	// Check if already a member
	existing, err := s.repo.GetMember(ctx, listID, email)
	if err == nil && existing != nil {
		if existing.Status == SubActive {
			return nil, errors.New("already subscribed")
		}
		// Reactivate
		existing.Status = SubPending
		existing.ConfirmToken = generateToken()
		expires := time.Now().Add(48 * time.Hour)
		existing.ConfirmExpires = &expires
		existing.UpdatedAt = time.Now()

		if err := s.repo.UpdateMember(ctx, existing); err != nil {
			return nil, err
		}

		if list.RequireConfirm {
			s.sender.SendConfirmation(ctx, list, existing)
		}
		return existing, nil
	}

	member := &Member{
		ID:           uuid.New(),
		ListID:       listID,
		Email:        email,
		Name:         name,
		Status:       SubPending,
		Role:         RoleMember,
		DeliveryMode: DeliveryImmediate,
		SubscribedAt: time.Now(),
		UpdatedAt:    time.Now(),
	}

	if list.RequireConfirm {
		member.ConfirmToken = generateToken()
		expires := time.Now().Add(48 * time.Hour)
		member.ConfirmExpires = &expires
	} else if list.RequireApproval {
		member.Status = SubPending
	} else {
		member.Status = SubActive
	}

	// Generate unsubscribe token
	member.UnsubToken = generateToken()

	// Set moderation threshold
	if list.ModerateFirst > 0 {
		member.ModeratedUntil = list.ModerateFirst
	}

	if err := s.repo.AddMember(ctx, member); err != nil {
		return nil, err
	}

	// Send confirmation email
	if list.RequireConfirm {
		if err := s.sender.SendConfirmation(ctx, list, member); err != nil {
			s.logger.Error("failed to send confirmation", "email", email, "error", err)
		}
	} else if member.Status == SubActive {
		// Send welcome immediately
		if list.WelcomeMessage != "" {
			s.sender.SendWelcome(ctx, list, member)
		}
		// Update member count
		list.MemberCount++
		s.repo.UpdateList(ctx, list)
	}

	s.logger.Info("subscription request", "list", list.Address, "email", email, "status", member.Status)
	return member, nil
}

// ConfirmSubscription confirms a pending subscription
func (s *Service) ConfirmSubscription(ctx context.Context, token string) error {
	member, err := s.repo.GetMemberByToken(ctx, token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	if member.ConfirmExpires != nil && time.Now().After(*member.ConfirmExpires) {
		return errors.New("confirmation token expired")
	}

	list, err := s.repo.GetList(ctx, member.ListID)
	if err != nil {
		return err
	}

	if list.RequireApproval {
		// Still needs admin approval
		member.Status = SubPending
		member.ConfirmToken = ""
		member.ConfirmExpires = nil
	} else {
		member.Status = SubActive
		member.ConfirmToken = ""
		member.ConfirmExpires = nil

		// Send welcome
		if list.WelcomeMessage != "" {
			s.sender.SendWelcome(ctx, list, member)
		}

		list.MemberCount++
		s.repo.UpdateList(ctx, list)
	}

	member.UpdatedAt = time.Now()
	return s.repo.UpdateMember(ctx, member)
}

// Unsubscribe removes a member from a list
func (s *Service) Unsubscribe(ctx context.Context, listID uuid.UUID, email string) error {
	list, err := s.repo.GetList(ctx, listID)
	if err != nil {
		return err
	}

	member, err := s.repo.GetMember(ctx, listID, email)
	if err != nil {
		return err
	}

	if member.Status == SubUnsubscribed {
		return errors.New("already unsubscribed")
	}

	member.Status = SubUnsubscribed
	now := time.Now()
	member.UnsubscribedAt = &now
	member.UpdatedAt = now

	if err := s.repo.UpdateMember(ctx, member); err != nil {
		return err
	}

	// Send goodbye
	if list.GoodbyeMessage != "" {
		s.sender.SendGoodbye(ctx, list, member)
	}

	// Update count
	list.MemberCount--
	s.repo.UpdateList(ctx, list)

	s.logger.Info("unsubscribed", "list", list.Address, "email", email)
	return nil
}

// UnsubscribeByToken unsubscribes using one-click token
func (s *Service) UnsubscribeByToken(ctx context.Context, token string) error {
	member, err := s.repo.GetMemberByUnsubToken(ctx, token)
	if err != nil {
		return errors.New("invalid token")
	}

	return s.Unsubscribe(ctx, member.ListID, member.Email)
}

// ProcessIncoming processes an incoming message to a list
func (s *Service) ProcessIncoming(ctx context.Context, listAddress, from, subject, body, bodyHTML string, headers map[string]string) error {
	list, err := s.getListByAddress(ctx, listAddress)
	if err != nil {
		return err
	}
	if !list.IsActive {
		return errors.New("list is not active")
	}

	fromEmail := extractEmail(from)
	member, err := s.repo.GetMember(ctx, list.ID, fromEmail)

	// Check posting permissions
	if list.Type == TypeAnnouncement {
		// Only owners and moderators can post
		if member == nil || (member.Role != RoleOwner && member.Role != RoleModerator) {
			return s.handleNonMemberPost(ctx, list, from, subject, body, bodyHTML, headers, "only admins can post")
		}
	}

	if member == nil {
		// Non-member post
		return s.handleNonMemberPost(ctx, list, from, subject, body, bodyHTML, headers, "non-member")
	}

	if member.Status != SubActive {
		return errors.New("sender is not an active member")
	}

	if !list.MembersCanPost {
		if member.Role != RoleOwner && member.Role != RoleModerator {
			return errors.New("members cannot post to this list")
		}
	}

	// Check if still in moderation period
	if member.ModeratedUntil > 0 && member.PostCount < member.ModeratedUntil {
		return s.queueForModeration(ctx, list, from, subject, body, bodyHTML, headers, "new member moderation")
	}

	// Check moderated list type
	if list.Type == TypeModerated {
		if member.Role != RoleOwner && member.Role != RoleModerator {
			return s.queueForModeration(ctx, list, from, subject, body, bodyHTML, headers, "moderated list")
		}
	}

	// Distribute to members
	return s.distribute(ctx, list, from, subject, body, bodyHTML, member)
}

func (s *Service) handleNonMemberPost(ctx context.Context, list *MailingList, from, subject, body, bodyHTML string, headers map[string]string, reason string) error {
	switch list.NonMemberAction {
	case ActionReject:
		// TODO: Send rejection notice
		return errors.New("non-members cannot post to this list")
	case ActionDiscard:
		s.logger.Info("discarded non-member post", "list", list.Address, "from", from)
		return nil
	case ActionModerate:
		return s.queueForModeration(ctx, list, from, subject, body, bodyHTML, headers, reason)
	case ActionAccept:
		return s.distribute(ctx, list, from, subject, body, bodyHTML, nil)
	default:
		return errors.New("unknown non-member action")
	}
}

func (s *Service) queueForModeration(ctx context.Context, list *MailingList, from, subject, body, bodyHTML string, headers map[string]string, reason string) error {
	headersJSON, _ := json.Marshal(headers)

	msg := &PendingMessage{
		ID:         uuid.New(),
		ListID:     list.ID,
		From:       from,
		Subject:    subject,
		Body:       body,
		BodyHTML:   bodyHTML,
		Headers:    string(headersJSON),
		Reason:     reason,
		ReceivedAt: time.Now(),
		ExpiresAt:  time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	if err := s.repo.CreatePendingMessage(ctx, msg); err != nil {
		return err
	}

	// Notify moderators
	s.sender.SendModerationNotice(ctx, list, msg)

	s.logger.Info("message queued for moderation", "list", list.Address, "from", from, "reason", reason)
	return nil
}

func (s *Service) distribute(ctx context.Context, list *MailingList, from, subject, body, bodyHTML string, sender *Member) error {
	// Get active members (immediate delivery)
	members, err := s.repo.GetActiveMembers(ctx, list.ID)
	if err != nil {
		return err
	}

	// Filter to immediate delivery only
	var recipients []*Member
	for _, m := range members {
		if m.DeliveryMode == DeliveryImmediate && m.Email != extractEmail(from) {
			recipients = append(recipients, m)
		}
	}

	// Add subject prefix
	if list.SubjectPrefix != "" && !strings.Contains(subject, list.SubjectPrefix) {
		subject = list.SubjectPrefix + " " + subject
	}

	// Add footer
	if list.FooterText != "" {
		body = body + "\n\n--\n" + list.FooterText
	}
	if list.FooterHTML != "" && bodyHTML != "" {
		bodyHTML = bodyHTML + "<hr>" + list.FooterHTML
	}

	// Send to all recipients
	if err := s.sender.SendToList(ctx, list, from, subject, body, bodyHTML, recipients); err != nil {
		return err
	}

	// Update stats
	list.MessageCount++
	now := time.Now()
	list.LastPostAt = &now
	s.repo.UpdateList(ctx, list)

	// Update sender post count
	if sender != nil {
		sender.PostCount++
		sender.UpdatedAt = time.Now()
		s.repo.UpdateMember(ctx, sender)
	}

	s.logger.Info("distributed message", "list", list.Address, "from", from, "recipients", len(recipients))
	return nil
}

// ApproveMessage approves a pending message
func (s *Service) ApproveMessage(ctx context.Context, msgID uuid.UUID, approverID uuid.UUID) error {
	msg, err := s.repo.GetPendingMessage(ctx, msgID)
	if err != nil {
		return err
	}

	list, err := s.repo.GetList(ctx, msg.ListID)
	if err != nil {
		return err
	}

	// Distribute the message
	if err := s.distribute(ctx, list, msg.From, msg.Subject, msg.Body, msg.BodyHTML, nil); err != nil {
		return err
	}

	// Mark as handled
	now := time.Now()
	msg.HandledAt = &now
	msg.HandledBy = &approverID
	msg.Decision = "approve"

	return s.repo.UpdatePendingMessage(ctx, msg)
}

// RejectMessage rejects a pending message
func (s *Service) RejectMessage(ctx context.Context, msgID uuid.UUID, approverID uuid.UUID, reason string) error {
	msg, err := s.repo.GetPendingMessage(ctx, msgID)
	if err != nil {
		return err
	}

	now := time.Now()
	msg.HandledAt = &now
	msg.HandledBy = &approverID
	msg.Decision = "reject"

	// TODO: Send rejection notice to sender

	return s.repo.UpdatePendingMessage(ctx, msg)
}

func (s *Service) getListByAddress(ctx context.Context, address string) (*MailingList, error) {
	addr := strings.ToLower(address)

	s.mu.RLock()
	if list, ok := s.lists[addr]; ok {
		s.mu.RUnlock()
		return list, nil
	}
	s.mu.RUnlock()

	list, err := s.repo.GetListByAddress(ctx, address)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.lists[addr] = list
	s.mu.Unlock()

	return list, nil
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func extractEmail(from string) string {
	// Handle "Name <email>" format
	if idx := strings.Index(from, "<"); idx >= 0 {
		end := strings.Index(from, ">")
		if end > idx {
			return strings.ToLower(strings.TrimSpace(from[idx+1 : end]))
		}
	}
	return strings.ToLower(strings.TrimSpace(from))
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
		`CREATE TABLE IF NOT EXISTS mailing_lists (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			address TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			description TEXT,
			type TEXT NOT NULL DEFAULT 'discussion',
			subject_prefix TEXT,
			reply_to TEXT DEFAULT 'list',
			custom_reply_to TEXT,
			footer_text TEXT,
			footer_html TEXT,
			welcome_message TEXT,
			goodbye_message TEXT,
			require_approval INTEGER DEFAULT 0,
			require_confirmation INTEGER DEFAULT 1,
			allow_self_unsub INTEGER DEFAULT 1,
			members_can_post INTEGER DEFAULT 1,
			non_member_action TEXT DEFAULT 'moderate',
			moderate_first_n INTEGER DEFAULT 0,
			max_message_size INTEGER DEFAULT 10485760,
			allow_attachments INTEGER DEFAULT 1,
			digest_enabled INTEGER DEFAULT 0,
			digest_frequency TEXT DEFAULT 'daily',
			digest_day INTEGER DEFAULT 0,
			digest_time TEXT DEFAULT '08:00',
			archive_enabled INTEGER DEFAULT 1,
			archive_public INTEGER DEFAULT 0,
			member_count INTEGER DEFAULT 0,
			message_count INTEGER DEFAULT 0,
			last_post_at DATETIME,
			is_active INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_mailing_lists_org ON mailing_lists(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_mailing_lists_address ON mailing_lists(address)`,
		
		`CREATE TABLE IF NOT EXISTS mailing_list_members (
			id TEXT PRIMARY KEY,
			list_id TEXT NOT NULL,
			email TEXT NOT NULL,
			name TEXT,
			status TEXT NOT NULL DEFAULT 'pending',
			role TEXT NOT NULL DEFAULT 'member',
			delivery_mode TEXT NOT NULL DEFAULT 'immediate',
			confirm_token TEXT,
			confirm_expires DATETIME,
			post_count INTEGER DEFAULT 0,
			moderated_until INTEGER DEFAULT 0,
			bounce_count INTEGER DEFAULT 0,
			last_bounce_at DATETIME,
			unsub_token TEXT,
			unsubscribed_at DATETIME,
			subscribed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(list_id, email),
			FOREIGN KEY (list_id) REFERENCES mailing_lists(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ml_members_list ON mailing_list_members(list_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_ml_members_token ON mailing_list_members(confirm_token)`,
		`CREATE INDEX IF NOT EXISTS idx_ml_members_unsub ON mailing_list_members(unsub_token)`,
		
		`CREATE TABLE IF NOT EXISTS mailing_list_pending (
			id TEXT PRIMARY KEY,
			list_id TEXT NOT NULL,
			from_addr TEXT NOT NULL,
			subject TEXT NOT NULL,
			body TEXT NOT NULL,
			body_html TEXT,
			headers TEXT,
			reason TEXT,
			received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			handled_at DATETIME,
			handled_by TEXT,
			decision TEXT,
			FOREIGN KEY (list_id) REFERENCES mailing_lists(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ml_pending_list ON mailing_list_pending(list_id, handled_at)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) CreateList(ctx context.Context, list *MailingList) error {
	query := `
	INSERT INTO mailing_lists (
		id, org_id, address, name, description, type, subject_prefix, reply_to, custom_reply_to,
		footer_text, footer_html, welcome_message, goodbye_message, require_approval,
		require_confirmation, allow_self_unsub, members_can_post, non_member_action,
		moderate_first_n, max_message_size, allow_attachments, digest_enabled, digest_frequency,
		digest_day, digest_time, archive_enabled, archive_public, member_count, message_count,
		last_post_at, is_active, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query,
		list.ID.String(), list.OrgID.String(), list.Address, list.Name, list.Description,
		list.Type, list.SubjectPrefix, list.ReplyTo, list.CustomReplyTo, list.FooterText,
		list.FooterHTML, list.WelcomeMessage, list.GoodbyeMessage, list.RequireApproval,
		list.RequireConfirm, list.AllowSelfUnsub, list.MembersCanPost, list.NonMemberAction,
		list.ModerateFirst, list.MaxMessageSize, list.AllowAttachments, list.DigestEnabled,
		list.DigestFrequency, list.DigestDay, list.DigestTime, list.ArchiveEnabled,
		list.ArchivePublic, list.MemberCount, list.MessageCount, list.LastPostAt,
		list.IsActive, list.CreatedAt, list.UpdatedAt)
	return err
}

func (r *SQLiteRepository) GetList(ctx context.Context, id uuid.UUID) (*MailingList, error) {
	query := `
	SELECT id, org_id, address, name, description, type, subject_prefix, reply_to, custom_reply_to,
		footer_text, footer_html, welcome_message, goodbye_message, require_approval,
		require_confirmation, allow_self_unsub, members_can_post, non_member_action,
		moderate_first_n, max_message_size, allow_attachments, digest_enabled, digest_frequency,
		digest_day, digest_time, archive_enabled, archive_public, member_count, message_count,
		last_post_at, is_active, created_at, updated_at
	FROM mailing_lists WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanList(row)
}

func (r *SQLiteRepository) GetListByAddress(ctx context.Context, address string) (*MailingList, error) {
	query := `
	SELECT id, org_id, address, name, description, type, subject_prefix, reply_to, custom_reply_to,
		footer_text, footer_html, welcome_message, goodbye_message, require_approval,
		require_confirmation, allow_self_unsub, members_can_post, non_member_action,
		moderate_first_n, max_message_size, allow_attachments, digest_enabled, digest_frequency,
		digest_day, digest_time, archive_enabled, archive_public, member_count, message_count,
		last_post_at, is_active, created_at, updated_at
	FROM mailing_lists WHERE LOWER(address) = LOWER(?)
	`
	row := r.db.QueryRowContext(ctx, query, address)
	return r.scanList(row)
}

func (r *SQLiteRepository) UpdateList(ctx context.Context, list *MailingList) error {
	query := `
	UPDATE mailing_lists SET
		name = ?, description = ?, type = ?, subject_prefix = ?, reply_to = ?, custom_reply_to = ?,
		footer_text = ?, footer_html = ?, welcome_message = ?, goodbye_message = ?,
		require_approval = ?, require_confirmation = ?, allow_self_unsub = ?, members_can_post = ?,
		non_member_action = ?, moderate_first_n = ?, max_message_size = ?, allow_attachments = ?,
		digest_enabled = ?, digest_frequency = ?, digest_day = ?, digest_time = ?,
		archive_enabled = ?, archive_public = ?, member_count = ?, message_count = ?,
		last_post_at = ?, is_active = ?, updated_at = ?
	WHERE id = ?
	`
	_, err := r.db.ExecContext(ctx, query,
		list.Name, list.Description, list.Type, list.SubjectPrefix, list.ReplyTo, list.CustomReplyTo,
		list.FooterText, list.FooterHTML, list.WelcomeMessage, list.GoodbyeMessage,
		list.RequireApproval, list.RequireConfirm, list.AllowSelfUnsub, list.MembersCanPost,
		list.NonMemberAction, list.ModerateFirst, list.MaxMessageSize, list.AllowAttachments,
		list.DigestEnabled, list.DigestFrequency, list.DigestDay, list.DigestTime,
		list.ArchiveEnabled, list.ArchivePublic, list.MemberCount, list.MessageCount,
		list.LastPostAt, list.IsActive, time.Now(), list.ID.String())
	return err
}

func (r *SQLiteRepository) DeleteList(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM mailing_lists WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*MailingList, error) {
	query := `
	SELECT id, org_id, address, name, description, type, subject_prefix, reply_to, custom_reply_to,
		footer_text, footer_html, welcome_message, goodbye_message, require_approval,
		require_confirmation, allow_self_unsub, members_can_post, non_member_action,
		moderate_first_n, max_message_size, allow_attachments, digest_enabled, digest_frequency,
		digest_day, digest_time, archive_enabled, archive_public, member_count, message_count,
		last_post_at, is_active, created_at, updated_at
	FROM mailing_lists WHERE org_id = ? ORDER BY name
	`
	rows, err := r.db.QueryContext(ctx, query, orgID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var lists []*MailingList
	for rows.Next() {
		list, err := r.scanListRow(rows)
		if err != nil {
			return nil, err
		}
		lists = append(lists, list)
	}
	return lists, rows.Err()
}

func (r *SQLiteRepository) scanList(row *sql.Row) (*MailingList, error) {
	var list MailingList
	var idStr, orgIDStr string

	err := row.Scan(
		&idStr, &orgIDStr, &list.Address, &list.Name, &list.Description, &list.Type,
		&list.SubjectPrefix, &list.ReplyTo, &list.CustomReplyTo, &list.FooterText,
		&list.FooterHTML, &list.WelcomeMessage, &list.GoodbyeMessage, &list.RequireApproval,
		&list.RequireConfirm, &list.AllowSelfUnsub, &list.MembersCanPost, &list.NonMemberAction,
		&list.ModerateFirst, &list.MaxMessageSize, &list.AllowAttachments, &list.DigestEnabled,
		&list.DigestFrequency, &list.DigestDay, &list.DigestTime, &list.ArchiveEnabled,
		&list.ArchivePublic, &list.MemberCount, &list.MessageCount, &list.LastPostAt,
		&list.IsActive, &list.CreatedAt, &list.UpdatedAt)
	if err != nil {
		return nil, err
	}

	list.ID, _ = uuid.Parse(idStr)
	list.OrgID, _ = uuid.Parse(orgIDStr)
	return &list, nil
}

func (r *SQLiteRepository) scanListRow(rows *sql.Rows) (*MailingList, error) {
	var list MailingList
	var idStr, orgIDStr string

	err := rows.Scan(
		&idStr, &orgIDStr, &list.Address, &list.Name, &list.Description, &list.Type,
		&list.SubjectPrefix, &list.ReplyTo, &list.CustomReplyTo, &list.FooterText,
		&list.FooterHTML, &list.WelcomeMessage, &list.GoodbyeMessage, &list.RequireApproval,
		&list.RequireConfirm, &list.AllowSelfUnsub, &list.MembersCanPost, &list.NonMemberAction,
		&list.ModerateFirst, &list.MaxMessageSize, &list.AllowAttachments, &list.DigestEnabled,
		&list.DigestFrequency, &list.DigestDay, &list.DigestTime, &list.ArchiveEnabled,
		&list.ArchivePublic, &list.MemberCount, &list.MessageCount, &list.LastPostAt,
		&list.IsActive, &list.CreatedAt, &list.UpdatedAt)
	if err != nil {
		return nil, err
	}

	list.ID, _ = uuid.Parse(idStr)
	list.OrgID, _ = uuid.Parse(orgIDStr)
	return &list, nil
}

// Member repository methods
func (r *SQLiteRepository) AddMember(ctx context.Context, member *Member) error {
	query := `
	INSERT INTO mailing_list_members (
		id, list_id, email, name, status, role, delivery_mode, confirm_token, confirm_expires,
		post_count, moderated_until, bounce_count, last_bounce_at, unsub_token,
		unsubscribed_at, subscribed_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query,
		member.ID.String(), member.ListID.String(), member.Email, member.Name,
		member.Status, member.Role, member.DeliveryMode, member.ConfirmToken,
		member.ConfirmExpires, member.PostCount, member.ModeratedUntil, member.BounceCount,
		member.LastBounceAt, member.UnsubToken, member.UnsubscribedAt,
		member.SubscribedAt, member.UpdatedAt)
	return err
}

func (r *SQLiteRepository) GetMember(ctx context.Context, listID uuid.UUID, email string) (*Member, error) {
	query := `
	SELECT id, list_id, email, name, status, role, delivery_mode, confirm_token, confirm_expires,
		post_count, moderated_until, bounce_count, last_bounce_at, unsub_token,
		unsubscribed_at, subscribed_at, updated_at
	FROM mailing_list_members WHERE list_id = ? AND LOWER(email) = LOWER(?)
	`
	row := r.db.QueryRowContext(ctx, query, listID.String(), email)
	return r.scanMember(row)
}

func (r *SQLiteRepository) GetMemberByID(ctx context.Context, id uuid.UUID) (*Member, error) {
	query := `
	SELECT id, list_id, email, name, status, role, delivery_mode, confirm_token, confirm_expires,
		post_count, moderated_until, bounce_count, last_bounce_at, unsub_token,
		unsubscribed_at, subscribed_at, updated_at
	FROM mailing_list_members WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanMember(row)
}

func (r *SQLiteRepository) GetMemberByToken(ctx context.Context, token string) (*Member, error) {
	query := `
	SELECT id, list_id, email, name, status, role, delivery_mode, confirm_token, confirm_expires,
		post_count, moderated_until, bounce_count, last_bounce_at, unsub_token,
		unsubscribed_at, subscribed_at, updated_at
	FROM mailing_list_members WHERE confirm_token = ?
	`
	row := r.db.QueryRowContext(ctx, query, token)
	return r.scanMember(row)
}

func (r *SQLiteRepository) GetMemberByUnsubToken(ctx context.Context, token string) (*Member, error) {
	query := `
	SELECT id, list_id, email, name, status, role, delivery_mode, confirm_token, confirm_expires,
		post_count, moderated_until, bounce_count, last_bounce_at, unsub_token,
		unsubscribed_at, subscribed_at, updated_at
	FROM mailing_list_members WHERE unsub_token = ?
	`
	row := r.db.QueryRowContext(ctx, query, token)
	return r.scanMember(row)
}

func (r *SQLiteRepository) UpdateMember(ctx context.Context, member *Member) error {
	query := `
	UPDATE mailing_list_members SET
		name = ?, status = ?, role = ?, delivery_mode = ?, confirm_token = ?, confirm_expires = ?,
		post_count = ?, moderated_until = ?, bounce_count = ?, last_bounce_at = ?, unsub_token = ?,
		unsubscribed_at = ?, updated_at = ?
	WHERE id = ?
	`
	_, err := r.db.ExecContext(ctx, query,
		member.Name, member.Status, member.Role, member.DeliveryMode, member.ConfirmToken,
		member.ConfirmExpires, member.PostCount, member.ModeratedUntil, member.BounceCount,
		member.LastBounceAt, member.UnsubToken, member.UnsubscribedAt, time.Now(),
		member.ID.String())
	return err
}

func (r *SQLiteRepository) RemoveMember(ctx context.Context, listID uuid.UUID, email string) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM mailing_list_members WHERE list_id = ? AND LOWER(email) = LOWER(?)",
		listID.String(), email)
	return err
}

func (r *SQLiteRepository) ListMembers(ctx context.Context, listID uuid.UUID, status SubscriptionStatus) ([]*Member, error) {
	query := `
	SELECT id, list_id, email, name, status, role, delivery_mode, confirm_token, confirm_expires,
		post_count, moderated_until, bounce_count, last_bounce_at, unsub_token,
		unsubscribed_at, subscribed_at, updated_at
	FROM mailing_list_members WHERE list_id = ? AND status = ?
	ORDER BY email
	`
	rows, err := r.db.QueryContext(ctx, query, listID.String(), status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*Member
	for rows.Next() {
		member, err := r.scanMemberRow(rows)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

func (r *SQLiteRepository) GetActiveMembers(ctx context.Context, listID uuid.UUID) ([]*Member, error) {
	return r.ListMembers(ctx, listID, SubActive)
}

func (r *SQLiteRepository) GetDigestMembers(ctx context.Context, listID uuid.UUID) ([]*Member, error) {
	query := `
	SELECT id, list_id, email, name, status, role, delivery_mode, confirm_token, confirm_expires,
		post_count, moderated_until, bounce_count, last_bounce_at, unsub_token,
		unsubscribed_at, subscribed_at, updated_at
	FROM mailing_list_members WHERE list_id = ? AND status = 'active' AND delivery_mode = 'digest'
	ORDER BY email
	`
	rows, err := r.db.QueryContext(ctx, query, listID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*Member
	for rows.Next() {
		member, err := r.scanMemberRow(rows)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

func (r *SQLiteRepository) scanMember(row *sql.Row) (*Member, error) {
	var member Member
	var idStr, listIDStr string

	err := row.Scan(
		&idStr, &listIDStr, &member.Email, &member.Name, &member.Status, &member.Role,
		&member.DeliveryMode, &member.ConfirmToken, &member.ConfirmExpires, &member.PostCount,
		&member.ModeratedUntil, &member.BounceCount, &member.LastBounceAt, &member.UnsubToken,
		&member.UnsubscribedAt, &member.SubscribedAt, &member.UpdatedAt)
	if err != nil {
		return nil, err
	}

	member.ID, _ = uuid.Parse(idStr)
	member.ListID, _ = uuid.Parse(listIDStr)
	return &member, nil
}

func (r *SQLiteRepository) scanMemberRow(rows *sql.Rows) (*Member, error) {
	var member Member
	var idStr, listIDStr string

	err := rows.Scan(
		&idStr, &listIDStr, &member.Email, &member.Name, &member.Status, &member.Role,
		&member.DeliveryMode, &member.ConfirmToken, &member.ConfirmExpires, &member.PostCount,
		&member.ModeratedUntil, &member.BounceCount, &member.LastBounceAt, &member.UnsubToken,
		&member.UnsubscribedAt, &member.SubscribedAt, &member.UpdatedAt)
	if err != nil {
		return nil, err
	}

	member.ID, _ = uuid.Parse(idStr)
	member.ListID, _ = uuid.Parse(listIDStr)
	return &member, nil
}

// Pending message methods
func (r *SQLiteRepository) CreatePendingMessage(ctx context.Context, msg *PendingMessage) error {
	query := `
	INSERT INTO mailing_list_pending (id, list_id, from_addr, subject, body, body_html, headers, reason, received_at, expires_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query,
		msg.ID.String(), msg.ListID.String(), msg.From, msg.Subject, msg.Body, msg.BodyHTML,
		msg.Headers, msg.Reason, msg.ReceivedAt, msg.ExpiresAt)
	return err
}

func (r *SQLiteRepository) GetPendingMessage(ctx context.Context, id uuid.UUID) (*PendingMessage, error) {
	query := `
	SELECT id, list_id, from_addr, subject, body, body_html, headers, reason, received_at, expires_at, handled_at, handled_by, decision
	FROM mailing_list_pending WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())

	var msg PendingMessage
	var idStr, listIDStr string
	var handledByStr sql.NullString

	err := row.Scan(&idStr, &listIDStr, &msg.From, &msg.Subject, &msg.Body, &msg.BodyHTML,
		&msg.Headers, &msg.Reason, &msg.ReceivedAt, &msg.ExpiresAt, &msg.HandledAt,
		&handledByStr, &msg.Decision)
	if err != nil {
		return nil, err
	}

	msg.ID, _ = uuid.Parse(idStr)
	msg.ListID, _ = uuid.Parse(listIDStr)
	if handledByStr.Valid {
		id, _ := uuid.Parse(handledByStr.String)
		msg.HandledBy = &id
	}

	return &msg, nil
}

func (r *SQLiteRepository) ListPendingMessages(ctx context.Context, listID uuid.UUID) ([]*PendingMessage, error) {
	query := `
	SELECT id, list_id, from_addr, subject, body, body_html, headers, reason, received_at, expires_at, handled_at, handled_by, decision
	FROM mailing_list_pending WHERE list_id = ? AND handled_at IS NULL ORDER BY received_at
	`
	rows, err := r.db.QueryContext(ctx, query, listID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*PendingMessage
	for rows.Next() {
		var msg PendingMessage
		var idStr, listIDStr string
		var handledByStr sql.NullString

		err := rows.Scan(&idStr, &listIDStr, &msg.From, &msg.Subject, &msg.Body, &msg.BodyHTML,
			&msg.Headers, &msg.Reason, &msg.ReceivedAt, &msg.ExpiresAt, &msg.HandledAt,
			&handledByStr, &msg.Decision)
		if err != nil {
			return nil, err
		}

		msg.ID, _ = uuid.Parse(idStr)
		msg.ListID, _ = uuid.Parse(listIDStr)
		if handledByStr.Valid {
			id, _ := uuid.Parse(handledByStr.String)
			msg.HandledBy = &id
		}
		messages = append(messages, &msg)
	}
	return messages, rows.Err()
}

func (r *SQLiteRepository) UpdatePendingMessage(ctx context.Context, msg *PendingMessage) error {
	var handledBy *string
	if msg.HandledBy != nil {
		s := msg.HandledBy.String()
		handledBy = &s
	}

	query := `
	UPDATE mailing_list_pending SET handled_at = ?, handled_by = ?, decision = ? WHERE id = ?
	`
	_, err := r.db.ExecContext(ctx, query, msg.HandledAt, handledBy, msg.Decision, msg.ID.String())
	return err
}

func (r *SQLiteRepository) DeletePendingMessage(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM mailing_list_pending WHERE id = ?", id.String())
	return err
}
