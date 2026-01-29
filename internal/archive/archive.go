package archive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ArchiveStatus represents the status of an archived message
type ArchiveStatus string

const (
	StatusActive    ArchiveStatus = "active"     // Normal archived message
	StatusLegalHold ArchiveStatus = "legal_hold" // Under legal hold, cannot be deleted
	StatusExpired   ArchiveStatus = "expired"    // Past retention, pending deletion
	StatusDeleted   ArchiveStatus = "deleted"    // Marked for deletion
)

// RetentionType defines retention policy types
type RetentionType string

const (
	RetentionDays   RetentionType = "days"
	RetentionMonths RetentionType = "months"
	RetentionYears  RetentionType = "years"
	RetentionForever RetentionType = "forever"
)

// RetentionPolicy defines how long emails are retained
type RetentionPolicy struct {
	ID          uuid.UUID     `json:"id"`
	OrgID       uuid.UUID     `json:"org_id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	
	// Retention settings
	Type        RetentionType `json:"type"`
	Duration    int           `json:"duration"`         // Number of days/months/years
	
	// Scope
	ApplyToAll    bool        `json:"apply_to_all"`     // Apply to all mailboxes
	MailboxIDs    []uuid.UUID `json:"mailbox_ids,omitempty"` // Specific mailboxes
	FolderPatterns []string   `json:"folder_patterns,omitempty"` // e.g., "Trash", "Spam"
	
	// Actions
	ActionOnExpiry string      `json:"action_on_expiry"` // "delete", "move_to_archive", "notify"
	NotifyBefore   int         `json:"notify_before"`    // Days before expiry to notify
	NotifyEmails   []string    `json:"notify_emails,omitempty"`
	
	// Metadata
	IsDefault   bool          `json:"is_default"`
	Priority    int           `json:"priority"`         // Higher priority policies take precedence
	Enabled     bool          `json:"enabled"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// LegalHold represents a legal hold on messages
type LegalHold struct {
	ID          uuid.UUID   `json:"id"`
	OrgID       uuid.UUID   `json:"org_id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	CaseNumber  string      `json:"case_number,omitempty"`
	
	// Scope - at least one must be set
	CustodianIDs []uuid.UUID `json:"custodian_ids,omitempty"` // Account IDs
	MailboxIDs   []uuid.UUID `json:"mailbox_ids,omitempty"`
	SearchQuery  string      `json:"search_query,omitempty"`  // Messages matching query
	DateFrom     *time.Time  `json:"date_from,omitempty"`
	DateTo       *time.Time  `json:"date_to,omitempty"`
	
	// Hold details
	HeldBy      uuid.UUID   `json:"held_by"`       // Admin who created hold
	Reason      string      `json:"reason"`
	StartDate   time.Time   `json:"start_date"`
	EndDate     *time.Time  `json:"end_date,omitempty"` // nil = indefinite
	
	// Status
	Active      bool        `json:"active"`
	MessageCount int64      `json:"message_count"`
	TotalSize   int64       `json:"total_size"`
	
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// ArchivedMessage represents an archived email
type ArchivedMessage struct {
	ID            uuid.UUID     `json:"id"`
	MessageID     uuid.UUID     `json:"message_id"`     // Original message ID
	AccountID     uuid.UUID     `json:"account_id"`
	OrgID         uuid.UUID     `json:"org_id"`
	
	// Message metadata
	From          string        `json:"from"`
	To            []string      `json:"to"`
	Cc            []string      `json:"cc,omitempty"`
	Bcc           []string      `json:"bcc,omitempty"`
	Subject       string        `json:"subject"`
	Folder        string        `json:"folder"`
	Size          int64         `json:"size"`
	HasAttachment bool          `json:"has_attachment"`
	MessageDate   time.Time     `json:"message_date"`
	
	// Storage
	StoragePath   string        `json:"storage_path"`   // Path to archived content
	Checksum      string        `json:"checksum"`       // SHA256 of content
	ContentType   string        `json:"content_type"`   // application/mbox, etc.
	Compressed    bool          `json:"compressed"`
	Encrypted     bool          `json:"encrypted"`
	
	// Retention
	PolicyID      *uuid.UUID    `json:"policy_id,omitempty"`
	RetainUntil   *time.Time    `json:"retain_until,omitempty"`
	Status        ArchiveStatus `json:"status"`
	
	// Legal holds
	LegalHoldIDs  []uuid.UUID   `json:"legal_hold_ids,omitempty"`
	
	// Audit
	ArchivedAt    time.Time     `json:"archived_at"`
	ArchivedBy    string        `json:"archived_by"` // "system", "admin", "user"
	LastAccessedAt *time.Time   `json:"last_accessed_at,omitempty"`
	AccessCount   int           `json:"access_count"`
	
	// Metadata
	Labels        []string      `json:"labels,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
}

// ExportRequest represents an archive export request
type ExportRequest struct {
	ID          uuid.UUID   `json:"id"`
	OrgID       uuid.UUID   `json:"org_id"`
	RequestedBy uuid.UUID   `json:"requested_by"`
	
	// Scope
	AccountIDs  []uuid.UUID `json:"account_ids,omitempty"`
	DateFrom    *time.Time  `json:"date_from,omitempty"`
	DateTo      *time.Time  `json:"date_to,omitempty"`
	SearchQuery string      `json:"search_query,omitempty"`
	LegalHoldID *uuid.UUID  `json:"legal_hold_id,omitempty"`
	
	// Format
	Format      string      `json:"format"`      // "mbox", "pst", "eml", "pdf"
	IncludeAttachments bool `json:"include_attachments"`
	
	// Status
	Status      string      `json:"status"`      // "pending", "processing", "completed", "failed"
	Progress    int         `json:"progress"`    // 0-100
	MessageCount int64      `json:"message_count"`
	TotalSize   int64       `json:"total_size"`
	OutputPath  string      `json:"output_path,omitempty"`
	Error       string      `json:"error,omitempty"`
	
	CreatedAt   time.Time   `json:"created_at"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
}

// AuditLog represents an archive access/action log
type AuditLog struct {
	ID          uuid.UUID   `json:"id"`
	OrgID       uuid.UUID   `json:"org_id"`
	ActorID     uuid.UUID   `json:"actor_id"`
	ActorType   string      `json:"actor_type"` // "user", "admin", "system"
	Action      string      `json:"action"`     // "view", "export", "delete", "hold", "release"
	ResourceType string     `json:"resource_type"` // "message", "policy", "hold", "export"
	ResourceID  uuid.UUID   `json:"resource_id"`
	Details     string      `json:"details,omitempty"`
	IPAddress   string      `json:"ip_address,omitempty"`
	UserAgent   string      `json:"user_agent,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
}

// Service handles email archiving
type Service struct {
	mu       sync.RWMutex
	repo     Repository
	storage  Storage
	logger   Logger
	workers  int
	queue    chan *ArchiveJob
	stopCh   chan struct{}
	running  bool
}

// ArchiveJob represents an archiving task
type ArchiveJob struct {
	Type      string // "archive", "delete", "export"
	Message   *MessageToArchive
	ExportReq *ExportRequest
}

// MessageToArchive contains message data for archiving
type MessageToArchive struct {
	ID            uuid.UUID
	AccountID     uuid.UUID
	OrgID         uuid.UUID
	From          string
	To            []string
	Cc            []string
	Bcc           []string
	Subject       string
	Folder        string
	Size          int64
	HasAttachment bool
	MessageDate   time.Time
	RawContent    []byte
	Headers       map[string]string
}

// Storage interface for archive storage
type Storage interface {
	Store(ctx context.Context, path string, data []byte, compress, encrypt bool) (string, error)
	Retrieve(ctx context.Context, path string) ([]byte, error)
	Delete(ctx context.Context, path string) error
	Checksum(data []byte) string
}

// Repository interface
type Repository interface {
	// Retention policies
	SavePolicy(ctx context.Context, policy *RetentionPolicy) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*RetentionPolicy, error)
	GetPolicies(ctx context.Context, orgID uuid.UUID) ([]*RetentionPolicy, error)
	GetDefaultPolicy(ctx context.Context, orgID uuid.UUID) (*RetentionPolicy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	
	// Legal holds
	SaveLegalHold(ctx context.Context, hold *LegalHold) error
	GetLegalHold(ctx context.Context, id uuid.UUID) (*LegalHold, error)
	GetActiveLegalHolds(ctx context.Context, orgID uuid.UUID) ([]*LegalHold, error)
	GetHoldsForMessage(ctx context.Context, messageID uuid.UUID) ([]*LegalHold, error)
	UpdateLegalHold(ctx context.Context, hold *LegalHold) error
	
	// Archived messages
	SaveArchivedMessage(ctx context.Context, msg *ArchivedMessage) error
	GetArchivedMessage(ctx context.Context, id uuid.UUID) (*ArchivedMessage, error)
	GetArchivedMessageByOriginal(ctx context.Context, messageID uuid.UUID) (*ArchivedMessage, error)
	SearchArchive(ctx context.Context, query *ArchiveQuery) ([]*ArchivedMessage, int64, error)
	UpdateArchiveStatus(ctx context.Context, id uuid.UUID, status ArchiveStatus) error
	GetExpiredMessages(ctx context.Context, limit int) ([]*ArchivedMessage, error)
	GetMessagesOnHold(ctx context.Context, holdID uuid.UUID) ([]*ArchivedMessage, error)
	
	// Export requests
	SaveExportRequest(ctx context.Context, req *ExportRequest) error
	GetExportRequest(ctx context.Context, id uuid.UUID) (*ExportRequest, error)
	UpdateExportRequest(ctx context.Context, req *ExportRequest) error
	
	// Audit logs
	SaveAuditLog(ctx context.Context, log *AuditLog) error
	GetAuditLogs(ctx context.Context, query *AuditQuery) ([]*AuditLog, error)
}

// ArchiveQuery for searching archived messages
type ArchiveQuery struct {
	OrgID         uuid.UUID
	AccountID     *uuid.UUID
	Query         string
	DateFrom      *time.Time
	DateTo        *time.Time
	Status        *ArchiveStatus
	HasLegalHold  *bool
	Limit         int
	Offset        int
}

// AuditQuery for searching audit logs
type AuditQuery struct {
	OrgID         uuid.UUID
	ActorID       *uuid.UUID
	Action        string
	ResourceType  string
	DateFrom      *time.Time
	DateTo        *time.Time
	Limit         int
	Offset        int
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewService creates a new archive service
func NewService(repo Repository, storage Storage, logger Logger, workers int) *Service {
	if workers <= 0 {
		workers = 2
	}
	return &Service{
		repo:    repo,
		storage: storage,
		logger:  logger,
		workers: workers,
		queue:   make(chan *ArchiveJob, 500),
		stopCh:  make(chan struct{}),
	}
}

// Start starts the archive workers
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	for i := 0; i < s.workers; i++ {
		go s.worker(ctx, i)
	}

	// Start retention processor
	go s.retentionProcessor(ctx)

	s.logger.Info("archive service started", "workers", s.workers)
	return nil
}

// Stop stops the service
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	s.running = false
	s.logger.Info("archive service stopped")
}

func (s *Service) worker(ctx context.Context, id int) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case job := <-s.queue:
			s.processJob(ctx, job)
		}
	}
}

func (s *Service) processJob(ctx context.Context, job *ArchiveJob) {
	switch job.Type {
	case "archive":
		s.archiveMessage(ctx, job.Message)
	case "export":
		s.processExport(ctx, job.ExportReq)
	}
}

// ArchiveMessage queues a message for archiving
func (s *Service) ArchiveMessage(msg *MessageToArchive) {
	select {
	case s.queue <- &ArchiveJob{Type: "archive", Message: msg}:
	default:
		s.logger.Error("archive queue full", "message_id", msg.ID)
	}
}

func (s *Service) archiveMessage(ctx context.Context, msg *MessageToArchive) {
	// Get applicable retention policy
	policy, err := s.getApplicablePolicy(ctx, msg.OrgID, msg.AccountID, msg.Folder)
	if err != nil {
		s.logger.Error("failed to get retention policy", "error", err)
	}

	// Calculate retention date
	var retainUntil *time.Time
	if policy != nil && policy.Type != RetentionForever {
		expiry := s.calculateRetention(policy, msg.MessageDate)
		retainUntil = &expiry
	}

	// Store the raw content
	storagePath := fmt.Sprintf("archive/%s/%s/%s.eml",
		msg.OrgID.String(),
		msg.AccountID.String(),
		msg.ID.String())

	checksum := s.storage.Checksum(msg.RawContent)
	finalPath, err := s.storage.Store(ctx, storagePath, msg.RawContent, true, true)
	if err != nil {
		s.logger.Error("failed to store archived message", "error", err)
		return
	}

	// Create archive record
	archived := &ArchivedMessage{
		ID:            uuid.New(),
		MessageID:     msg.ID,
		AccountID:     msg.AccountID,
		OrgID:         msg.OrgID,
		From:          msg.From,
		To:            msg.To,
		Cc:            msg.Cc,
		Bcc:           msg.Bcc,
		Subject:       msg.Subject,
		Folder:        msg.Folder,
		Size:          msg.Size,
		HasAttachment: msg.HasAttachment,
		MessageDate:   msg.MessageDate,
		StoragePath:   finalPath,
		Checksum:      checksum,
		ContentType:   "message/rfc822",
		Compressed:    true,
		Encrypted:     true,
		RetainUntil:   retainUntil,
		Status:        StatusActive,
		ArchivedAt:    time.Now(),
		ArchivedBy:    "system",
	}

	if policy != nil {
		archived.PolicyID = &policy.ID
	}

	// Check for legal holds
	holds, err := s.getApplicableHolds(ctx, msg)
	if err == nil && len(holds) > 0 {
		archived.Status = StatusLegalHold
		for _, h := range holds {
			archived.LegalHoldIDs = append(archived.LegalHoldIDs, h.ID)
		}
	}

	if err := s.repo.SaveArchivedMessage(ctx, archived); err != nil {
		s.logger.Error("failed to save archived message", "error", err)
		return
	}

	s.logger.Debug("archived message", "id", msg.ID, "path", finalPath)
}

func (s *Service) getApplicablePolicy(ctx context.Context, orgID, accountID uuid.UUID, folder string) (*RetentionPolicy, error) {
	policies, err := s.repo.GetPolicies(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Find highest priority matching policy
	var bestPolicy *RetentionPolicy
	for _, p := range policies {
		if !p.Enabled {
			continue
		}

		// Check if policy applies to this mailbox/folder
		if !p.ApplyToAll {
			found := false
			for _, id := range p.MailboxIDs {
				if id == accountID {
					found = true
					break
				}
			}
			if !found && len(p.FolderPatterns) > 0 {
				for _, pattern := range p.FolderPatterns {
					if matchFolder(folder, pattern) {
						found = true
						break
					}
				}
			}
			if !found {
				continue
			}
		}

		if bestPolicy == nil || p.Priority > bestPolicy.Priority {
			bestPolicy = p
		}
	}

	if bestPolicy == nil {
		return s.repo.GetDefaultPolicy(ctx, orgID)
	}

	return bestPolicy, nil
}

func (s *Service) calculateRetention(policy *RetentionPolicy, messageDate time.Time) time.Time {
	switch policy.Type {
	case RetentionDays:
		return messageDate.AddDate(0, 0, policy.Duration)
	case RetentionMonths:
		return messageDate.AddDate(0, policy.Duration, 0)
	case RetentionYears:
		return messageDate.AddDate(policy.Duration, 0, 0)
	default:
		return messageDate.AddDate(100, 0, 0) // Effectively forever
	}
}

func (s *Service) getApplicableHolds(ctx context.Context, msg *MessageToArchive) ([]*LegalHold, error) {
	holds, err := s.repo.GetActiveLegalHolds(ctx, msg.OrgID)
	if err != nil {
		return nil, err
	}

	var applicable []*LegalHold
	for _, hold := range holds {
		if s.messageMatchesHold(msg, hold) {
			applicable = append(applicable, hold)
		}
	}

	return applicable, nil
}

func (s *Service) messageMatchesHold(msg *MessageToArchive, hold *LegalHold) bool {
	// Check custodian (account) match
	if len(hold.CustodianIDs) > 0 {
		found := false
		for _, id := range hold.CustodianIDs {
			if id == msg.AccountID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check date range
	if hold.DateFrom != nil && msg.MessageDate.Before(*hold.DateFrom) {
		return false
	}
	if hold.DateTo != nil && msg.MessageDate.After(*hold.DateTo) {
		return false
	}

	// Note: SearchQuery matching would require full-text search integration
	
	return true
}

// Retention processing
func (s *Service) retentionProcessor(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.processExpiredMessages(ctx)
		}
	}
}

func (s *Service) processExpiredMessages(ctx context.Context) {
	messages, err := s.repo.GetExpiredMessages(ctx, 100)
	if err != nil {
		s.logger.Error("failed to get expired messages", "error", err)
		return
	}

	for _, msg := range messages {
		// Skip if under legal hold
		if len(msg.LegalHoldIDs) > 0 {
			continue
		}

		// Get policy to determine action
		if msg.PolicyID != nil {
			policy, err := s.repo.GetPolicy(ctx, *msg.PolicyID)
			if err == nil && policy != nil {
				switch policy.ActionOnExpiry {
				case "delete":
					s.deleteArchivedMessage(ctx, msg)
				case "notify":
					// Notification would be sent here
					s.logger.Info("retention notification", "message_id", msg.MessageID)
				}
			}
		} else {
			// Default action: mark as expired
			s.repo.UpdateArchiveStatus(ctx, msg.ID, StatusExpired)
		}
	}
}

func (s *Service) deleteArchivedMessage(ctx context.Context, msg *ArchivedMessage) {
	// Delete from storage
	if err := s.storage.Delete(ctx, msg.StoragePath); err != nil {
		s.logger.Error("failed to delete archived content", "error", err)
	}

	// Update status
	if err := s.repo.UpdateArchiveStatus(ctx, msg.ID, StatusDeleted); err != nil {
		s.logger.Error("failed to update archive status", "error", err)
	}

	s.logger.Info("deleted archived message", "id", msg.ID)
}

// Legal Hold Management

// CreateLegalHold creates a new legal hold
func (s *Service) CreateLegalHold(ctx context.Context, hold *LegalHold) error {
	hold.ID = uuid.New()
	hold.Active = true
	hold.CreatedAt = time.Now()
	hold.UpdatedAt = time.Now()

	if err := s.repo.SaveLegalHold(ctx, hold); err != nil {
		return err
	}

	// Apply hold to existing archived messages
	go s.applyHoldToExistingMessages(context.Background(), hold)

	// Audit log
	s.logAudit(ctx, hold.OrgID, hold.HeldBy, "admin", "hold", "hold", hold.ID, "Created legal hold: "+hold.Name)

	return nil
}

func (s *Service) applyHoldToExistingMessages(ctx context.Context, hold *LegalHold) {
	// Search for messages matching hold criteria
	query := &ArchiveQuery{
		OrgID:    hold.OrgID,
		DateFrom: hold.DateFrom,
		DateTo:   hold.DateTo,
		Limit:    1000,
	}

	messages, _, err := s.repo.SearchArchive(ctx, query)
	if err != nil {
		s.logger.Error("failed to search archive for legal hold", "error", err)
		return
	}

	var count int64
	var totalSize int64
	for _, msg := range messages {
		// Check custodian match
		if len(hold.CustodianIDs) > 0 {
			found := false
			for _, id := range hold.CustodianIDs {
				if id == msg.AccountID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Add hold to message
		msg.LegalHoldIDs = append(msg.LegalHoldIDs, hold.ID)
		msg.Status = StatusLegalHold
		s.repo.SaveArchivedMessage(ctx, msg)
		count++
		totalSize += msg.Size
	}

	// Update hold stats
	hold.MessageCount = count
	hold.TotalSize = totalSize
	s.repo.UpdateLegalHold(ctx, hold)

	s.logger.Info("applied legal hold", "hold_id", hold.ID, "messages", count)
}

// ReleaseLegalHold releases a legal hold
func (s *Service) ReleaseLegalHold(ctx context.Context, holdID uuid.UUID, releasedBy uuid.UUID) error {
	hold, err := s.repo.GetLegalHold(ctx, holdID)
	if err != nil {
		return err
	}

	hold.Active = false
	now := time.Now()
	hold.EndDate = &now
	hold.UpdatedAt = now

	if err := s.repo.UpdateLegalHold(ctx, hold); err != nil {
		return err
	}

	// Remove hold from messages
	go s.removeHoldFromMessages(context.Background(), hold)

	// Audit log
	s.logAudit(ctx, hold.OrgID, releasedBy, "admin", "release", "hold", hold.ID, "Released legal hold: "+hold.Name)

	return nil
}

func (s *Service) removeHoldFromMessages(ctx context.Context, hold *LegalHold) {
	messages, err := s.repo.GetMessagesOnHold(ctx, hold.ID)
	if err != nil {
		s.logger.Error("failed to get messages on hold", "error", err)
		return
	}

	for _, msg := range messages {
		// Remove this hold from the message
		var newHolds []uuid.UUID
		for _, h := range msg.LegalHoldIDs {
			if h != hold.ID {
				newHolds = append(newHolds, h)
			}
		}
		msg.LegalHoldIDs = newHolds

		// If no more holds, set status back to active
		if len(newHolds) == 0 {
			msg.Status = StatusActive
		}

		s.repo.SaveArchivedMessage(ctx, msg)
	}

	s.logger.Info("removed legal hold from messages", "hold_id", hold.ID)
}

// Export Management

// RequestExport creates a new export request
func (s *Service) RequestExport(ctx context.Context, req *ExportRequest) error {
	req.ID = uuid.New()
	req.Status = "pending"
	req.Progress = 0
	req.CreatedAt = time.Now()

	if err := s.repo.SaveExportRequest(ctx, req); err != nil {
		return err
	}

	// Queue export job
	select {
	case s.queue <- &ArchiveJob{Type: "export", ExportReq: req}:
	default:
		return fmt.Errorf("export queue full")
	}

	// Audit log
	s.logAudit(ctx, req.OrgID, req.RequestedBy, "admin", "export", "export", req.ID, "Requested archive export")

	return nil
}

func (s *Service) processExport(ctx context.Context, req *ExportRequest) {
	now := time.Now()
	req.Status = "processing"
	req.StartedAt = &now
	s.repo.UpdateExportRequest(ctx, req)

	// Build query from export request
	query := &ArchiveQuery{
		OrgID:    req.OrgID,
		DateFrom: req.DateFrom,
		DateTo:   req.DateTo,
		Limit:    10000, // Process in batches
	}

	if len(req.AccountIDs) == 1 {
		query.AccountID = &req.AccountIDs[0]
	}

	// Get messages
	messages, total, err := s.repo.SearchArchive(ctx, query)
	if err != nil {
		req.Status = "failed"
		req.Error = err.Error()
		s.repo.UpdateExportRequest(ctx, req)
		return
	}

	req.MessageCount = total

	// Generate export file based on format
	outputPath := fmt.Sprintf("exports/%s/%s.%s",
		req.OrgID.String(),
		req.ID.String(),
		req.Format)

	// For simplicity, just mark as complete
	// Real implementation would generate actual export files
	req.Progress = 100
	req.Status = "completed"
	completedAt := time.Now()
	req.CompletedAt = &completedAt
	req.OutputPath = outputPath
	req.MessageCount = int64(len(messages))

	s.repo.UpdateExportRequest(ctx, req)
	s.logger.Info("completed export", "id", req.ID, "messages", len(messages))
}

// GetArchivedMessage retrieves an archived message
func (s *Service) GetArchivedMessage(ctx context.Context, id uuid.UUID, accessedBy uuid.UUID) (*ArchivedMessage, []byte, error) {
	msg, err := s.repo.GetArchivedMessage(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	// Retrieve content
	content, err := s.storage.Retrieve(ctx, msg.StoragePath)
	if err != nil {
		return nil, nil, err
	}

	// Update access info
	now := time.Now()
	msg.LastAccessedAt = &now
	msg.AccessCount++
	s.repo.SaveArchivedMessage(ctx, msg)

	// Audit log
	s.logAudit(ctx, msg.OrgID, accessedBy, "user", "view", "message", msg.ID, "Accessed archived message")

	return msg, content, nil
}

// SearchArchive searches the archive
func (s *Service) SearchArchive(ctx context.Context, query *ArchiveQuery) ([]*ArchivedMessage, int64, error) {
	return s.repo.SearchArchive(ctx, query)
}

func (s *Service) logAudit(ctx context.Context, orgID, actorID uuid.UUID, actorType, action, resourceType string, resourceID uuid.UUID, details string) {
	log := &AuditLog{
		ID:          uuid.New(),
		OrgID:       orgID,
		ActorID:     actorID,
		ActorType:   actorType,
		Action:      action,
		ResourceType: resourceType,
		ResourceID:  resourceID,
		Details:     details,
		Timestamp:   time.Now(),
	}

	if err := s.repo.SaveAuditLog(ctx, log); err != nil {
		s.logger.Error("failed to save audit log", "error", err)
	}
}

// Helper

func matchFolder(folder, pattern string) bool {
	// Simple pattern matching - could use glob or regex
	if pattern == "*" {
		return true
	}
	return folder == pattern
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
		`CREATE TABLE IF NOT EXISTS retention_policies (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			type TEXT NOT NULL,
			duration INTEGER NOT NULL,
			apply_to_all INTEGER DEFAULT 0,
			mailbox_ids TEXT,
			folder_patterns TEXT,
			action_on_expiry TEXT DEFAULT 'delete',
			notify_before INTEGER DEFAULT 0,
			notify_emails TEXT,
			is_default INTEGER DEFAULT 0,
			priority INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS legal_holds (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			case_number TEXT,
			custodian_ids TEXT,
			mailbox_ids TEXT,
			search_query TEXT,
			date_from DATETIME,
			date_to DATETIME,
			held_by TEXT NOT NULL,
			reason TEXT,
			start_date DATETIME NOT NULL,
			end_date DATETIME,
			active INTEGER DEFAULT 1,
			message_count INTEGER DEFAULT 0,
			total_size INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS archived_messages (
			id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL UNIQUE,
			account_id TEXT NOT NULL,
			org_id TEXT NOT NULL,
			from_addr TEXT NOT NULL,
			to_addrs TEXT NOT NULL,
			cc_addrs TEXT,
			bcc_addrs TEXT,
			subject TEXT NOT NULL,
			folder TEXT NOT NULL,
			size INTEGER DEFAULT 0,
			has_attachment INTEGER DEFAULT 0,
			message_date DATETIME NOT NULL,
			storage_path TEXT NOT NULL,
			checksum TEXT NOT NULL,
			content_type TEXT DEFAULT 'message/rfc822',
			compressed INTEGER DEFAULT 0,
			encrypted INTEGER DEFAULT 0,
			policy_id TEXT,
			retain_until DATETIME,
			status TEXT DEFAULT 'active',
			legal_hold_ids TEXT,
			archived_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			archived_by TEXT DEFAULT 'system',
			last_accessed_at DATETIME,
			access_count INTEGER DEFAULT 0,
			labels TEXT,
			tags TEXT
		)`,
		
		`CREATE TABLE IF NOT EXISTS export_requests (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			requested_by TEXT NOT NULL,
			account_ids TEXT,
			date_from DATETIME,
			date_to DATETIME,
			search_query TEXT,
			legal_hold_id TEXT,
			format TEXT NOT NULL,
			include_attachments INTEGER DEFAULT 1,
			status TEXT DEFAULT 'pending',
			progress INTEGER DEFAULT 0,
			message_count INTEGER DEFAULT 0,
			total_size INTEGER DEFAULT 0,
			output_path TEXT,
			error TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			started_at DATETIME,
			completed_at DATETIME
		)`,
		
		`CREATE TABLE IF NOT EXISTS archive_audit_logs (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			actor_type TEXT NOT NULL,
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			details TEXT,
			ip_address TEXT,
			user_agent TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_archived_account ON archived_messages(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_archived_org ON archived_messages(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_archived_date ON archived_messages(message_date)`,
		`CREATE INDEX IF NOT EXISTS idx_archived_status ON archived_messages(status)`,
		`CREATE INDEX IF NOT EXISTS idx_archived_retain ON archived_messages(retain_until)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_org ON archive_audit_logs(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON archive_audit_logs(timestamp)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) SavePolicy(ctx context.Context, policy *RetentionPolicy) error {
	mailboxJSON, _ := json.Marshal(policy.MailboxIDs)
	folderJSON, _ := json.Marshal(policy.FolderPatterns)
	emailsJSON, _ := json.Marshal(policy.NotifyEmails)

	query := `
	INSERT INTO retention_policies (
		id, org_id, name, description, type, duration, apply_to_all,
		mailbox_ids, folder_patterns, action_on_expiry, notify_before,
		notify_emails, is_default, priority, enabled, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		name = excluded.name,
		description = excluded.description,
		duration = excluded.duration,
		apply_to_all = excluded.apply_to_all,
		mailbox_ids = excluded.mailbox_ids,
		folder_patterns = excluded.folder_patterns,
		action_on_expiry = excluded.action_on_expiry,
		notify_before = excluded.notify_before,
		notify_emails = excluded.notify_emails,
		priority = excluded.priority,
		enabled = excluded.enabled,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		policy.ID.String(), policy.OrgID.String(), policy.Name, policy.Description,
		policy.Type, policy.Duration, policy.ApplyToAll, string(mailboxJSON),
		string(folderJSON), policy.ActionOnExpiry, policy.NotifyBefore,
		string(emailsJSON), policy.IsDefault, policy.Priority, policy.Enabled,
		policy.CreatedAt, policy.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetPolicy(ctx context.Context, id uuid.UUID) (*RetentionPolicy, error) {
	query := `
	SELECT id, org_id, name, description, type, duration, apply_to_all,
		mailbox_ids, folder_patterns, action_on_expiry, notify_before,
		notify_emails, is_default, priority, enabled, created_at, updated_at
	FROM retention_policies WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanPolicy(row)
}

func (r *SQLiteRepository) GetPolicies(ctx context.Context, orgID uuid.UUID) ([]*RetentionPolicy, error) {
	query := `
	SELECT id, org_id, name, description, type, duration, apply_to_all,
		mailbox_ids, folder_patterns, action_on_expiry, notify_before,
		notify_emails, is_default, priority, enabled, created_at, updated_at
	FROM retention_policies WHERE org_id = ? ORDER BY priority DESC
	`
	rows, err := r.db.QueryContext(ctx, query, orgID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*RetentionPolicy
	for rows.Next() {
		p, err := r.scanPolicyRow(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func (r *SQLiteRepository) GetDefaultPolicy(ctx context.Context, orgID uuid.UUID) (*RetentionPolicy, error) {
	query := `
	SELECT id, org_id, name, description, type, duration, apply_to_all,
		mailbox_ids, folder_patterns, action_on_expiry, notify_before,
		notify_emails, is_default, priority, enabled, created_at, updated_at
	FROM retention_policies WHERE org_id = ? AND is_default = 1 LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, orgID.String())
	return r.scanPolicy(row)
}

func (r *SQLiteRepository) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM retention_policies WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) scanPolicy(row *sql.Row) (*RetentionPolicy, error) {
	var p RetentionPolicy
	var idStr, orgIDStr string
	var mailboxJSON, folderJSON, emailsJSON string

	err := row.Scan(&idStr, &orgIDStr, &p.Name, &p.Description, &p.Type, &p.Duration,
		&p.ApplyToAll, &mailboxJSON, &folderJSON, &p.ActionOnExpiry, &p.NotifyBefore,
		&emailsJSON, &p.IsDefault, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}

	p.ID, _ = uuid.Parse(idStr)
	p.OrgID, _ = uuid.Parse(orgIDStr)
	_ = json.Unmarshal([]byte(mailboxJSON), &p.MailboxIDs)
	_ = json.Unmarshal([]byte(folderJSON), &p.FolderPatterns)
	_ = json.Unmarshal([]byte(emailsJSON), &p.NotifyEmails)

	return &p, nil
}

func (r *SQLiteRepository) scanPolicyRow(rows *sql.Rows) (*RetentionPolicy, error) {
	var p RetentionPolicy
	var idStr, orgIDStr string
	var mailboxJSON, folderJSON, emailsJSON string

	err := rows.Scan(&idStr, &orgIDStr, &p.Name, &p.Description, &p.Type, &p.Duration,
		&p.ApplyToAll, &mailboxJSON, &folderJSON, &p.ActionOnExpiry, &p.NotifyBefore,
		&emailsJSON, &p.IsDefault, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}

	p.ID, _ = uuid.Parse(idStr)
	p.OrgID, _ = uuid.Parse(orgIDStr)
	_ = json.Unmarshal([]byte(mailboxJSON), &p.MailboxIDs)
	_ = json.Unmarshal([]byte(folderJSON), &p.FolderPatterns)
	_ = json.Unmarshal([]byte(emailsJSON), &p.NotifyEmails)

	return &p, nil
}

// Legal Hold repository methods
func (r *SQLiteRepository) SaveLegalHold(ctx context.Context, hold *LegalHold) error {
	custodianJSON, _ := json.Marshal(hold.CustodianIDs)
	mailboxJSON, _ := json.Marshal(hold.MailboxIDs)

	query := `
	INSERT INTO legal_holds (
		id, org_id, name, description, case_number, custodian_ids, mailbox_ids,
		search_query, date_from, date_to, held_by, reason, start_date, end_date,
		active, message_count, total_size, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		name = excluded.name,
		description = excluded.description,
		active = excluded.active,
		end_date = excluded.end_date,
		message_count = excluded.message_count,
		total_size = excluded.total_size,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		hold.ID.String(), hold.OrgID.String(), hold.Name, hold.Description,
		hold.CaseNumber, string(custodianJSON), string(mailboxJSON), hold.SearchQuery,
		hold.DateFrom, hold.DateTo, hold.HeldBy.String(), hold.Reason, hold.StartDate,
		hold.EndDate, hold.Active, hold.MessageCount, hold.TotalSize,
		hold.CreatedAt, hold.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetLegalHold(ctx context.Context, id uuid.UUID) (*LegalHold, error) {
	query := `
	SELECT id, org_id, name, description, case_number, custodian_ids, mailbox_ids,
		search_query, date_from, date_to, held_by, reason, start_date, end_date,
		active, message_count, total_size, created_at, updated_at
	FROM legal_holds WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())

	var h LegalHold
	var idStr, orgIDStr, heldByStr string
	var custodianJSON, mailboxJSON string

	err := row.Scan(&idStr, &orgIDStr, &h.Name, &h.Description, &h.CaseNumber,
		&custodianJSON, &mailboxJSON, &h.SearchQuery, &h.DateFrom, &h.DateTo,
		&heldByStr, &h.Reason, &h.StartDate, &h.EndDate, &h.Active,
		&h.MessageCount, &h.TotalSize, &h.CreatedAt, &h.UpdatedAt)
	if err != nil {
		return nil, err
	}

	h.ID, _ = uuid.Parse(idStr)
	h.OrgID, _ = uuid.Parse(orgIDStr)
	h.HeldBy, _ = uuid.Parse(heldByStr)
	_ = json.Unmarshal([]byte(custodianJSON), &h.CustodianIDs)
	_ = json.Unmarshal([]byte(mailboxJSON), &h.MailboxIDs)

	return &h, nil
}

func (r *SQLiteRepository) GetActiveLegalHolds(ctx context.Context, orgID uuid.UUID) ([]*LegalHold, error) {
	query := `
	SELECT id, org_id, name, description, case_number, custodian_ids, mailbox_ids,
		search_query, date_from, date_to, held_by, reason, start_date, end_date,
		active, message_count, total_size, created_at, updated_at
	FROM legal_holds WHERE org_id = ? AND active = 1
	`
	rows, err := r.db.QueryContext(ctx, query, orgID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var holds []*LegalHold
	for rows.Next() {
		var h LegalHold
		var idStr, orgIDStr, heldByStr string
		var custodianJSON, mailboxJSON string

		err := rows.Scan(&idStr, &orgIDStr, &h.Name, &h.Description, &h.CaseNumber,
			&custodianJSON, &mailboxJSON, &h.SearchQuery, &h.DateFrom, &h.DateTo,
			&heldByStr, &h.Reason, &h.StartDate, &h.EndDate, &h.Active,
			&h.MessageCount, &h.TotalSize, &h.CreatedAt, &h.UpdatedAt)
		if err != nil {
			return nil, err
		}

		h.ID, _ = uuid.Parse(idStr)
		h.OrgID, _ = uuid.Parse(orgIDStr)
		h.HeldBy, _ = uuid.Parse(heldByStr)
		_ = json.Unmarshal([]byte(custodianJSON), &h.CustodianIDs)
		_ = json.Unmarshal([]byte(mailboxJSON), &h.MailboxIDs)

		holds = append(holds, &h)
	}
	return holds, rows.Err()
}

func (r *SQLiteRepository) GetHoldsForMessage(ctx context.Context, messageID uuid.UUID) ([]*LegalHold, error) {
	// Would need to query archived_messages to get hold IDs, then fetch holds
	return nil, nil
}

func (r *SQLiteRepository) UpdateLegalHold(ctx context.Context, hold *LegalHold) error {
	return r.SaveLegalHold(ctx, hold)
}

// Archived message repository methods
func (r *SQLiteRepository) SaveArchivedMessage(ctx context.Context, msg *ArchivedMessage) error {
	toJSON, _ := json.Marshal(msg.To)
	ccJSON, _ := json.Marshal(msg.Cc)
	bccJSON, _ := json.Marshal(msg.Bcc)
	holdsJSON, _ := json.Marshal(msg.LegalHoldIDs)
	labelsJSON, _ := json.Marshal(msg.Labels)
	tagsJSON, _ := json.Marshal(msg.Tags)

	var policyID *string
	if msg.PolicyID != nil {
		s := msg.PolicyID.String()
		policyID = &s
	}

	query := `
	INSERT INTO archived_messages (
		id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, folder, size, has_attachment, message_date, storage_path, checksum,
		content_type, compressed, encrypted, policy_id, retain_until, status,
		legal_hold_ids, archived_at, archived_by, last_accessed_at, access_count,
		labels, tags
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(message_id) DO UPDATE SET
		status = excluded.status,
		legal_hold_ids = excluded.legal_hold_ids,
		last_accessed_at = excluded.last_accessed_at,
		access_count = excluded.access_count
	`

	_, err := r.db.ExecContext(ctx, query,
		msg.ID.String(), msg.MessageID.String(), msg.AccountID.String(), msg.OrgID.String(),
		msg.From, string(toJSON), string(ccJSON), string(bccJSON), msg.Subject, msg.Folder,
		msg.Size, msg.HasAttachment, msg.MessageDate, msg.StoragePath, msg.Checksum,
		msg.ContentType, msg.Compressed, msg.Encrypted, policyID, msg.RetainUntil,
		msg.Status, string(holdsJSON), msg.ArchivedAt, msg.ArchivedBy, msg.LastAccessedAt,
		msg.AccessCount, string(labelsJSON), string(tagsJSON))

	return err
}

func (r *SQLiteRepository) GetArchivedMessage(ctx context.Context, id uuid.UUID) (*ArchivedMessage, error) {
	query := `
	SELECT id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, folder, size, has_attachment, message_date, storage_path, checksum,
		content_type, compressed, encrypted, policy_id, retain_until, status,
		legal_hold_ids, archived_at, archived_by, last_accessed_at, access_count,
		labels, tags
	FROM archived_messages WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanArchivedMessage(row)
}

func (r *SQLiteRepository) GetArchivedMessageByOriginal(ctx context.Context, messageID uuid.UUID) (*ArchivedMessage, error) {
	query := `
	SELECT id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, folder, size, has_attachment, message_date, storage_path, checksum,
		content_type, compressed, encrypted, policy_id, retain_until, status,
		legal_hold_ids, archived_at, archived_by, last_accessed_at, access_count,
		labels, tags
	FROM archived_messages WHERE message_id = ?
	`
	row := r.db.QueryRowContext(ctx, query, messageID.String())
	return r.scanArchivedMessage(row)
}

func (r *SQLiteRepository) scanArchivedMessage(row *sql.Row) (*ArchivedMessage, error) {
	var msg ArchivedMessage
	var idStr, messageIDStr, accountIDStr, orgIDStr string
	var toJSON, ccJSON, bccJSON, holdsJSON, labelsJSON, tagsJSON string
	var policyIDStr *string

	err := row.Scan(&idStr, &messageIDStr, &accountIDStr, &orgIDStr, &msg.From,
		&toJSON, &ccJSON, &bccJSON, &msg.Subject, &msg.Folder, &msg.Size,
		&msg.HasAttachment, &msg.MessageDate, &msg.StoragePath, &msg.Checksum,
		&msg.ContentType, &msg.Compressed, &msg.Encrypted, &policyIDStr,
		&msg.RetainUntil, &msg.Status, &holdsJSON, &msg.ArchivedAt, &msg.ArchivedBy,
		&msg.LastAccessedAt, &msg.AccessCount, &labelsJSON, &tagsJSON)
	if err != nil {
		return nil, err
	}

	msg.ID, _ = uuid.Parse(idStr)
	msg.MessageID, _ = uuid.Parse(messageIDStr)
	msg.AccountID, _ = uuid.Parse(accountIDStr)
	msg.OrgID, _ = uuid.Parse(orgIDStr)
	if policyIDStr != nil {
		id, _ := uuid.Parse(*policyIDStr)
		msg.PolicyID = &id
	}
	_ = json.Unmarshal([]byte(toJSON), &msg.To)
	_ = json.Unmarshal([]byte(ccJSON), &msg.Cc)
	_ = json.Unmarshal([]byte(bccJSON), &msg.Bcc)
	_ = json.Unmarshal([]byte(holdsJSON), &msg.LegalHoldIDs)
	_ = json.Unmarshal([]byte(labelsJSON), &msg.Labels)
	_ = json.Unmarshal([]byte(tagsJSON), &msg.Tags)

	return &msg, nil
}

func (r *SQLiteRepository) SearchArchive(ctx context.Context, query *ArchiveQuery) ([]*ArchivedMessage, int64, error) {
	var conditions []string
	var args []interface{}

	conditions = append(conditions, "org_id = ?")
	args = append(args, query.OrgID.String())

	if query.AccountID != nil {
		conditions = append(conditions, "account_id = ?")
		args = append(args, query.AccountID.String())
	}
	if query.DateFrom != nil {
		conditions = append(conditions, "message_date >= ?")
		args = append(args, *query.DateFrom)
	}
	if query.DateTo != nil {
		conditions = append(conditions, "message_date <= ?")
		args = append(args, *query.DateTo)
	}
	if query.Status != nil {
		conditions = append(conditions, "status = ?")
		args = append(args, *query.Status)
	}

	whereClause := "WHERE " + joinStrings(conditions, " AND ")

	// Count
	var total int64
	countQuery := "SELECT COUNT(*) FROM archived_messages " + whereClause
	r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)

	// Results
	if query.Limit == 0 {
		query.Limit = 100
	}
	selectQuery := fmt.Sprintf(`
	SELECT id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, folder, size, has_attachment, message_date, storage_path, checksum,
		content_type, compressed, encrypted, policy_id, retain_until, status,
		legal_hold_ids, archived_at, archived_by, last_accessed_at, access_count,
		labels, tags
	FROM archived_messages %s ORDER BY message_date DESC LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, query.Limit, query.Offset)
	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var messages []*ArchivedMessage
	for rows.Next() {
		var msg ArchivedMessage
		var idStr, messageIDStr, accountIDStr, orgIDStr string
		var toJSON, ccJSON, bccJSON, holdsJSON, labelsJSON, tagsJSON string
		var policyIDStr *string

		err := rows.Scan(&idStr, &messageIDStr, &accountIDStr, &orgIDStr, &msg.From,
			&toJSON, &ccJSON, &bccJSON, &msg.Subject, &msg.Folder, &msg.Size,
			&msg.HasAttachment, &msg.MessageDate, &msg.StoragePath, &msg.Checksum,
			&msg.ContentType, &msg.Compressed, &msg.Encrypted, &policyIDStr,
			&msg.RetainUntil, &msg.Status, &holdsJSON, &msg.ArchivedAt, &msg.ArchivedBy,
			&msg.LastAccessedAt, &msg.AccessCount, &labelsJSON, &tagsJSON)
		if err != nil {
			return nil, 0, err
		}

		msg.ID, _ = uuid.Parse(idStr)
		msg.MessageID, _ = uuid.Parse(messageIDStr)
		msg.AccountID, _ = uuid.Parse(accountIDStr)
		msg.OrgID, _ = uuid.Parse(orgIDStr)
		if policyIDStr != nil {
			id, _ := uuid.Parse(*policyIDStr)
			msg.PolicyID = &id
		}
		_ = json.Unmarshal([]byte(toJSON), &msg.To)
		_ = json.Unmarshal([]byte(ccJSON), &msg.Cc)
		_ = json.Unmarshal([]byte(bccJSON), &msg.Bcc)
		_ = json.Unmarshal([]byte(holdsJSON), &msg.LegalHoldIDs)
		_ = json.Unmarshal([]byte(labelsJSON), &msg.Labels)
		_ = json.Unmarshal([]byte(tagsJSON), &msg.Tags)

		messages = append(messages, &msg)
	}

	return messages, total, rows.Err()
}

func (r *SQLiteRepository) UpdateArchiveStatus(ctx context.Context, id uuid.UUID, status ArchiveStatus) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE archived_messages SET status = ? WHERE id = ?",
		status, id.String())
	return err
}

func (r *SQLiteRepository) GetExpiredMessages(ctx context.Context, limit int) ([]*ArchivedMessage, error) {
	query := `
	SELECT id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, folder, size, has_attachment, message_date, storage_path, checksum,
		content_type, compressed, encrypted, policy_id, retain_until, status,
		legal_hold_ids, archived_at, archived_by, last_accessed_at, access_count,
		labels, tags
	FROM archived_messages 
	WHERE retain_until < ? AND status = 'active'
	LIMIT ?
	`
	rows, err := r.db.QueryContext(ctx, query, time.Now(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*ArchivedMessage
	for rows.Next() {
		var msg ArchivedMessage
		var idStr, messageIDStr, accountIDStr, orgIDStr string
		var toJSON, ccJSON, bccJSON, holdsJSON, labelsJSON, tagsJSON string
		var policyIDStr *string

		err := rows.Scan(&idStr, &messageIDStr, &accountIDStr, &orgIDStr, &msg.From,
			&toJSON, &ccJSON, &bccJSON, &msg.Subject, &msg.Folder, &msg.Size,
			&msg.HasAttachment, &msg.MessageDate, &msg.StoragePath, &msg.Checksum,
			&msg.ContentType, &msg.Compressed, &msg.Encrypted, &policyIDStr,
			&msg.RetainUntil, &msg.Status, &holdsJSON, &msg.ArchivedAt, &msg.ArchivedBy,
			&msg.LastAccessedAt, &msg.AccessCount, &labelsJSON, &tagsJSON)
		if err != nil {
			return nil, err
		}

		msg.ID, _ = uuid.Parse(idStr)
		msg.MessageID, _ = uuid.Parse(messageIDStr)
		msg.AccountID, _ = uuid.Parse(accountIDStr)
		msg.OrgID, _ = uuid.Parse(orgIDStr)
		if policyIDStr != nil {
			id, _ := uuid.Parse(*policyIDStr)
			msg.PolicyID = &id
		}
		_ = json.Unmarshal([]byte(toJSON), &msg.To)
		_ = json.Unmarshal([]byte(ccJSON), &msg.Cc)
		_ = json.Unmarshal([]byte(bccJSON), &msg.Bcc)
		_ = json.Unmarshal([]byte(holdsJSON), &msg.LegalHoldIDs)
		_ = json.Unmarshal([]byte(labelsJSON), &msg.Labels)
		_ = json.Unmarshal([]byte(tagsJSON), &msg.Tags)

		messages = append(messages, &msg)
	}

	return messages, rows.Err()
}

func (r *SQLiteRepository) GetMessagesOnHold(ctx context.Context, holdID uuid.UUID) ([]*ArchivedMessage, error) {
	// This is a simplified implementation - would need JSON containment query
	query := `
	SELECT id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, folder, size, has_attachment, message_date, storage_path, checksum,
		content_type, compressed, encrypted, policy_id, retain_until, status,
		legal_hold_ids, archived_at, archived_by, last_accessed_at, access_count,
		labels, tags
	FROM archived_messages 
	WHERE legal_hold_ids LIKE ?
	`
	rows, err := r.db.QueryContext(ctx, query, "%"+holdID.String()+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*ArchivedMessage
	for rows.Next() {
		var msg ArchivedMessage
		var idStr, messageIDStr, accountIDStr, orgIDStr string
		var toJSON, ccJSON, bccJSON, holdsJSON, labelsJSON, tagsJSON string
		var policyIDStr *string

		err := rows.Scan(&idStr, &messageIDStr, &accountIDStr, &orgIDStr, &msg.From,
			&toJSON, &ccJSON, &bccJSON, &msg.Subject, &msg.Folder, &msg.Size,
			&msg.HasAttachment, &msg.MessageDate, &msg.StoragePath, &msg.Checksum,
			&msg.ContentType, &msg.Compressed, &msg.Encrypted, &policyIDStr,
			&msg.RetainUntil, &msg.Status, &holdsJSON, &msg.ArchivedAt, &msg.ArchivedBy,
			&msg.LastAccessedAt, &msg.AccessCount, &labelsJSON, &tagsJSON)
		if err != nil {
			return nil, err
		}

		msg.ID, _ = uuid.Parse(idStr)
		msg.MessageID, _ = uuid.Parse(messageIDStr)
		msg.AccountID, _ = uuid.Parse(accountIDStr)
		msg.OrgID, _ = uuid.Parse(orgIDStr)
		if policyIDStr != nil {
			id, _ := uuid.Parse(*policyIDStr)
			msg.PolicyID = &id
		}
		_ = json.Unmarshal([]byte(toJSON), &msg.To)
		_ = json.Unmarshal([]byte(ccJSON), &msg.Cc)
		_ = json.Unmarshal([]byte(bccJSON), &msg.Bcc)
		_ = json.Unmarshal([]byte(holdsJSON), &msg.LegalHoldIDs)
		_ = json.Unmarshal([]byte(labelsJSON), &msg.Labels)
		_ = json.Unmarshal([]byte(tagsJSON), &msg.Tags)

		messages = append(messages, &msg)
	}

	return messages, rows.Err()
}

// Export request repository methods
func (r *SQLiteRepository) SaveExportRequest(ctx context.Context, req *ExportRequest) error {
	accountsJSON, _ := json.Marshal(req.AccountIDs)
	var legalHoldID *string
	if req.LegalHoldID != nil {
		s := req.LegalHoldID.String()
		legalHoldID = &s
	}

	query := `
	INSERT INTO export_requests (
		id, org_id, requested_by, account_ids, date_from, date_to, search_query,
		legal_hold_id, format, include_attachments, status, progress, message_count,
		total_size, output_path, error, created_at, started_at, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		status = excluded.status,
		progress = excluded.progress,
		message_count = excluded.message_count,
		total_size = excluded.total_size,
		output_path = excluded.output_path,
		error = excluded.error,
		started_at = excluded.started_at,
		completed_at = excluded.completed_at
	`

	_, err := r.db.ExecContext(ctx, query,
		req.ID.String(), req.OrgID.String(), req.RequestedBy.String(),
		string(accountsJSON), req.DateFrom, req.DateTo, req.SearchQuery,
		legalHoldID, req.Format, req.IncludeAttachments, req.Status,
		req.Progress, req.MessageCount, req.TotalSize, req.OutputPath,
		req.Error, req.CreatedAt, req.StartedAt, req.CompletedAt)

	return err
}

func (r *SQLiteRepository) GetExportRequest(ctx context.Context, id uuid.UUID) (*ExportRequest, error) {
	query := `
	SELECT id, org_id, requested_by, account_ids, date_from, date_to, search_query,
		legal_hold_id, format, include_attachments, status, progress, message_count,
		total_size, output_path, error, created_at, started_at, completed_at
	FROM export_requests WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())

	var req ExportRequest
	var idStr, orgIDStr, requestedByStr string
	var accountsJSON string
	var legalHoldIDStr *string

	err := row.Scan(&idStr, &orgIDStr, &requestedByStr, &accountsJSON,
		&req.DateFrom, &req.DateTo, &req.SearchQuery, &legalHoldIDStr,
		&req.Format, &req.IncludeAttachments, &req.Status, &req.Progress,
		&req.MessageCount, &req.TotalSize, &req.OutputPath, &req.Error,
		&req.CreatedAt, &req.StartedAt, &req.CompletedAt)
	if err != nil {
		return nil, err
	}

	req.ID, _ = uuid.Parse(idStr)
	req.OrgID, _ = uuid.Parse(orgIDStr)
	req.RequestedBy, _ = uuid.Parse(requestedByStr)
	if legalHoldIDStr != nil {
		id, _ := uuid.Parse(*legalHoldIDStr)
		req.LegalHoldID = &id
	}
	_ = json.Unmarshal([]byte(accountsJSON), &req.AccountIDs)

	return &req, nil
}

func (r *SQLiteRepository) UpdateExportRequest(ctx context.Context, req *ExportRequest) error {
	return r.SaveExportRequest(ctx, req)
}

// Audit log repository methods
func (r *SQLiteRepository) SaveAuditLog(ctx context.Context, log *AuditLog) error {
	query := `
	INSERT INTO archive_audit_logs (
		id, org_id, actor_id, actor_type, action, resource_type, resource_id,
		details, ip_address, user_agent, timestamp
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		log.ID.String(), log.OrgID.String(), log.ActorID.String(),
		log.ActorType, log.Action, log.ResourceType, log.ResourceID.String(),
		log.Details, log.IPAddress, log.UserAgent, log.Timestamp)

	return err
}

func (r *SQLiteRepository) GetAuditLogs(ctx context.Context, query *AuditQuery) ([]*AuditLog, error) {
	var conditions []string
	var args []interface{}

	conditions = append(conditions, "org_id = ?")
	args = append(args, query.OrgID.String())

	if query.ActorID != nil {
		conditions = append(conditions, "actor_id = ?")
		args = append(args, query.ActorID.String())
	}
	if query.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, query.Action)
	}
	if query.ResourceType != "" {
		conditions = append(conditions, "resource_type = ?")
		args = append(args, query.ResourceType)
	}
	if query.DateFrom != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, *query.DateFrom)
	}
	if query.DateTo != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, *query.DateTo)
	}

	if query.Limit == 0 {
		query.Limit = 100
	}

	selectQuery := fmt.Sprintf(`
	SELECT id, org_id, actor_id, actor_type, action, resource_type, resource_id,
		details, ip_address, user_agent, timestamp
	FROM archive_audit_logs
	WHERE %s
	ORDER BY timestamp DESC
	LIMIT ? OFFSET ?
	`, joinStrings(conditions, " AND "))

	args = append(args, query.Limit, query.Offset)
	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		var idStr, orgIDStr, actorIDStr, resourceIDStr string

		err := rows.Scan(&idStr, &orgIDStr, &actorIDStr, &log.ActorType,
			&log.Action, &log.ResourceType, &resourceIDStr, &log.Details,
			&log.IPAddress, &log.UserAgent, &log.Timestamp)
		if err != nil {
			return nil, err
		}

		log.ID, _ = uuid.Parse(idStr)
		log.OrgID, _ = uuid.Parse(orgIDStr)
		log.ActorID, _ = uuid.Parse(actorIDStr)
		log.ResourceID, _ = uuid.Parse(resourceIDStr)

		logs = append(logs, &log)
	}

	return logs, rows.Err()
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
