package scheduler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ScheduleStatus represents the status of a scheduled email
type ScheduleStatus string

const (
	StatusPending   ScheduleStatus = "pending"
	StatusSending   ScheduleStatus = "sending"
	StatusSent      ScheduleStatus = "sent"
	StatusFailed    ScheduleStatus = "failed"
	StatusCancelled ScheduleStatus = "cancelled"
)

// ScheduleType represents the type of schedule
type ScheduleType string

const (
	TypeOneTime    ScheduleType = "one_time"
	TypeRecurring  ScheduleType = "recurring"
	TypeCampaign   ScheduleType = "campaign"
)

// RecurrencePattern defines how often an email recurs
type RecurrencePattern string

const (
	RecurDaily   RecurrencePattern = "daily"
	RecurWeekly  RecurrencePattern = "weekly"
	RecurMonthly RecurrencePattern = "monthly"
	RecurYearly  RecurrencePattern = "yearly"
	RecurCustom  RecurrencePattern = "custom"
)

// ScheduledEmail represents an email scheduled for future delivery
type ScheduledEmail struct {
	ID              uuid.UUID         `json:"id"`
	OrgID           uuid.UUID         `json:"org_id"`
	AccountID       uuid.UUID         `json:"account_id"`
	Type            ScheduleType      `json:"type"`
	Status          ScheduleStatus    `json:"status"`
	
	// Email content
	From            string            `json:"from"`
	To              []string          `json:"to"`
	Cc              []string          `json:"cc,omitempty"`
	Bcc             []string          `json:"bcc,omitempty"`
	Subject         string            `json:"subject"`
	Body            string            `json:"body"`
	BodyHTML        string            `json:"body_html,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Attachments     []Attachment      `json:"attachments,omitempty"`
	
	// Scheduling
	ScheduledAt     time.Time         `json:"scheduled_at"`
	Timezone        string            `json:"timezone"`
	
	// Recurrence (for recurring emails)
	Recurrence      *RecurrenceConfig `json:"recurrence,omitempty"`
	NextRunAt       *time.Time        `json:"next_run_at,omitempty"`
	LastRunAt       *time.Time        `json:"last_run_at,omitempty"`
	RunCount        int               `json:"run_count"`
	MaxRuns         int               `json:"max_runs,omitempty"`
	
	// Campaign (for bulk sends)
	CampaignID      *uuid.UUID        `json:"campaign_id,omitempty"`
	TemplateID      *uuid.UUID        `json:"template_id,omitempty"`
	TemplateData    json.RawMessage   `json:"template_data,omitempty"`
	
	// Tracking
	TrackOpens      bool              `json:"track_opens"`
	TrackClicks     bool              `json:"track_clicks"`
	
	// Result
	SentAt          *time.Time        `json:"sent_at,omitempty"`
	ErrorMessage    string            `json:"error_message,omitempty"`
	RetryCount      int               `json:"retry_count"`
	MaxRetries      int               `json:"max_retries"`
	
	// Metadata
	Tags            []string          `json:"tags,omitempty"`
	Metadata        json.RawMessage   `json:"metadata,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	StoragePath string `json:"storage_path"`
}

// RecurrenceConfig defines recurrence settings
type RecurrenceConfig struct {
	Pattern     RecurrencePattern `json:"pattern"`
	Interval    int               `json:"interval"`     // Every N days/weeks/months
	DaysOfWeek  []int             `json:"days_of_week,omitempty"` // 0=Sun, 6=Sat
	DayOfMonth  int               `json:"day_of_month,omitempty"`
	MonthOfYear int               `json:"month_of_year,omitempty"`
	Time        string            `json:"time"`         // HH:MM format
	EndDate     *time.Time        `json:"end_date,omitempty"`
	CronExpr    string            `json:"cron_expr,omitempty"` // For custom patterns
}

// Campaign represents an email campaign
type Campaign struct {
	ID              uuid.UUID       `json:"id"`
	OrgID           uuid.UUID       `json:"org_id"`
	AccountID       uuid.UUID       `json:"account_id"`
	Name            string          `json:"name"`
	Description     string          `json:"description,omitempty"`
	Status          CampaignStatus  `json:"status"`
	
	// Content
	TemplateID      *uuid.UUID      `json:"template_id,omitempty"`
	Subject         string          `json:"subject"`
	Body            string          `json:"body"`
	BodyHTML        string          `json:"body_html,omitempty"`
	
	// Recipients
	ListID          *uuid.UUID      `json:"list_id,omitempty"`  // Mailing list
	Recipients      []string        `json:"recipients,omitempty"`
	TotalRecipients int             `json:"total_recipients"`
	
	// Schedule
	ScheduledAt     *time.Time      `json:"scheduled_at,omitempty"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	
	// Stats
	SentCount       int             `json:"sent_count"`
	FailedCount     int             `json:"failed_count"`
	OpenCount       int             `json:"open_count"`
	ClickCount      int             `json:"click_count"`
	BounceCount     int             `json:"bounce_count"`
	UnsubCount      int             `json:"unsub_count"`
	
	// Settings
	TrackOpens      bool            `json:"track_opens"`
	TrackClicks     bool            `json:"track_clicks"`
	BatchSize       int             `json:"batch_size"`
	BatchDelay      int             `json:"batch_delay_seconds"`
	
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// CampaignStatus represents campaign state
type CampaignStatus string

const (
	CampaignDraft     CampaignStatus = "draft"
	CampaignScheduled CampaignStatus = "scheduled"
	CampaignSending   CampaignStatus = "sending"
	CampaignPaused    CampaignStatus = "paused"
	CampaignCompleted CampaignStatus = "completed"
	CampaignCancelled CampaignStatus = "cancelled"
)

// Scheduler manages scheduled email delivery
type Scheduler struct {
	mu          sync.RWMutex
	repo        Repository
	sender      EmailSender
	logger      Logger
	workers     int
	ticker      *time.Ticker
	stopCh      chan struct{}
	running     bool
}

// EmailSender interface for sending emails
type EmailSender interface {
	Send(ctx context.Context, email *ScheduledEmail) error
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// Repository interface for scheduled emails
type Repository interface {
	// Scheduled emails
	CreateScheduledEmail(ctx context.Context, email *ScheduledEmail) error
	GetScheduledEmail(ctx context.Context, id uuid.UUID) (*ScheduledEmail, error)
	UpdateScheduledEmail(ctx context.Context, email *ScheduledEmail) error
	DeleteScheduledEmail(ctx context.Context, id uuid.UUID) error
	GetPendingEmails(ctx context.Context, before time.Time, limit int) ([]*ScheduledEmail, error)
	GetScheduledEmailsByAccount(ctx context.Context, accountID uuid.UUID) ([]*ScheduledEmail, error)
	
	// Campaigns
	CreateCampaign(ctx context.Context, campaign *Campaign) error
	GetCampaign(ctx context.Context, id uuid.UUID) (*Campaign, error)
	UpdateCampaign(ctx context.Context, campaign *Campaign) error
	DeleteCampaign(ctx context.Context, id uuid.UUID) error
	GetCampaignsByOrg(ctx context.Context, orgID uuid.UUID) ([]*Campaign, error)
	GetPendingCampaigns(ctx context.Context, before time.Time) ([]*Campaign, error)
}

// NewScheduler creates a new email scheduler
func NewScheduler(repo Repository, sender EmailSender, logger Logger, workers int) *Scheduler {
	if workers <= 0 {
		workers = 4
	}
	return &Scheduler{
		repo:    repo,
		sender:  sender,
		logger:  logger,
		workers: workers,
		stopCh:  make(chan struct{}),
	}
}

// Start begins the scheduler
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("scheduler already running")
	}
	s.running = true
	s.ticker = time.NewTicker(10 * time.Second)
	s.mu.Unlock()

	s.logger.Info("scheduler started", "workers", s.workers)

	go s.run(ctx)
	return nil
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	s.ticker.Stop()
	s.running = false
	s.logger.Info("scheduler stopped")
}

func (s *Scheduler) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-s.ticker.C:
			s.processPending(ctx)
		}
	}
}

func (s *Scheduler) processPending(ctx context.Context) {
	// Get pending emails due for delivery
	emails, err := s.repo.GetPendingEmails(ctx, time.Now(), 100)
	if err != nil {
		s.logger.Error("failed to get pending emails", "error", err)
		return
	}

	if len(emails) == 0 {
		return
	}

	s.logger.Debug("processing pending emails", "count", len(emails))

	// Process in parallel with worker pool
	sem := make(chan struct{}, s.workers)
	var wg sync.WaitGroup

	for _, email := range emails {
		wg.Add(1)
		sem <- struct{}{}

		go func(email *ScheduledEmail) {
			defer wg.Done()
			defer func() { <-sem }()

			s.processEmail(ctx, email)
		}(email)
	}

	wg.Wait()
}

func (s *Scheduler) processEmail(ctx context.Context, email *ScheduledEmail) {
	// Mark as sending
	email.Status = StatusSending
	email.UpdatedAt = time.Now()
	if err := s.repo.UpdateScheduledEmail(ctx, email); err != nil {
		s.logger.Error("failed to update email status", "id", email.ID, "error", err)
		return
	}

	// Send the email
	err := s.sender.Send(ctx, email)
	now := time.Now()

	if err != nil {
		email.RetryCount++
		email.ErrorMessage = err.Error()

		if email.RetryCount >= email.MaxRetries {
			email.Status = StatusFailed
			s.logger.Error("email failed permanently", "id", email.ID, "error", err)
		} else {
			// Schedule retry with exponential backoff
			email.Status = StatusPending
			retryDelay := time.Duration(email.RetryCount*email.RetryCount) * time.Minute
			nextTry := now.Add(retryDelay)
			email.ScheduledAt = nextTry
			s.logger.Info("email scheduled for retry", "id", email.ID, "retry", email.RetryCount, "at", nextTry)
		}
	} else {
		email.Status = StatusSent
		email.SentAt = &now
		email.ErrorMessage = ""
		s.logger.Info("email sent", "id", email.ID, "to", email.To)

		// Handle recurrence
		if email.Recurrence != nil && email.Type == TypeRecurring {
			s.scheduleNextRecurrence(ctx, email)
		}
	}

	email.UpdatedAt = now
	if err := s.repo.UpdateScheduledEmail(ctx, email); err != nil {
		s.logger.Error("failed to update email after send", "id", email.ID, "error", err)
	}
}

func (s *Scheduler) scheduleNextRecurrence(ctx context.Context, email *ScheduledEmail) {
	if email.Recurrence == nil {
		return
	}

	// Check max runs
	if email.MaxRuns > 0 && email.RunCount >= email.MaxRuns {
		s.logger.Info("recurring email reached max runs", "id", email.ID, "runs", email.RunCount)
		return
	}

	// Check end date
	if email.Recurrence.EndDate != nil && time.Now().After(*email.Recurrence.EndDate) {
		s.logger.Info("recurring email passed end date", "id", email.ID)
		return
	}

	// Calculate next run time
	nextRun := s.calculateNextRun(email)
	if nextRun == nil {
		return
	}

	// Create new scheduled email for next occurrence
	newEmail := &ScheduledEmail{
		ID:          uuid.New(),
		OrgID:       email.OrgID,
		AccountID:   email.AccountID,
		Type:        TypeRecurring,
		Status:      StatusPending,
		From:        email.From,
		To:          email.To,
		Cc:          email.Cc,
		Bcc:         email.Bcc,
		Subject:     email.Subject,
		Body:        email.Body,
		BodyHTML:    email.BodyHTML,
		Headers:     email.Headers,
		Attachments: email.Attachments,
		ScheduledAt: *nextRun,
		Timezone:    email.Timezone,
		Recurrence:  email.Recurrence,
		RunCount:    email.RunCount + 1,
		MaxRuns:     email.MaxRuns,
		TrackOpens:  email.TrackOpens,
		TrackClicks: email.TrackClicks,
		MaxRetries:  email.MaxRetries,
		Tags:        email.Tags,
		Metadata:    email.Metadata,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.repo.CreateScheduledEmail(ctx, newEmail); err != nil {
		s.logger.Error("failed to schedule next recurrence", "id", email.ID, "error", err)
	} else {
		s.logger.Info("scheduled next recurrence", "original", email.ID, "new", newEmail.ID, "at", nextRun)
	}
}

func (s *Scheduler) calculateNextRun(email *ScheduledEmail) *time.Time {
	if email.Recurrence == nil {
		return nil
	}

	rec := email.Recurrence
	base := email.ScheduledAt
	if email.LastRunAt != nil {
		base = *email.LastRunAt
	}

	var next time.Time

	switch rec.Pattern {
	case RecurDaily:
		next = base.AddDate(0, 0, rec.Interval)

	case RecurWeekly:
		next = base.AddDate(0, 0, 7*rec.Interval)
		// Adjust to specific day of week if configured
		if len(rec.DaysOfWeek) > 0 {
			// Find next matching day
			for i := 1; i <= 7; i++ {
				candidate := base.AddDate(0, 0, i)
				for _, dow := range rec.DaysOfWeek {
					if int(candidate.Weekday()) == dow {
						next = candidate
						goto found
					}
				}
			}
		found:
		}

	case RecurMonthly:
		next = base.AddDate(0, rec.Interval, 0)
		if rec.DayOfMonth > 0 {
			next = time.Date(next.Year(), next.Month(), rec.DayOfMonth,
				next.Hour(), next.Minute(), next.Second(), 0, next.Location())
		}

	case RecurYearly:
		next = base.AddDate(rec.Interval, 0, 0)

	default:
		return nil
	}

	// Apply time if specified
	if rec.Time != "" {
		var hour, min int
		fmt.Sscanf(rec.Time, "%d:%d", &hour, &min)
		next = time.Date(next.Year(), next.Month(), next.Day(), hour, min, 0, 0, next.Location())
	}

	return &next
}

// Schedule schedules an email for future delivery
func (s *Scheduler) Schedule(ctx context.Context, email *ScheduledEmail) error {
	if email.ID == uuid.Nil {
		email.ID = uuid.New()
	}
	if email.Status == "" {
		email.Status = StatusPending
	}
	if email.Type == "" {
		email.Type = TypeOneTime
	}
	if email.MaxRetries == 0 {
		email.MaxRetries = 3
	}
	email.CreatedAt = time.Now()
	email.UpdatedAt = time.Now()

	return s.repo.CreateScheduledEmail(ctx, email)
}

// Cancel cancels a scheduled email
func (s *Scheduler) Cancel(ctx context.Context, id uuid.UUID) error {
	email, err := s.repo.GetScheduledEmail(ctx, id)
	if err != nil {
		return err
	}

	if email.Status == StatusSent {
		return errors.New("cannot cancel already sent email")
	}

	email.Status = StatusCancelled
	email.UpdatedAt = time.Now()

	return s.repo.UpdateScheduledEmail(ctx, email)
}

// Reschedule changes the scheduled time of an email
func (s *Scheduler) Reschedule(ctx context.Context, id uuid.UUID, newTime time.Time) error {
	email, err := s.repo.GetScheduledEmail(ctx, id)
	if err != nil {
		return err
	}

	if email.Status == StatusSent {
		return errors.New("cannot reschedule already sent email")
	}

	email.ScheduledAt = newTime
	email.Status = StatusPending
	email.UpdatedAt = time.Now()

	return s.repo.UpdateScheduledEmail(ctx, email)
}

// GetPending returns pending scheduled emails for an account
func (s *Scheduler) GetPending(ctx context.Context, accountID uuid.UUID) ([]*ScheduledEmail, error) {
	return s.repo.GetScheduledEmailsByAccount(ctx, accountID)
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
		`CREATE TABLE IF NOT EXISTS scheduled_emails (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'one_time',
			status TEXT NOT NULL DEFAULT 'pending',
			from_addr TEXT NOT NULL,
			to_addrs TEXT NOT NULL,
			cc_addrs TEXT,
			bcc_addrs TEXT,
			subject TEXT NOT NULL,
			body TEXT NOT NULL,
			body_html TEXT,
			headers TEXT,
			attachments TEXT,
			scheduled_at DATETIME NOT NULL,
			timezone TEXT DEFAULT 'UTC',
			recurrence TEXT,
			next_run_at DATETIME,
			last_run_at DATETIME,
			run_count INTEGER DEFAULT 0,
			max_runs INTEGER DEFAULT 0,
			campaign_id TEXT,
			template_id TEXT,
			template_data TEXT,
			track_opens INTEGER DEFAULT 0,
			track_clicks INTEGER DEFAULT 0,
			sent_at DATETIME,
			error_message TEXT,
			retry_count INTEGER DEFAULT 0,
			max_retries INTEGER DEFAULT 3,
			tags TEXT,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scheduled_emails_status ON scheduled_emails(status, scheduled_at)`,
		`CREATE INDEX IF NOT EXISTS idx_scheduled_emails_account ON scheduled_emails(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scheduled_emails_campaign ON scheduled_emails(campaign_id)`,
		
		`CREATE TABLE IF NOT EXISTS campaigns (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			status TEXT NOT NULL DEFAULT 'draft',
			template_id TEXT,
			subject TEXT NOT NULL,
			body TEXT NOT NULL,
			body_html TEXT,
			list_id TEXT,
			recipients TEXT,
			total_recipients INTEGER DEFAULT 0,
			scheduled_at DATETIME,
			started_at DATETIME,
			completed_at DATETIME,
			sent_count INTEGER DEFAULT 0,
			failed_count INTEGER DEFAULT 0,
			open_count INTEGER DEFAULT 0,
			click_count INTEGER DEFAULT 0,
			bounce_count INTEGER DEFAULT 0,
			unsub_count INTEGER DEFAULT 0,
			track_opens INTEGER DEFAULT 1,
			track_clicks INTEGER DEFAULT 1,
			batch_size INTEGER DEFAULT 100,
			batch_delay INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_campaigns_org ON campaigns(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) CreateScheduledEmail(ctx context.Context, email *ScheduledEmail) error {
	toJSON, _ := json.Marshal(email.To)
	ccJSON, _ := json.Marshal(email.Cc)
	bccJSON, _ := json.Marshal(email.Bcc)
	headersJSON, _ := json.Marshal(email.Headers)
	attachJSON, _ := json.Marshal(email.Attachments)
	recurJSON, _ := json.Marshal(email.Recurrence)
	tagsJSON, _ := json.Marshal(email.Tags)

	query := `
	INSERT INTO scheduled_emails (
		id, org_id, account_id, type, status, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, body, body_html, headers, attachments, scheduled_at, timezone,
		recurrence, next_run_at, last_run_at, run_count, max_runs, campaign_id,
		template_id, template_data, track_opens, track_clicks, sent_at, error_message,
		retry_count, max_retries, tags, metadata, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var campaignID, templateID *string
	if email.CampaignID != nil {
		s := email.CampaignID.String()
		campaignID = &s
	}
	if email.TemplateID != nil {
		s := email.TemplateID.String()
		templateID = &s
	}

	_, err := r.db.ExecContext(ctx, query,
		email.ID.String(), email.OrgID.String(), email.AccountID.String(),
		email.Type, email.Status, email.From, string(toJSON), string(ccJSON), string(bccJSON),
		email.Subject, email.Body, email.BodyHTML, string(headersJSON), string(attachJSON),
		email.ScheduledAt, email.Timezone, string(recurJSON), email.NextRunAt, email.LastRunAt,
		email.RunCount, email.MaxRuns, campaignID, templateID, email.TemplateData,
		email.TrackOpens, email.TrackClicks, email.SentAt, email.ErrorMessage,
		email.RetryCount, email.MaxRetries, string(tagsJSON), email.Metadata,
		email.CreatedAt, email.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetScheduledEmail(ctx context.Context, id uuid.UUID) (*ScheduledEmail, error) {
	query := `
	SELECT id, org_id, account_id, type, status, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, body, body_html, headers, attachments, scheduled_at, timezone,
		recurrence, next_run_at, last_run_at, run_count, max_runs, campaign_id,
		template_id, template_data, track_opens, track_clicks, sent_at, error_message,
		retry_count, max_retries, tags, metadata, created_at, updated_at
	FROM scheduled_emails WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanEmail(row)
}

func (r *SQLiteRepository) UpdateScheduledEmail(ctx context.Context, email *ScheduledEmail) error {
	toJSON, _ := json.Marshal(email.To)
	ccJSON, _ := json.Marshal(email.Cc)
	bccJSON, _ := json.Marshal(email.Bcc)
	headersJSON, _ := json.Marshal(email.Headers)
	attachJSON, _ := json.Marshal(email.Attachments)
	recurJSON, _ := json.Marshal(email.Recurrence)
	tagsJSON, _ := json.Marshal(email.Tags)

	query := `
	UPDATE scheduled_emails SET
		type = ?, status = ?, from_addr = ?, to_addrs = ?, cc_addrs = ?, bcc_addrs = ?,
		subject = ?, body = ?, body_html = ?, headers = ?, attachments = ?,
		scheduled_at = ?, timezone = ?, recurrence = ?, next_run_at = ?, last_run_at = ?,
		run_count = ?, max_runs = ?, campaign_id = ?, template_id = ?, template_data = ?,
		track_opens = ?, track_clicks = ?, sent_at = ?, error_message = ?,
		retry_count = ?, max_retries = ?, tags = ?, metadata = ?, updated_at = ?
	WHERE id = ?
	`

	var campaignID, templateID *string
	if email.CampaignID != nil {
		s := email.CampaignID.String()
		campaignID = &s
	}
	if email.TemplateID != nil {
		s := email.TemplateID.String()
		templateID = &s
	}

	_, err := r.db.ExecContext(ctx, query,
		email.Type, email.Status, email.From, string(toJSON), string(ccJSON), string(bccJSON),
		email.Subject, email.Body, email.BodyHTML, string(headersJSON), string(attachJSON),
		email.ScheduledAt, email.Timezone, string(recurJSON), email.NextRunAt, email.LastRunAt,
		email.RunCount, email.MaxRuns, campaignID, templateID, email.TemplateData,
		email.TrackOpens, email.TrackClicks, email.SentAt, email.ErrorMessage,
		email.RetryCount, email.MaxRetries, string(tagsJSON), email.Metadata,
		time.Now(), email.ID.String())

	return err
}

func (r *SQLiteRepository) DeleteScheduledEmail(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM scheduled_emails WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) GetPendingEmails(ctx context.Context, before time.Time, limit int) ([]*ScheduledEmail, error) {
	query := `
	SELECT id, org_id, account_id, type, status, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, body, body_html, headers, attachments, scheduled_at, timezone,
		recurrence, next_run_at, last_run_at, run_count, max_runs, campaign_id,
		template_id, template_data, track_opens, track_clicks, sent_at, error_message,
		retry_count, max_retries, tags, metadata, created_at, updated_at
	FROM scheduled_emails 
	WHERE status = 'pending' AND scheduled_at <= ?
	ORDER BY scheduled_at ASC
	LIMIT ?
	`
	rows, err := r.db.QueryContext(ctx, query, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []*ScheduledEmail
	for rows.Next() {
		email, err := r.scanEmailRow(rows)
		if err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}
	return emails, rows.Err()
}

func (r *SQLiteRepository) GetScheduledEmailsByAccount(ctx context.Context, accountID uuid.UUID) ([]*ScheduledEmail, error) {
	query := `
	SELECT id, org_id, account_id, type, status, from_addr, to_addrs, cc_addrs, bcc_addrs,
		subject, body, body_html, headers, attachments, scheduled_at, timezone,
		recurrence, next_run_at, last_run_at, run_count, max_runs, campaign_id,
		template_id, template_data, track_opens, track_clicks, sent_at, error_message,
		retry_count, max_retries, tags, metadata, created_at, updated_at
	FROM scheduled_emails 
	WHERE account_id = ? AND status IN ('pending', 'sending')
	ORDER BY scheduled_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []*ScheduledEmail
	for rows.Next() {
		email, err := r.scanEmailRow(rows)
		if err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}
	return emails, rows.Err()
}

func (r *SQLiteRepository) scanEmail(row *sql.Row) (*ScheduledEmail, error) {
	var email ScheduledEmail
	var idStr, orgIDStr, accountIDStr string
	var toJSON, ccJSON, bccJSON, headersJSON, attachJSON, recurJSON, tagsJSON string
	var campaignIDStr, templateIDStr sql.NullString

	err := row.Scan(
		&idStr, &orgIDStr, &accountIDStr, &email.Type, &email.Status,
		&email.From, &toJSON, &ccJSON, &bccJSON, &email.Subject, &email.Body,
		&email.BodyHTML, &headersJSON, &attachJSON, &email.ScheduledAt, &email.Timezone,
		&recurJSON, &email.NextRunAt, &email.LastRunAt, &email.RunCount, &email.MaxRuns,
		&campaignIDStr, &templateIDStr, &email.TemplateData, &email.TrackOpens,
		&email.TrackClicks, &email.SentAt, &email.ErrorMessage, &email.RetryCount,
		&email.MaxRetries, &tagsJSON, &email.Metadata, &email.CreatedAt, &email.UpdatedAt)
	if err != nil {
		return nil, err
	}

	email.ID, _ = uuid.Parse(idStr)
	email.OrgID, _ = uuid.Parse(orgIDStr)
	email.AccountID, _ = uuid.Parse(accountIDStr)
	_ = json.Unmarshal([]byte(toJSON), &email.To)
	_ = json.Unmarshal([]byte(ccJSON), &email.Cc)
	_ = json.Unmarshal([]byte(bccJSON), &email.Bcc)
	_ = json.Unmarshal([]byte(headersJSON), &email.Headers)
	_ = json.Unmarshal([]byte(attachJSON), &email.Attachments)
	_ = json.Unmarshal([]byte(recurJSON), &email.Recurrence)
	_ = json.Unmarshal([]byte(tagsJSON), &email.Tags)

	if campaignIDStr.Valid {
		id, _ := uuid.Parse(campaignIDStr.String)
		email.CampaignID = &id
	}
	if templateIDStr.Valid {
		id, _ := uuid.Parse(templateIDStr.String)
		email.TemplateID = &id
	}

	return &email, nil
}

func (r *SQLiteRepository) scanEmailRow(rows *sql.Rows) (*ScheduledEmail, error) {
	var email ScheduledEmail
	var idStr, orgIDStr, accountIDStr string
	var toJSON, ccJSON, bccJSON, headersJSON, attachJSON, recurJSON, tagsJSON string
	var campaignIDStr, templateIDStr sql.NullString

	err := rows.Scan(
		&idStr, &orgIDStr, &accountIDStr, &email.Type, &email.Status,
		&email.From, &toJSON, &ccJSON, &bccJSON, &email.Subject, &email.Body,
		&email.BodyHTML, &headersJSON, &attachJSON, &email.ScheduledAt, &email.Timezone,
		&recurJSON, &email.NextRunAt, &email.LastRunAt, &email.RunCount, &email.MaxRuns,
		&campaignIDStr, &templateIDStr, &email.TemplateData, &email.TrackOpens,
		&email.TrackClicks, &email.SentAt, &email.ErrorMessage, &email.RetryCount,
		&email.MaxRetries, &tagsJSON, &email.Metadata, &email.CreatedAt, &email.UpdatedAt)
	if err != nil {
		return nil, err
	}

	email.ID, _ = uuid.Parse(idStr)
	email.OrgID, _ = uuid.Parse(orgIDStr)
	email.AccountID, _ = uuid.Parse(accountIDStr)
	_ = json.Unmarshal([]byte(toJSON), &email.To)
	_ = json.Unmarshal([]byte(ccJSON), &email.Cc)
	_ = json.Unmarshal([]byte(bccJSON), &email.Bcc)
	_ = json.Unmarshal([]byte(headersJSON), &email.Headers)
	_ = json.Unmarshal([]byte(attachJSON), &email.Attachments)
	_ = json.Unmarshal([]byte(recurJSON), &email.Recurrence)
	_ = json.Unmarshal([]byte(tagsJSON), &email.Tags)

	if campaignIDStr.Valid {
		id, _ := uuid.Parse(campaignIDStr.String)
		email.CampaignID = &id
	}
	if templateIDStr.Valid {
		id, _ := uuid.Parse(templateIDStr.String)
		email.TemplateID = &id
	}

	return &email, nil
}

// Campaign methods
func (r *SQLiteRepository) CreateCampaign(ctx context.Context, campaign *Campaign) error {
	recipientsJSON, _ := json.Marshal(campaign.Recipients)

	query := `
	INSERT INTO campaigns (
		id, org_id, account_id, name, description, status, template_id, subject, body, body_html,
		list_id, recipients, total_recipients, scheduled_at, started_at, completed_at,
		sent_count, failed_count, open_count, click_count, bounce_count, unsub_count,
		track_opens, track_clicks, batch_size, batch_delay, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var templateID, listID *string
	if campaign.TemplateID != nil {
		s := campaign.TemplateID.String()
		templateID = &s
	}
	if campaign.ListID != nil {
		s := campaign.ListID.String()
		listID = &s
	}

	_, err := r.db.ExecContext(ctx, query,
		campaign.ID.String(), campaign.OrgID.String(), campaign.AccountID.String(),
		campaign.Name, campaign.Description, campaign.Status, templateID,
		campaign.Subject, campaign.Body, campaign.BodyHTML, listID, string(recipientsJSON),
		campaign.TotalRecipients, campaign.ScheduledAt, campaign.StartedAt, campaign.CompletedAt,
		campaign.SentCount, campaign.FailedCount, campaign.OpenCount, campaign.ClickCount,
		campaign.BounceCount, campaign.UnsubCount, campaign.TrackOpens, campaign.TrackClicks,
		campaign.BatchSize, campaign.BatchDelay, campaign.CreatedAt, campaign.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetCampaign(ctx context.Context, id uuid.UUID) (*Campaign, error) {
	query := `
	SELECT id, org_id, account_id, name, description, status, template_id, subject, body, body_html,
		list_id, recipients, total_recipients, scheduled_at, started_at, completed_at,
		sent_count, failed_count, open_count, click_count, bounce_count, unsub_count,
		track_opens, track_clicks, batch_size, batch_delay, created_at, updated_at
	FROM campaigns WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanCampaign(row)
}

func (r *SQLiteRepository) UpdateCampaign(ctx context.Context, campaign *Campaign) error {
	recipientsJSON, _ := json.Marshal(campaign.Recipients)

	query := `
	UPDATE campaigns SET
		name = ?, description = ?, status = ?, template_id = ?, subject = ?, body = ?, body_html = ?,
		list_id = ?, recipients = ?, total_recipients = ?, scheduled_at = ?, started_at = ?, completed_at = ?,
		sent_count = ?, failed_count = ?, open_count = ?, click_count = ?, bounce_count = ?, unsub_count = ?,
		track_opens = ?, track_clicks = ?, batch_size = ?, batch_delay = ?, updated_at = ?
	WHERE id = ?
	`

	var templateID, listID *string
	if campaign.TemplateID != nil {
		s := campaign.TemplateID.String()
		templateID = &s
	}
	if campaign.ListID != nil {
		s := campaign.ListID.String()
		listID = &s
	}

	_, err := r.db.ExecContext(ctx, query,
		campaign.Name, campaign.Description, campaign.Status, templateID,
		campaign.Subject, campaign.Body, campaign.BodyHTML, listID, string(recipientsJSON),
		campaign.TotalRecipients, campaign.ScheduledAt, campaign.StartedAt, campaign.CompletedAt,
		campaign.SentCount, campaign.FailedCount, campaign.OpenCount, campaign.ClickCount,
		campaign.BounceCount, campaign.UnsubCount, campaign.TrackOpens, campaign.TrackClicks,
		campaign.BatchSize, campaign.BatchDelay, time.Now(), campaign.ID.String())

	return err
}

func (r *SQLiteRepository) DeleteCampaign(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM campaigns WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) GetCampaignsByOrg(ctx context.Context, orgID uuid.UUID) ([]*Campaign, error) {
	query := `
	SELECT id, org_id, account_id, name, description, status, template_id, subject, body, body_html,
		list_id, recipients, total_recipients, scheduled_at, started_at, completed_at,
		sent_count, failed_count, open_count, click_count, bounce_count, unsub_count,
		track_opens, track_clicks, batch_size, batch_delay, created_at, updated_at
	FROM campaigns WHERE org_id = ? ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, orgID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var campaigns []*Campaign
	for rows.Next() {
		campaign, err := r.scanCampaignRow(rows)
		if err != nil {
			return nil, err
		}
		campaigns = append(campaigns, campaign)
	}
	return campaigns, rows.Err()
}

func (r *SQLiteRepository) GetPendingCampaigns(ctx context.Context, before time.Time) ([]*Campaign, error) {
	query := `
	SELECT id, org_id, account_id, name, description, status, template_id, subject, body, body_html,
		list_id, recipients, total_recipients, scheduled_at, started_at, completed_at,
		sent_count, failed_count, open_count, click_count, bounce_count, unsub_count,
		track_opens, track_clicks, batch_size, batch_delay, created_at, updated_at
	FROM campaigns WHERE status = 'scheduled' AND scheduled_at <= ?
	`
	rows, err := r.db.QueryContext(ctx, query, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var campaigns []*Campaign
	for rows.Next() {
		campaign, err := r.scanCampaignRow(rows)
		if err != nil {
			return nil, err
		}
		campaigns = append(campaigns, campaign)
	}
	return campaigns, rows.Err()
}

func (r *SQLiteRepository) scanCampaign(row *sql.Row) (*Campaign, error) {
	var campaign Campaign
	var idStr, orgIDStr, accountIDStr string
	var templateIDStr, listIDStr sql.NullString
	var recipientsJSON string

	err := row.Scan(
		&idStr, &orgIDStr, &accountIDStr, &campaign.Name, &campaign.Description,
		&campaign.Status, &templateIDStr, &campaign.Subject, &campaign.Body, &campaign.BodyHTML,
		&listIDStr, &recipientsJSON, &campaign.TotalRecipients, &campaign.ScheduledAt,
		&campaign.StartedAt, &campaign.CompletedAt, &campaign.SentCount, &campaign.FailedCount,
		&campaign.OpenCount, &campaign.ClickCount, &campaign.BounceCount, &campaign.UnsubCount,
		&campaign.TrackOpens, &campaign.TrackClicks, &campaign.BatchSize, &campaign.BatchDelay,
		&campaign.CreatedAt, &campaign.UpdatedAt)
	if err != nil {
		return nil, err
	}

	campaign.ID, _ = uuid.Parse(idStr)
	campaign.OrgID, _ = uuid.Parse(orgIDStr)
	campaign.AccountID, _ = uuid.Parse(accountIDStr)
	_ = json.Unmarshal([]byte(recipientsJSON), &campaign.Recipients)

	if templateIDStr.Valid {
		id, _ := uuid.Parse(templateIDStr.String)
		campaign.TemplateID = &id
	}
	if listIDStr.Valid {
		id, _ := uuid.Parse(listIDStr.String)
		campaign.ListID = &id
	}

	return &campaign, nil
}

func (r *SQLiteRepository) scanCampaignRow(rows *sql.Rows) (*Campaign, error) {
	var campaign Campaign
	var idStr, orgIDStr, accountIDStr string
	var templateIDStr, listIDStr sql.NullString
	var recipientsJSON string

	err := rows.Scan(
		&idStr, &orgIDStr, &accountIDStr, &campaign.Name, &campaign.Description,
		&campaign.Status, &templateIDStr, &campaign.Subject, &campaign.Body, &campaign.BodyHTML,
		&listIDStr, &recipientsJSON, &campaign.TotalRecipients, &campaign.ScheduledAt,
		&campaign.StartedAt, &campaign.CompletedAt, &campaign.SentCount, &campaign.FailedCount,
		&campaign.OpenCount, &campaign.ClickCount, &campaign.BounceCount, &campaign.UnsubCount,
		&campaign.TrackOpens, &campaign.TrackClicks, &campaign.BatchSize, &campaign.BatchDelay,
		&campaign.CreatedAt, &campaign.UpdatedAt)
	if err != nil {
		return nil, err
	}

	campaign.ID, _ = uuid.Parse(idStr)
	campaign.OrgID, _ = uuid.Parse(orgIDStr)
	campaign.AccountID, _ = uuid.Parse(accountIDStr)
	_ = json.Unmarshal([]byte(recipientsJSON), &campaign.Recipients)

	if templateIDStr.Valid {
		id, _ := uuid.Parse(templateIDStr.String)
		campaign.TemplateID = &id
	}
	if listIDStr.Valid {
		id, _ := uuid.Parse(listIDStr.String)
		campaign.ListID = &id
	}

	return &campaign, nil
}
