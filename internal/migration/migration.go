package migration

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MigrationSource represents the source email provider
type MigrationSource string

const (
	SourceGmail      MigrationSource = "gmail"
	SourceOutlook    MigrationSource = "outlook"
	SourceExchange   MigrationSource = "exchange"
	SourceYahoo      MigrationSource = "yahoo"
	SourceIMAP       MigrationSource = "imap"
	SourceMbox       MigrationSource = "mbox"
	SourceMaildir    MigrationSource = "maildir"
	SourcePST        MigrationSource = "pst"
	SourceEML        MigrationSource = "eml"
	SourceThunderbird MigrationSource = "thunderbird"
	SourceAppleMail  MigrationSource = "apple_mail"
)

// MigrationStatus represents the status of a migration
type MigrationStatus string

const (
	StatusPending    MigrationStatus = "pending"
	StatusRunning    MigrationStatus = "running"
	StatusPaused     MigrationStatus = "paused"
	StatusCompleted  MigrationStatus = "completed"
	StatusFailed     MigrationStatus = "failed"
	StatusCancelled  MigrationStatus = "cancelled"
)

// MigrationJob represents a migration job
type MigrationJob struct {
	ID          uuid.UUID       `json:"id"`
	AccountID   uuid.UUID       `json:"account_id"`
	OrgID       uuid.UUID       `json:"org_id"`
	
	// Source configuration
	Source      MigrationSource `json:"source"`
	SourceEmail string          `json:"source_email"`
	
	// Credentials (encrypted)
	Credentials *SourceCredentials `json:"credentials,omitempty"`
	
	// Status
	Status      MigrationStatus `json:"status"`
	Progress    *MigrationProgress `json:"progress"`
	
	// Options
	Options     *MigrationOptions `json:"options"`
	
	// Error info
	ErrorMessage string         `json:"error_message,omitempty"`
	ErrorCount   int            `json:"error_count"`
	
	// Timing
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// SourceCredentials holds source authentication info
type SourceCredentials struct {
	// OAuth2
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenExpiry  *time.Time `json:"token_expiry,omitempty"`
	
	// Basic Auth (IMAP)
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	
	// Server (IMAP/Exchange)
	Server       string `json:"server,omitempty"`
	Port         int    `json:"port,omitempty"`
	UseSSL       bool   `json:"use_ssl"`
	UseTLS       bool   `json:"use_tls"`
	
	// File-based (mbox, maildir, PST)
	FilePath     string `json:"file_path,omitempty"`
}

// MigrationProgress tracks migration progress
type MigrationProgress struct {
	TotalFolders    int    `json:"total_folders"`
	MigratedFolders int    `json:"migrated_folders"`
	
	TotalEmails     int    `json:"total_emails"`
	MigratedEmails  int    `json:"migrated_emails"`
	SkippedEmails   int    `json:"skipped_emails"`
	FailedEmails    int    `json:"failed_emails"`
	
	TotalContacts   int    `json:"total_contacts"`
	MigratedContacts int   `json:"migrated_contacts"`
	
	TotalCalendars  int    `json:"total_calendars"`
	MigratedEvents  int    `json:"migrated_events"`
	
	TotalBytes      int64  `json:"total_bytes"`
	MigratedBytes   int64  `json:"migrated_bytes"`
	
	CurrentFolder   string `json:"current_folder,omitempty"`
	CurrentEmail    string `json:"current_email,omitempty"`
	
	EstimatedTimeRemaining int64 `json:"estimated_time_remaining"` // seconds
	BytesPerSecond         int64 `json:"bytes_per_second"`
}

// MigrationOptions configures what to migrate
type MigrationOptions struct {
	// What to migrate
	MigrateEmails     bool     `json:"migrate_emails"`
	MigrateContacts   bool     `json:"migrate_contacts"`
	MigrateCalendars  bool     `json:"migrate_calendars"`
	MigrateTasks      bool     `json:"migrate_tasks"`
	MigrateLabels     bool     `json:"migrate_labels"`
	MigrateFilters    bool     `json:"migrate_filters"`
	
	// Folder mapping
	FolderMappings    map[string]string `json:"folder_mappings,omitempty"`
	ExcludeFolders    []string          `json:"exclude_folders,omitempty"`
	IncludeFolders    []string          `json:"include_folders,omitempty"`
	
	// Date range
	StartDate         *time.Time `json:"start_date,omitempty"`
	EndDate           *time.Time `json:"end_date,omitempty"`
	
	// Size limits
	MaxMessageSize    int64      `json:"max_message_size,omitempty"` // bytes
	MaxAttachmentSize int64      `json:"max_attachment_size,omitempty"`
	
	// Deduplication
	SkipDuplicates    bool       `json:"skip_duplicates"`
	DuplicateCheck    string     `json:"duplicate_check"` // "message_id", "hash", "both"
	
	// Processing
	BatchSize         int        `json:"batch_size"`
	ConcurrentFolders int        `json:"concurrent_folders"`
	
	// Preserve metadata
	PreserveReadStatus bool      `json:"preserve_read_status"`
	PreserveFlagged    bool      `json:"preserve_flagged"`
	PreserveLabels     bool      `json:"preserve_labels"`
	PreserveDates      bool      `json:"preserve_dates"`
}

// MigrationError represents an error during migration
type MigrationError struct {
	ID          uuid.UUID   `json:"id"`
	JobID       uuid.UUID   `json:"job_id"`
	
	Type        string      `json:"type"`         // folder, email, contact, etc.
	ItemID      string      `json:"item_id"`
	ItemSubject string      `json:"item_subject,omitempty"`
	Folder      string      `json:"folder,omitempty"`
	
	Error       string      `json:"error"`
	Retryable   bool        `json:"retryable"`
	RetryCount  int         `json:"retry_count"`
	
	CreatedAt   time.Time   `json:"created_at"`
}

// MigrationService handles email migration
type MigrationService struct {
	mu       sync.RWMutex
	repo     MigrationRepository
	logger   Logger
	
	// Active migrations
	jobs     map[uuid.UUID]*runningJob
	
	// Importers
	importers map[MigrationSource]Importer
}

// runningJob tracks a running migration
type runningJob struct {
	job       *MigrationJob
	cancel    context.CancelFunc
	pauseCh   chan struct{}
	resumeCh  chan struct{}
	isPaused  bool
}

// MigrationRepository interface
type MigrationRepository interface {
	SaveJob(ctx context.Context, job *MigrationJob) error
	GetJob(ctx context.Context, id uuid.UUID) (*MigrationJob, error)
	GetJobsForAccount(ctx context.Context, accountID uuid.UUID) ([]*MigrationJob, error)
	DeleteJob(ctx context.Context, id uuid.UUID) error
	
	SaveError(ctx context.Context, err *MigrationError) error
	GetErrorsForJob(ctx context.Context, jobID uuid.UUID) ([]*MigrationError, error)
	ClearErrors(ctx context.Context, jobID uuid.UUID) error
}

// Importer interface for different sources
type Importer interface {
	Connect(ctx context.Context, creds *SourceCredentials) error
	Disconnect() error
	
	ListFolders(ctx context.Context) ([]FolderInfo, error)
	CountEmails(ctx context.Context, folder string) (int, error)
	FetchEmails(ctx context.Context, folder string, offset, limit int) ([]EmailData, error)
	
	// Optional methods for contacts/calendars
	ListContacts(ctx context.Context) ([]ContactData, error)
	ListEvents(ctx context.Context) ([]EventData, error)
}

// FolderInfo represents a source folder
type FolderInfo struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	ParentPath string `json:"parent_path,omitempty"`
	EmailCount int    `json:"email_count"`
	Type       string `json:"type"` // inbox, sent, drafts, trash, spam, custom
}

// EmailData represents an email to migrate
type EmailData struct {
	MessageID   string
	Subject     string
	From        string
	To          []string
	Cc          []string
	Bcc         []string
	Date        time.Time
	Body        string
	HTMLBody    string
	Headers     map[string][]string
	Attachments []AttachmentData
	Labels      []string
	Flags       []string // \Seen, \Flagged, etc.
	RawMessage  []byte
}

// AttachmentData represents an attachment
type AttachmentData struct {
	Filename    string
	ContentType string
	Size        int64
	Data        []byte
}

// ContactData represents a contact to migrate
type ContactData struct {
	Email       string
	Name        string
	FirstName   string
	LastName    string
	Phone       string
	Organization string
	VCardData   string
}

// EventData represents a calendar event to migrate
type EventData struct {
	Summary     string
	Description string
	Start       time.Time
	End         time.Time
	Location    string
	ICalData    string
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewMigrationService creates a new migration service
func NewMigrationService(repo MigrationRepository, logger Logger) *MigrationService {
	s := &MigrationService{
		repo:      repo,
		logger:    logger,
		jobs:      make(map[uuid.UUID]*runningJob),
		importers: make(map[MigrationSource]Importer),
	}
	
	// Register built-in importers
	s.importers[SourceMbox] = &MboxImporter{}
	s.importers[SourceMaildir] = &MaildirImporter{}
	s.importers[SourceEML] = &EMLImporter{}
	
	return s
}

// RegisterImporter registers a custom importer
func (s *MigrationService) RegisterImporter(source MigrationSource, importer Importer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.importers[source] = importer
}

// CreateJob creates a new migration job
func (s *MigrationService) CreateJob(ctx context.Context, job *MigrationJob) error {
	job.ID = uuid.New()
	job.Status = StatusPending
	job.Progress = &MigrationProgress{}
	job.CreatedAt = time.Now()
	job.UpdatedAt = time.Now()

	// Set default options
	if job.Options == nil {
		job.Options = &MigrationOptions{
			MigrateEmails:      true,
			BatchSize:          100,
			ConcurrentFolders:  3,
			SkipDuplicates:     true,
			DuplicateCheck:     "message_id",
			PreserveReadStatus: true,
			PreserveFlagged:    true,
			PreserveLabels:     true,
			PreserveDates:      true,
		}
	}

	if err := s.repo.SaveJob(ctx, job); err != nil {
		return err
	}

	s.logger.Info("created migration job", "id", job.ID, "source", job.Source)
	return nil
}

// StartJob starts a migration job
func (s *MigrationService) StartJob(ctx context.Context, jobID uuid.UUID) error {
	job, err := s.repo.GetJob(ctx, jobID)
	if err != nil {
		return err
	}

	if job.Status == StatusRunning {
		return fmt.Errorf("job is already running")
	}

	// Get importer
	importer, ok := s.importers[job.Source]
	if !ok {
		return fmt.Errorf("unsupported source: %s", job.Source)
	}

	// Create running job
	jobCtx, cancel := context.WithCancel(context.Background())
	rj := &runningJob{
		job:      job,
		cancel:   cancel,
		pauseCh:  make(chan struct{}),
		resumeCh: make(chan struct{}),
	}

	s.mu.Lock()
	s.jobs[job.ID] = rj
	s.mu.Unlock()

	// Update status
	now := time.Now()
	job.Status = StatusRunning
	job.StartedAt = &now
	job.UpdatedAt = now
	s.repo.SaveJob(ctx, job)

	// Start migration in background
	go s.runMigration(jobCtx, rj, importer)

	s.logger.Info("started migration job", "id", job.ID)
	return nil
}

// PauseJob pauses a running migration
func (s *MigrationService) PauseJob(ctx context.Context, jobID uuid.UUID) error {
	s.mu.Lock()
	rj, ok := s.jobs[jobID]
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("job not running")
	}

	if rj.isPaused {
		return nil
	}

	rj.isPaused = true
	close(rj.pauseCh)
	rj.pauseCh = make(chan struct{})

	rj.job.Status = StatusPaused
	rj.job.UpdatedAt = time.Now()
	s.repo.SaveJob(ctx, rj.job)

	s.logger.Info("paused migration job", "id", jobID)
	return nil
}

// ResumeJob resumes a paused migration
func (s *MigrationService) ResumeJob(ctx context.Context, jobID uuid.UUID) error {
	s.mu.Lock()
	rj, ok := s.jobs[jobID]
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("job not found")
	}

	if !rj.isPaused {
		return nil
	}

	rj.isPaused = false
	close(rj.resumeCh)
	rj.resumeCh = make(chan struct{})

	rj.job.Status = StatusRunning
	rj.job.UpdatedAt = time.Now()
	s.repo.SaveJob(ctx, rj.job)

	s.logger.Info("resumed migration job", "id", jobID)
	return nil
}

// CancelJob cancels a migration
func (s *MigrationService) CancelJob(ctx context.Context, jobID uuid.UUID) error {
	s.mu.Lock()
	rj, ok := s.jobs[jobID]
	s.mu.Unlock()

	if ok {
		rj.cancel()
		delete(s.jobs, jobID)
	}

	job, err := s.repo.GetJob(ctx, jobID)
	if err != nil {
		return err
	}

	job.Status = StatusCancelled
	job.UpdatedAt = time.Now()
	return s.repo.SaveJob(ctx, job)
}

// GetJob retrieves a migration job
func (s *MigrationService) GetJob(ctx context.Context, jobID uuid.UUID) (*MigrationJob, error) {
	return s.repo.GetJob(ctx, jobID)
}

// GetJobs retrieves all jobs for an account
func (s *MigrationService) GetJobs(ctx context.Context, accountID uuid.UUID) ([]*MigrationJob, error) {
	return s.repo.GetJobsForAccount(ctx, accountID)
}

// GetErrors retrieves errors for a job
func (s *MigrationService) GetErrors(ctx context.Context, jobID uuid.UUID) ([]*MigrationError, error) {
	return s.repo.GetErrorsForJob(ctx, jobID)
}

// Core migration logic

func (s *MigrationService) runMigration(ctx context.Context, rj *runningJob, importer Importer) {
	job := rj.job

	defer func() {
		s.mu.Lock()
		delete(s.jobs, job.ID)
		s.mu.Unlock()
	}()

	// Connect to source
	if err := importer.Connect(ctx, job.Credentials); err != nil {
		s.failJob(ctx, job, fmt.Sprintf("failed to connect: %v", err))
		return
	}
	defer importer.Disconnect()

	// List folders
	folders, err := importer.ListFolders(ctx)
	if err != nil {
		s.failJob(ctx, job, fmt.Sprintf("failed to list folders: %v", err))
		return
	}

	job.Progress.TotalFolders = len(folders)
	s.repo.SaveJob(ctx, job)

	// Count total emails
	for _, folder := range folders {
		if s.shouldSkipFolder(folder, job.Options) {
			continue
		}
		count, err := importer.CountEmails(ctx, folder.Path)
		if err == nil {
			job.Progress.TotalEmails += count
		}
	}
	s.repo.SaveJob(ctx, job)

	// Migrate each folder
	for _, folder := range folders {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Check for pause
		if rj.isPaused {
			select {
			case <-rj.resumeCh:
			case <-ctx.Done():
				return
			}
		}

		if s.shouldSkipFolder(folder, job.Options) {
			continue
		}

		s.migrateFolder(ctx, rj, importer, folder)
		
		job.Progress.MigratedFolders++
		job.UpdatedAt = time.Now()
		s.repo.SaveJob(ctx, job)
	}

	// Migrate contacts if enabled
	if job.Options.MigrateContacts {
		s.migrateContacts(ctx, rj, importer)
	}

	// Migrate calendars if enabled
	if job.Options.MigrateCalendars {
		s.migrateCalendars(ctx, rj, importer)
	}

	// Complete
	now := time.Now()
	job.Status = StatusCompleted
	job.CompletedAt = &now
	job.UpdatedAt = now
	s.repo.SaveJob(ctx, job)

	s.logger.Info("completed migration job", "id", job.ID,
		"emails", job.Progress.MigratedEmails,
		"contacts", job.Progress.MigratedContacts)
}

func (s *MigrationService) migrateFolder(ctx context.Context, rj *runningJob, importer Importer, folder FolderInfo) {
	job := rj.job
	opts := job.Options

	job.Progress.CurrentFolder = folder.Name
	s.repo.SaveJob(ctx, job)

	offset := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Check for pause
		if rj.isPaused {
			select {
			case <-rj.resumeCh:
			case <-ctx.Done():
				return
			}
		}

		// Fetch batch
		emails, err := importer.FetchEmails(ctx, folder.Path, offset, opts.BatchSize)
		if err != nil {
			s.recordError(ctx, job.ID, "folder", folder.Path, folder.Name, err.Error(), true)
			break
		}

		if len(emails) == 0 {
			break
		}

		// Process batch
		for _, email := range emails {
			if err := s.migrateEmail(ctx, job, email, folder); err != nil {
				job.Progress.FailedEmails++
				s.recordError(ctx, job.ID, "email", email.MessageID, email.Subject, err.Error(), true)
			} else {
				job.Progress.MigratedEmails++
			}

			job.Progress.CurrentEmail = email.Subject
			job.UpdatedAt = time.Now()
		}

		s.repo.SaveJob(ctx, job)
		offset += len(emails)
	}
}

func (s *MigrationService) migrateEmail(ctx context.Context, job *MigrationJob, email EmailData, folder FolderInfo) error {
	opts := job.Options

	// Check date range
	if opts.StartDate != nil && email.Date.Before(*opts.StartDate) {
		job.Progress.SkippedEmails++
		return nil
	}
	if opts.EndDate != nil && email.Date.After(*opts.EndDate) {
		job.Progress.SkippedEmails++
		return nil
	}

	// Check size
	if opts.MaxMessageSize > 0 && int64(len(email.RawMessage)) > opts.MaxMessageSize {
		job.Progress.SkippedEmails++
		return nil
	}

	// TODO: Check duplicates if enabled
	// TODO: Actually store the email in the target system

	job.Progress.MigratedBytes += int64(len(email.RawMessage))
	return nil
}

func (s *MigrationService) migrateContacts(ctx context.Context, rj *runningJob, importer Importer) {
	job := rj.job

	contacts, err := importer.ListContacts(ctx)
	if err != nil {
		s.logger.Error("failed to list contacts", "error", err)
		return
	}

	job.Progress.TotalContacts = len(contacts)
	s.repo.SaveJob(ctx, job)

	for range contacts {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// TODO: Actually store the contact
		job.Progress.MigratedContacts++
	}

	job.UpdatedAt = time.Now()
	s.repo.SaveJob(ctx, job)
}

func (s *MigrationService) migrateCalendars(ctx context.Context, rj *runningJob, importer Importer) {
	job := rj.job

	events, err := importer.ListEvents(ctx)
	if err != nil {
		s.logger.Error("failed to list events", "error", err)
		return
	}

	job.Progress.TotalCalendars = 1 // TODO: Support multiple calendars
	s.repo.SaveJob(ctx, job)

	for range events {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// TODO: Actually store the event
		job.Progress.MigratedEvents++
	}

	job.UpdatedAt = time.Now()
	s.repo.SaveJob(ctx, job)
}

func (s *MigrationService) shouldSkipFolder(folder FolderInfo, opts *MigrationOptions) bool {
	// Check exclude list
	for _, exclude := range opts.ExcludeFolders {
		if strings.EqualFold(folder.Path, exclude) || strings.EqualFold(folder.Name, exclude) {
			return true
		}
	}

	// Check include list (if specified)
	if len(opts.IncludeFolders) > 0 {
		found := false
		for _, include := range opts.IncludeFolders {
			if strings.EqualFold(folder.Path, include) || strings.EqualFold(folder.Name, include) {
				found = true
				break
			}
		}
		return !found
	}

	return false
}

func (s *MigrationService) failJob(ctx context.Context, job *MigrationJob, errMsg string) {
	job.Status = StatusFailed
	job.ErrorMessage = errMsg
	job.UpdatedAt = time.Now()
	s.repo.SaveJob(ctx, job)
	s.logger.Error("migration failed", "id", job.ID, "error", errMsg)
}

func (s *MigrationService) recordError(ctx context.Context, jobID uuid.UUID, errType, itemID, subject, errMsg string, retryable bool) {
	migErr := &MigrationError{
		ID:          uuid.New(),
		JobID:       jobID,
		Type:        errType,
		ItemID:      itemID,
		ItemSubject: subject,
		Error:       errMsg,
		Retryable:   retryable,
		CreatedAt:   time.Now(),
	}
	s.repo.SaveError(ctx, migErr)
}

// Built-in Importers

// MboxImporter imports from mbox files
type MboxImporter struct {
	file     *os.File
	scanner  *bufio.Scanner
	filePath string
}

func (i *MboxImporter) Connect(ctx context.Context, creds *SourceCredentials) error {
	if creds.FilePath == "" {
		return fmt.Errorf("file path required")
	}
	i.filePath = creds.FilePath
	return nil
}

func (i *MboxImporter) Disconnect() error {
	if i.file != nil {
		return i.file.Close()
	}
	return nil
}

func (i *MboxImporter) ListFolders(ctx context.Context) ([]FolderInfo, error) {
	// Mbox is a single file = single folder
	return []FolderInfo{{
		Name:       filepath.Base(i.filePath),
		Path:       i.filePath,
		Type:       "custom",
		EmailCount: -1, // Unknown until counted
	}}, nil
}

func (i *MboxImporter) CountEmails(ctx context.Context, folder string) (int, error) {
	file, err := os.Open(folder)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "From ") {
			count++
		}
	}
	return count, scanner.Err()
}

func (i *MboxImporter) FetchEmails(ctx context.Context, folder string, offset, limit int) ([]EmailData, error) {
	file, err := os.Open(folder)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var emails []EmailData
	scanner := bufio.NewScanner(file)
	// Increase buffer size for large emails
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	currentEmail := 0
	var currentMessage strings.Builder
	inMessage := false

	for scanner.Scan() {
		line := scanner.Text()
		
		if strings.HasPrefix(line, "From ") {
			// End previous message
			if inMessage && currentMessage.Len() > 0 {
				if currentEmail > offset && currentEmail <= offset+limit {
					email := parseEmail(currentMessage.String())
					emails = append(emails, email)
				}
				currentMessage.Reset()
			}
			
			inMessage = true
			currentEmail++
			
			if currentEmail > offset+limit {
				break
			}
		} else if inMessage {
			currentMessage.WriteString(line)
			currentMessage.WriteString("\n")
		}
	}

	// Don't forget the last message
	if inMessage && currentMessage.Len() > 0 && currentEmail > offset && currentEmail <= offset+limit {
		email := parseEmail(currentMessage.String())
		emails = append(emails, email)
	}

	return emails, scanner.Err()
}

func (i *MboxImporter) ListContacts(ctx context.Context) ([]ContactData, error) {
	return nil, nil // Mbox doesn't have contacts
}

func (i *MboxImporter) ListEvents(ctx context.Context) ([]EventData, error) {
	return nil, nil // Mbox doesn't have events
}

// MaildirImporter imports from Maildir format
type MaildirImporter struct {
	rootPath string
}

func (i *MaildirImporter) Connect(ctx context.Context, creds *SourceCredentials) error {
	if creds.FilePath == "" {
		return fmt.Errorf("maildir path required")
	}
	i.rootPath = creds.FilePath
	return nil
}

func (i *MaildirImporter) Disconnect() error {
	return nil
}

func (i *MaildirImporter) ListFolders(ctx context.Context) ([]FolderInfo, error) {
	var folders []FolderInfo

	// Main folders: cur, new, tmp
	mainDirs := []string{"cur", "new"}
	for _, dir := range mainDirs {
		path := filepath.Join(i.rootPath, dir)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			folders = append(folders, FolderInfo{
				Name: dir,
				Path: path,
				Type: "inbox",
			})
		}
	}

	// Subfolders (start with .)
	entries, err := os.ReadDir(i.rootPath)
	if err != nil {
		return folders, err
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".") {
			name := strings.TrimPrefix(entry.Name(), ".")
			for _, subdir := range mainDirs {
				path := filepath.Join(i.rootPath, entry.Name(), subdir)
				if info, err := os.Stat(path); err == nil && info.IsDir() {
					folders = append(folders, FolderInfo{
						Name: name + "/" + subdir,
						Path: path,
						Type: "custom",
					})
				}
			}
		}
	}

	return folders, nil
}

func (i *MaildirImporter) CountEmails(ctx context.Context, folder string) (int, error) {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return 0, err
	}
	
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count, nil
}

func (i *MaildirImporter) FetchEmails(ctx context.Context, folder string, offset, limit int) ([]EmailData, error) {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return nil, err
	}

	var emails []EmailData
	current := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if current < offset {
			current++
			continue
		}

		if current >= offset+limit {
			break
		}

		filePath := filepath.Join(folder, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		email := parseEmail(string(data))
		
		// Parse flags from filename (e.g., 1234567890.M1P1.hostname:2,S)
		if strings.Contains(entry.Name(), ":2,") {
			flags := strings.Split(entry.Name(), ":2,")[1]
			if strings.Contains(flags, "S") {
				email.Flags = append(email.Flags, "\\Seen")
			}
			if strings.Contains(flags, "F") {
				email.Flags = append(email.Flags, "\\Flagged")
			}
			if strings.Contains(flags, "R") {
				email.Flags = append(email.Flags, "\\Answered")
			}
			if strings.Contains(flags, "T") {
				email.Flags = append(email.Flags, "\\Deleted")
			}
			if strings.Contains(flags, "D") {
				email.Flags = append(email.Flags, "\\Draft")
			}
		}

		emails = append(emails, email)
		current++
	}

	return emails, nil
}

func (i *MaildirImporter) ListContacts(ctx context.Context) ([]ContactData, error) {
	return nil, nil
}

func (i *MaildirImporter) ListEvents(ctx context.Context) ([]EventData, error) {
	return nil, nil
}

// EMLImporter imports from .eml files
type EMLImporter struct {
	rootPath string
}

func (i *EMLImporter) Connect(ctx context.Context, creds *SourceCredentials) error {
	if creds.FilePath == "" {
		return fmt.Errorf("directory path required")
	}
	i.rootPath = creds.FilePath
	return nil
}

func (i *EMLImporter) Disconnect() error {
	return nil
}

func (i *EMLImporter) ListFolders(ctx context.Context) ([]FolderInfo, error) {
	var folders []FolderInfo

	err := filepath.Walk(i.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Check if directory contains .eml files
			entries, _ := os.ReadDir(path)
			hasEml := false
			for _, e := range entries {
				if strings.HasSuffix(strings.ToLower(e.Name()), ".eml") {
					hasEml = true
					break
				}
			}
			if hasEml {
				relPath, _ := filepath.Rel(i.rootPath, path)
				if relPath == "." {
					relPath = "Root"
				}
				folders = append(folders, FolderInfo{
					Name: relPath,
					Path: path,
					Type: "custom",
				})
			}
		}
		return nil
	})

	return folders, err
}

func (i *EMLImporter) CountEmails(ctx context.Context, folder string) (int, error) {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return 0, err
	}
	
	count := 0
	for _, entry := range entries {
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".eml") {
			count++
		}
	}
	return count, nil
}

func (i *EMLImporter) FetchEmails(ctx context.Context, folder string, offset, limit int) ([]EmailData, error) {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return nil, err
	}

	var emails []EmailData
	current := 0

	for _, entry := range entries {
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".eml") {
			continue
		}

		if current < offset {
			current++
			continue
		}

		if current >= offset+limit {
			break
		}

		filePath := filepath.Join(folder, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		email := parseEmail(string(data))
		email.RawMessage = data
		emails = append(emails, email)
		current++
	}

	return emails, nil
}

func (i *EMLImporter) ListContacts(ctx context.Context) ([]ContactData, error) {
	return nil, nil
}

func (i *EMLImporter) ListEvents(ctx context.Context) ([]EventData, error) {
	return nil, nil
}

// Helper to parse email from raw message
func parseEmail(raw string) EmailData {
	email := EmailData{
		Headers:    make(map[string][]string),
		RawMessage: []byte(raw),
	}

	// Split headers and body
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	if len(parts) == 1 {
		parts = strings.SplitN(raw, "\n\n", 2)
	}

	headerSection := parts[0]
	if len(parts) > 1 {
		email.Body = parts[1]
	}

	// Parse headers
	lines := strings.Split(headerSection, "\n")
	var currentHeader, currentValue string

	for _, line := range lines {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// Continuation of previous header
			currentValue += " " + strings.TrimSpace(line)
		} else {
			// Save previous header
			if currentHeader != "" {
				email.Headers[currentHeader] = append(email.Headers[currentHeader], currentValue)
				setEmailField(&email, currentHeader, currentValue)
			}
			
			// Parse new header
			colonIdx := strings.Index(line, ":")
			if colonIdx > 0 {
				currentHeader = strings.TrimSpace(line[:colonIdx])
				currentValue = strings.TrimSpace(line[colonIdx+1:])
			}
		}
	}

	// Don't forget last header
	if currentHeader != "" {
		email.Headers[currentHeader] = append(email.Headers[currentHeader], currentValue)
		setEmailField(&email, currentHeader, currentValue)
	}

	return email
}

func setEmailField(email *EmailData, header, value string) {
	switch strings.ToLower(header) {
	case "message-id":
		email.MessageID = strings.Trim(value, "<>")
	case "subject":
		email.Subject = decodeHeader(value)
	case "from":
		email.From = decodeHeader(value)
	case "to":
		email.To = parseAddressList(value)
	case "cc":
		email.Cc = parseAddressList(value)
	case "bcc":
		email.Bcc = parseAddressList(value)
	case "date":
		if t, err := parseDate(value); err == nil {
			email.Date = t
		}
	}
}

func parseAddressList(value string) []string {
	var addresses []string
	for _, addr := range strings.Split(value, ",") {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			addresses = append(addresses, decodeHeader(addr))
		}
	}
	return addresses
}

func decodeHeader(value string) string {
	// Handle encoded words (=?charset?encoding?text?=)
	if !strings.Contains(value, "=?") {
		return value
	}

	// Simple base64 decoding for common cases
	result := value
	for strings.Contains(result, "=?") {
		start := strings.Index(result, "=?")
		end := strings.Index(result[start+2:], "?=")
		if end == -1 {
			break
		}
		end += start + 2 + 2

		encoded := result[start:end]
		parts := strings.Split(encoded[2:len(encoded)-2], "?")
		if len(parts) >= 3 {
			encoding := strings.ToUpper(parts[1])
			text := parts[2]

			var decoded string
			switch encoding {
			case "B":
				if b, err := base64.StdEncoding.DecodeString(text); err == nil {
					decoded = string(b)
				}
			case "Q":
				decoded = strings.ReplaceAll(text, "_", " ")
				decoded = strings.ReplaceAll(decoded, "=", "%")
			default:
				decoded = text
			}

			result = result[:start] + decoded + result[end:]
		} else {
			break
		}
	}

	return result
}

func parseDate(value string) (time.Time, error) {
	formats := []string{
		time.RFC1123Z,
		time.RFC1123,
		time.RFC822Z,
		time.RFC822,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, value); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", value)
}

// Gmail OAuth Importer (placeholder structure)
type GmailImporter struct {
	client      *http.Client
	accessToken string
}

func (i *GmailImporter) Connect(ctx context.Context, creds *SourceCredentials) error {
	if creds.AccessToken == "" {
		return fmt.Errorf("access token required")
	}
	i.accessToken = creds.AccessToken
	i.client = &http.Client{Timeout: 30 * time.Second}
	return nil
}

func (i *GmailImporter) Disconnect() error {
	return nil
}

func (i *GmailImporter) ListFolders(ctx context.Context) ([]FolderInfo, error) {
	// Would call Gmail API to list labels
	return nil, fmt.Errorf("not implemented - requires Google API client")
}

func (i *GmailImporter) CountEmails(ctx context.Context, folder string) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (i *GmailImporter) FetchEmails(ctx context.Context, folder string, offset, limit int) ([]EmailData, error) {
	return nil, fmt.Errorf("not implemented")
}

func (i *GmailImporter) ListContacts(ctx context.Context) ([]ContactData, error) {
	return nil, fmt.Errorf("not implemented")
}

func (i *GmailImporter) ListEvents(ctx context.Context) ([]EventData, error) {
	return nil, fmt.Errorf("not implemented")
}

// SQLite Repository

// SQLiteMigrationRepository implements MigrationRepository
type SQLiteMigrationRepository struct {
	db *sql.DB
}

// NewSQLiteMigrationRepository creates a new repository
func NewSQLiteMigrationRepository(db *sql.DB) (*SQLiteMigrationRepository, error) {
	repo := &SQLiteMigrationRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteMigrationRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS migration_jobs (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			org_id TEXT NOT NULL,
			source TEXT NOT NULL,
			source_email TEXT,
			credentials TEXT,
			status TEXT NOT NULL,
			progress TEXT,
			options TEXT,
			error_message TEXT,
			error_count INTEGER DEFAULT 0,
			started_at DATETIME,
			completed_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS migration_errors (
			id TEXT PRIMARY KEY,
			job_id TEXT NOT NULL,
			type TEXT NOT NULL,
			item_id TEXT,
			item_subject TEXT,
			folder TEXT,
			error TEXT NOT NULL,
			retryable INTEGER DEFAULT 0,
			retry_count INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_migration_account ON migration_jobs(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_migration_status ON migration_jobs(status)`,
		`CREATE INDEX IF NOT EXISTS idx_migration_error_job ON migration_errors(job_id)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteMigrationRepository) SaveJob(ctx context.Context, job *MigrationJob) error {
	credsJSON, _ := json.Marshal(job.Credentials)
	progressJSON, _ := json.Marshal(job.Progress)
	optionsJSON, _ := json.Marshal(job.Options)

	query := `
	INSERT INTO migration_jobs (
		id, account_id, org_id, source, source_email, credentials, status,
		progress, options, error_message, error_count, started_at, completed_at,
		created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		status = excluded.status,
		progress = excluded.progress,
		error_message = excluded.error_message,
		error_count = excluded.error_count,
		started_at = excluded.started_at,
		completed_at = excluded.completed_at,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		job.ID.String(), job.AccountID.String(), job.OrgID.String(),
		string(job.Source), job.SourceEmail, string(credsJSON),
		string(job.Status), string(progressJSON), string(optionsJSON),
		job.ErrorMessage, job.ErrorCount, job.StartedAt, job.CompletedAt,
		job.CreatedAt, job.UpdatedAt)

	return err
}

func (r *SQLiteMigrationRepository) GetJob(ctx context.Context, id uuid.UUID) (*MigrationJob, error) {
	query := `
	SELECT id, account_id, org_id, source, source_email, credentials, status,
		progress, options, error_message, error_count, started_at, completed_at,
		created_at, updated_at
	FROM migration_jobs WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())

	var job MigrationJob
	var idStr, accountIDStr, orgIDStr string
	var credsJSON, progressJSON, optionsJSON string

	err := row.Scan(&idStr, &accountIDStr, &orgIDStr, &job.Source, &job.SourceEmail,
		&credsJSON, &job.Status, &progressJSON, &optionsJSON,
		&job.ErrorMessage, &job.ErrorCount, &job.StartedAt, &job.CompletedAt,
		&job.CreatedAt, &job.UpdatedAt)
	if err != nil {
		return nil, err
	}

	job.ID, _ = uuid.Parse(idStr)
	job.AccountID, _ = uuid.Parse(accountIDStr)
	job.OrgID, _ = uuid.Parse(orgIDStr)

	if credsJSON != "" {
		job.Credentials = &SourceCredentials{}
		_ = json.Unmarshal([]byte(credsJSON), job.Credentials)
	}
	if progressJSON != "" {
		job.Progress = &MigrationProgress{}
		_ = json.Unmarshal([]byte(progressJSON), job.Progress)
	}
	if optionsJSON != "" {
		job.Options = &MigrationOptions{}
		_ = json.Unmarshal([]byte(optionsJSON), job.Options)
	}

	return &job, nil
}

func (r *SQLiteMigrationRepository) GetJobsForAccount(ctx context.Context, accountID uuid.UUID) ([]*MigrationJob, error) {
	query := `
	SELECT id, account_id, org_id, source, source_email, credentials, status,
		progress, options, error_message, error_count, started_at, completed_at,
		created_at, updated_at
	FROM migration_jobs WHERE account_id = ?
	ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*MigrationJob
	for rows.Next() {
		var job MigrationJob
		var idStr, accountIDStr, orgIDStr string
		var credsJSON, progressJSON, optionsJSON string

		err := rows.Scan(&idStr, &accountIDStr, &orgIDStr, &job.Source, &job.SourceEmail,
			&credsJSON, &job.Status, &progressJSON, &optionsJSON,
			&job.ErrorMessage, &job.ErrorCount, &job.StartedAt, &job.CompletedAt,
			&job.CreatedAt, &job.UpdatedAt)
		if err != nil {
			return nil, err
		}

		job.ID, _ = uuid.Parse(idStr)
		job.AccountID, _ = uuid.Parse(accountIDStr)
		job.OrgID, _ = uuid.Parse(orgIDStr)

		if credsJSON != "" {
			job.Credentials = &SourceCredentials{}
			_ = json.Unmarshal([]byte(credsJSON), job.Credentials)
		}
		if progressJSON != "" {
			job.Progress = &MigrationProgress{}
			_ = json.Unmarshal([]byte(progressJSON), job.Progress)
		}
		if optionsJSON != "" {
			job.Options = &MigrationOptions{}
			_ = json.Unmarshal([]byte(optionsJSON), job.Options)
		}

		jobs = append(jobs, &job)
	}
	return jobs, rows.Err()
}

func (r *SQLiteMigrationRepository) DeleteJob(ctx context.Context, id uuid.UUID) error {
	r.db.ExecContext(ctx, "DELETE FROM migration_errors WHERE job_id = ?", id.String())
	_, err := r.db.ExecContext(ctx, "DELETE FROM migration_jobs WHERE id = ?", id.String())
	return err
}

func (r *SQLiteMigrationRepository) SaveError(ctx context.Context, migErr *MigrationError) error {
	query := `
	INSERT INTO migration_errors (
		id, job_id, type, item_id, item_subject, folder, error, retryable, retry_count, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query,
		migErr.ID.String(), migErr.JobID.String(), migErr.Type, migErr.ItemID,
		migErr.ItemSubject, migErr.Folder, migErr.Error, migErr.Retryable,
		migErr.RetryCount, migErr.CreatedAt)
	return err
}

func (r *SQLiteMigrationRepository) GetErrorsForJob(ctx context.Context, jobID uuid.UUID) ([]*MigrationError, error) {
	query := `
	SELECT id, job_id, type, item_id, item_subject, folder, error, retryable, retry_count, created_at
	FROM migration_errors WHERE job_id = ?
	ORDER BY created_at DESC
	LIMIT 1000
	`
	rows, err := r.db.QueryContext(ctx, query, jobID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var errors []*MigrationError
	for rows.Next() {
		var migErr MigrationError
		var idStr, jobIDStr string

		err := rows.Scan(&idStr, &jobIDStr, &migErr.Type, &migErr.ItemID,
			&migErr.ItemSubject, &migErr.Folder, &migErr.Error,
			&migErr.Retryable, &migErr.RetryCount, &migErr.CreatedAt)
		if err != nil {
			return nil, err
		}

		migErr.ID, _ = uuid.Parse(idStr)
		migErr.JobID, _ = uuid.Parse(jobIDStr)
		errors = append(errors, &migErr)
	}
	return errors, rows.Err()
}

func (r *SQLiteMigrationRepository) ClearErrors(ctx context.Context, jobID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM migration_errors WHERE job_id = ?", jobID.String())
	return err
}

// IMAP Importer (uses external imap library)
type IMAPImporter struct {
	server   string
	port     int
	username string
	password string
	useSSL   bool
	// conn would be the IMAP connection
}

func (i *IMAPImporter) Connect(ctx context.Context, creds *SourceCredentials) error {
	i.server = creds.Server
	i.port = creds.Port
	i.username = creds.Username
	i.password = creds.Password
	i.useSSL = creds.UseSSL

	// Would establish IMAP connection here
	// Using external library like github.com/emersion/go-imap
	return fmt.Errorf("not implemented - requires go-imap library")
}

func (i *IMAPImporter) Disconnect() error {
	return nil
}

func (i *IMAPImporter) ListFolders(ctx context.Context) ([]FolderInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (i *IMAPImporter) CountEmails(ctx context.Context, folder string) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (i *IMAPImporter) FetchEmails(ctx context.Context, folder string, offset, limit int) ([]EmailData, error) {
	return nil, fmt.Errorf("not implemented")
}

func (i *IMAPImporter) ListContacts(ctx context.Context) ([]ContactData, error) {
	return nil, nil
}

func (i *IMAPImporter) ListEvents(ctx context.Context) ([]EventData, error) {
	return nil, nil
}

// Export functionality

// ExportFormat represents export file format
type ExportFormat string

const (
	ExportMbox    ExportFormat = "mbox"
	ExportMaildir ExportFormat = "maildir"
	ExportEML     ExportFormat = "eml"
	ExportPST     ExportFormat = "pst"
)

// Exporter handles email export
type Exporter struct {
	outputDir string
	format    ExportFormat
	logger    Logger
}

// NewExporter creates a new exporter
func NewExporter(outputDir string, format ExportFormat, logger Logger) *Exporter {
	return &Exporter{
		outputDir: outputDir,
		format:    format,
		logger:    logger,
	}
}

// ExportEmails exports emails to the specified format
func (e *Exporter) ExportEmails(ctx context.Context, emails []EmailData, folderName string) error {
	switch e.format {
	case ExportMbox:
		return e.exportMbox(ctx, emails, folderName)
	case ExportMaildir:
		return e.exportMaildir(ctx, emails, folderName)
	case ExportEML:
		return e.exportEML(ctx, emails, folderName)
	default:
		return fmt.Errorf("unsupported export format: %s", e.format)
	}
}

func (e *Exporter) exportMbox(ctx context.Context, emails []EmailData, folderName string) error {
	filename := filepath.Join(e.outputDir, folderName+".mbox")
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, email := range emails {
		// Mbox format: "From " line followed by message
		fromLine := fmt.Sprintf("From %s %s\n", 
			email.From, 
			email.Date.Format("Mon Jan 2 15:04:05 2006"))
		writer.WriteString(fromLine)
		writer.Write(email.RawMessage)
		writer.WriteString("\n\n")
	}
	return writer.Flush()
}

func (e *Exporter) exportMaildir(ctx context.Context, emails []EmailData, folderName string) error {
	// Create maildir structure
	dirs := []string{"cur", "new", "tmp"}
	for _, dir := range dirs {
		path := filepath.Join(e.outputDir, folderName, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}

	for i, email := range emails {
		// Maildir filename format
		flags := ""
		for _, f := range email.Flags {
			switch f {
			case "\\Seen":
				flags += "S"
			case "\\Flagged":
				flags += "F"
			case "\\Answered":
				flags += "R"
			case "\\Deleted":
				flags += "T"
			case "\\Draft":
				flags += "D"
			}
		}

		filename := fmt.Sprintf("%d.%d.localhost:2,%s", 
			email.Date.Unix(), i, flags)
		
		dir := "cur"
		if !strings.Contains(flags, "S") {
			dir = "new"
		}
		
		filepath := filepath.Join(e.outputDir, folderName, dir, filename)
		if err := os.WriteFile(filepath, email.RawMessage, 0644); err != nil {
			return err
		}
	}
	return nil
}

func (e *Exporter) exportEML(ctx context.Context, emails []EmailData, folderName string) error {
	outputPath := filepath.Join(e.outputDir, folderName)
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return err
	}

	for i, email := range emails {
		// Create filename from subject (sanitized)
		subject := email.Subject
		if subject == "" {
			subject = "no_subject"
		}
		// Sanitize filename
		subject = strings.Map(func(r rune) rune {
			if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
				return '_'
			}
			return r
		}, subject)
		if len(subject) > 50 {
			subject = subject[:50]
		}

		filename := fmt.Sprintf("%d_%s.eml", i+1, subject)
		filepath := filepath.Join(outputPath, filename)

		if err := os.WriteFile(filepath, email.RawMessage, 0644); err != nil {
			return err
		}
	}
	return nil
}

// BackupService handles full mailbox backup
type BackupService struct {
	exporter *Exporter
	logger   Logger
}

// Backup creates a full mailbox backup
func (b *BackupService) Backup(ctx context.Context, accountID uuid.UUID, format ExportFormat) (string, error) {
	// Would iterate through all folders and export
	// Returns path to backup archive
	return "", fmt.Errorf("not implemented")
}

// Restore restores from a backup
func (b *BackupService) Restore(ctx context.Context, accountID uuid.UUID, backupPath string) error {
	// Would parse backup and import emails
	return fmt.Errorf("not implemented")
}
