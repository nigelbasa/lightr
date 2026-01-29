package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Admin API for system management

// SystemStats represents system statistics
type SystemStats struct {
	// Server info
	ServerID      string    `json:"server_id"`
	Version       string    `json:"version"`
	Uptime        int64     `json:"uptime_seconds"`
	StartedAt     time.Time `json:"started_at"`
	
	// Runtime
	GoVersion     string    `json:"go_version"`
	NumGoroutines int       `json:"num_goroutines"`
	NumCPU        int       `json:"num_cpu"`
	
	// Memory
	MemAlloc      uint64    `json:"mem_alloc_bytes"`
	MemTotalAlloc uint64    `json:"mem_total_alloc_bytes"`
	MemSys        uint64    `json:"mem_sys_bytes"`
	MemNumGC      uint32    `json:"mem_num_gc"`
	
	// Counts
	TotalOrgs       int64   `json:"total_orgs"`
	TotalAccounts   int64   `json:"total_accounts"`
	TotalDomains    int64   `json:"total_domains"`
	TotalMailboxes  int64   `json:"total_mailboxes"`
	TotalEmails     int64   `json:"total_emails"`
	TotalStorageBytes int64 `json:"total_storage_bytes"`
	
	// Activity (last 24h)
	EmailsReceived24h  int64 `json:"emails_received_24h"`
	EmailsSent24h      int64 `json:"emails_sent_24h"`
	ActiveConnections  int   `json:"active_connections"`
	
	// Queue status
	QueueSize          int   `json:"queue_size"`
	QueueProcessing    int   `json:"queue_processing"`
	
	Timestamp time.Time `json:"timestamp"`
}

// Organization management
type Organization struct {
	ID          uuid.UUID         `json:"id"`
	Name        string            `json:"name"`
	Slug        string            `json:"slug"`
	
	// Plan & limits
	Plan        string            `json:"plan"`     // free, starter, business, enterprise
	MaxAccounts int               `json:"max_accounts"`
	MaxDomains  int               `json:"max_domains"`
	MaxStorage  int64             `json:"max_storage_bytes"`
	
	// Current usage
	AccountCount int              `json:"account_count"`
	DomainCount  int              `json:"domain_count"`
	StorageUsed  int64            `json:"storage_used_bytes"`
	
	// Settings
	Settings    map[string]interface{} `json:"settings,omitempty"`
	
	// Status
	Status      string            `json:"status"` // active, suspended, deleted
	SuspendedAt *time.Time        `json:"suspended_at,omitempty"`
	SuspendReason string          `json:"suspend_reason,omitempty"`
	
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Domain management
type Domain struct {
	ID            uuid.UUID `json:"id"`
	OrgID         uuid.UUID `json:"org_id"`
	
	Name          string    `json:"name"`
	
	// Verification
	Verified      bool      `json:"verified"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`
	VerificationToken string `json:"verification_token,omitempty"`
	
	// DNS records
	MXVerified    bool      `json:"mx_verified"`
	SPFVerified   bool      `json:"spf_verified"`
	DKIMVerified  bool      `json:"dkim_verified"`
	DMARCVerified bool      `json:"dmarc_verified"`
	
	// DKIM key
	DKIMSelector  string    `json:"dkim_selector,omitempty"`
	DKIMPublicKey string    `json:"dkim_public_key,omitempty"`
	
	// Settings
	CatchAll      bool      `json:"catch_all"`
	CatchAllTarget string   `json:"catch_all_target,omitempty"`
	
	Status        string    `json:"status"` // pending, active, suspended
	
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Account management
type Account struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	
	// Role
	Role        string    `json:"role"` // admin, user
	IsOrgAdmin  bool      `json:"is_org_admin"`
	
	// Quota
	QuotaBytes     int64  `json:"quota_bytes"`
	QuotaUsedBytes int64  `json:"quota_used_bytes"`
	
	// Status
	Status      string    `json:"status"` // active, suspended, deleted
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	LastActiveAt *time.Time `json:"last_active_at,omitempty"`
	
	// MFA
	MFAEnabled  bool      `json:"mfa_enabled"`
	
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID          uuid.UUID         `json:"id"`
	OrgID       uuid.UUID         `json:"org_id"`
	AccountID   *uuid.UUID        `json:"account_id,omitempty"`
	
	Action      string            `json:"action"`
	Resource    string            `json:"resource"`
	ResourceID  string            `json:"resource_id,omitempty"`
	
	Actor       string            `json:"actor"` // email or "system"
	ActorIP     string            `json:"actor_ip,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	
	Details     map[string]interface{} `json:"details,omitempty"`
	
	Success     bool              `json:"success"`
	ErrorMsg    string            `json:"error_msg,omitempty"`
	
	CreatedAt   time.Time         `json:"created_at"`
}

// QueuedEmail represents an email in the queue
type QueuedEmail struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	
	From        string    `json:"from"`
	To          []string  `json:"to"`
	Subject     string    `json:"subject"`
	
	Status      string    `json:"status"` // queued, processing, sent, failed, deferred
	Attempts    int       `json:"attempts"`
	MaxAttempts int       `json:"max_attempts"`
	
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	
	SizeBytes   int64     `json:"size_bytes"`
	
	QueuedAt    time.Time `json:"queued_at"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
}

// AdminService provides admin functionality
type AdminService struct {
	mu        sync.RWMutex
	repo      AdminRepository
	logger    Logger
	startedAt time.Time
	serverID  string
	version   string
}

// AdminRepository interface
type AdminRepository interface {
	// Stats
	GetStats(ctx context.Context) (*SystemStats, error)
	
	// Organizations
	CreateOrg(ctx context.Context, org *Organization) error
	GetOrg(ctx context.Context, id uuid.UUID) (*Organization, error)
	GetOrgBySlug(ctx context.Context, slug string) (*Organization, error)
	ListOrgs(ctx context.Context, filter OrgFilter) ([]*Organization, int64, error)
	UpdateOrg(ctx context.Context, org *Organization) error
	SuspendOrg(ctx context.Context, id uuid.UUID, reason string) error
	DeleteOrg(ctx context.Context, id uuid.UUID) error
	
	// Domains
	CreateDomain(ctx context.Context, domain *Domain) error
	GetDomain(ctx context.Context, id uuid.UUID) (*Domain, error)
	GetDomainByName(ctx context.Context, name string) (*Domain, error)
	ListDomains(ctx context.Context, filter DomainFilter) ([]*Domain, int64, error)
	UpdateDomain(ctx context.Context, domain *Domain) error
	DeleteDomain(ctx context.Context, id uuid.UUID) error
	
	// Accounts
	CreateAccount(ctx context.Context, account *Account) error
	GetAccount(ctx context.Context, id uuid.UUID) (*Account, error)
	GetAccountByEmail(ctx context.Context, email string) (*Account, error)
	ListAccounts(ctx context.Context, filter AccountFilter) ([]*Account, int64, error)
	UpdateAccount(ctx context.Context, account *Account) error
	SuspendAccount(ctx context.Context, id uuid.UUID, reason string) error
	DeleteAccount(ctx context.Context, id uuid.UUID) error
	
	// Audit logs
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	GetAuditLogs(ctx context.Context, filter AuditFilter) ([]*AuditLog, int64, error)
	
	// Queue
	GetQueuedEmails(ctx context.Context, filter QueueFilter) ([]*QueuedEmail, int64, error)
	RetryQueuedEmail(ctx context.Context, id uuid.UUID) error
	DeleteQueuedEmail(ctx context.Context, id uuid.UUID) error
	FlushQueue(ctx context.Context, filter QueueFilter) error
}

// Filter types
type OrgFilter struct {
	Search  string
	Status  string
	Plan    string
	Limit   int
	Offset  int
}

type DomainFilter struct {
	OrgID    *uuid.UUID
	Search   string
	Verified *bool
	Status   string
	Limit    int
	Offset   int
}

type AccountFilter struct {
	OrgID   *uuid.UUID
	Search  string
	Role    string
	Status  string
	Limit   int
	Offset  int
}

type AuditFilter struct {
	OrgID     *uuid.UUID
	AccountID *uuid.UUID
	Action    string
	Resource  string
	StartDate *time.Time
	EndDate   *time.Time
	Limit     int
	Offset    int
}

type QueueFilter struct {
	OrgID  *uuid.UUID
	Status string
	Limit  int
	Offset int
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewAdminService creates a new admin service
func NewAdminService(repo AdminRepository, logger Logger, version string) *AdminService {
	return &AdminService{
		repo:      repo,
		logger:    logger,
		startedAt: time.Now(),
		serverID:  uuid.New().String()[:8],
		version:   version,
	}
}

// System Stats

// GetStats returns system statistics
func (s *AdminService) GetStats(ctx context.Context) (*SystemStats, error) {
	stats, err := s.repo.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	// Add runtime stats
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	stats.ServerID = s.serverID
	stats.Version = s.version
	stats.Uptime = int64(time.Since(s.startedAt).Seconds())
	stats.StartedAt = s.startedAt
	stats.GoVersion = runtime.Version()
	stats.NumGoroutines = runtime.NumGoroutine()
	stats.NumCPU = runtime.NumCPU()
	stats.MemAlloc = mem.Alloc
	stats.MemTotalAlloc = mem.TotalAlloc
	stats.MemSys = mem.Sys
	stats.MemNumGC = mem.NumGC
	stats.Timestamp = time.Now()

	return stats, nil
}

// Organization Management

// CreateOrg creates a new organization
func (s *AdminService) CreateOrg(ctx context.Context, org *Organization) error {
	org.ID = uuid.New()
	org.Status = "active"
	org.CreatedAt = time.Now()
	org.UpdatedAt = time.Now()

	if err := s.repo.CreateOrg(ctx, org); err != nil {
		return err
	}

	s.logAudit(ctx, nil, "create", "organization", org.ID.String(), nil, true, "")
	s.logger.Info("created organization", "id", org.ID, "name", org.Name)
	return nil
}

// GetOrg retrieves an organization
func (s *AdminService) GetOrg(ctx context.Context, id uuid.UUID) (*Organization, error) {
	return s.repo.GetOrg(ctx, id)
}

// ListOrgs lists organizations
func (s *AdminService) ListOrgs(ctx context.Context, filter OrgFilter) ([]*Organization, int64, error) {
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	return s.repo.ListOrgs(ctx, filter)
}

// UpdateOrg updates an organization
func (s *AdminService) UpdateOrg(ctx context.Context, org *Organization) error {
	org.UpdatedAt = time.Now()
	if err := s.repo.UpdateOrg(ctx, org); err != nil {
		return err
	}
	s.logAudit(ctx, nil, "update", "organization", org.ID.String(), nil, true, "")
	return nil
}

// SuspendOrg suspends an organization
func (s *AdminService) SuspendOrg(ctx context.Context, id uuid.UUID, reason string) error {
	if err := s.repo.SuspendOrg(ctx, id, reason); err != nil {
		return err
	}
	s.logAudit(ctx, nil, "suspend", "organization", id.String(), 
		map[string]interface{}{"reason": reason}, true, "")
	s.logger.Info("suspended organization", "id", id, "reason", reason)
	return nil
}

// DeleteOrg deletes an organization
func (s *AdminService) DeleteOrg(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.DeleteOrg(ctx, id); err != nil {
		return err
	}
	s.logAudit(ctx, nil, "delete", "organization", id.String(), nil, true, "")
	return nil
}

// Domain Management

// CreateDomain creates a new domain
func (s *AdminService) CreateDomain(ctx context.Context, domain *Domain) error {
	domain.ID = uuid.New()
	domain.Status = "pending"
	domain.VerificationToken = generateToken()
	domain.DKIMSelector = "lightr"
	domain.CreatedAt = time.Now()
	domain.UpdatedAt = time.Now()

	if err := s.repo.CreateDomain(ctx, domain); err != nil {
		return err
	}

	s.logAudit(ctx, &domain.OrgID, "create", "domain", domain.ID.String(),
		map[string]interface{}{"name": domain.Name}, true, "")
	return nil
}

// GetDomain retrieves a domain
func (s *AdminService) GetDomain(ctx context.Context, id uuid.UUID) (*Domain, error) {
	return s.repo.GetDomain(ctx, id)
}

// VerifyDomain verifies a domain
func (s *AdminService) VerifyDomain(ctx context.Context, id uuid.UUID) error {
	domain, err := s.repo.GetDomain(ctx, id)
	if err != nil {
		return err
	}

	// TODO: Perform actual DNS verification
	// Check TXT record for verification token
	// Check MX, SPF, DKIM, DMARC records

	now := time.Now()
	domain.Verified = true
	domain.VerifiedAt = &now
	domain.Status = "active"
	domain.UpdatedAt = now

	if err := s.repo.UpdateDomain(ctx, domain); err != nil {
		return err
	}

	s.logAudit(ctx, &domain.OrgID, "verify", "domain", domain.ID.String(), nil, true, "")
	return nil
}

// ListDomains lists domains
func (s *AdminService) ListDomains(ctx context.Context, filter DomainFilter) ([]*Domain, int64, error) {
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	return s.repo.ListDomains(ctx, filter)
}

// DeleteDomain deletes a domain
func (s *AdminService) DeleteDomain(ctx context.Context, id uuid.UUID) error {
	domain, err := s.repo.GetDomain(ctx, id)
	if err != nil {
		return err
	}
	
	if err := s.repo.DeleteDomain(ctx, id); err != nil {
		return err
	}
	
	s.logAudit(ctx, &domain.OrgID, "delete", "domain", id.String(), nil, true, "")
	return nil
}

// Account Management

// CreateAccount creates a new account
func (s *AdminService) CreateAccount(ctx context.Context, account *Account) error {
	account.ID = uuid.New()
	account.Status = "active"
	account.CreatedAt = time.Now()
	account.UpdatedAt = time.Now()

	if err := s.repo.CreateAccount(ctx, account); err != nil {
		return err
	}

	s.logAudit(ctx, &account.OrgID, "create", "account", account.ID.String(),
		map[string]interface{}{"email": account.Email}, true, "")
	return nil
}

// GetAccount retrieves an account
func (s *AdminService) GetAccount(ctx context.Context, id uuid.UUID) (*Account, error) {
	return s.repo.GetAccount(ctx, id)
}

// ListAccounts lists accounts
func (s *AdminService) ListAccounts(ctx context.Context, filter AccountFilter) ([]*Account, int64, error) {
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	return s.repo.ListAccounts(ctx, filter)
}

// UpdateAccount updates an account
func (s *AdminService) UpdateAccount(ctx context.Context, account *Account) error {
	account.UpdatedAt = time.Now()
	if err := s.repo.UpdateAccount(ctx, account); err != nil {
		return err
	}
	s.logAudit(ctx, &account.OrgID, "update", "account", account.ID.String(), nil, true, "")
	return nil
}

// SuspendAccount suspends an account
func (s *AdminService) SuspendAccount(ctx context.Context, id uuid.UUID, reason string) error {
	account, err := s.repo.GetAccount(ctx, id)
	if err != nil {
		return err
	}
	
	if err := s.repo.SuspendAccount(ctx, id, reason); err != nil {
		return err
	}
	
	s.logAudit(ctx, &account.OrgID, "suspend", "account", id.String(),
		map[string]interface{}{"reason": reason}, true, "")
	return nil
}

// ResetPassword initiates password reset
func (s *AdminService) ResetPassword(ctx context.Context, accountID uuid.UUID) (string, error) {
	account, err := s.repo.GetAccount(ctx, accountID)
	if err != nil {
		return "", err
	}

	// Generate reset token
	token := generateToken()
	
	// TODO: Store token and send reset email
	
	s.logAudit(ctx, &account.OrgID, "reset_password", "account", accountID.String(), nil, true, "")
	return token, nil
}

// DeleteAccount deletes an account
func (s *AdminService) DeleteAccount(ctx context.Context, id uuid.UUID) error {
	account, err := s.repo.GetAccount(ctx, id)
	if err != nil {
		return err
	}
	
	if err := s.repo.DeleteAccount(ctx, id); err != nil {
		return err
	}
	
	s.logAudit(ctx, &account.OrgID, "delete", "account", id.String(), nil, true, "")
	return nil
}

// Audit Logs

// GetAuditLogs retrieves audit logs
func (s *AdminService) GetAuditLogs(ctx context.Context, filter AuditFilter) ([]*AuditLog, int64, error) {
	if filter.Limit == 0 {
		filter.Limit = 100
	}
	return s.repo.GetAuditLogs(ctx, filter)
}

func (s *AdminService) logAudit(ctx context.Context, orgID *uuid.UUID, action, resource, resourceID string, details map[string]interface{}, success bool, errMsg string) {
	log := &AuditLog{
		ID:         uuid.New(),
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Actor:      "system", // Would get from context
		Details:    details,
		Success:    success,
		ErrorMsg:   errMsg,
		CreatedAt:  time.Now(),
	}
	
	if orgID != nil {
		log.OrgID = *orgID
	}
	
	s.repo.CreateAuditLog(ctx, log)
}

// Queue Management

// GetQueuedEmails retrieves queued emails
func (s *AdminService) GetQueuedEmails(ctx context.Context, filter QueueFilter) ([]*QueuedEmail, int64, error) {
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	return s.repo.GetQueuedEmails(ctx, filter)
}

// RetryQueuedEmail retries a queued email
func (s *AdminService) RetryQueuedEmail(ctx context.Context, id uuid.UUID) error {
	return s.repo.RetryQueuedEmail(ctx, id)
}

// DeleteQueuedEmail deletes a queued email
func (s *AdminService) DeleteQueuedEmail(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteQueuedEmail(ctx, id)
}

// FlushQueue flushes the queue based on filter
func (s *AdminService) FlushQueue(ctx context.Context, filter QueueFilter) error {
	return s.repo.FlushQueue(ctx, filter)
}

// Helper
func generateToken() string {
	return uuid.New().String()
}

// HTTP Handler for Admin API

type AdminHandler struct {
	service *AdminService
}

func NewAdminHandler(service *AdminService) *AdminHandler {
	return &AdminHandler{service: service}
}

// Mount mounts the admin API routes
func (h *AdminHandler) Mount(mux *http.ServeMux) {
	// Stats
	mux.HandleFunc("GET /admin/stats", h.handleStats)
	
	// Organizations
	mux.HandleFunc("GET /admin/orgs", h.handleListOrgs)
	mux.HandleFunc("POST /admin/orgs", h.handleCreateOrg)
	mux.HandleFunc("GET /admin/orgs/{id}", h.handleGetOrg)
	mux.HandleFunc("PUT /admin/orgs/{id}", h.handleUpdateOrg)
	mux.HandleFunc("POST /admin/orgs/{id}/suspend", h.handleSuspendOrg)
	mux.HandleFunc("DELETE /admin/orgs/{id}", h.handleDeleteOrg)
	
	// Domains
	mux.HandleFunc("GET /admin/domains", h.handleListDomains)
	mux.HandleFunc("POST /admin/domains", h.handleCreateDomain)
	mux.HandleFunc("GET /admin/domains/{id}", h.handleGetDomain)
	mux.HandleFunc("POST /admin/domains/{id}/verify", h.handleVerifyDomain)
	mux.HandleFunc("DELETE /admin/domains/{id}", h.handleDeleteDomain)
	
	// Accounts
	mux.HandleFunc("GET /admin/accounts", h.handleListAccounts)
	mux.HandleFunc("POST /admin/accounts", h.handleCreateAccount)
	mux.HandleFunc("GET /admin/accounts/{id}", h.handleGetAccount)
	mux.HandleFunc("PUT /admin/accounts/{id}", h.handleUpdateAccount)
	mux.HandleFunc("POST /admin/accounts/{id}/suspend", h.handleSuspendAccount)
	mux.HandleFunc("POST /admin/accounts/{id}/reset-password", h.handleResetPassword)
	mux.HandleFunc("DELETE /admin/accounts/{id}", h.handleDeleteAccount)
	
	// Audit logs
	mux.HandleFunc("GET /admin/audit-logs", h.handleListAuditLogs)
	
	// Queue
	mux.HandleFunc("GET /admin/queue", h.handleListQueue)
	mux.HandleFunc("POST /admin/queue/{id}/retry", h.handleRetryQueued)
	mux.HandleFunc("DELETE /admin/queue/{id}", h.handleDeleteQueued)
	mux.HandleFunc("POST /admin/queue/flush", h.handleFlushQueue)
}

func (h *AdminHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.service.GetStats(r.Context())
	if err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	h.writeJSON(w, stats)
}

func (h *AdminHandler) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	filter := OrgFilter{
		Search: r.URL.Query().Get("search"),
		Status: r.URL.Query().Get("status"),
		Plan:   r.URL.Query().Get("plan"),
	}
	
	orgs, total, err := h.service.ListOrgs(r.Context(), filter)
	if err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	h.writeJSON(w, map[string]interface{}{
		"data":  orgs,
		"total": total,
	})
}

func (h *AdminHandler) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var org Organization
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	if err := h.service.CreateOrg(r.Context(), &org); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusCreated)
	h.writeJSON(w, org)
}

func (h *AdminHandler) handleGetOrg(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	org, err := h.service.GetOrg(r.Context(), id)
	if err != nil {
		h.writeError(w, err, http.StatusNotFound)
		return
	}
	
	h.writeJSON(w, org)
}

func (h *AdminHandler) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	var org Organization
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	org.ID = id
	
	if err := h.service.UpdateOrg(r.Context(), &org); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	h.writeJSON(w, org)
}

func (h *AdminHandler) handleSuspendOrg(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	var req struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	
	if err := h.service.SuspendOrg(r.Context(), id, req.Reason); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	if err := h.service.DeleteOrg(r.Context(), id); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) handleListDomains(w http.ResponseWriter, r *http.Request) {
	filter := DomainFilter{
		Search: r.URL.Query().Get("search"),
		Status: r.URL.Query().Get("status"),
	}
	
	if orgIDStr := r.URL.Query().Get("org_id"); orgIDStr != "" {
		if id, err := uuid.Parse(orgIDStr); err == nil {
			filter.OrgID = &id
		}
	}
	
	domains, total, err := h.service.ListDomains(r.Context(), filter)
	if err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	h.writeJSON(w, map[string]interface{}{
		"data":  domains,
		"total": total,
	})
}

func (h *AdminHandler) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var domain Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	if err := h.service.CreateDomain(r.Context(), &domain); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusCreated)
	h.writeJSON(w, domain)
}

func (h *AdminHandler) handleGetDomain(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	domain, err := h.service.GetDomain(r.Context(), id)
	if err != nil {
		h.writeError(w, err, http.StatusNotFound)
		return
	}
	
	h.writeJSON(w, domain)
}

func (h *AdminHandler) handleVerifyDomain(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	if err := h.service.VerifyDomain(r.Context(), id); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	if err := h.service.DeleteDomain(r.Context(), id); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	filter := AccountFilter{
		Search: r.URL.Query().Get("search"),
		Role:   r.URL.Query().Get("role"),
		Status: r.URL.Query().Get("status"),
	}
	
	if orgIDStr := r.URL.Query().Get("org_id"); orgIDStr != "" {
		if id, err := uuid.Parse(orgIDStr); err == nil {
			filter.OrgID = &id
		}
	}
	
	accounts, total, err := h.service.ListAccounts(r.Context(), filter)
	if err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	h.writeJSON(w, map[string]interface{}{
		"data":  accounts,
		"total": total,
	})
}

func (h *AdminHandler) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var account Account
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	if err := h.service.CreateAccount(r.Context(), &account); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusCreated)
	h.writeJSON(w, account)
}

func (h *AdminHandler) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	account, err := h.service.GetAccount(r.Context(), id)
	if err != nil {
		h.writeError(w, err, http.StatusNotFound)
		return
	}
	
	h.writeJSON(w, account)
}

func (h *AdminHandler) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	var account Account
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	account.ID = id
	
	if err := h.service.UpdateAccount(r.Context(), &account); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	h.writeJSON(w, account)
}

func (h *AdminHandler) handleSuspendAccount(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	var req struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	
	if err := h.service.SuspendAccount(r.Context(), id, req.Reason); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	token, err := h.service.ResetPassword(r.Context(), id)
	if err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	h.writeJSON(w, map[string]string{"reset_token": token})
}

func (h *AdminHandler) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	if err := h.service.DeleteAccount(r.Context(), id); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	filter := AuditFilter{
		Action:   r.URL.Query().Get("action"),
		Resource: r.URL.Query().Get("resource"),
	}
	
	if orgIDStr := r.URL.Query().Get("org_id"); orgIDStr != "" {
		if id, err := uuid.Parse(orgIDStr); err == nil {
			filter.OrgID = &id
		}
	}
	
	logs, total, err := h.service.GetAuditLogs(r.Context(), filter)
	if err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	h.writeJSON(w, map[string]interface{}{
		"data":  logs,
		"total": total,
	})
}

func (h *AdminHandler) handleListQueue(w http.ResponseWriter, r *http.Request) {
	filter := QueueFilter{
		Status: r.URL.Query().Get("status"),
	}
	
	emails, total, err := h.service.GetQueuedEmails(r.Context(), filter)
	if err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	h.writeJSON(w, map[string]interface{}{
		"data":  emails,
		"total": total,
	})
}

func (h *AdminHandler) handleRetryQueued(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	if err := h.service.RetryQueuedEmail(r.Context(), id); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) handleDeleteQueued(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, err, http.StatusBadRequest)
		return
	}
	
	if err := h.service.DeleteQueuedEmail(r.Context(), id); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) handleFlushQueue(w http.ResponseWriter, r *http.Request) {
	var filter QueueFilter
	json.NewDecoder(r.Body).Decode(&filter)
	
	if err := h.service.FlushQueue(r.Context(), filter); err != nil {
		h.writeError(w, err, http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (h *AdminHandler) writeError(w http.ResponseWriter, err error, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// SQLite Repository

// SQLiteAdminRepository implements AdminRepository
type SQLiteAdminRepository struct {
	db *sql.DB
}

// NewSQLiteAdminRepository creates a new repository
func NewSQLiteAdminRepository(db *sql.DB) (*SQLiteAdminRepository, error) {
	repo := &SQLiteAdminRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteAdminRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS admin_organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT UNIQUE NOT NULL,
			plan TEXT DEFAULT 'free',
			max_accounts INTEGER DEFAULT 5,
			max_domains INTEGER DEFAULT 1,
			max_storage INTEGER DEFAULT 1073741824,
			account_count INTEGER DEFAULT 0,
			domain_count INTEGER DEFAULT 0,
			storage_used INTEGER DEFAULT 0,
			settings TEXT,
			status TEXT DEFAULT 'active',
			suspended_at DATETIME,
			suspend_reason TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS admin_domains (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT UNIQUE NOT NULL,
			verified INTEGER DEFAULT 0,
			verified_at DATETIME,
			verification_token TEXT,
			mx_verified INTEGER DEFAULT 0,
			spf_verified INTEGER DEFAULT 0,
			dkim_verified INTEGER DEFAULT 0,
			dmarc_verified INTEGER DEFAULT 0,
			dkim_selector TEXT,
			dkim_public_key TEXT,
			catch_all INTEGER DEFAULT 0,
			catch_all_target TEXT,
			status TEXT DEFAULT 'pending',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS admin_accounts (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			display_name TEXT,
			role TEXT DEFAULT 'user',
			is_org_admin INTEGER DEFAULT 0,
			quota_bytes INTEGER DEFAULT 1073741824,
			quota_used_bytes INTEGER DEFAULT 0,
			status TEXT DEFAULT 'active',
			last_login_at DATETIME,
			last_active_at DATETIME,
			mfa_enabled INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS admin_audit_logs (
			id TEXT PRIMARY KEY,
			org_id TEXT,
			account_id TEXT,
			action TEXT NOT NULL,
			resource TEXT NOT NULL,
			resource_id TEXT,
			actor TEXT NOT NULL,
			actor_ip TEXT,
			user_agent TEXT,
			details TEXT,
			success INTEGER DEFAULT 1,
			error_msg TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS admin_queue (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			from_addr TEXT NOT NULL,
			to_addrs TEXT NOT NULL,
			subject TEXT,
			status TEXT DEFAULT 'queued',
			attempts INTEGER DEFAULT 0,
			max_attempts INTEGER DEFAULT 3,
			next_retry_at DATETIME,
			last_error TEXT,
			size_bytes INTEGER DEFAULT 0,
			queued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			processed_at DATETIME
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_admin_org_slug ON admin_organizations(slug)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_domain_org ON admin_domains(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_domain_name ON admin_domains(name)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_account_org ON admin_accounts(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_account_email ON admin_accounts(email)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_audit_org ON admin_audit_logs(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_queue_status ON admin_queue(status)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteAdminRepository) GetStats(ctx context.Context) (*SystemStats, error) {
	stats := &SystemStats{}
	
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_organizations").Scan(&stats.TotalOrgs)
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_accounts").Scan(&stats.TotalAccounts)
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_domains").Scan(&stats.TotalDomains)
	r.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(storage_used), 0) FROM admin_organizations").Scan(&stats.TotalStorageBytes)
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_queue WHERE status = 'queued'").Scan(&stats.QueueSize)
	r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_queue WHERE status = 'processing'").Scan(&stats.QueueProcessing)
	
	return stats, nil
}

// Organization methods (simplified)

func (r *SQLiteAdminRepository) CreateOrg(ctx context.Context, org *Organization) error {
	settingsJSON, _ := json.Marshal(org.Settings)
	
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_organizations (id, name, slug, plan, max_accounts, max_domains, max_storage, settings, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		org.ID.String(), org.Name, org.Slug, org.Plan, org.MaxAccounts, org.MaxDomains, org.MaxStorage,
		string(settingsJSON), org.Status, org.CreatedAt, org.UpdatedAt)
	return err
}

func (r *SQLiteAdminRepository) GetOrg(ctx context.Context, id uuid.UUID) (*Organization, error) {
	var org Organization
	var idStr string
	var settingsJSON string
	
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, slug, plan, max_accounts, max_domains, max_storage, account_count, domain_count, storage_used, settings, status, suspended_at, suspend_reason, created_at, updated_at
		FROM admin_organizations WHERE id = ?`, id.String()).Scan(
		&idStr, &org.Name, &org.Slug, &org.Plan, &org.MaxAccounts, &org.MaxDomains, &org.MaxStorage,
		&org.AccountCount, &org.DomainCount, &org.StorageUsed, &settingsJSON, &org.Status,
		&org.SuspendedAt, &org.SuspendReason, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, err
	}
	
	org.ID, _ = uuid.Parse(idStr)
	json.Unmarshal([]byte(settingsJSON), &org.Settings)
	
	return &org, nil
}

func (r *SQLiteAdminRepository) GetOrgBySlug(ctx context.Context, slug string) (*Organization, error) {
	var idStr string
	err := r.db.QueryRowContext(ctx, "SELECT id FROM admin_organizations WHERE slug = ?", slug).Scan(&idStr)
	if err != nil {
		return nil, err
	}
	id, _ := uuid.Parse(idStr)
	return r.GetOrg(ctx, id)
}

func (r *SQLiteAdminRepository) ListOrgs(ctx context.Context, filter OrgFilter) ([]*Organization, int64, error) {
	query := "SELECT id, name, slug, plan, max_accounts, max_domains, max_storage, account_count, domain_count, storage_used, status, created_at, updated_at FROM admin_organizations WHERE 1=1"
	countQuery := "SELECT COUNT(*) FROM admin_organizations WHERE 1=1"
	var args []interface{}
	
	if filter.Search != "" {
		query += " AND (name LIKE ? OR slug LIKE ?)"
		countQuery += " AND (name LIKE ? OR slug LIKE ?)"
		searchTerm := "%" + filter.Search + "%"
		args = append(args, searchTerm, searchTerm)
	}
	if filter.Status != "" {
		query += " AND status = ?"
		countQuery += " AND status = ?"
		args = append(args, filter.Status)
	}
	if filter.Plan != "" {
		query += " AND plan = ?"
		countQuery += " AND plan = ?"
		args = append(args, filter.Plan)
	}
	
	var total int64
	r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", filter.Limit, filter.Offset)
	
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	
	var orgs []*Organization
	for rows.Next() {
		var org Organization
		var idStr string
		rows.Scan(&idStr, &org.Name, &org.Slug, &org.Plan, &org.MaxAccounts, &org.MaxDomains, &org.MaxStorage,
			&org.AccountCount, &org.DomainCount, &org.StorageUsed, &org.Status, &org.CreatedAt, &org.UpdatedAt)
		org.ID, _ = uuid.Parse(idStr)
		orgs = append(orgs, &org)
	}
	
	return orgs, total, rows.Err()
}

func (r *SQLiteAdminRepository) UpdateOrg(ctx context.Context, org *Organization) error {
	settingsJSON, _ := json.Marshal(org.Settings)
	
	_, err := r.db.ExecContext(ctx, `
		UPDATE admin_organizations SET name = ?, slug = ?, plan = ?, max_accounts = ?, max_domains = ?, max_storage = ?, settings = ?, status = ?, updated_at = ?
		WHERE id = ?`,
		org.Name, org.Slug, org.Plan, org.MaxAccounts, org.MaxDomains, org.MaxStorage,
		string(settingsJSON), org.Status, org.UpdatedAt, org.ID.String())
	return err
}

func (r *SQLiteAdminRepository) SuspendOrg(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE admin_organizations SET status = 'suspended', suspended_at = ?, suspend_reason = ?, updated_at = ?
		WHERE id = ?`, time.Now(), reason, time.Now(), id.String())
	return err
}

func (r *SQLiteAdminRepository) DeleteOrg(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM admin_organizations WHERE id = ?", id.String())
	return err
}

// Domain methods

func (r *SQLiteAdminRepository) CreateDomain(ctx context.Context, domain *Domain) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_domains (id, org_id, name, verification_token, dkim_selector, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		domain.ID.String(), domain.OrgID.String(), domain.Name, domain.VerificationToken,
		domain.DKIMSelector, domain.Status, domain.CreatedAt, domain.UpdatedAt)
	return err
}

func (r *SQLiteAdminRepository) GetDomain(ctx context.Context, id uuid.UUID) (*Domain, error) {
	var domain Domain
	var idStr, orgIDStr string
	
	err := r.db.QueryRowContext(ctx, `
		SELECT id, org_id, name, verified, verified_at, verification_token, mx_verified, spf_verified, dkim_verified, dmarc_verified,
		dkim_selector, dkim_public_key, catch_all, catch_all_target, status, created_at, updated_at
		FROM admin_domains WHERE id = ?`, id.String()).Scan(
		&idStr, &orgIDStr, &domain.Name, &domain.Verified, &domain.VerifiedAt, &domain.VerificationToken,
		&domain.MXVerified, &domain.SPFVerified, &domain.DKIMVerified, &domain.DMARCVerified,
		&domain.DKIMSelector, &domain.DKIMPublicKey, &domain.CatchAll, &domain.CatchAllTarget,
		&domain.Status, &domain.CreatedAt, &domain.UpdatedAt)
	if err != nil {
		return nil, err
	}
	
	domain.ID, _ = uuid.Parse(idStr)
	domain.OrgID, _ = uuid.Parse(orgIDStr)
	
	return &domain, nil
}

func (r *SQLiteAdminRepository) GetDomainByName(ctx context.Context, name string) (*Domain, error) {
	var idStr string
	err := r.db.QueryRowContext(ctx, "SELECT id FROM admin_domains WHERE name = ?", name).Scan(&idStr)
	if err != nil {
		return nil, err
	}
	id, _ := uuid.Parse(idStr)
	return r.GetDomain(ctx, id)
}

func (r *SQLiteAdminRepository) ListDomains(ctx context.Context, filter DomainFilter) ([]*Domain, int64, error) {
	query := "SELECT id, org_id, name, verified, status, created_at, updated_at FROM admin_domains WHERE 1=1"
	countQuery := "SELECT COUNT(*) FROM admin_domains WHERE 1=1"
	var args []interface{}
	
	if filter.OrgID != nil {
		query += " AND org_id = ?"
		countQuery += " AND org_id = ?"
		args = append(args, filter.OrgID.String())
	}
	if filter.Search != "" {
		query += " AND name LIKE ?"
		countQuery += " AND name LIKE ?"
		args = append(args, "%"+filter.Search+"%")
	}
	if filter.Status != "" {
		query += " AND status = ?"
		countQuery += " AND status = ?"
		args = append(args, filter.Status)
	}
	
	var total int64
	r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", filter.Limit, filter.Offset)
	
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	
	var domains []*Domain
	for rows.Next() {
		var domain Domain
		var idStr, orgIDStr string
		rows.Scan(&idStr, &orgIDStr, &domain.Name, &domain.Verified, &domain.Status, &domain.CreatedAt, &domain.UpdatedAt)
		domain.ID, _ = uuid.Parse(idStr)
		domain.OrgID, _ = uuid.Parse(orgIDStr)
		domains = append(domains, &domain)
	}
	
	return domains, total, rows.Err()
}

func (r *SQLiteAdminRepository) UpdateDomain(ctx context.Context, domain *Domain) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE admin_domains SET verified = ?, verified_at = ?, mx_verified = ?, spf_verified = ?, dkim_verified = ?, dmarc_verified = ?,
		dkim_public_key = ?, catch_all = ?, catch_all_target = ?, status = ?, updated_at = ?
		WHERE id = ?`,
		domain.Verified, domain.VerifiedAt, domain.MXVerified, domain.SPFVerified, domain.DKIMVerified, domain.DMARCVerified,
		domain.DKIMPublicKey, domain.CatchAll, domain.CatchAllTarget, domain.Status, domain.UpdatedAt, domain.ID.String())
	return err
}

func (r *SQLiteAdminRepository) DeleteDomain(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM admin_domains WHERE id = ?", id.String())
	return err
}

// Account methods (simplified)

func (r *SQLiteAdminRepository) CreateAccount(ctx context.Context, account *Account) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_accounts (id, org_id, email, display_name, role, is_org_admin, quota_bytes, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account.ID.String(), account.OrgID.String(), account.Email, account.DisplayName,
		account.Role, account.IsOrgAdmin, account.QuotaBytes, account.Status, account.CreatedAt, account.UpdatedAt)
	return err
}

func (r *SQLiteAdminRepository) GetAccount(ctx context.Context, id uuid.UUID) (*Account, error) {
	var account Account
	var idStr, orgIDStr string
	
	err := r.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, display_name, role, is_org_admin, quota_bytes, quota_used_bytes, status, last_login_at, last_active_at, mfa_enabled, created_at, updated_at
		FROM admin_accounts WHERE id = ?`, id.String()).Scan(
		&idStr, &orgIDStr, &account.Email, &account.DisplayName, &account.Role, &account.IsOrgAdmin,
		&account.QuotaBytes, &account.QuotaUsedBytes, &account.Status, &account.LastLoginAt,
		&account.LastActiveAt, &account.MFAEnabled, &account.CreatedAt, &account.UpdatedAt)
	if err != nil {
		return nil, err
	}
	
	account.ID, _ = uuid.Parse(idStr)
	account.OrgID, _ = uuid.Parse(orgIDStr)
	
	return &account, nil
}

func (r *SQLiteAdminRepository) GetAccountByEmail(ctx context.Context, email string) (*Account, error) {
	var idStr string
	err := r.db.QueryRowContext(ctx, "SELECT id FROM admin_accounts WHERE email = ?", email).Scan(&idStr)
	if err != nil {
		return nil, err
	}
	id, _ := uuid.Parse(idStr)
	return r.GetAccount(ctx, id)
}

func (r *SQLiteAdminRepository) ListAccounts(ctx context.Context, filter AccountFilter) ([]*Account, int64, error) {
	query := "SELECT id, org_id, email, display_name, role, status, created_at FROM admin_accounts WHERE 1=1"
	countQuery := "SELECT COUNT(*) FROM admin_accounts WHERE 1=1"
	var args []interface{}
	
	if filter.OrgID != nil {
		query += " AND org_id = ?"
		countQuery += " AND org_id = ?"
		args = append(args, filter.OrgID.String())
	}
	if filter.Search != "" {
		query += " AND (email LIKE ? OR display_name LIKE ?)"
		countQuery += " AND (email LIKE ? OR display_name LIKE ?)"
		searchTerm := "%" + filter.Search + "%"
		args = append(args, searchTerm, searchTerm)
	}
	if filter.Role != "" {
		query += " AND role = ?"
		countQuery += " AND role = ?"
		args = append(args, filter.Role)
	}
	if filter.Status != "" {
		query += " AND status = ?"
		countQuery += " AND status = ?"
		args = append(args, filter.Status)
	}
	
	var total int64
	r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", filter.Limit, filter.Offset)
	
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	
	var accounts []*Account
	for rows.Next() {
		var account Account
		var idStr, orgIDStr string
		rows.Scan(&idStr, &orgIDStr, &account.Email, &account.DisplayName, &account.Role, &account.Status, &account.CreatedAt)
		account.ID, _ = uuid.Parse(idStr)
		account.OrgID, _ = uuid.Parse(orgIDStr)
		accounts = append(accounts, &account)
	}
	
	return accounts, total, rows.Err()
}

func (r *SQLiteAdminRepository) UpdateAccount(ctx context.Context, account *Account) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE admin_accounts SET display_name = ?, role = ?, is_org_admin = ?, quota_bytes = ?, status = ?, mfa_enabled = ?, updated_at = ?
		WHERE id = ?`,
		account.DisplayName, account.Role, account.IsOrgAdmin, account.QuotaBytes, account.Status, account.MFAEnabled, account.UpdatedAt, account.ID.String())
	return err
}

func (r *SQLiteAdminRepository) SuspendAccount(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE admin_accounts SET status = 'suspended', updated_at = ? WHERE id = ?", time.Now(), id.String())
	return err
}

func (r *SQLiteAdminRepository) DeleteAccount(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM admin_accounts WHERE id = ?", id.String())
	return err
}

// Audit log methods

func (r *SQLiteAdminRepository) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	detailsJSON, _ := json.Marshal(log.Details)
	
	var accountIDStr *string
	if log.AccountID != nil {
		s := log.AccountID.String()
		accountIDStr = &s
	}
	
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_audit_logs (id, org_id, account_id, action, resource, resource_id, actor, actor_ip, user_agent, details, success, error_msg, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.ID.String(), log.OrgID.String(), accountIDStr, log.Action, log.Resource, log.ResourceID,
		log.Actor, log.ActorIP, log.UserAgent, string(detailsJSON), log.Success, log.ErrorMsg, log.CreatedAt)
	return err
}

func (r *SQLiteAdminRepository) GetAuditLogs(ctx context.Context, filter AuditFilter) ([]*AuditLog, int64, error) {
	query := "SELECT id, org_id, account_id, action, resource, resource_id, actor, actor_ip, details, success, error_msg, created_at FROM admin_audit_logs WHERE 1=1"
	countQuery := "SELECT COUNT(*) FROM admin_audit_logs WHERE 1=1"
	var args []interface{}
	
	if filter.OrgID != nil {
		query += " AND org_id = ?"
		countQuery += " AND org_id = ?"
		args = append(args, filter.OrgID.String())
	}
	if filter.Action != "" {
		query += " AND action = ?"
		countQuery += " AND action = ?"
		args = append(args, filter.Action)
	}
	if filter.Resource != "" {
		query += " AND resource = ?"
		countQuery += " AND resource = ?"
		args = append(args, filter.Resource)
	}
	
	var total int64
	r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", filter.Limit, filter.Offset)
	
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	
	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		var idStr, orgIDStr string
		var accountIDStr *string
		var detailsJSON string
		
		rows.Scan(&idStr, &orgIDStr, &accountIDStr, &log.Action, &log.Resource, &log.ResourceID,
			&log.Actor, &log.ActorIP, &detailsJSON, &log.Success, &log.ErrorMsg, &log.CreatedAt)
		
		log.ID, _ = uuid.Parse(idStr)
		log.OrgID, _ = uuid.Parse(orgIDStr)
		if accountIDStr != nil {
			id, _ := uuid.Parse(*accountIDStr)
			log.AccountID = &id
		}
		json.Unmarshal([]byte(detailsJSON), &log.Details)
		
		logs = append(logs, &log)
	}
	
	return logs, total, rows.Err()
}

// Queue methods

func (r *SQLiteAdminRepository) GetQueuedEmails(ctx context.Context, filter QueueFilter) ([]*QueuedEmail, int64, error) {
	query := "SELECT id, org_id, from_addr, to_addrs, subject, status, attempts, max_attempts, next_retry_at, last_error, size_bytes, queued_at, processed_at FROM admin_queue WHERE 1=1"
	countQuery := "SELECT COUNT(*) FROM admin_queue WHERE 1=1"
	var args []interface{}
	
	if filter.OrgID != nil {
		query += " AND org_id = ?"
		countQuery += " AND org_id = ?"
		args = append(args, filter.OrgID.String())
	}
	if filter.Status != "" {
		query += " AND status = ?"
		countQuery += " AND status = ?"
		args = append(args, filter.Status)
	}
	
	var total int64
	r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	
	query += fmt.Sprintf(" ORDER BY queued_at DESC LIMIT %d OFFSET %d", filter.Limit, filter.Offset)
	
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	
	var emails []*QueuedEmail
	for rows.Next() {
		var email QueuedEmail
		var idStr, orgIDStr, toAddrsJSON string
		
		rows.Scan(&idStr, &orgIDStr, &email.From, &toAddrsJSON, &email.Subject, &email.Status,
			&email.Attempts, &email.MaxAttempts, &email.NextRetryAt, &email.LastError,
			&email.SizeBytes, &email.QueuedAt, &email.ProcessedAt)
		
		email.ID, _ = uuid.Parse(idStr)
		email.OrgID, _ = uuid.Parse(orgIDStr)
		json.Unmarshal([]byte(toAddrsJSON), &email.To)
		
		emails = append(emails, &email)
	}
	
	return emails, total, rows.Err()
}

func (r *SQLiteAdminRepository) RetryQueuedEmail(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "UPDATE admin_queue SET status = 'queued', next_retry_at = NULL WHERE id = ?", id.String())
	return err
}

func (r *SQLiteAdminRepository) DeleteQueuedEmail(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM admin_queue WHERE id = ?", id.String())
	return err
}

func (r *SQLiteAdminRepository) FlushQueue(ctx context.Context, filter QueueFilter) error {
	query := "DELETE FROM admin_queue WHERE 1=1"
	var args []interface{}
	
	if filter.OrgID != nil {
		query += " AND org_id = ?"
		args = append(args, filter.OrgID.String())
	}
	if filter.Status != "" {
		query += " AND status = ?"
		args = append(args, filter.Status)
	}
	
	_, err := r.db.ExecContext(ctx, query, args...)
	return err
}
