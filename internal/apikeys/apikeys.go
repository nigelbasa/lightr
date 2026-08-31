package apikeys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// API Key Management for REST receivers and external integrations

var (
	ErrKeyNotFound      = errors.New("api key not found")
	ErrKeyExpired       = errors.New("api key expired")
	ErrKeyRevoked       = errors.New("api key revoked")
	ErrKeyRateLimited   = errors.New("api key rate limited")
	ErrInvalidKey       = errors.New("invalid api key format")
	ErrPermissionDenied = errors.New("permission denied")
)

// KeyType represents the type of API key
type KeyType string

const (
	KeyTypeMaster      KeyType = "master"      // Full access
	KeyTypeAdmin       KeyType = "admin"       // Admin operations
	KeyTypeOrg         KeyType = "org"         // Organization-scoped operations
	KeyTypeDomain      KeyType = "domain"      // Domain-scoped operations
	KeyTypeAccount     KeyType = "account"     // Account-scoped operations
	KeyTypeSending     KeyType = "sending"     // Send emails only
	KeyTypeReceiving   KeyType = "receiving"   // Receive webhooks only
	KeyTypeReadOnly    KeyType = "readonly"    // Read-only access
	KeyTypeWebhook     KeyType = "webhook"     // Webhook delivery
	KeyTypeIntegration KeyType = "integration" // Third-party integrations
)

// Permission represents an API permission
type Permission string

const (
	PermSendEmail      Permission = "email:send"
	PermReadEmail      Permission = "email:read"
	PermDeleteEmail    Permission = "email:delete"
	PermManageMailbox  Permission = "mailbox:manage"
	PermManageDomain   Permission = "domain:manage"
	PermManageUser     Permission = "user:manage"
	PermManageOrg      Permission = "org:manage"
	PermManageAPIKeys  Permission = "apikey:manage"
	PermViewAnalytics  Permission = "analytics:view"
	PermManageWebhooks Permission = "webhooks:manage"
	PermAdminAccess    Permission = "admin:access"
	PermSuperAdmin     Permission = "super:admin"
)

// APIKey represents an API key
type APIKey struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`

	// Key data (prefix is visible, hash is stored)
	Prefix  string `json:"prefix"` // First 8 chars for identification
	KeyHash string `json:"-"`      // SHA-256 hash of full key

	// Ownership
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
	DomainID       *uuid.UUID `json:"domain_id,omitempty"`
	AccountID      *uuid.UUID `json:"account_id,omitempty"`
	UserID         *uuid.UUID `json:"user_id,omitempty"` // legacy alias for account/user scope

	// Type and permissions
	Type        KeyType      `json:"type"`
	Permissions []Permission `json:"permissions"`

	// Restrictions
	AllowedIPs     []string `json:"allowed_ips,omitempty"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	RateLimit      int      `json:"rate_limit"`  // Requests per minute
	DailyLimit     int      `json:"daily_limit"` // Requests per day

	// Status
	Active     bool       `json:"active"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`

	// Usage tracking
	UsageCount int64 `json:"usage_count"`
	UsageToday int64 `json:"usage_today"`

	// Metadata
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// APIKeyCreate holds data for creating a new key
type APIKeyCreate struct {
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Type           KeyType           `json:"type"`
	Permissions    []Permission      `json:"permissions,omitempty"`
	OrganizationID *uuid.UUID        `json:"organization_id,omitempty"`
	DomainID       *uuid.UUID        `json:"domain_id,omitempty"`
	AccountID      *uuid.UUID        `json:"account_id,omitempty"`
	UserID         *uuid.UUID        `json:"user_id,omitempty"`
	AllowedIPs     []string          `json:"allowed_ips,omitempty"`
	AllowedDomains []string          `json:"allowed_domains,omitempty"`
	RateLimit      int               `json:"rate_limit,omitempty"`
	DailyLimit     int               `json:"daily_limit,omitempty"`
	ExpiresIn      time.Duration     `json:"expires_in,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// APIKeyResult returned when creating a key (only time full key is visible)
type APIKeyResult struct {
	Key    *APIKey `json:"key"`
	Secret string  `json:"secret"` // Full key, only shown once
}

// UsageRecord tracks API key usage
type UsageRecord struct {
	ID        uuid.UUID `json:"id"`
	KeyID     uuid.UUID `json:"key_id"`
	Endpoint  string    `json:"endpoint"`
	Method    string    `json:"method"`
	Status    int       `json:"status"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Duration  int64     `json:"duration_ms"`
	Timestamp time.Time `json:"timestamp"`
}

// APIKeyService manages API keys
type APIKeyService struct {
	repo APIKeyRepository
}

// APIKeyRepository defines storage operations
type APIKeyRepository interface {
	Create(ctx context.Context, key *APIKey) error
	Get(ctx context.Context, id uuid.UUID) (*APIKey, error)
	GetByHash(ctx context.Context, hash string) (*APIKey, error)
	GetByPrefix(ctx context.Context, prefix string) ([]*APIKey, error)
	List(ctx context.Context, orgID *uuid.UUID, limit, offset int) ([]*APIKey, error)
	Update(ctx context.Context, key *APIKey) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error
	IncrementUsage(ctx context.Context, id uuid.UUID) error
	ResetDailyUsage(ctx context.Context) error
	RecordUsage(ctx context.Context, record *UsageRecord) error
	GetUsage(ctx context.Context, keyID uuid.UUID, from, to time.Time) ([]*UsageRecord, error)
}

// NewAPIKeyService creates a new API key service
func NewAPIKeyService(repo APIKeyRepository) *APIKeyService {
	return &APIKeyService{repo: repo}
}

// GenerateKey generates a new API key
func (s *APIKeyService) GenerateKey(ctx context.Context, create *APIKeyCreate) (*APIKeyResult, error) {
	// Generate random key (32 bytes = 256 bits)
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encode as base64 with prefix
	secret := fmt.Sprintf("ltr_%s", base64.RawURLEncoding.EncodeToString(keyBytes))

	// Hash for storage
	hash := sha256.Sum256([]byte(secret))
	hashStr := hex.EncodeToString(hash[:])

	// Create key object
	key := &APIKey{
		ID:             uuid.New(),
		Name:           create.Name,
		Description:    create.Description,
		Prefix:         secret[:12], // "ltr_" + 8 chars
		KeyHash:        hashStr,
		OrganizationID: create.OrganizationID,
		DomainID:       create.DomainID,
		AccountID:      firstScopeUUID(create.AccountID, create.UserID),
		UserID:         firstScopeUUID(create.AccountID, create.UserID),
		Type:           create.Type,
		Permissions:    s.resolvePermissions(create.Type, create.Permissions),
		AllowedIPs:     create.AllowedIPs,
		AllowedDomains: create.AllowedDomains,
		RateLimit:      create.RateLimit,
		DailyLimit:     create.DailyLimit,
		Active:         true,
		Metadata:       create.Metadata,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Set defaults
	if key.RateLimit == 0 {
		key.RateLimit = 1000 // Default: 1000 requests/minute
	}
	if key.DailyLimit == 0 {
		key.DailyLimit = 100000 // Default: 100k requests/day
	}

	// Set expiration
	if create.ExpiresIn > 0 {
		exp := time.Now().Add(create.ExpiresIn)
		key.ExpiresAt = &exp
	}

	// Save to repository
	if err := s.repo.Create(ctx, key); err != nil {
		return nil, err
	}

	return &APIKeyResult{
		Key:    key,
		Secret: secret,
	}, nil
}

// resolvePermissions returns permissions based on key type
func (s *APIKeyService) resolvePermissions(keyType KeyType, custom []Permission) []Permission {
	if len(custom) > 0 {
		return custom
	}

	switch keyType {
	case KeyTypeMaster:
		return []Permission{PermSuperAdmin}
	case KeyTypeAdmin:
		return []Permission{
			PermSendEmail, PermReadEmail, PermDeleteEmail,
			PermManageMailbox, PermManageDomain, PermManageUser,
			PermManageOrg, PermManageAPIKeys,
			PermViewAnalytics, PermManageWebhooks, PermAdminAccess,
		}
	case KeyTypeOrg:
		return []Permission{
			PermManageOrg, PermManageDomain, PermManageUser,
			PermManageWebhooks, PermManageAPIKeys, PermViewAnalytics, PermAdminAccess,
		}
	case KeyTypeDomain:
		return []Permission{
			PermManageDomain, PermManageUser, PermManageMailbox,
			PermManageWebhooks, PermSendEmail, PermReadEmail,
		}
	case KeyTypeAccount:
		return []Permission{PermReadEmail, PermSendEmail, PermManageMailbox}
	case KeyTypeSending:
		return []Permission{PermSendEmail}
	case KeyTypeReceiving:
		return []Permission{PermReadEmail}
	case KeyTypeReadOnly:
		return []Permission{PermReadEmail, PermViewAnalytics}
	case KeyTypeWebhook:
		return []Permission{PermManageWebhooks}
	case KeyTypeIntegration:
		return []Permission{PermSendEmail, PermReadEmail, PermViewAnalytics}
	default:
		return []Permission{}
	}
}

// ValidateKey validates an API key and returns the key object
func (s *APIKeyService) ValidateKey(ctx context.Context, secret string) (*APIKey, error) {
	// Validate format
	if !strings.HasPrefix(secret, "ltr_") || len(secret) < 20 {
		return nil, ErrInvalidKey
	}

	// Hash the key
	hash := sha256.Sum256([]byte(secret))
	hashStr := hex.EncodeToString(hash[:])

	// Look up in repository
	key, err := s.repo.GetByHash(ctx, hashStr)
	if err != nil {
		return nil, ErrKeyNotFound
	}

	// Validate state
	if err := s.validateKeyState(key); err != nil {
		return nil, err
	}

	return key, nil
}

func (s *APIKeyService) validateKeyState(key *APIKey) error {
	if !key.Active {
		return ErrKeyRevoked
	}

	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return ErrKeyExpired
	}

	if key.DailyLimit > 0 && key.UsageToday >= int64(key.DailyLimit) {
		return ErrKeyRateLimited
	}

	return nil
}

// ValidatePermission checks if a key has a specific permission
func (s *APIKeyService) ValidatePermission(key *APIKey, required Permission) error {
	// Super admin has all permissions
	for _, p := range key.Permissions {
		if p == PermSuperAdmin || p == required {
			return nil
		}
	}
	return ErrPermissionDenied
}

// ValidateIP checks if request IP is allowed
func (s *APIKeyService) ValidateIP(key *APIKey, ip string) error {
	if len(key.AllowedIPs) == 0 {
		return nil // No IP restriction
	}

	for _, allowed := range key.AllowedIPs {
		if allowed == ip || allowed == "*" {
			return nil
		}
		// Could add CIDR matching here
	}

	return ErrPermissionDenied
}

// RecordUsage records API key usage
func (s *APIKeyService) RecordUsage(ctx context.Context, key *APIKey, r *http.Request, status int, duration time.Duration) {
	ip := getClientIP(r)

	// Update last used
	s.repo.UpdateLastUsed(ctx, key.ID, ip)
	s.repo.IncrementUsage(ctx, key.ID)

	// Record detailed usage
	record := &UsageRecord{
		ID:        uuid.New(),
		KeyID:     key.ID,
		Endpoint:  r.URL.Path,
		Method:    r.Method,
		Status:    status,
		IP:        ip,
		UserAgent: r.UserAgent(),
		Duration:  duration.Milliseconds(),
		Timestamp: time.Now(),
	}
	s.repo.RecordUsage(ctx, record)
}

// RevokeKey revokes an API key
func (s *APIKeyService) RevokeKey(ctx context.Context, id uuid.UUID) error {
	key, err := s.repo.Get(ctx, id)
	if err != nil {
		return err
	}

	key.Active = false
	key.UpdatedAt = time.Now()

	return s.repo.Update(ctx, key)
}

// RotateKey creates a new key and revokes the old one
func (s *APIKeyService) RotateKey(ctx context.Context, id uuid.UUID) (*APIKeyResult, error) {
	oldKey, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// Create new key with same settings
	result, err := s.GenerateKey(ctx, &APIKeyCreate{
		Name:           oldKey.Name + " (rotated)",
		Description:    oldKey.Description,
		Type:           oldKey.Type,
		Permissions:    oldKey.Permissions,
		OrganizationID: oldKey.OrganizationID,
		DomainID:       oldKey.DomainID,
		AccountID:      firstScopeUUID(oldKey.AccountID, oldKey.UserID),
		UserID:         oldKey.UserID,
		AllowedIPs:     oldKey.AllowedIPs,
		AllowedDomains: oldKey.AllowedDomains,
		RateLimit:      oldKey.RateLimit,
		DailyLimit:     oldKey.DailyLimit,
		Metadata:       oldKey.Metadata,
	})
	if err != nil {
		return nil, err
	}

	// Revoke old key
	if err := s.RevokeKey(ctx, id); err != nil {
		return nil, err
	}

	return result, nil
}

// List lists API keys for an organization
func (s *APIKeyService) List(ctx context.Context, orgID *uuid.UUID, limit, offset int) ([]*APIKey, error) {
	return s.repo.List(ctx, orgID, limit, offset)
}

// Delete permanently deletes an API key
func (s *APIKeyService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.repo.Delete(ctx, id)
}

func (s *APIKeyService) Get(ctx context.Context, id uuid.UUID) (*APIKey, error) {
	return s.repo.Get(ctx, id)
}

// Middleware returns HTTP middleware for API key authentication
func (s *APIKeyService) Middleware(required ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Extract API key from header
			authHeader := r.Header.Get("Authorization")
			var secret string

			if strings.HasPrefix(authHeader, "Bearer ") {
				secret = strings.TrimPrefix(authHeader, "Bearer ")
			} else if key := r.Header.Get("X-API-Key"); key != "" {
				secret = key
			} else if key := r.URL.Query().Get("api_key"); key != "" {
				secret = key
			}

			if secret == "" {
				http.Error(w, "API key required", http.StatusUnauthorized)
				return
			}

			// Validate key
			key, err := s.ValidateKey(r.Context(), secret)
			if err != nil {
				status := http.StatusUnauthorized
				if err == ErrKeyRateLimited {
					status = http.StatusTooManyRequests
				}
				http.Error(w, err.Error(), status)
				return
			}

			// Validate IP
			if err := s.ValidateIP(key, getClientIP(r)); err != nil {
				http.Error(w, "IP not allowed", http.StatusForbidden)
				return
			}

			// Validate permissions
			for _, perm := range required {
				if err := s.ValidatePermission(key, perm); err != nil {
					http.Error(w, "Permission denied", http.StatusForbidden)
					return
				}
			}

			// Add key to context
			ctx := context.WithValue(r.Context(), apiKeyContextKey, key)

			// Wrap response writer to capture status
			wrapped := &statusWriter{ResponseWriter: w, status: 200}

			// Call next handler
			next.ServeHTTP(wrapped, r.WithContext(ctx))

			// Record usage
			usageCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.RecordUsage(usageCtx, key, r, wrapped.status, time.Since(start))
		})
	}
}

type contextKey string

const apiKeyContextKey contextKey = "api_key"

// GetAPIKey extracts API key from request context
func GetAPIKey(ctx context.Context) *APIKey {
	if key, ok := ctx.Value(apiKeyContextKey).(*APIKey); ok {
		return key
	}
	return nil
}

func BootstrapKey(secret string) *APIKey {
	hash := sha256.Sum256([]byte(secret))
	hashStr := hex.EncodeToString(hash[:])
	return &APIKey{
		ID:          uuid.Nil,
		Name:        "bootstrap-admin",
		Prefix:      "bootstrap",
		KeyHash:     hashStr,
		Type:        KeyTypeAdmin,
		Permissions: []Permission{PermSuperAdmin},
		Active:      true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func getClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.Trim(strings.TrimSpace(r.RemoteAddr), "[]")
}

// SQLite Repository Implementation

type SQLiteAPIKeyRepository struct {
	db     *sql.DB
	driver string
}

func NewSQLiteAPIKeyRepository(db *sql.DB) (*SQLiteAPIKeyRepository, error) {
	return NewSQLAPIKeyRepository(db, "sqlite")
}

func NewPostgresAPIKeyRepository(db *sql.DB) (*SQLiteAPIKeyRepository, error) {
	return NewSQLAPIKeyRepository(db, "postgres")
}

func NewSQLAPIKeyRepository(db *sql.DB, driver string) (*SQLiteAPIKeyRepository, error) {
	repo := &SQLiteAPIKeyRepository{db: db, driver: driver}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteAPIKeyRepository) bind(query string) string {
	if r.driver != "postgres" {
		return query
	}

	var out strings.Builder
	index := 1
	for _, ch := range query {
		if ch == '?' {
			out.WriteString(fmt.Sprintf("$%d", index))
			index++
			continue
		}
		out.WriteRune(ch)
	}
	return out.String()
}

func (r *SQLiteAPIKeyRepository) execContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return r.db.ExecContext(ctx, r.bind(query), args...)
}

func (r *SQLiteAPIKeyRepository) queryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, r.bind(query), args...)
}

func (r *SQLiteAPIKeyRepository) queryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return r.db.QueryRowContext(ctx, r.bind(query), args...)
}

func (r *SQLiteAPIKeyRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS api_keys (
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
		)`,

		`CREATE TABLE IF NOT EXISTS api_key_usage (
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
		)`,

		`CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(organization_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_key_usage_key ON api_key_usage(key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_key_usage_time ON api_key_usage(timestamp)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(r.bind(q)); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`ALTER TABLE api_keys ADD COLUMN domain_id TEXT`,
		`ALTER TABLE api_keys ADD COLUMN account_id TEXT`,
	} {
		if _, err := r.db.Exec(r.bind(q)); err != nil && !isIgnorableAlterError(err) {
			return err
		}
	}
	for _, q := range []string{
		`CREATE INDEX IF NOT EXISTS idx_api_keys_domain ON api_keys(domain_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_account ON api_keys(account_id)`,
	} {
		if _, err := r.db.Exec(r.bind(q)); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteAPIKeyRepository) Create(ctx context.Context, key *APIKey) error {
	permsJSON, _ := json.Marshal(key.Permissions)
	ipsJSON, _ := json.Marshal(key.AllowedIPs)
	domainsJSON, _ := json.Marshal(key.AllowedDomains)
	metaJSON, _ := json.Marshal(key.Metadata)

	var orgID, domainID, accountID, userID *string
	if key.OrganizationID != nil {
		s := key.OrganizationID.String()
		orgID = &s
	}
	if key.DomainID != nil {
		s := key.DomainID.String()
		domainID = &s
	}
	if key.AccountID != nil {
		s := key.AccountID.String()
		accountID = &s
	}
	if key.UserID != nil {
		s := key.UserID.String()
		userID = &s
	}

	_, err := r.execContext(ctx, `
		INSERT INTO api_keys (id, name, description, prefix, key_hash, organization_id, domain_id, account_id, user_id,
			type, permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
			expires_at, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID.String(), key.Name, key.Description, key.Prefix, key.KeyHash,
		orgID, domainID, accountID, userID, string(key.Type), string(permsJSON), string(ipsJSON),
		string(domainsJSON), key.RateLimit, key.DailyLimit, key.Active,
		key.ExpiresAt, string(metaJSON), key.CreatedAt, key.UpdatedAt)

	return err
}

func (r *SQLiteAPIKeyRepository) Get(ctx context.Context, id uuid.UUID) (*APIKey, error) {
	return r.scanKey(r.queryRowContext(ctx, `
		SELECT id, name, description, prefix, key_hash, organization_id, user_id, type,
			domain_id, account_id,
			permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
			expires_at, last_used_at, last_used_ip, usage_count, usage_today, metadata,
			created_at, updated_at
		FROM api_keys WHERE id = ?`, id.String()))
}

func (r *SQLiteAPIKeyRepository) GetByHash(ctx context.Context, hash string) (*APIKey, error) {
	return r.scanKey(r.queryRowContext(ctx, `
		SELECT id, name, description, prefix, key_hash, organization_id, user_id, type,
			domain_id, account_id,
			permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
			expires_at, last_used_at, last_used_ip, usage_count, usage_today, metadata,
			created_at, updated_at
		FROM api_keys WHERE key_hash = ?`, hash))
}

func (r *SQLiteAPIKeyRepository) scanKey(row *sql.Row) (*APIKey, error) {
	var key APIKey
	var idStr string
	var orgID, domainID, accountID, userID *string
	var keyType string
	var permsJSON, ipsJSON, domainsJSON, metaJSON string
	var lastUsedIP sql.NullString

	err := row.Scan(&idStr, &key.Name, &key.Description, &key.Prefix, &key.KeyHash,
		&orgID, &userID, &keyType, &domainID, &accountID, &permsJSON, &ipsJSON, &domainsJSON,
		&key.RateLimit, &key.DailyLimit, &key.Active, &key.ExpiresAt,
		&key.LastUsedAt, &lastUsedIP, &key.UsageCount, &key.UsageToday,
		&metaJSON, &key.CreatedAt, &key.UpdatedAt)
	if err != nil {
		return nil, err
	}

	key.ID, _ = uuid.Parse(idStr)
	key.Type = KeyType(keyType)

	if orgID != nil {
		id, _ := uuid.Parse(*orgID)
		key.OrganizationID = &id
	}
	if domainID != nil {
		id, _ := uuid.Parse(*domainID)
		key.DomainID = &id
	}
	if accountID != nil {
		id, _ := uuid.Parse(*accountID)
		key.AccountID = &id
	}
	if userID != nil {
		id, _ := uuid.Parse(*userID)
		key.UserID = &id
	}

	json.Unmarshal([]byte(permsJSON), &key.Permissions)
	json.Unmarshal([]byte(ipsJSON), &key.AllowedIPs)
	json.Unmarshal([]byte(domainsJSON), &key.AllowedDomains)
	json.Unmarshal([]byte(metaJSON), &key.Metadata)
	if lastUsedIP.Valid {
		key.LastUsedIP = lastUsedIP.String
	}

	return &key, nil
}

func (r *SQLiteAPIKeyRepository) GetByPrefix(ctx context.Context, prefix string) ([]*APIKey, error) {
	rows, err := r.queryContext(ctx, `
		SELECT id, name, description, prefix, key_hash, organization_id, user_id, type, domain_id, account_id,
			permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
			expires_at, last_used_at, last_used_ip, usage_count, usage_today, metadata,
			created_at, updated_at
		FROM api_keys WHERE prefix LIKE ?`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		var key APIKey
		var idStr string
		var orgID, domainID, accountID, userID *string
		var keyType string
		var permsJSON, ipsJSON, domainsJSON, metaJSON string
		var lastUsedIP sql.NullString

		err := rows.Scan(&idStr, &key.Name, &key.Description, &key.Prefix, &key.KeyHash,
			&orgID, &userID, &keyType, &domainID, &accountID, &permsJSON, &ipsJSON, &domainsJSON,
			&key.RateLimit, &key.DailyLimit, &key.Active, &key.ExpiresAt,
			&key.LastUsedAt, &lastUsedIP, &key.UsageCount, &key.UsageToday,
			&metaJSON, &key.CreatedAt, &key.UpdatedAt)
		if err != nil {
			return nil, err
		}

		key.ID, _ = uuid.Parse(idStr)
		key.Type = KeyType(keyType)
		if orgID != nil {
			id, _ := uuid.Parse(*orgID)
			key.OrganizationID = &id
		}
		if domainID != nil {
			id, _ := uuid.Parse(*domainID)
			key.DomainID = &id
		}
		if accountID != nil {
			id, _ := uuid.Parse(*accountID)
			key.AccountID = &id
		}
		if userID != nil {
			id, _ := uuid.Parse(*userID)
			key.UserID = &id
		}
		json.Unmarshal([]byte(permsJSON), &key.Permissions)
		json.Unmarshal([]byte(ipsJSON), &key.AllowedIPs)
		json.Unmarshal([]byte(domainsJSON), &key.AllowedDomains)
		json.Unmarshal([]byte(metaJSON), &key.Metadata)
		if lastUsedIP.Valid {
			key.LastUsedIP = lastUsedIP.String
		}

		keys = append(keys, &key)
	}

	return keys, rows.Err()
}

func (r *SQLiteAPIKeyRepository) List(ctx context.Context, orgID *uuid.UUID, limit, offset int) ([]*APIKey, error) {
	var rows *sql.Rows
	var err error

	if orgID != nil {
		rows, err = r.queryContext(ctx, `
			SELECT id, name, description, prefix, key_hash, organization_id, user_id, type, domain_id, account_id,
				permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
				expires_at, last_used_at, last_used_ip, usage_count, usage_today, metadata,
				created_at, updated_at
			FROM api_keys WHERE organization_id = ?
			ORDER BY created_at DESC LIMIT ? OFFSET ?`, orgID.String(), limit, offset)
	} else {
		rows, err = r.queryContext(ctx, `
			SELECT id, name, description, prefix, key_hash, organization_id, user_id, type, domain_id, account_id,
				permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
				expires_at, last_used_at, last_used_ip, usage_count, usage_today, metadata,
				created_at, updated_at
			FROM api_keys ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		var key APIKey
		var idStr string
		var org, domainID, accountID, user *string
		var keyType string
		var permsJSON, ipsJSON, domainsJSON, metaJSON string
		var lastUsedIP sql.NullString

		err := rows.Scan(&idStr, &key.Name, &key.Description, &key.Prefix, &key.KeyHash,
			&org, &user, &keyType, &domainID, &accountID, &permsJSON, &ipsJSON, &domainsJSON,
			&key.RateLimit, &key.DailyLimit, &key.Active, &key.ExpiresAt,
			&key.LastUsedAt, &lastUsedIP, &key.UsageCount, &key.UsageToday,
			&metaJSON, &key.CreatedAt, &key.UpdatedAt)
		if err != nil {
			return nil, err
		}

		key.ID, _ = uuid.Parse(idStr)
		key.Type = KeyType(keyType)
		if org != nil {
			id, _ := uuid.Parse(*org)
			key.OrganizationID = &id
		}
		if user != nil {
			id, _ := uuid.Parse(*user)
			key.UserID = &id
		}
		if domainID != nil {
			id, _ := uuid.Parse(*domainID)
			key.DomainID = &id
		}
		if accountID != nil {
			id, _ := uuid.Parse(*accountID)
			key.AccountID = &id
		}
		json.Unmarshal([]byte(permsJSON), &key.Permissions)
		json.Unmarshal([]byte(ipsJSON), &key.AllowedIPs)
		json.Unmarshal([]byte(domainsJSON), &key.AllowedDomains)
		json.Unmarshal([]byte(metaJSON), &key.Metadata)
		if lastUsedIP.Valid {
			key.LastUsedIP = lastUsedIP.String
		}

		keys = append(keys, &key)
	}

	return keys, rows.Err()
}

func (r *SQLiteAPIKeyRepository) Update(ctx context.Context, key *APIKey) error {
	permsJSON, _ := json.Marshal(key.Permissions)
	ipsJSON, _ := json.Marshal(key.AllowedIPs)
	domainsJSON, _ := json.Marshal(key.AllowedDomains)
	metaJSON, _ := json.Marshal(key.Metadata)

	_, err := r.execContext(ctx, `
		UPDATE api_keys SET
			name = ?, description = ?, permissions = ?, allowed_ips = ?,
			allowed_domains = ?, rate_limit = ?, daily_limit = ?, active = ?,
			expires_at = ?, metadata = ?, organization_id = ?, domain_id = ?, account_id = ?, user_id = ?, updated_at = ?
		WHERE id = ?`,
		key.Name, key.Description, string(permsJSON), string(ipsJSON),
		string(domainsJSON), key.RateLimit, key.DailyLimit, key.Active,
		key.ExpiresAt, string(metaJSON), uuidStringPtr(key.OrganizationID), uuidStringPtr(key.DomainID), uuidStringPtr(key.AccountID), uuidStringPtr(key.UserID), key.UpdatedAt, key.ID.String())

	return err
}

func (r *SQLiteAPIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.execContext(ctx, "DELETE FROM api_keys WHERE id = ?", id.String())
	return err
}

func (r *SQLiteAPIKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := r.execContext(ctx, `
		UPDATE api_keys SET last_used_at = ?, last_used_ip = ? WHERE id = ?`,
		time.Now(), ip, id.String())
	return err
}

func (r *SQLiteAPIKeyRepository) IncrementUsage(ctx context.Context, id uuid.UUID) error {
	_, err := r.execContext(ctx, `
		UPDATE api_keys SET usage_count = usage_count + 1, usage_today = usage_today + 1
		WHERE id = ?`, id.String())
	return err
}

func (r *SQLiteAPIKeyRepository) ResetDailyUsage(ctx context.Context) error {
	_, err := r.execContext(ctx, "UPDATE api_keys SET usage_today = 0")
	return err
}

func (r *SQLiteAPIKeyRepository) RecordUsage(ctx context.Context, record *UsageRecord) error {
	_, err := r.execContext(ctx, `
		INSERT INTO api_key_usage (id, key_id, endpoint, method, status, ip, user_agent, duration_ms, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID.String(), record.KeyID.String(), record.Endpoint, record.Method,
		record.Status, record.IP, record.UserAgent, record.Duration, record.Timestamp)
	return err
}

func (r *SQLiteAPIKeyRepository) GetUsage(ctx context.Context, keyID uuid.UUID, from, to time.Time) ([]*UsageRecord, error) {
	rows, err := r.queryContext(ctx, `
		SELECT id, key_id, endpoint, method, status, ip, user_agent, duration_ms, timestamp
		FROM api_key_usage WHERE key_id = ? AND timestamp BETWEEN ? AND ?
		ORDER BY timestamp DESC`, keyID.String(), from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*UsageRecord
	for rows.Next() {
		var r UsageRecord
		var idStr, keyStr string
		err := rows.Scan(&idStr, &keyStr, &r.Endpoint, &r.Method, &r.Status,
			&r.IP, &r.UserAgent, &r.Duration, &r.Timestamp)
		if err != nil {
			return nil, err
		}
		r.ID, _ = uuid.Parse(idStr)
		r.KeyID, _ = uuid.Parse(keyStr)
		records = append(records, &r)
	}

	return records, rows.Err()
}

func uuidStringPtr(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func firstScopeUUID(values ...*uuid.UUID) *uuid.UUID {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func isIgnorableAlterError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists")
}
