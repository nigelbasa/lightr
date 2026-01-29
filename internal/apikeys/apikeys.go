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
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// API Key Management for REST receivers and external integrations

var (
	ErrKeyNotFound    = errors.New("api key not found")
	ErrKeyExpired     = errors.New("api key expired")
	ErrKeyRevoked     = errors.New("api key revoked")
	ErrKeyRateLimited = errors.New("api key rate limited")
	ErrInvalidKey     = errors.New("invalid api key format")
	ErrPermissionDenied = errors.New("permission denied")
)

// KeyType represents the type of API key
type KeyType string

const (
	KeyTypeMaster     KeyType = "master"      // Full access
	KeyTypeAdmin      KeyType = "admin"       // Admin operations
	KeyTypeSending    KeyType = "sending"     // Send emails only
	KeyTypeReceiving  KeyType = "receiving"   // Receive webhooks only
	KeyTypeReadOnly   KeyType = "readonly"    // Read-only access
	KeyTypeWebhook    KeyType = "webhook"     // Webhook delivery
	KeyTypeIntegration KeyType = "integration" // Third-party integrations
)

// Permission represents an API permission
type Permission string

const (
	PermSendEmail       Permission = "email:send"
	PermReadEmail       Permission = "email:read"
	PermDeleteEmail     Permission = "email:delete"
	PermManageMailbox   Permission = "mailbox:manage"
	PermManageDomain    Permission = "domain:manage"
	PermManageUser      Permission = "user:manage"
	PermViewAnalytics   Permission = "analytics:view"
	PermManageWebhooks  Permission = "webhooks:manage"
	PermAdminAccess     Permission = "admin:access"
	PermSuperAdmin      Permission = "super:admin"
)

// APIKey represents an API key
type APIKey struct {
	ID            uuid.UUID         `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	
	// Key data (prefix is visible, hash is stored)
	Prefix        string            `json:"prefix"`        // First 8 chars for identification
	KeyHash       string            `json:"-"`             // SHA-256 hash of full key
	
	// Ownership
	OrganizationID *uuid.UUID       `json:"organization_id,omitempty"`
	UserID         *uuid.UUID       `json:"user_id,omitempty"`
	
	// Type and permissions
	Type          KeyType           `json:"type"`
	Permissions   []Permission      `json:"permissions"`
	
	// Restrictions
	AllowedIPs    []string          `json:"allowed_ips,omitempty"`
	AllowedDomains []string         `json:"allowed_domains,omitempty"`
	RateLimit     int               `json:"rate_limit"`      // Requests per minute
	DailyLimit    int               `json:"daily_limit"`     // Requests per day
	
	// Status
	Active        bool              `json:"active"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	LastUsedAt    *time.Time        `json:"last_used_at,omitempty"`
	LastUsedIP    string            `json:"last_used_ip,omitempty"`
	
	// Usage tracking
	UsageCount    int64             `json:"usage_count"`
	UsageToday    int64             `json:"usage_today"`
	
	// Metadata
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// APIKeyCreate holds data for creating a new key
type APIKeyCreate struct {
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Type           KeyType           `json:"type"`
	Permissions    []Permission      `json:"permissions,omitempty"`
	OrganizationID *uuid.UUID        `json:"organization_id,omitempty"`
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
	repo   APIKeyRepository
	cache  map[string]*APIKey // In-memory cache by hash
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
	return &APIKeyService{
		repo:  repo,
		cache: make(map[string]*APIKey),
	}
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
		UserID:         create.UserID,
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
			PermViewAnalytics, PermManageWebhooks, PermAdminAccess,
		}
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
	
	// Check cache first
	if key, ok := s.cache[hashStr]; ok {
		if err := s.validateKeyState(key); err != nil {
			return nil, err
		}
		return key, nil
	}
	
	// Look up in repository
	key, err := s.repo.GetByHash(ctx, hashStr)
	if err != nil {
		return nil, ErrKeyNotFound
	}
	
	// Validate state
	if err := s.validateKeyState(key); err != nil {
		return nil, err
	}
	
	// Cache for future lookups
	s.cache[hashStr] = key
	
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
	
	// Remove from cache
	delete(s.cache, key.KeyHash)
	
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
	key, err := s.repo.Get(ctx, id)
	if err != nil {
		return err
	}
	
	// Remove from cache
	delete(s.cache, key.KeyHash)
	
	return s.repo.Delete(ctx, id)
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
			go s.RecordUsage(r.Context(), key, r, wrapped.status, time.Since(start))
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

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}

// SQLite Repository Implementation

type SQLiteAPIKeyRepository struct {
	db *sql.DB
}

func NewSQLiteAPIKeyRepository(db *sql.DB) (*SQLiteAPIKeyRepository, error) {
	repo := &SQLiteAPIKeyRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
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
			user_id TEXT,
			type TEXT NOT NULL,
			permissions TEXT NOT NULL,
			allowed_ips TEXT,
			allowed_domains TEXT,
			rate_limit INTEGER DEFAULT 1000,
			daily_limit INTEGER DEFAULT 100000,
			active INTEGER DEFAULT 1,
			expires_at DATETIME,
			last_used_at DATETIME,
			last_used_ip TEXT,
			usage_count INTEGER DEFAULT 0,
			usage_today INTEGER DEFAULT 0,
			metadata TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
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
			timestamp DATETIME NOT NULL,
			FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(organization_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_key_usage_key ON api_key_usage(key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_key_usage_time ON api_key_usage(timestamp)`,
	}
	
	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
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
	
	var orgID, userID *string
	if key.OrganizationID != nil {
		s := key.OrganizationID.String()
		orgID = &s
	}
	if key.UserID != nil {
		s := key.UserID.String()
		userID = &s
	}
	
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, name, description, prefix, key_hash, organization_id, user_id,
			type, permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
			expires_at, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID.String(), key.Name, key.Description, key.Prefix, key.KeyHash,
		orgID, userID, string(key.Type), string(permsJSON), string(ipsJSON),
		string(domainsJSON), key.RateLimit, key.DailyLimit, key.Active,
		key.ExpiresAt, string(metaJSON), key.CreatedAt, key.UpdatedAt)
	
	return err
}

func (r *SQLiteAPIKeyRepository) Get(ctx context.Context, id uuid.UUID) (*APIKey, error) {
	return r.scanKey(r.db.QueryRowContext(ctx, `
		SELECT id, name, description, prefix, key_hash, organization_id, user_id, type,
			permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
			expires_at, last_used_at, last_used_ip, usage_count, usage_today, metadata,
			created_at, updated_at
		FROM api_keys WHERE id = ?`, id.String()))
}

func (r *SQLiteAPIKeyRepository) GetByHash(ctx context.Context, hash string) (*APIKey, error) {
	return r.scanKey(r.db.QueryRowContext(ctx, `
		SELECT id, name, description, prefix, key_hash, organization_id, user_id, type,
			permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
			expires_at, last_used_at, last_used_ip, usage_count, usage_today, metadata,
			created_at, updated_at
		FROM api_keys WHERE key_hash = ?`, hash))
}

func (r *SQLiteAPIKeyRepository) scanKey(row *sql.Row) (*APIKey, error) {
	var key APIKey
	var idStr string
	var orgID, userID *string
	var keyType string
	var permsJSON, ipsJSON, domainsJSON, metaJSON string
	
	err := row.Scan(&idStr, &key.Name, &key.Description, &key.Prefix, &key.KeyHash,
		&orgID, &userID, &keyType, &permsJSON, &ipsJSON, &domainsJSON,
		&key.RateLimit, &key.DailyLimit, &key.Active, &key.ExpiresAt,
		&key.LastUsedAt, &key.LastUsedIP, &key.UsageCount, &key.UsageToday,
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
	if userID != nil {
		id, _ := uuid.Parse(*userID)
		key.UserID = &id
	}
	
	json.Unmarshal([]byte(permsJSON), &key.Permissions)
	json.Unmarshal([]byte(ipsJSON), &key.AllowedIPs)
	json.Unmarshal([]byte(domainsJSON), &key.AllowedDomains)
	json.Unmarshal([]byte(metaJSON), &key.Metadata)
	
	return &key, nil
}

func (r *SQLiteAPIKeyRepository) GetByPrefix(ctx context.Context, prefix string) ([]*APIKey, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, description, prefix, key_hash, organization_id, user_id, type,
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
		var orgID, userID *string
		var keyType string
		var permsJSON, ipsJSON, domainsJSON, metaJSON string
		
		err := rows.Scan(&idStr, &key.Name, &key.Description, &key.Prefix, &key.KeyHash,
			&orgID, &userID, &keyType, &permsJSON, &ipsJSON, &domainsJSON,
			&key.RateLimit, &key.DailyLimit, &key.Active, &key.ExpiresAt,
			&key.LastUsedAt, &key.LastUsedIP, &key.UsageCount, &key.UsageToday,
			&metaJSON, &key.CreatedAt, &key.UpdatedAt)
		if err != nil {
			return nil, err
		}
		
		key.ID, _ = uuid.Parse(idStr)
		key.Type = KeyType(keyType)
		json.Unmarshal([]byte(permsJSON), &key.Permissions)
		json.Unmarshal([]byte(ipsJSON), &key.AllowedIPs)
		json.Unmarshal([]byte(domainsJSON), &key.AllowedDomains)
		json.Unmarshal([]byte(metaJSON), &key.Metadata)
		
		keys = append(keys, &key)
	}
	
	return keys, rows.Err()
}

func (r *SQLiteAPIKeyRepository) List(ctx context.Context, orgID *uuid.UUID, limit, offset int) ([]*APIKey, error) {
	var rows *sql.Rows
	var err error
	
	if orgID != nil {
		rows, err = r.db.QueryContext(ctx, `
			SELECT id, name, description, prefix, key_hash, organization_id, user_id, type,
				permissions, allowed_ips, allowed_domains, rate_limit, daily_limit, active,
				expires_at, last_used_at, last_used_ip, usage_count, usage_today, metadata,
				created_at, updated_at
			FROM api_keys WHERE organization_id = ?
			ORDER BY created_at DESC LIMIT ? OFFSET ?`, orgID.String(), limit, offset)
	} else {
		rows, err = r.db.QueryContext(ctx, `
			SELECT id, name, description, prefix, key_hash, organization_id, user_id, type,
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
		var org, user *string
		var keyType string
		var permsJSON, ipsJSON, domainsJSON, metaJSON string
		
		err := rows.Scan(&idStr, &key.Name, &key.Description, &key.Prefix, &key.KeyHash,
			&org, &user, &keyType, &permsJSON, &ipsJSON, &domainsJSON,
			&key.RateLimit, &key.DailyLimit, &key.Active, &key.ExpiresAt,
			&key.LastUsedAt, &key.LastUsedIP, &key.UsageCount, &key.UsageToday,
			&metaJSON, &key.CreatedAt, &key.UpdatedAt)
		if err != nil {
			return nil, err
		}
		
		key.ID, _ = uuid.Parse(idStr)
		key.Type = KeyType(keyType)
		json.Unmarshal([]byte(permsJSON), &key.Permissions)
		
		keys = append(keys, &key)
	}
	
	return keys, rows.Err()
}

func (r *SQLiteAPIKeyRepository) Update(ctx context.Context, key *APIKey) error {
	permsJSON, _ := json.Marshal(key.Permissions)
	ipsJSON, _ := json.Marshal(key.AllowedIPs)
	domainsJSON, _ := json.Marshal(key.AllowedDomains)
	metaJSON, _ := json.Marshal(key.Metadata)
	
	_, err := r.db.ExecContext(ctx, `
		UPDATE api_keys SET
			name = ?, description = ?, permissions = ?, allowed_ips = ?,
			allowed_domains = ?, rate_limit = ?, daily_limit = ?, active = ?,
			expires_at = ?, metadata = ?, updated_at = ?
		WHERE id = ?`,
		key.Name, key.Description, string(permsJSON), string(ipsJSON),
		string(domainsJSON), key.RateLimit, key.DailyLimit, key.Active,
		key.ExpiresAt, string(metaJSON), key.UpdatedAt, key.ID.String())
	
	return err
}

func (r *SQLiteAPIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM api_keys WHERE id = ?", id.String())
	return err
}

func (r *SQLiteAPIKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE api_keys SET last_used_at = ?, last_used_ip = ? WHERE id = ?`,
		time.Now(), ip, id.String())
	return err
}

func (r *SQLiteAPIKeyRepository) IncrementUsage(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE api_keys SET usage_count = usage_count + 1, usage_today = usage_today + 1
		WHERE id = ?`, id.String())
	return err
}

func (r *SQLiteAPIKeyRepository) ResetDailyUsage(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "UPDATE api_keys SET usage_today = 0")
	return err
}

func (r *SQLiteAPIKeyRepository) RecordUsage(ctx context.Context, record *UsageRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO api_key_usage (id, key_id, endpoint, method, status, ip, user_agent, duration_ms, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID.String(), record.KeyID.String(), record.Endpoint, record.Method,
		record.Status, record.IP, record.UserAgent, record.Duration, record.Timestamp)
	return err
}

func (r *SQLiteAPIKeyRepository) GetUsage(ctx context.Context, keyID uuid.UUID, from, to time.Time) ([]*UsageRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
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
