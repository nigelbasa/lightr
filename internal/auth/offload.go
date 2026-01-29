package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

// AuthProvider represents the type of external auth provider
type AuthProvider string

const (
	ProviderLDAP      AuthProvider = "ldap"
	ProviderOAuth2    AuthProvider = "oauth2"
	ProviderOIDC      AuthProvider = "oidc"
	ProviderSAML      AuthProvider = "saml"
	ProviderWebhook   AuthProvider = "webhook"
	ProviderRadius    AuthProvider = "radius"
	ProviderKerberos  AuthProvider = "kerberos"
	ProviderDatabase  AuthProvider = "database"
)

// OffloadResult contains the result of an offloaded authentication
type OffloadResult struct {
	Success       bool              `json:"success"`
	UserID        string            `json:"user_id,omitempty"`
	Email         string            `json:"email"`
	DisplayName   string            `json:"display_name,omitempty"`
	Groups        []string          `json:"groups,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	RefreshToken  string            `json:"refresh_token,omitempty"`
	AccessToken   string            `json:"access_token,omitempty"`
	Error         string            `json:"error,omitempty"`
	ErrorCode     string            `json:"error_code,omitempty"`
	ProviderData  json.RawMessage   `json:"provider_data,omitempty"`
}

// ProviderConfig holds configuration for an auth provider
type ProviderConfig struct {
	ID          uuid.UUID        `json:"id"`
	OrgID       uuid.UUID        `json:"org_id"`
	Name        string           `json:"name"`
	Provider    AuthProvider     `json:"provider"`
	Enabled     bool             `json:"enabled"`
	Priority    int              `json:"priority"`      // Lower = higher priority
	Config      json.RawMessage  `json:"config"`        // Provider-specific config
	Domains     []string         `json:"domains"`       // Domains this provider handles
	Default     bool             `json:"default"`       // Default for org
	AutoProvision bool           `json:"auto_provision"` // Create accounts on first auth
	SyncGroups  bool             `json:"sync_groups"`   // Sync group memberships
	SyncProfile bool             `json:"sync_profile"`  // Sync profile data
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// LDAPConfig holds LDAP-specific configuration
type LDAPConfig struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	UseTLS         bool     `json:"use_tls"`
	StartTLS       bool     `json:"start_tls"`
	SkipVerify     bool     `json:"skip_verify"`
	CACertFile     string   `json:"ca_cert_file,omitempty"`
	BindDN         string   `json:"bind_dn"`
	BindPassword   string   `json:"bind_password"`
	BaseDN         string   `json:"base_dn"`
	UserFilter     string   `json:"user_filter"`      // e.g., "(uid=%s)" or "(sAMAccountName=%s)"
	GroupFilter    string   `json:"group_filter"`     // e.g., "(member=%s)"
	GroupBaseDN    string   `json:"group_base_dn"`
	EmailAttr      string   `json:"email_attr"`       // e.g., "mail"
	DisplayNameAttr string  `json:"display_name_attr"` // e.g., "displayName"
	GroupAttr      string   `json:"group_attr"`       // e.g., "memberOf"
	Timeout        int      `json:"timeout_seconds"`
}

// OAuth2Config holds OAuth2/OIDC-specific configuration
type OAuth2Config struct {
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	AuthURL        string   `json:"auth_url"`
	TokenURL       string   `json:"token_url"`
	UserInfoURL    string   `json:"userinfo_url"`
	Scopes         []string `json:"scopes"`
	RedirectURL    string   `json:"redirect_url"`
	
	// OIDC specific
	Issuer         string   `json:"issuer,omitempty"`
	JWKSURL        string   `json:"jwks_url,omitempty"`
	
	// Field mappings
	EmailField     string   `json:"email_field"`       // e.g., "email"
	NameField      string   `json:"name_field"`        // e.g., "name"
	GroupsField    string   `json:"groups_field"`      // e.g., "groups"
	
	// Hosted domain restriction (Google)
	HostedDomain   string   `json:"hosted_domain,omitempty"`
}

// SAMLConfig holds SAML-specific configuration
type SAMLConfig struct {
	EntityID         string `json:"entity_id"`
	SSOURL           string `json:"sso_url"`
	SLOURL           string `json:"slo_url,omitempty"`
	Certificate      string `json:"certificate"`       // IdP certificate
	PrivateKey       string `json:"private_key"`       // SP private key
	SPCertificate    string `json:"sp_certificate"`    // SP certificate
	ACSPath          string `json:"acs_path"`          // Assertion Consumer Service path
	EmailAttr        string `json:"email_attr"`
	DisplayNameAttr  string `json:"display_name_attr"`
	GroupsAttr       string `json:"groups_attr"`
	SignRequests     bool   `json:"sign_requests"`
	WantAssertionsSigned bool `json:"want_assertions_signed"`
}

// WebhookConfig holds webhook-specific configuration
type WebhookConfig struct {
	URL            string            `json:"url"`
	Method         string            `json:"method"`           // POST, GET
	Headers        map[string]string `json:"headers"`
	AuthHeader     string            `json:"auth_header"`      // e.g., "Authorization"
	AuthValue      string            `json:"auth_value"`       // e.g., "Bearer xxx"
	TimeoutSeconds int               `json:"timeout_seconds"`
	RetryCount     int               `json:"retry_count"`
	TLSSkipVerify  bool              `json:"tls_skip_verify"`
	
	// Request format
	RequestFormat  string            `json:"request_format"`   // "json", "form"
	UsernameField  string            `json:"username_field"`   // Field name for username
	PasswordField  string            `json:"password_field"`   // Field name for password
	
	// Response parsing
	SuccessField   string            `json:"success_field"`    // JSON path to success bool
	EmailField     string            `json:"email_field"`
	NameField      string            `json:"name_field"`
	GroupsField    string            `json:"groups_field"`
	ErrorField     string            `json:"error_field"`
}

// Offloader is the main auth offloading interface
type Offloader interface {
	Authenticate(ctx context.Context, username, password string) (*OffloadResult, error)
	ValidateToken(ctx context.Context, token string) (*OffloadResult, error)
	RefreshToken(ctx context.Context, refreshToken string) (*OffloadResult, error)
	GetProviderType() AuthProvider
	Close() error
}

// OffloadManager manages multiple auth providers
type OffloadManager struct {
	mu        sync.RWMutex
	providers map[uuid.UUID]Offloader
	configs   map[uuid.UUID]*ProviderConfig
	repo      ProviderRepository
	logger    Logger
}

// Logger interface for auth logging
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// ProviderRepository stores provider configurations
type ProviderRepository interface {
	GetProviderConfig(ctx context.Context, id uuid.UUID) (*ProviderConfig, error)
	GetProvidersByOrg(ctx context.Context, orgID uuid.UUID) ([]*ProviderConfig, error)
	GetProviderForDomain(ctx context.Context, orgID uuid.UUID, domain string) (*ProviderConfig, error)
	SaveProviderConfig(ctx context.Context, config *ProviderConfig) error
	DeleteProviderConfig(ctx context.Context, id uuid.UUID) error
	GetDefaultProvider(ctx context.Context, orgID uuid.UUID) (*ProviderConfig, error)
}

// NewOffloadManager creates a new offload manager
func NewOffloadManager(repo ProviderRepository, logger Logger) *OffloadManager {
	return &OffloadManager{
		providers: make(map[uuid.UUID]Offloader),
		configs:   make(map[uuid.UUID]*ProviderConfig),
		repo:      repo,
		logger:    logger,
	}
}

// RegisterProvider registers and initializes a provider
func (m *OffloadManager) RegisterProvider(ctx context.Context, config *ProviderConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Close existing provider if any
	if existing, ok := m.providers[config.ID]; ok {
		existing.Close()
	}

	// Create provider based on type
	var provider Offloader
	var err error

	switch config.Provider {
	case ProviderLDAP:
		provider, err = NewLDAPOffloader(config)
	case ProviderOAuth2, ProviderOIDC:
		provider, err = NewOAuth2Offloader(config)
	case ProviderSAML:
		provider, err = NewSAMLOffloader(config)
	case ProviderWebhook:
		provider, err = NewWebhookOffloader(config)
	default:
		return fmt.Errorf("unsupported provider type: %s", config.Provider)
	}

	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	m.providers[config.ID] = provider
	m.configs[config.ID] = config

	// Save to repository
	if err := m.repo.SaveProviderConfig(ctx, config); err != nil {
		m.logger.Error("failed to save provider config", "error", err)
	}

	return nil
}

// Authenticate attempts authentication against configured providers
func (m *OffloadManager) Authenticate(ctx context.Context, orgID uuid.UUID, username, password string) (*OffloadResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Extract domain from username if email
	domain := extractAuthDomain(username)

	// Try domain-specific provider first
	if domain != "" {
		config, err := m.repo.GetProviderForDomain(ctx, orgID, domain)
		if err == nil && config != nil && config.Enabled {
			if provider, ok := m.providers[config.ID]; ok {
				result, err := provider.Authenticate(ctx, username, password)
				if err == nil && result.Success {
					m.logger.Info("auth succeeded via domain provider", "provider", config.Name, "user", username)
					return result, nil
				}
				m.logger.Debug("domain provider auth failed", "provider", config.Name, "error", err)
			}
		}
	}

	// Get all providers for org, sorted by priority
	configs, err := m.repo.GetProvidersByOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get providers: %w", err)
	}

	var lastErr error
	for _, config := range configs {
		if !config.Enabled {
			continue
		}

		provider, ok := m.providers[config.ID]
		if !ok {
			continue
		}

		result, err := provider.Authenticate(ctx, username, password)
		if err != nil {
			lastErr = err
			m.logger.Debug("provider auth failed", "provider", config.Name, "error", err)
			continue
		}

		if result.Success {
			m.logger.Info("auth succeeded", "provider", config.Name, "user", username)
			return result, nil
		}

		lastErr = errors.New(result.Error)
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("no providers available")
}

// ProvisionAccount creates or updates a local account from auth result
func (m *OffloadManager) ProvisionAccount(ctx context.Context, orgID uuid.UUID, result *OffloadResult, accountRepo domain.AccountRepository) (*domain.Account, error) {
	// Check if account exists
	existing, err := accountRepo.GetAccountByEmail(result.Email)
	if err == nil && existing != nil {
		// Update existing account
		existing.DisplayName = result.DisplayName
		existing.UpdatedAt = time.Now()
		// Sync groups if enabled
		// accountRepo.UpdateAccount(existing)
		return existing, nil
	}

	// Create new account
	account := &domain.Account{
		ID:           uuid.New(),
		OrgID:        orgID,
		Email:        result.Email,
		DisplayName:  result.DisplayName,
		AuthMode:     domain.AuthModeOffloaded,
		Status:       "active",
		StorageQuota: 1024 * 1024 * 1024, // 1GB default
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := accountRepo.CreateAccount(account); err != nil {
		return nil, fmt.Errorf("failed to provision account: %w", err)
	}

	m.logger.Info("provisioned new account", "email", result.Email)
	return account, nil
}

// Close shuts down all providers
func (m *OffloadManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, provider := range m.providers {
		if err := provider.Close(); err != nil {
			m.logger.Error("failed to close provider", "id", id, "error", err)
		}
	}

	m.providers = make(map[uuid.UUID]Offloader)
	m.configs = make(map[uuid.UUID]*ProviderConfig)

	return nil
}

// WebhookOffloader implements Offloader for webhook-based auth
type WebhookOffloader struct {
	config     *ProviderConfig
	webhookCfg *WebhookConfig
	client     *http.Client
}

// NewWebhookOffloader creates a new webhook offloader
func NewWebhookOffloader(config *ProviderConfig) (*WebhookOffloader, error) {
	var webhookCfg WebhookConfig
	if err := json.Unmarshal(config.Config, &webhookCfg); err != nil {
		return nil, fmt.Errorf("invalid webhook config: %w", err)
	}

	// Set defaults
	if webhookCfg.Method == "" {
		webhookCfg.Method = "POST"
	}
	if webhookCfg.TimeoutSeconds == 0 {
		webhookCfg.TimeoutSeconds = 10
	}
	if webhookCfg.RequestFormat == "" {
		webhookCfg.RequestFormat = "json"
	}
	if webhookCfg.UsernameField == "" {
		webhookCfg.UsernameField = "username"
	}
	if webhookCfg.PasswordField == "" {
		webhookCfg.PasswordField = "password"
	}
	if webhookCfg.SuccessField == "" {
		webhookCfg.SuccessField = "success"
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: webhookCfg.TLSSkipVerify,
		},
	}

	client := &http.Client{
		Timeout:   time.Duration(webhookCfg.TimeoutSeconds) * time.Second,
		Transport: transport,
	}

	return &WebhookOffloader{
		config:     config,
		webhookCfg: &webhookCfg,
		client:     client,
	}, nil
}

func (w *WebhookOffloader) Authenticate(ctx context.Context, username, password string) (*OffloadResult, error) {
	var body io.Reader
	var contentType string

	switch w.webhookCfg.RequestFormat {
	case "json":
		data := map[string]string{
			w.webhookCfg.UsernameField: username,
			w.webhookCfg.PasswordField: password,
		}
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(jsonData)
		contentType = "application/json"

	case "form":
		formData := url.Values{}
		formData.Set(w.webhookCfg.UsernameField, username)
		formData.Set(w.webhookCfg.PasswordField, password)
		body = strings.NewReader(formData.Encode())
		contentType = "application/x-www-form-urlencoded"

	default:
		return nil, fmt.Errorf("unsupported request format: %s", w.webhookCfg.RequestFormat)
	}

	req, err := http.NewRequestWithContext(ctx, w.webhookCfg.Method, w.webhookCfg.URL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)

	// Add custom headers
	for k, v := range w.webhookCfg.Headers {
		req.Header.Set(k, v)
	}

	// Add auth header if configured
	if w.webhookCfg.AuthHeader != "" && w.webhookCfg.AuthValue != "" {
		req.Header.Set(w.webhookCfg.AuthHeader, w.webhookCfg.AuthValue)
	}

	// Execute with retry
	var resp *http.Response
	var lastErr error
	maxRetries := w.webhookCfg.RetryCount
	if maxRetries == 0 {
		maxRetries = 1
	}

	for i := 0; i < maxRetries; i++ {
		resp, err = w.client.Do(req)
		if err == nil {
			break
		}
		lastErr = err
		time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
	}

	if resp == nil {
		return nil, fmt.Errorf("webhook request failed after %d attempts: %w", maxRetries, lastErr)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	result := &OffloadResult{
		ProviderData: respBody,
	}

	// Check success
	if success, ok := getNestedValue(respData, w.webhookCfg.SuccessField).(bool); ok {
		result.Success = success
	} else if resp.StatusCode == http.StatusOK {
		result.Success = true
	}

	// Extract fields
	if email, ok := getNestedValue(respData, w.webhookCfg.EmailField).(string); ok {
		result.Email = email
	} else {
		result.Email = username // Fallback to username
	}

	if name, ok := getNestedValue(respData, w.webhookCfg.NameField).(string); ok {
		result.DisplayName = name
	}

	if groups, ok := getNestedValue(respData, w.webhookCfg.GroupsField).([]interface{}); ok {
		for _, g := range groups {
			if gs, ok := g.(string); ok {
				result.Groups = append(result.Groups, gs)
			}
		}
	}

	if errMsg, ok := getNestedValue(respData, w.webhookCfg.ErrorField).(string); ok {
		result.Error = errMsg
	}

	return result, nil
}

func (w *WebhookOffloader) ValidateToken(ctx context.Context, token string) (*OffloadResult, error) {
	return nil, errors.New("token validation not supported for webhook provider")
}

func (w *WebhookOffloader) RefreshToken(ctx context.Context, refreshToken string) (*OffloadResult, error) {
	return nil, errors.New("token refresh not supported for webhook provider")
}

func (w *WebhookOffloader) GetProviderType() AuthProvider {
	return ProviderWebhook
}

func (w *WebhookOffloader) Close() error {
	return nil
}

// Helper functions

func extractAuthDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

func getNestedValue(data map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	var current interface{} = data

	for _, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			current = m[part]
		} else {
			return nil
		}
	}

	return current
}

// SQLiteProviderRepository implements ProviderRepository
type SQLiteProviderRepository struct {
	db *sql.DB
}

// NewSQLiteProviderRepository creates a new repository
func NewSQLiteProviderRepository(db *sql.DB) (*SQLiteProviderRepository, error) {
	repo := &SQLiteProviderRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteProviderRepository) migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS auth_providers (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		name TEXT NOT NULL,
		provider TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		priority INTEGER DEFAULT 100,
		config TEXT NOT NULL,
		domains TEXT,
		is_default INTEGER DEFAULT 0,
		auto_provision INTEGER DEFAULT 0,
		sync_groups INTEGER DEFAULT 0,
		sync_profile INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(org_id, name)
	);
	CREATE INDEX IF NOT EXISTS idx_auth_providers_org ON auth_providers(org_id);
	CREATE INDEX IF NOT EXISTS idx_auth_providers_org_default ON auth_providers(org_id, is_default);
	`
	_, err := r.db.Exec(query)
	return err
}

func (r *SQLiteProviderRepository) GetProviderConfig(ctx context.Context, id uuid.UUID) (*ProviderConfig, error) {
	query := `
	SELECT id, org_id, name, provider, enabled, priority, config, domains, is_default, 
	       auto_provision, sync_groups, sync_profile, created_at, updated_at
	FROM auth_providers WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanConfig(row)
}

func (r *SQLiteProviderRepository) GetProvidersByOrg(ctx context.Context, orgID uuid.UUID) ([]*ProviderConfig, error) {
	query := `
	SELECT id, org_id, name, provider, enabled, priority, config, domains, is_default,
	       auto_provision, sync_groups, sync_profile, created_at, updated_at
	FROM auth_providers WHERE org_id = ? ORDER BY priority ASC
	`
	rows, err := r.db.QueryContext(ctx, query, orgID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []*ProviderConfig
	for rows.Next() {
		config, err := r.scanConfigRow(rows)
		if err != nil {
			return nil, err
		}
		configs = append(configs, config)
	}
	return configs, rows.Err()
}

func (r *SQLiteProviderRepository) GetProviderForDomain(ctx context.Context, orgID uuid.UUID, domain string) (*ProviderConfig, error) {
	query := `
	SELECT id, org_id, name, provider, enabled, priority, config, domains, is_default,
	       auto_provision, sync_groups, sync_profile, created_at, updated_at
	FROM auth_providers 
	WHERE org_id = ? AND enabled = 1 AND domains LIKE ?
	ORDER BY priority ASC LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, orgID.String(), "%"+domain+"%")
	return r.scanConfig(row)
}

func (r *SQLiteProviderRepository) GetDefaultProvider(ctx context.Context, orgID uuid.UUID) (*ProviderConfig, error) {
	query := `
	SELECT id, org_id, name, provider, enabled, priority, config, domains, is_default,
	       auto_provision, sync_groups, sync_profile, created_at, updated_at
	FROM auth_providers WHERE org_id = ? AND is_default = 1 AND enabled = 1
	`
	row := r.db.QueryRowContext(ctx, query, orgID.String())
	return r.scanConfig(row)
}

func (r *SQLiteProviderRepository) SaveProviderConfig(ctx context.Context, config *ProviderConfig) error {
	domainsJSON, _ := json.Marshal(config.Domains)
	
	query := `
	INSERT INTO auth_providers (id, org_id, name, provider, enabled, priority, config, domains, 
	                            is_default, auto_provision, sync_groups, sync_profile, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		name = excluded.name,
		provider = excluded.provider,
		enabled = excluded.enabled,
		priority = excluded.priority,
		config = excluded.config,
		domains = excluded.domains,
		is_default = excluded.is_default,
		auto_provision = excluded.auto_provision,
		sync_groups = excluded.sync_groups,
		sync_profile = excluded.sync_profile,
		updated_at = excluded.updated_at
	`
	_, err := r.db.ExecContext(ctx, query,
		config.ID.String(), config.OrgID.String(), config.Name, config.Provider,
		config.Enabled, config.Priority, config.Config, string(domainsJSON),
		config.Default, config.AutoProvision, config.SyncGroups, config.SyncProfile,
		config.CreatedAt, time.Now())
	return err
}

func (r *SQLiteProviderRepository) DeleteProviderConfig(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM auth_providers WHERE id = ?", id.String())
	return err
}

func (r *SQLiteProviderRepository) scanConfig(row *sql.Row) (*ProviderConfig, error) {
	var config ProviderConfig
	var idStr, orgIDStr string
	var domainsJSON string
	
	err := row.Scan(&idStr, &orgIDStr, &config.Name, &config.Provider, &config.Enabled,
		&config.Priority, &config.Config, &domainsJSON, &config.Default,
		&config.AutoProvision, &config.SyncGroups, &config.SyncProfile,
		&config.CreatedAt, &config.UpdatedAt)
	if err != nil {
		return nil, err
	}
	
	config.ID, _ = uuid.Parse(idStr)
	config.OrgID, _ = uuid.Parse(orgIDStr)
	_ = json.Unmarshal([]byte(domainsJSON), &config.Domains)
	
	return &config, nil
}

func (r *SQLiteProviderRepository) scanConfigRow(rows *sql.Rows) (*ProviderConfig, error) {
	var config ProviderConfig
	var idStr, orgIDStr string
	var domainsJSON string
	
	err := rows.Scan(&idStr, &orgIDStr, &config.Name, &config.Provider, &config.Enabled,
		&config.Priority, &config.Config, &domainsJSON, &config.Default,
		&config.AutoProvision, &config.SyncGroups, &config.SyncProfile,
		&config.CreatedAt, &config.UpdatedAt)
	if err != nil {
		return nil, err
	}
	
	config.ID, _ = uuid.Parse(idStr)
	config.OrgID, _ = uuid.Parse(orgIDStr)
	_ = json.Unmarshal([]byte(domainsJSON), &config.Domains)
	
	return &config, nil
}
