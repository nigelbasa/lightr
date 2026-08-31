package permissions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Permission management and sudo-like privilege escalation for sensitive operations

var (
	ErrPermissionDenied   = errors.New("permission denied")
	ErrSudoRequired       = errors.New("sudo required for this operation")
	ErrNotRoot            = errors.New("operation requires root privileges")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrSessionExpired     = errors.New("sudo session expired")
	ErrMFARequired        = errors.New("multi-factor authentication required")
	ErrOperationBlocked   = errors.New("operation blocked by policy")
)

// PrivilegeLevel represents the required privilege level
type PrivilegeLevel int

const (
	LevelUser      PrivilegeLevel = 0 // Normal user operations
	LevelOperator  PrivilegeLevel = 1 // Operator-level (view sensitive data)
	LevelAdmin     PrivilegeLevel = 2 // Admin-level (modify settings)
	LevelSuperUser PrivilegeLevel = 3 // Super admin (system changes)
	LevelRoot      PrivilegeLevel = 4 // Root-level (dangerous operations)
)

// Operation represents a privileged operation
type Operation string

const (
	// User operations (Level 0)
	OpReadEmail     Operation = "read_email"
	OpSendEmail     Operation = "send_email"
	OpManageFilters Operation = "manage_filters"

	// Operator operations (Level 1)
	OpViewLogs  Operation = "view_logs"
	OpViewStats Operation = "view_stats"
	OpViewQueue Operation = "view_queue"

	// Admin operations (Level 2)
	OpCreateUser   Operation = "create_user"
	OpDeleteUser   Operation = "delete_user"
	OpModifyUser   Operation = "modify_user"
	OpManageDomain Operation = "manage_domain"
	OpManageKeys   Operation = "manage_keys"
	OpPurgeQueue   Operation = "purge_queue"

	// Super admin operations (Level 3)
	OpModifyConfig   Operation = "modify_config"
	OpRestartService Operation = "restart_service"
	OpViewSecrets    Operation = "view_secrets"
	OpManageCluster  Operation = "manage_cluster"
	OpExportData     Operation = "export_data"

	// Root operations (Level 4)
	OpDeleteAllData   Operation = "delete_all_data"
	OpModifySystem    Operation = "modify_system"
	OpInstallPlugin   Operation = "install_plugin"
	OpDatabaseAdmin   Operation = "database_admin"
	OpRotateMasterKey Operation = "rotate_master_key"
)

// OperationConfig defines requirements for an operation
type OperationConfig struct {
	Level          PrivilegeLevel `json:"level"`
	RequiresMFA    bool           `json:"requires_mfa"`
	RequiresSudo   bool           `json:"requires_sudo"`
	AuditLog       bool           `json:"audit_log"`
	AllowRemote    bool           `json:"allow_remote"`
	Cooldown       time.Duration  `json:"cooldown"`
	MaxPerHour     int            `json:"max_per_hour"`
	RequiresReason bool           `json:"requires_reason"`
}

// Default operation configurations
var operationConfigs = map[Operation]OperationConfig{
	// User operations
	OpReadEmail:     {Level: LevelUser, AuditLog: false, AllowRemote: true},
	OpSendEmail:     {Level: LevelUser, AuditLog: false, AllowRemote: true},
	OpManageFilters: {Level: LevelUser, AuditLog: true, AllowRemote: true},

	// Operator operations
	OpViewLogs:  {Level: LevelOperator, AuditLog: true, AllowRemote: true},
	OpViewStats: {Level: LevelOperator, AuditLog: false, AllowRemote: true},
	OpViewQueue: {Level: LevelOperator, AuditLog: false, AllowRemote: true},

	// Admin operations
	OpCreateUser:   {Level: LevelAdmin, RequiresSudo: true, AuditLog: true, AllowRemote: true},
	OpDeleteUser:   {Level: LevelAdmin, RequiresSudo: true, AuditLog: true, AllowRemote: true, RequiresReason: true},
	OpModifyUser:   {Level: LevelAdmin, RequiresSudo: true, AuditLog: true, AllowRemote: true},
	OpManageDomain: {Level: LevelAdmin, RequiresSudo: true, AuditLog: true, AllowRemote: true},
	OpManageKeys:   {Level: LevelAdmin, RequiresSudo: true, RequiresMFA: true, AuditLog: true, AllowRemote: true},
	OpPurgeQueue:   {Level: LevelAdmin, RequiresSudo: true, AuditLog: true, AllowRemote: true},

	// Super admin operations
	OpModifyConfig:   {Level: LevelSuperUser, RequiresSudo: true, RequiresMFA: true, AuditLog: true, AllowRemote: false},
	OpRestartService: {Level: LevelSuperUser, RequiresSudo: true, AuditLog: true, AllowRemote: false, Cooldown: 5 * time.Minute},
	OpViewSecrets:    {Level: LevelSuperUser, RequiresSudo: true, RequiresMFA: true, AuditLog: true, AllowRemote: false},
	OpManageCluster:  {Level: LevelSuperUser, RequiresSudo: true, AuditLog: true, AllowRemote: false},
	OpExportData:     {Level: LevelSuperUser, RequiresSudo: true, RequiresMFA: true, AuditLog: true, AllowRemote: false, RequiresReason: true},

	// Root operations
	OpDeleteAllData:   {Level: LevelRoot, RequiresSudo: true, RequiresMFA: true, AuditLog: true, AllowRemote: false, RequiresReason: true, Cooldown: 1 * time.Hour, MaxPerHour: 1},
	OpModifySystem:    {Level: LevelRoot, RequiresSudo: true, RequiresMFA: true, AuditLog: true, AllowRemote: false},
	OpInstallPlugin:   {Level: LevelRoot, RequiresSudo: true, RequiresMFA: true, AuditLog: true, AllowRemote: false},
	OpDatabaseAdmin:   {Level: LevelRoot, RequiresSudo: true, RequiresMFA: true, AuditLog: true, AllowRemote: false},
	OpRotateMasterKey: {Level: LevelRoot, RequiresSudo: true, RequiresMFA: true, AuditLog: true, AllowRemote: false, RequiresReason: true, Cooldown: 24 * time.Hour},
}

// SudoSession represents an elevated privilege session
type SudoSession struct {
	ID          uuid.UUID      `json:"id"`
	UserID      uuid.UUID      `json:"user_id"`
	Level       PrivilegeLevel `json:"level"`
	MFAVerified bool           `json:"mfa_verified"`
	RemoteIP    string         `json:"remote_ip"`
	Reason      string         `json:"reason,omitempty"`

	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`

	// Operations performed in this session
	Operations []string `json:"operations"`
}

// PermissionPolicy defines permission rules
type PermissionPolicy struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`

	// Who
	UserID  *uuid.UUID `json:"user_id,omitempty"`
	RoleID  *uuid.UUID `json:"role_id,omitempty"`
	GroupID *uuid.UUID `json:"group_id,omitempty"`

	// What
	Operations []Operation `json:"operations"`
	Effect     string      `json:"effect"` // allow, deny

	// Conditions
	Conditions map[string]interface{} `json:"conditions,omitempty"`

	// Metadata
	Priority  int       `json:"priority"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditEntry records a privileged operation
type AuditEntry struct {
	ID        uuid.UUID              `json:"id"`
	UserID    uuid.UUID              `json:"user_id"`
	SessionID *uuid.UUID             `json:"session_id,omitempty"`
	Operation Operation              `json:"operation"`
	Target    string                 `json:"target,omitempty"`
	Result    string                 `json:"result"` // success, denied, error
	Reason    string                 `json:"reason,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	RemoteIP  string                 `json:"remote_ip,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// PermissionManager manages permissions and sudo sessions
type PermissionManager struct {
	repo        PermissionRepository
	sessions    map[uuid.UUID]*SudoSession
	sessionTTL  time.Duration
	mfaVerifier MFAVerifier
	logger      Logger
}

// PermissionRepository defines storage operations
type PermissionRepository interface {
	// Policies
	CreatePolicy(ctx context.Context, policy *PermissionPolicy) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*PermissionPolicy, error)
	ListPolicies(ctx context.Context, userID *uuid.UUID) ([]*PermissionPolicy, error)
	UpdatePolicy(ctx context.Context, policy *PermissionPolicy) error
	DeletePolicy(ctx context.Context, id uuid.UUID) error

	// Sudo sessions
	CreateSession(ctx context.Context, session *SudoSession) error
	GetSession(ctx context.Context, id uuid.UUID) (*SudoSession, error)
	GetActiveSession(ctx context.Context, userID uuid.UUID) (*SudoSession, error)
	UpdateSession(ctx context.Context, session *SudoSession) error
	DeleteSession(ctx context.Context, id uuid.UUID) error
	CleanExpiredSessions(ctx context.Context) error

	// Audit
	RecordAudit(ctx context.Context, entry *AuditEntry) error
	GetAuditLog(ctx context.Context, userID *uuid.UUID, from, to time.Time, limit int) ([]*AuditEntry, error)
	GetOperationHistory(ctx context.Context, op Operation, hours int) ([]*AuditEntry, error)

	// User privileges
	GetUserLevel(ctx context.Context, userID uuid.UUID) (PrivilegeLevel, error)
	SetUserLevel(ctx context.Context, userID uuid.UUID, level PrivilegeLevel) error
}

// MFAVerifier verifies multi-factor authentication
type MFAVerifier interface {
	Verify(ctx context.Context, userID uuid.UUID, code string) error
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
}

// NewPermissionManager creates a new permission manager
func NewPermissionManager(repo PermissionRepository, mfaVerifier MFAVerifier, logger Logger) *PermissionManager {
	return &PermissionManager{
		repo:        repo,
		sessions:    make(map[uuid.UUID]*SudoSession),
		sessionTTL:  15 * time.Minute,
		mfaVerifier: mfaVerifier,
		logger:      logger,
	}
}

// Sudo elevates privileges for a user
func (m *PermissionManager) Sudo(ctx context.Context, userID uuid.UUID, password string, mfaCode string, reason string, remoteIP string) (*SudoSession, error) {
	// Verify user's password (would call auth service)
	// For now, assume this is done externally

	// Get user's maximum privilege level
	level, err := m.repo.GetUserLevel(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Check if MFA is required for this level
	mfaVerified := false
	if level >= LevelAdmin && m.mfaVerifier != nil {
		if mfaCode == "" {
			return nil, ErrMFARequired
		}
		if err := m.mfaVerifier.Verify(ctx, userID, mfaCode); err != nil {
			return nil, ErrInvalidCredentials
		}
		mfaVerified = true
	}

	// Create session
	session := &SudoSession{
		ID:          uuid.New(),
		UserID:      userID,
		Level:       level,
		MFAVerified: mfaVerified,
		RemoteIP:    remoteIP,
		Reason:      reason,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(m.sessionTTL),
		LastUsedAt:  time.Now(),
		Operations:  []string{},
	}

	if err := m.repo.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	// Cache session
	m.sessions[session.ID] = session

	m.logger.Info("sudo session created", "user_id", userID, "session_id", session.ID, "level", level)

	return session, nil
}

// CheckPermission checks if an operation is allowed
func (m *PermissionManager) CheckPermission(ctx context.Context, userID uuid.UUID, op Operation, sessionID *uuid.UUID, remoteIP string) error {
	config, ok := operationConfigs[op]
	if !ok {
		return ErrPermissionDenied
	}

	// Get user's base level
	userLevel, err := m.repo.GetUserLevel(ctx, userID)
	if err != nil {
		return err
	}

	// Check if user has sufficient base privileges
	if userLevel < config.Level {
		m.recordAudit(ctx, userID, sessionID, op, "denied", "insufficient privileges", remoteIP)
		return ErrPermissionDenied
	}

	// Check remote access restriction
	if !config.AllowRemote && remoteIP != "" && !isLocalIP(remoteIP) {
		m.recordAudit(ctx, userID, sessionID, op, "denied", "remote access not allowed", remoteIP)
		return ErrOperationBlocked
	}

	// Check if sudo is required
	if config.RequiresSudo {
		session, err := m.getValidSession(ctx, userID, sessionID)
		if err != nil {
			m.recordAudit(ctx, userID, sessionID, op, "denied", "sudo required", remoteIP)
			return ErrSudoRequired
		}

		// Check session level
		if session.Level < config.Level {
			return ErrPermissionDenied
		}

		// Check MFA requirement
		if config.RequiresMFA && !session.MFAVerified {
			return ErrMFARequired
		}

		// Update session
		session.LastUsedAt = time.Now()
		session.Operations = append(session.Operations, string(op))
	}

	// Check cooldown
	if config.Cooldown > 0 {
		history, err := m.repo.GetOperationHistory(ctx, op, 24)
		if err == nil && len(history) > 0 {
			lastOp := history[0]
			if time.Since(lastOp.Timestamp) < config.Cooldown {
				remaining := config.Cooldown - time.Since(lastOp.Timestamp)
				m.recordAudit(ctx, userID, sessionID, op, "denied",
					fmt.Sprintf("cooldown: %v remaining", remaining), remoteIP)
				return fmt.Errorf("operation on cooldown for %v", remaining)
			}
		}
	}

	// Check rate limit
	if config.MaxPerHour > 0 {
		history, err := m.repo.GetOperationHistory(ctx, op, 1)
		if err == nil && len(history) >= config.MaxPerHour {
			m.recordAudit(ctx, userID, sessionID, op, "denied", "rate limit exceeded", remoteIP)
			return fmt.Errorf("rate limit exceeded: max %d per hour", config.MaxPerHour)
		}
	}

	// Check policies
	if err := m.checkPolicies(ctx, userID, op); err != nil {
		return err
	}

	return nil
}

// Execute executes a privileged operation with full checks
func (m *PermissionManager) Execute(ctx context.Context, userID uuid.UUID, op Operation, sessionID *uuid.UUID, remoteIP string, reason string, fn func() error) error {
	config := operationConfigs[op]

	// Check permission first
	if err := m.CheckPermission(ctx, userID, op, sessionID, remoteIP); err != nil {
		return err
	}

	// Check if reason is required
	if config.RequiresReason && reason == "" {
		return fmt.Errorf("reason required for operation %s", op)
	}

	// Execute the operation
	err := fn()

	// Record audit
	result := "success"
	if err != nil {
		result = "error"
	}

	if config.AuditLog {
		m.recordAudit(ctx, userID, sessionID, op, result, reason, remoteIP)
	}

	return err
}

func (m *PermissionManager) getValidSession(ctx context.Context, userID uuid.UUID, sessionID *uuid.UUID) (*SudoSession, error) {
	var session *SudoSession
	var err error

	if sessionID != nil {
		// Check specific session
		session, err = m.repo.GetSession(ctx, *sessionID)
		if err != nil {
			return nil, err
		}
		if session.UserID != userID {
			return nil, ErrPermissionDenied
		}
	} else {
		// Get active session for user
		session, err = m.repo.GetActiveSession(ctx, userID)
		if err != nil {
			return nil, ErrSessionExpired
		}
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		m.repo.DeleteSession(ctx, session.ID)
		return nil, ErrSessionExpired
	}

	return session, nil
}

func (m *PermissionManager) checkPolicies(ctx context.Context, userID uuid.UUID, op Operation) error {
	policies, err := m.repo.ListPolicies(ctx, &userID)
	if err != nil {
		return nil // No policies = allowed
	}

	// Sort by priority and check
	for _, policy := range policies {
		if !policy.Active {
			continue
		}

		// Check if policy applies to this operation
		for _, policyOp := range policy.Operations {
			if policyOp == op {
				if policy.Effect == "deny" {
					return ErrOperationBlocked
				}
			}
		}
	}

	return nil
}

func (m *PermissionManager) recordAudit(ctx context.Context, userID uuid.UUID, sessionID *uuid.UUID, op Operation, result, reason, remoteIP string) {
	entry := &AuditEntry{
		ID:        uuid.New(),
		UserID:    userID,
		SessionID: sessionID,
		Operation: op,
		Result:    result,
		Reason:    reason,
		RemoteIP:  remoteIP,
		Timestamp: time.Now(),
	}

	if err := m.repo.RecordAudit(ctx, entry); err != nil {
		m.logger.Error("failed to record audit", "error", err)
	}
}

// EndSudo ends a sudo session
func (m *PermissionManager) EndSudo(ctx context.Context, sessionID uuid.UUID) error {
	delete(m.sessions, sessionID)
	return m.repo.DeleteSession(ctx, sessionID)
}

// ExtendSession extends a sudo session
func (m *PermissionManager) ExtendSession(ctx context.Context, sessionID uuid.UUID) error {
	session, err := m.repo.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.ExpiresAt = time.Now().Add(m.sessionTTL)
	return m.repo.UpdateSession(ctx, session)
}

// GetAuditLog retrieves audit log entries
func (m *PermissionManager) GetAuditLog(ctx context.Context, userID *uuid.UUID, from, to time.Time, limit int) ([]*AuditEntry, error) {
	return m.repo.GetAuditLog(ctx, userID, from, to, limit)
}

// CreatePolicy creates a permission policy
func (m *PermissionManager) CreatePolicy(ctx context.Context, policy *PermissionPolicy) error {
	policy.ID = uuid.New()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	return m.repo.CreatePolicy(ctx, policy)
}

// Helper to check if IP is local
func isLocalIP(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == ""
}

// CheckSystemRoot checks if current process has root privileges
func CheckSystemRoot() bool {
	return checkSystemRoot()
}

// RunAsRoot runs a function with root privileges (Linux-specific)
func RunAsRoot(fn func() error) error {
	if !CheckSystemRoot() {
		return ErrNotRoot
	}
	return fn()
}

// DropPrivileges drops root privileges to a specified user
func DropPrivileges(username string) error {
	return dropPrivileges(username)
}

// SQLite Repository Implementation

type SQLitePermissionRepository struct {
	db     *sql.DB
	driver string
}

func NewSQLitePermissionRepository(db *sql.DB) (*SQLitePermissionRepository, error) {
	return NewSQLPermissionRepository(db, "sqlite")
}

func NewPostgresPermissionRepository(db *sql.DB) (*SQLitePermissionRepository, error) {
	return NewSQLPermissionRepository(db, "postgres")
}

func NewSQLPermissionRepository(db *sql.DB, driver string) (*SQLitePermissionRepository, error) {
	repo := &SQLitePermissionRepository{db: db, driver: driver}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLitePermissionRepository) bind(query string) string {
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

func (r *SQLitePermissionRepository) execContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return r.db.ExecContext(ctx, r.bind(query), args...)
}

func (r *SQLitePermissionRepository) queryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, r.bind(query), args...)
}

func (r *SQLitePermissionRepository) queryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return r.db.QueryRowContext(ctx, r.bind(query), args...)
}

func (r *SQLitePermissionRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS permission_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			user_id TEXT,
			role_id TEXT,
			group_id TEXT,
			operations TEXT NOT NULL,
			effect TEXT NOT NULL,
			conditions TEXT,
			priority INTEGER DEFAULT 0,
			active INTEGER DEFAULT 1,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS sudo_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			level INTEGER NOT NULL,
			mfa_verified INTEGER DEFAULT 0,
			remote_ip TEXT,
			reason TEXT,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			last_used_at DATETIME NOT NULL,
			operations TEXT
		)`,

		`CREATE TABLE IF NOT EXISTS permission_audit (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			session_id TEXT,
			operation TEXT NOT NULL,
			target TEXT,
			result TEXT NOT NULL,
			reason TEXT,
			details TEXT,
			remote_ip TEXT,
			user_agent TEXT,
			timestamp DATETIME NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS user_privileges (
			user_id TEXT PRIMARY KEY,
			level INTEGER NOT NULL DEFAULT 0,
			updated_at DATETIME NOT NULL
		)`,

		`CREATE INDEX IF NOT EXISTS idx_policies_user ON permission_policies(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sudo_sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sudo_sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_user ON permission_audit(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_operation ON permission_audit(operation)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON permission_audit(timestamp)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(r.bind(q)); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLitePermissionRepository) CreatePolicy(ctx context.Context, policy *PermissionPolicy) error {
	opsJSON, _ := json.Marshal(policy.Operations)
	condJSON, _ := json.Marshal(policy.Conditions)

	var userID, roleID, groupID *string
	if policy.UserID != nil {
		s := policy.UserID.String()
		userID = &s
	}
	if policy.RoleID != nil {
		s := policy.RoleID.String()
		roleID = &s
	}
	if policy.GroupID != nil {
		s := policy.GroupID.String()
		groupID = &s
	}

	_, err := r.execContext(ctx, `
		INSERT INTO permission_policies (id, name, description, user_id, role_id, group_id,
			operations, effect, conditions, priority, active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		policy.ID.String(), policy.Name, policy.Description, userID, roleID, groupID,
		string(opsJSON), policy.Effect, string(condJSON), policy.Priority, policy.Active,
		policy.CreatedAt, policy.UpdatedAt)

	return err
}

func (r *SQLitePermissionRepository) GetPolicy(ctx context.Context, id uuid.UUID) (*PermissionPolicy, error) {
	var policy PermissionPolicy
	var idStr string
	var userID, roleID, groupID *string
	var opsJSON, condJSON string

	err := r.queryRowContext(ctx, `
		SELECT id, name, description, user_id, role_id, group_id, operations, effect,
			conditions, priority, active, created_at, updated_at
		FROM permission_policies WHERE id = ?`, id.String()).Scan(
		&idStr, &policy.Name, &policy.Description, &userID, &roleID, &groupID,
		&opsJSON, &policy.Effect, &condJSON, &policy.Priority, &policy.Active,
		&policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return nil, err
	}

	policy.ID, _ = uuid.Parse(idStr)
	json.Unmarshal([]byte(opsJSON), &policy.Operations)
	json.Unmarshal([]byte(condJSON), &policy.Conditions)

	return &policy, nil
}

func (r *SQLitePermissionRepository) ListPolicies(ctx context.Context, userID *uuid.UUID) ([]*PermissionPolicy, error) {
	var rows *sql.Rows
	var err error

	if userID != nil {
		rows, err = r.queryContext(ctx, `
			SELECT id, name, description, user_id, role_id, group_id, operations, effect,
				conditions, priority, active, created_at, updated_at
			FROM permission_policies WHERE user_id = ? OR user_id IS NULL
			ORDER BY priority DESC`, userID.String())
	} else {
		rows, err = r.queryContext(ctx, `
			SELECT id, name, description, user_id, role_id, group_id, operations, effect,
				conditions, priority, active, created_at, updated_at
			FROM permission_policies ORDER BY priority DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*PermissionPolicy
	for rows.Next() {
		var policy PermissionPolicy
		var idStr string
		var uid, rid, gid *string
		var opsJSON, condJSON string

		err := rows.Scan(&idStr, &policy.Name, &policy.Description, &uid, &rid, &gid,
			&opsJSON, &policy.Effect, &condJSON, &policy.Priority, &policy.Active,
			&policy.CreatedAt, &policy.UpdatedAt)
		if err != nil {
			return nil, err
		}

		policy.ID, _ = uuid.Parse(idStr)
		json.Unmarshal([]byte(opsJSON), &policy.Operations)

		policies = append(policies, &policy)
	}

	return policies, rows.Err()
}

func (r *SQLitePermissionRepository) UpdatePolicy(ctx context.Context, policy *PermissionPolicy) error {
	opsJSON, _ := json.Marshal(policy.Operations)
	condJSON, _ := json.Marshal(policy.Conditions)

	_, err := r.execContext(ctx, `
		UPDATE permission_policies SET
			name = ?, description = ?, operations = ?, effect = ?, conditions = ?,
			priority = ?, active = ?, updated_at = ?
		WHERE id = ?`,
		policy.Name, policy.Description, string(opsJSON), policy.Effect, string(condJSON),
		policy.Priority, policy.Active, policy.UpdatedAt, policy.ID.String())

	return err
}

func (r *SQLitePermissionRepository) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := r.execContext(ctx, "DELETE FROM permission_policies WHERE id = ?", id.String())
	return err
}

func (r *SQLitePermissionRepository) CreateSession(ctx context.Context, session *SudoSession) error {
	opsJSON, _ := json.Marshal(session.Operations)

	_, err := r.execContext(ctx, `
		INSERT INTO sudo_sessions (id, user_id, level, mfa_verified, remote_ip, reason,
			created_at, expires_at, last_used_at, operations)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID.String(), session.UserID.String(), int(session.Level), session.MFAVerified,
		session.RemoteIP, session.Reason, session.CreatedAt, session.ExpiresAt,
		session.LastUsedAt, string(opsJSON))

	return err
}

func (r *SQLitePermissionRepository) GetSession(ctx context.Context, id uuid.UUID) (*SudoSession, error) {
	var session SudoSession
	var idStr, userStr string
	var level int
	var opsJSON string

	err := r.queryRowContext(ctx, `
		SELECT id, user_id, level, mfa_verified, remote_ip, reason, created_at,
			expires_at, last_used_at, operations
		FROM sudo_sessions WHERE id = ?`, id.String()).Scan(
		&idStr, &userStr, &level, &session.MFAVerified, &session.RemoteIP, &session.Reason,
		&session.CreatedAt, &session.ExpiresAt, &session.LastUsedAt, &opsJSON)
	if err != nil {
		return nil, err
	}

	session.ID, _ = uuid.Parse(idStr)
	session.UserID, _ = uuid.Parse(userStr)
	session.Level = PrivilegeLevel(level)
	json.Unmarshal([]byte(opsJSON), &session.Operations)

	return &session, nil
}

func (r *SQLitePermissionRepository) GetActiveSession(ctx context.Context, userID uuid.UUID) (*SudoSession, error) {
	rows, err := r.queryContext(ctx, `
		SELECT id, user_id, level, mfa_verified, remote_ip, reason, created_at,
			expires_at, last_used_at, operations
		FROM sudo_sessions WHERE user_id = ?
		ORDER BY created_at DESC`, userID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now().UTC()
	for rows.Next() {
		var session SudoSession
		var idStr, userStr string
		var level int
		var opsJSON string

		err := rows.Scan(
			&idStr, &userStr, &level, &session.MFAVerified, &session.RemoteIP, &session.Reason,
			&session.CreatedAt, &session.ExpiresAt, &session.LastUsedAt, &opsJSON)
		if err != nil {
			return nil, err
		}

		session.ID, _ = uuid.Parse(idStr)
		session.UserID, _ = uuid.Parse(userStr)
		session.Level = PrivilegeLevel(level)
		json.Unmarshal([]byte(opsJSON), &session.Operations)

		if session.ExpiresAt.After(now) {
			return &session, nil
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, sql.ErrNoRows
}

func (r *SQLitePermissionRepository) UpdateSession(ctx context.Context, session *SudoSession) error {
	opsJSON, _ := json.Marshal(session.Operations)

	_, err := r.execContext(ctx, `
		UPDATE sudo_sessions SET expires_at = ?, last_used_at = ?, operations = ?
		WHERE id = ?`, session.ExpiresAt, session.LastUsedAt, string(opsJSON), session.ID.String())

	return err
}

func (r *SQLitePermissionRepository) DeleteSession(ctx context.Context, id uuid.UUID) error {
	_, err := r.execContext(ctx, "DELETE FROM sudo_sessions WHERE id = ?", id.String())
	return err
}

func (r *SQLitePermissionRepository) CleanExpiredSessions(ctx context.Context) error {
	rows, err := r.queryContext(ctx, `SELECT id, expires_at FROM sudo_sessions`)
	if err != nil {
		return err
	}
	defer rows.Close()

	now := time.Now().UTC()
	var expiredIDs []string
	for rows.Next() {
		var id string
		var expiresAt time.Time
		if err := rows.Scan(&id, &expiresAt); err != nil {
			return err
		}
		if expiresAt.Before(now) {
			expiredIDs = append(expiredIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, id := range expiredIDs {
		if _, err := r.execContext(ctx, "DELETE FROM sudo_sessions WHERE id = ?", id); err != nil {
			return err
		}
	}

	return nil
}

func (r *SQLitePermissionRepository) RecordAudit(ctx context.Context, entry *AuditEntry) error {
	detailsJSON, _ := json.Marshal(entry.Details)

	var sessionID *string
	if entry.SessionID != nil {
		s := entry.SessionID.String()
		sessionID = &s
	}

	_, err := r.execContext(ctx, `
		INSERT INTO permission_audit (id, user_id, session_id, operation, target, result,
			reason, details, remote_ip, user_agent, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID.String(), entry.UserID.String(), sessionID, string(entry.Operation),
		entry.Target, entry.Result, entry.Reason, string(detailsJSON), entry.RemoteIP,
		entry.UserAgent, entry.Timestamp)

	return err
}

func (r *SQLitePermissionRepository) GetAuditLog(ctx context.Context, userID *uuid.UUID, from, to time.Time, limit int) ([]*AuditEntry, error) {
	var rows *sql.Rows
	var err error

	if userID != nil {
		rows, err = r.queryContext(ctx, `
			SELECT id, user_id, session_id, operation, target, result, reason, details,
				remote_ip, user_agent, timestamp
			FROM permission_audit WHERE user_id = ? AND timestamp BETWEEN ? AND ?
			ORDER BY timestamp DESC LIMIT ?`, userID.String(), from, to, limit)
	} else {
		rows, err = r.queryContext(ctx, `
			SELECT id, user_id, session_id, operation, target, result, reason, details,
				remote_ip, user_agent, timestamp
			FROM permission_audit WHERE timestamp BETWEEN ? AND ?
			ORDER BY timestamp DESC LIMIT ?`, from, to, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		var entry AuditEntry
		var idStr, userStr string
		var sessionID *string
		var op string
		var detailsJSON string

		err := rows.Scan(&idStr, &userStr, &sessionID, &op, &entry.Target, &entry.Result,
			&entry.Reason, &detailsJSON, &entry.RemoteIP, &entry.UserAgent, &entry.Timestamp)
		if err != nil {
			return nil, err
		}

		entry.ID, _ = uuid.Parse(idStr)
		entry.UserID, _ = uuid.Parse(userStr)
		entry.Operation = Operation(op)

		if sessionID != nil {
			id, _ := uuid.Parse(*sessionID)
			entry.SessionID = &id
		}

		json.Unmarshal([]byte(detailsJSON), &entry.Details)
		entries = append(entries, &entry)
	}

	return entries, rows.Err()
}

func (r *SQLitePermissionRepository) GetOperationHistory(ctx context.Context, op Operation, hours int) ([]*AuditEntry, error) {
	since := time.Now().Add(time.Duration(-hours) * time.Hour)

	rows, err := r.queryContext(ctx, `
		SELECT id, user_id, session_id, operation, target, result, reason, details,
			remote_ip, user_agent, timestamp
		FROM permission_audit WHERE operation = ? AND timestamp >= ? AND result = 'success'
		ORDER BY timestamp DESC`, string(op), since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		var entry AuditEntry
		var idStr, userStr string
		var sessionID *string
		var opStr string
		var detailsJSON string

		err := rows.Scan(&idStr, &userStr, &sessionID, &opStr, &entry.Target, &entry.Result,
			&entry.Reason, &detailsJSON, &entry.RemoteIP, &entry.UserAgent, &entry.Timestamp)
		if err != nil {
			return nil, err
		}

		entry.ID, _ = uuid.Parse(idStr)
		entry.UserID, _ = uuid.Parse(userStr)
		entry.Operation = Operation(opStr)

		entries = append(entries, &entry)
	}

	return entries, rows.Err()
}

func (r *SQLitePermissionRepository) GetUserLevel(ctx context.Context, userID uuid.UUID) (PrivilegeLevel, error) {
	var level int
	err := r.queryRowContext(ctx,
		"SELECT level FROM user_privileges WHERE user_id = ?", userID.String()).Scan(&level)
	if err == sql.ErrNoRows {
		return LevelUser, nil // Default level
	}
	if err != nil {
		return LevelUser, err
	}
	return PrivilegeLevel(level), nil
}

func (r *SQLitePermissionRepository) SetUserLevel(ctx context.Context, userID uuid.UUID, level PrivilegeLevel) error {
	_, err := r.execContext(ctx, `
		INSERT INTO user_privileges (user_id, level, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET level = excluded.level, updated_at = excluded.updated_at`,
		userID.String(), int(level), time.Now())
	return err
}
