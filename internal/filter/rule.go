package filter

import (
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Rule represents an email filtering rule
type Rule struct {
	ID          uuid.UUID   `json:"id"`
	OrgID       uuid.UUID   `json:"org_id"`
	AccountID   *uuid.UUID  `json:"account_id,omitempty"` // nil = org-wide rule
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Priority    int         `json:"priority"` // Lower = higher priority
	Conditions  []Condition `json:"conditions"`
	MatchType   MatchType   `json:"match_type"` // all, any
	Actions     []Action    `json:"actions"`
	IsActive    bool        `json:"is_active"`
	StopOnMatch bool        `json:"stop_on_match"` // Don't process further rules
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// MatchType defines how conditions are combined
type MatchType string

const (
	MatchAll MatchType = "all" // AND
	MatchAny MatchType = "any" // OR
)

// Condition defines a single filter condition
type Condition struct {
	Field    ConditionField    `json:"field"`
	Operator ConditionOperator `json:"operator"`
	Value    string            `json:"value"`
	Negate   bool              `json:"negate"` // NOT
}

// ConditionField is the email field to match
type ConditionField string

const (
	FieldFrom        ConditionField = "from"
	FieldTo          ConditionField = "to"
	FieldCc          ConditionField = "cc"
	FieldSubject     ConditionField = "subject"
	FieldBody        ConditionField = "body"
	FieldHeader      ConditionField = "header"
	FieldAttachment  ConditionField = "attachment"
	FieldSize        ConditionField = "size"
	FieldSpamScore   ConditionField = "spam_score"
	FieldSPFResult   ConditionField = "spf_result"
	FieldDKIMResult  ConditionField = "dkim_result"
	FieldDMARCResult ConditionField = "dmarc_result"
)

// ConditionOperator defines comparison operations
type ConditionOperator string

const (
	OpEquals      ConditionOperator = "equals"
	OpContains    ConditionOperator = "contains"
	OpStartsWith  ConditionOperator = "starts_with"
	OpEndsWith    ConditionOperator = "ends_with"
	OpMatches     ConditionOperator = "matches" // Regex
	OpGreaterThan ConditionOperator = "gt"
	OpLessThan    ConditionOperator = "lt"
	OpExists      ConditionOperator = "exists"
)

// Action defines what to do when rule matches
type Action struct {
	Type   ActionType `json:"type"`
	Params ActionParams `json:"params,omitempty"`
}

// ActionType defines available actions
type ActionType string

const (
	ActionReject      ActionType = "reject"       // Reject with error
	ActionDiscard     ActionType = "discard"      // Silently discard
	ActionQuarantine  ActionType = "quarantine"   // Hold for review
	ActionMove        ActionType = "move"         // Move to folder
	ActionLabel       ActionType = "label"        // Add label/tag
	ActionForward     ActionType = "forward"      // Forward to address
	ActionCopy        ActionType = "copy"         // Copy to address
	ActionRedirect    ActionType = "redirect"     // Redirect (no local delivery)
	ActionAddHeader   ActionType = "add_header"   // Add custom header
	ActionRemoveHeader ActionType = "remove_header"
	ActionModifySubject ActionType = "modify_subject"
	ActionSetFlag     ActionType = "set_flag"     // Set IMAP flag
	ActionNotify      ActionType = "notify"       // Send notification
	ActionWebhook     ActionType = "webhook"      // Call webhook
	ActionAutoReply   ActionType = "auto_reply"   // Send auto-reply
)

// ActionParams holds action-specific parameters
type ActionParams map[string]interface{}

// Email represents an email for filtering
type Email struct {
	From        string
	To          []string
	Cc          []string
	Subject     string
	Body        string
	HTMLBody    string
	Headers     map[string][]string
	Attachments []Attachment
	Size        int64
	SpamScore   float64
	SPFResult   string
	DKIMResult  string
	DMARCResult string
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string
	ContentType string
	Size        int64
}

// FilterResult contains the result of filtering
type FilterResult struct {
	Matched     bool
	MatchedRule *Rule
	Actions     []Action
	ShouldStop  bool
}

// Engine evaluates filtering rules
type Engine struct {
	repo Repository
}

// Repository defines rule storage
type Repository interface {
	Create(rule *Rule) error
	GetByID(id uuid.UUID) (*Rule, error)
	List(orgID uuid.UUID, accountID *uuid.UUID) ([]*Rule, error)
	Update(rule *Rule) error
	Delete(id uuid.UUID) error
}

// NewEngine creates a filter engine
func NewEngine(repo Repository) *Engine {
	return &Engine{repo: repo}
}

// Filter applies rules to an email
func (e *Engine) Filter(email *Email, orgID uuid.UUID, accountID *uuid.UUID) ([]*FilterResult, error) {
	// Get all applicable rules, sorted by priority
	rules, err := e.repo.List(orgID, accountID)
	if err != nil {
		return nil, err
	}

	var results []*FilterResult
	for _, rule := range rules {
		if !rule.IsActive {
			continue
		}

		if e.matchesRule(email, rule) {
			result := &FilterResult{
				Matched:     true,
				MatchedRule: rule,
				Actions:     rule.Actions,
				ShouldStop:  rule.StopOnMatch,
			}
			results = append(results, result)

			if rule.StopOnMatch {
				break
			}
		}
	}

	return results, nil
}

// matchesRule checks if email matches a rule
func (e *Engine) matchesRule(email *Email, rule *Rule) bool {
	if len(rule.Conditions) == 0 {
		return false
	}

	matchCount := 0
	for _, cond := range rule.Conditions {
		matches := e.matchesCondition(email, cond)
		if cond.Negate {
			matches = !matches
		}

		if matches {
			matchCount++
			if rule.MatchType == MatchAny {
				return true // OR: one match is enough
			}
		} else if rule.MatchType == MatchAll {
			return false // AND: one fail is enough
		}
	}

	// For MatchAll, all conditions must match
	return rule.MatchType == MatchAll && matchCount == len(rule.Conditions)
}

// matchesCondition evaluates a single condition
func (e *Engine) matchesCondition(email *Email, cond Condition) bool {
	var value string

	switch cond.Field {
	case FieldFrom:
		value = email.From
	case FieldTo:
		value = strings.Join(email.To, ", ")
	case FieldCc:
		value = strings.Join(email.Cc, ", ")
	case FieldSubject:
		value = email.Subject
	case FieldBody:
		value = email.Body + " " + email.HTMLBody
	case FieldHeader:
		// Value format: "Header-Name: value"
		parts := strings.SplitN(cond.Value, ":", 2)
		if len(parts) == 2 {
			headerName := strings.TrimSpace(parts[0])
			if vals, ok := email.Headers[headerName]; ok {
				value = strings.Join(vals, ", ")
				cond.Value = strings.TrimSpace(parts[1])
			}
		}
	case FieldAttachment:
		for _, att := range email.Attachments {
			if e.matchValue(att.Filename, cond.Operator, cond.Value) ||
				e.matchValue(att.ContentType, cond.Operator, cond.Value) {
				return true
			}
		}
		return false
	case FieldSize:
		return e.matchNumeric(float64(email.Size), cond.Operator, cond.Value)
	case FieldSpamScore:
		return e.matchNumeric(email.SpamScore, cond.Operator, cond.Value)
	case FieldSPFResult:
		value = email.SPFResult
	case FieldDKIMResult:
		value = email.DKIMResult
	case FieldDMARCResult:
		value = email.DMARCResult
	default:
		return false
	}

	return e.matchValue(value, cond.Operator, cond.Value)
}

func (e *Engine) matchValue(value string, op ConditionOperator, pattern string) bool {
	value = strings.ToLower(value)
	pattern = strings.ToLower(pattern)

	switch op {
	case OpEquals:
		return value == pattern
	case OpContains:
		return strings.Contains(value, pattern)
	case OpStartsWith:
		return strings.HasPrefix(value, pattern)
	case OpEndsWith:
		return strings.HasSuffix(value, pattern)
	case OpMatches:
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	case OpExists:
		return value != ""
	default:
		return false
	}
}

func (e *Engine) matchNumeric(value float64, op ConditionOperator, pattern string) bool {
	var threshold float64
	if err := json.Unmarshal([]byte(pattern), &threshold); err != nil {
		return false
	}

	switch op {
	case OpEquals:
		return value == threshold
	case OpGreaterThan:
		return value > threshold
	case OpLessThan:
		return value < threshold
	default:
		return false
	}
}

// SQLiteRepository implements Repository
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new filter repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) migrate() error {
	_, err := r.db.Exec(`
		CREATE TABLE IF NOT EXISTS filter_rules (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			account_id TEXT,
			name TEXT NOT NULL,
			description TEXT,
			priority INTEGER DEFAULT 100,
			conditions TEXT NOT NULL,
			match_type TEXT DEFAULT 'all',
			actions TEXT NOT NULL,
			is_active INTEGER DEFAULT 1,
			stop_on_match INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_filter_rules_org ON filter_rules(org_id);
		CREATE INDEX IF NOT EXISTS idx_filter_rules_account ON filter_rules(account_id);
		CREATE INDEX IF NOT EXISTS idx_filter_rules_priority ON filter_rules(priority);
	`)
	return err
}

func (r *SQLiteRepository) Create(rule *Rule) error {
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	condJSON, _ := json.Marshal(rule.Conditions)
	actJSON, _ := json.Marshal(rule.Actions)

	var accountID *string
	if rule.AccountID != nil {
		s := rule.AccountID.String()
		accountID = &s
	}

	_, err := r.db.Exec(`
		INSERT INTO filter_rules (id, org_id, account_id, name, description, priority, conditions, match_type, actions, is_active, stop_on_match, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rule.ID.String(), rule.OrgID.String(), accountID, rule.Name, rule.Description, rule.Priority, string(condJSON), rule.MatchType, string(actJSON), rule.IsActive, rule.StopOnMatch, rule.CreatedAt, rule.UpdatedAt)
	return err
}

func (r *SQLiteRepository) GetByID(id uuid.UUID) (*Rule, error) {
	row := r.db.QueryRow(`
		SELECT id, org_id, account_id, name, description, priority, conditions, match_type, actions, is_active, stop_on_match, created_at, updated_at
		FROM filter_rules WHERE id = ?
	`, id.String())
	return r.scanRule(row)
}

func (r *SQLiteRepository) List(orgID uuid.UUID, accountID *uuid.UUID) ([]*Rule, error) {
	query := `
		SELECT id, org_id, account_id, name, description, priority, conditions, match_type, actions, is_active, stop_on_match, created_at, updated_at
		FROM filter_rules WHERE org_id = ? AND (account_id IS NULL`
	args := []interface{}{orgID.String()}
	
	if accountID != nil {
		query += " OR account_id = ?"
		args = append(args, accountID.String())
	}
	query += ") ORDER BY priority ASC, created_at ASC"

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*Rule
	for rows.Next() {
		rule, err := r.scanRuleRow(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (r *SQLiteRepository) Update(rule *Rule) error {
	rule.UpdatedAt = time.Now()
	condJSON, _ := json.Marshal(rule.Conditions)
	actJSON, _ := json.Marshal(rule.Actions)

	_, err := r.db.Exec(`
		UPDATE filter_rules SET
			name = ?, description = ?, priority = ?, conditions = ?, match_type = ?,
			actions = ?, is_active = ?, stop_on_match = ?, updated_at = ?
		WHERE id = ?
	`, rule.Name, rule.Description, rule.Priority, string(condJSON), rule.MatchType, string(actJSON), rule.IsActive, rule.StopOnMatch, rule.UpdatedAt, rule.ID.String())
	return err
}

func (r *SQLiteRepository) Delete(id uuid.UUID) error {
	_, err := r.db.Exec(`DELETE FROM filter_rules WHERE id = ?`, id.String())
	return err
}

func (r *SQLiteRepository) scanRule(row *sql.Row) (*Rule, error) {
	var rule Rule
	var idStr, orgIDStr string
	var accountIDStr sql.NullString
	var condJSON, actJSON string

	err := row.Scan(&idStr, &orgIDStr, &accountIDStr, &rule.Name, &rule.Description, &rule.Priority, &condJSON, &rule.MatchType, &actJSON, &rule.IsActive, &rule.StopOnMatch, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return nil, err
	}

	rule.ID, _ = uuid.Parse(idStr)
	rule.OrgID, _ = uuid.Parse(orgIDStr)
	if accountIDStr.Valid {
		id, _ := uuid.Parse(accountIDStr.String)
		rule.AccountID = &id
	}
	_ = json.Unmarshal([]byte(condJSON), &rule.Conditions)
	_ = json.Unmarshal([]byte(actJSON), &rule.Actions)

	return &rule, nil
}

func (r *SQLiteRepository) scanRuleRow(rows *sql.Rows) (*Rule, error) {
	var rule Rule
	var idStr, orgIDStr string
	var accountIDStr sql.NullString
	var condJSON, actJSON string

	err := rows.Scan(&idStr, &orgIDStr, &accountIDStr, &rule.Name, &rule.Description, &rule.Priority, &condJSON, &rule.MatchType, &actJSON, &rule.IsActive, &rule.StopOnMatch, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return nil, err
	}

	rule.ID, _ = uuid.Parse(idStr)
	rule.OrgID, _ = uuid.Parse(orgIDStr)
	if accountIDStr.Valid {
		id, _ := uuid.Parse(accountIDStr.String)
		rule.AccountID = &id
	}
	_ = json.Unmarshal([]byte(condJSON), &rule.Conditions)
	_ = json.Unmarshal([]byte(actJSON), &rule.Actions)

	return &rule, nil
}
