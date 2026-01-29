package template

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"html/template"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Template represents an email template
type Template struct {
	ID          uuid.UUID         `json:"id"`
	OrgID       uuid.UUID         `json:"org_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Subject     string            `json:"subject"`
	HTMLBody    string            `json:"html_body"`
	TextBody    string            `json:"text_body"`
	Variables   []TemplateVar     `json:"variables"`
	Category    string            `json:"category"` // transactional, marketing, notification
	IsActive    bool              `json:"is_active"`
	Version     int               `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// TemplateVar defines a variable in a template
type TemplateVar struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     string `json:"default"`
}

// RenderedEmail is the result of rendering a template
type RenderedEmail struct {
	Subject  string
	HTMLBody string
	TextBody string
}

// Repository defines template storage operations
type Repository interface {
	Create(t *Template) error
	GetByID(id uuid.UUID) (*Template, error)
	GetByName(orgID uuid.UUID, name string) (*Template, error)
	List(orgID uuid.UUID, category string) ([]*Template, error)
	Update(t *Template) error
	Delete(id uuid.UUID) error
	CreateVersion(t *Template) error
	GetVersions(templateID uuid.UUID) ([]*Template, error)
}

// Engine renders email templates
type Engine struct {
	repo      Repository
	funcMap   template.FuncMap
	baseTempl *template.Template
}

// NewEngine creates a template engine
func NewEngine(repo Repository) *Engine {
	funcMap := template.FuncMap{
		"upper":      strings.ToUpper,
		"lower":      strings.ToLower,
		"title":      strings.Title,
		"trim":       strings.TrimSpace,
		"formatDate": formatDate,
		"formatMoney": formatMoney,
		"default":    defaultValue,
		"truncate":   truncate,
		"nl2br":      nl2br,
	}

	return &Engine{
		repo:    repo,
		funcMap: funcMap,
	}
}

// Render renders a template with the given data
func (e *Engine) Render(templateID uuid.UUID, data map[string]interface{}) (*RenderedEmail, error) {
	tmpl, err := e.repo.GetByID(templateID)
	if err != nil {
		return nil, err
	}
	return e.renderTemplate(tmpl, data)
}

// RenderByName renders a template by name
func (e *Engine) RenderByName(orgID uuid.UUID, name string, data map[string]interface{}) (*RenderedEmail, error) {
	tmpl, err := e.repo.GetByName(orgID, name)
	if err != nil {
		return nil, err
	}
	return e.renderTemplate(tmpl, data)
}

func (e *Engine) renderTemplate(tmpl *Template, data map[string]interface{}) (*RenderedEmail, error) {
	// Apply defaults for missing required variables
	for _, v := range tmpl.Variables {
		if _, ok := data[v.Name]; !ok && v.Default != "" {
			data[v.Name] = v.Default
		}
	}

	result := &RenderedEmail{}

	// Render subject
	subject, err := e.renderString(tmpl.Subject, data)
	if err != nil {
		return nil, err
	}
	result.Subject = subject

	// Render HTML body
	if tmpl.HTMLBody != "" {
		html, err := e.renderString(tmpl.HTMLBody, data)
		if err != nil {
			return nil, err
		}
		result.HTMLBody = html
	}

	// Render text body
	if tmpl.TextBody != "" {
		text, err := e.renderString(tmpl.TextBody, data)
		if err != nil {
			return nil, err
		}
		result.TextBody = text
	}

	return result, nil
}

func (e *Engine) renderString(tmplStr string, data map[string]interface{}) (string, error) {
	t, err := template.New("").Funcs(e.funcMap).Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// ValidateTemplate checks if a template is valid
func (e *Engine) ValidateTemplate(tmpl *Template) []string {
	var errors []string

	// Check subject
	if _, err := template.New("").Funcs(e.funcMap).Parse(tmpl.Subject); err != nil {
		errors = append(errors, "invalid subject template: "+err.Error())
	}

	// Check HTML body
	if tmpl.HTMLBody != "" {
		if _, err := template.New("").Funcs(e.funcMap).Parse(tmpl.HTMLBody); err != nil {
			errors = append(errors, "invalid HTML body template: "+err.Error())
		}
	}

	// Check text body
	if tmpl.TextBody != "" {
		if _, err := template.New("").Funcs(e.funcMap).Parse(tmpl.TextBody); err != nil {
			errors = append(errors, "invalid text body template: "+err.Error())
		}
	}

	return errors
}

// Template helper functions

func formatDate(t time.Time, layout string) string {
	return t.Format(layout)
}

func formatMoney(amount float64, currency string) string {
	switch currency {
	case "USD":
		return "$" + formatFloat(amount)
	case "EUR":
		return "€" + formatFloat(amount)
	case "GBP":
		return "£" + formatFloat(amount)
	default:
		return formatFloat(amount) + " " + currency
	}
}

func formatFloat(f float64) string {
	return strings.TrimRight(strings.TrimRight(
		strings.Replace(
			string(rune(int(f*100)/100)),
			".", ",", 1),
		"0"), ",")
}

func defaultValue(val, def interface{}) interface{} {
	if val == nil || val == "" {
		return def
	}
	return val
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length] + "..."
}

func nl2br(s string) template.HTML {
	return template.HTML(strings.ReplaceAll(s, "\n", "<br>"))
}

// SQLiteRepository implements Repository using SQLite
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new template repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) migrate() error {
	_, err := r.db.Exec(`
		CREATE TABLE IF NOT EXISTS email_templates (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			subject TEXT NOT NULL,
			html_body TEXT,
			text_body TEXT,
			variables TEXT,
			category TEXT DEFAULT 'transactional',
			is_active INTEGER DEFAULT 1,
			version INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(org_id, name, version)
		);
		CREATE INDEX IF NOT EXISTS idx_templates_org ON email_templates(org_id);
		CREATE INDEX IF NOT EXISTS idx_templates_category ON email_templates(category);
	`)
	return err
}

func (r *SQLiteRepository) Create(t *Template) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	t.Version = 1

	varsJSON, _ := json.Marshal(t.Variables)

	_, err := r.db.Exec(`
		INSERT INTO email_templates (id, org_id, name, description, subject, html_body, text_body, variables, category, is_active, version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, t.ID.String(), t.OrgID.String(), t.Name, t.Description, t.Subject, t.HTMLBody, t.TextBody, string(varsJSON), t.Category, t.IsActive, t.Version, t.CreatedAt, t.UpdatedAt)
	return err
}

func (r *SQLiteRepository) GetByID(id uuid.UUID) (*Template, error) {
	row := r.db.QueryRow(`
		SELECT id, org_id, name, description, subject, html_body, text_body, variables, category, is_active, version, created_at, updated_at
		FROM email_templates WHERE id = ?
	`, id.String())
	return r.scanTemplate(row)
}

func (r *SQLiteRepository) GetByName(orgID uuid.UUID, name string) (*Template, error) {
	row := r.db.QueryRow(`
		SELECT id, org_id, name, description, subject, html_body, text_body, variables, category, is_active, version, created_at, updated_at
		FROM email_templates WHERE org_id = ? AND name = ? AND is_active = 1
		ORDER BY version DESC LIMIT 1
	`, orgID.String(), name)
	return r.scanTemplate(row)
}

func (r *SQLiteRepository) List(orgID uuid.UUID, category string) ([]*Template, error) {
	query := `
		SELECT id, org_id, name, description, subject, html_body, text_body, variables, category, is_active, version, created_at, updated_at
		FROM email_templates WHERE org_id = ?
	`
	args := []interface{}{orgID.String()}
	
	if category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}
	query += " ORDER BY name, version DESC"

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*Template
	for rows.Next() {
		t, err := r.scanTemplateRow(rows)
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, nil
}

func (r *SQLiteRepository) Update(t *Template) error {
	t.UpdatedAt = time.Now()
	varsJSON, _ := json.Marshal(t.Variables)

	_, err := r.db.Exec(`
		UPDATE email_templates SET
			name = ?, description = ?, subject = ?, html_body = ?, text_body = ?,
			variables = ?, category = ?, is_active = ?, updated_at = ?
		WHERE id = ?
	`, t.Name, t.Description, t.Subject, t.HTMLBody, t.TextBody, string(varsJSON), t.Category, t.IsActive, t.UpdatedAt, t.ID.String())
	return err
}

func (r *SQLiteRepository) Delete(id uuid.UUID) error {
	_, err := r.db.Exec(`DELETE FROM email_templates WHERE id = ?`, id.String())
	return err
}

func (r *SQLiteRepository) CreateVersion(t *Template) error {
	// Get current max version
	var maxVersion int
	r.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM email_templates WHERE org_id = ? AND name = ?`,
		t.OrgID.String(), t.Name).Scan(&maxVersion)

	t.ID = uuid.New()
	t.Version = maxVersion + 1
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()

	varsJSON, _ := json.Marshal(t.Variables)

	_, err := r.db.Exec(`
		INSERT INTO email_templates (id, org_id, name, description, subject, html_body, text_body, variables, category, is_active, version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, t.ID.String(), t.OrgID.String(), t.Name, t.Description, t.Subject, t.HTMLBody, t.TextBody, string(varsJSON), t.Category, t.IsActive, t.Version, t.CreatedAt, t.UpdatedAt)
	return err
}

func (r *SQLiteRepository) GetVersions(templateID uuid.UUID) ([]*Template, error) {
	// First get org_id and name
	var orgID, name string
	err := r.db.QueryRow(`SELECT org_id, name FROM email_templates WHERE id = ?`, templateID.String()).Scan(&orgID, &name)
	if err != nil {
		return nil, err
	}

	rows, err := r.db.Query(`
		SELECT id, org_id, name, description, subject, html_body, text_body, variables, category, is_active, version, created_at, updated_at
		FROM email_templates WHERE org_id = ? AND name = ?
		ORDER BY version DESC
	`, orgID, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*Template
	for rows.Next() {
		t, err := r.scanTemplateRow(rows)
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, nil
}

func (r *SQLiteRepository) scanTemplate(row *sql.Row) (*Template, error) {
	var t Template
	var idStr, orgIDStr, varsJSON string
	var htmlBody, textBody sql.NullString

	err := row.Scan(&idStr, &orgIDStr, &t.Name, &t.Description, &t.Subject, &htmlBody, &textBody, &varsJSON, &t.Category, &t.IsActive, &t.Version, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}

	t.ID, _ = uuid.Parse(idStr)
	t.OrgID, _ = uuid.Parse(orgIDStr)
	t.HTMLBody = htmlBody.String
	t.TextBody = textBody.String
	json.Unmarshal([]byte(varsJSON), &t.Variables)

	return &t, nil
}

func (r *SQLiteRepository) scanTemplateRow(rows *sql.Rows) (*Template, error) {
	var t Template
	var idStr, orgIDStr, varsJSON string
	var htmlBody, textBody sql.NullString

	err := rows.Scan(&idStr, &orgIDStr, &t.Name, &t.Description, &t.Subject, &htmlBody, &textBody, &varsJSON, &t.Category, &t.IsActive, &t.Version, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}

	t.ID, _ = uuid.Parse(idStr)
	t.OrgID, _ = uuid.Parse(orgIDStr)
	t.HTMLBody = htmlBody.String
	t.TextBody = textBody.String
	json.Unmarshal([]byte(varsJSON), &t.Variables)

	return &t, nil
}
