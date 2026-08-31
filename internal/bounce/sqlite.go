package bounce

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SQLiteRepository implements Repository using SQLite
type SQLiteRepository struct {
	db     *sql.DB
	driver string
}

// NewSQLiteRepository creates a new bounce repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	return NewSQLRepository(db, "sqlite")
}

func NewPostgresRepository(db *sql.DB) (*SQLiteRepository, error) {
	return NewSQLRepository(db, "postgres")
}

func NewSQLRepository(db *sql.DB, driver string) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db, driver: driver}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) bind(query string) string {
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

func (r *SQLiteRepository) migrate() error {
	_, err := r.db.Exec(r.bind(`
		CREATE TABLE IF NOT EXISTS bounces (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			domain_id TEXT NOT NULL,
			original_msg_id TEXT,
			recipient_email TEXT NOT NULL,
			bounce_type TEXT NOT NULL,
			diagnostic_code TEXT,
			remote_mta TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		
		CREATE INDEX IF NOT EXISTS idx_bounces_recipient ON bounces(recipient_email);
		CREATE INDEX IF NOT EXISTS idx_bounces_org ON bounces(org_id);
		CREATE INDEX IF NOT EXISTS idx_bounces_type ON bounces(bounce_type);
		CREATE INDEX IF NOT EXISTS idx_bounces_created ON bounces(created_at);

		-- Suppression list for hard bounces
		CREATE TABLE IF NOT EXISTS suppression_list (
			email TEXT PRIMARY KEY,
			reason TEXT NOT NULL,
			org_id TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`))
	return err
}

func (r *SQLiteRepository) Create(record *BounceRecord) error {
	_, err := r.db.Exec(r.bind(`
		INSERT INTO bounces (id, org_id, domain_id, original_msg_id, recipient_email, bounce_type, diagnostic_code, remote_mta, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`),
		record.ID.String(),
		record.OrgID.String(),
		record.DomainID.String(),
		record.OriginalMsgID,
		record.RecipientEmail,
		string(record.BounceType),
		record.DiagnosticCode,
		record.RemoteMTA,
		record.CreatedAt,
	)
	if err != nil {
		return err
	}

	// Auto-suppress on hard bounce
	if record.BounceType == BounceTypeHard {
		query := `
			INSERT INTO suppression_list (email, reason, org_id, created_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(email) DO NOTHING
		`
		_, _ = r.db.Exec(r.bind(query), record.RecipientEmail, "hard_bounce", record.OrgID.String(), time.Now())
	}

	return nil
}

func (r *SQLiteRepository) GetByRecipient(email string) ([]*BounceRecord, error) {
	rows, err := r.db.Query(r.bind(`
		SELECT id, org_id, domain_id, original_msg_id, recipient_email, bounce_type, diagnostic_code, remote_mta, created_at
		FROM bounces
		WHERE recipient_email = ?
		ORDER BY created_at DESC
	`), email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanRecords(rows)
}

func (r *SQLiteRepository) CountByRecipient(email string, bounceType BounceType, since time.Time) (int, error) {
	var count int
	err := r.db.QueryRow(r.bind(`
		SELECT COUNT(*) FROM bounces
		WHERE recipient_email = ? AND bounce_type = ? AND created_at > ?
	`), email, string(bounceType), since).Scan(&count)
	return count, err
}

func (r *SQLiteRepository) ListByOrg(orgID uuid.UUID, limit int) ([]*BounceRecord, error) {
	rows, err := r.db.Query(r.bind(`
		SELECT id, org_id, domain_id, original_msg_id, recipient_email, bounce_type, diagnostic_code, remote_mta, created_at
		FROM bounces
		WHERE org_id = ?
		ORDER BY created_at DESC
		LIMIT ?
	`), orgID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanRecords(rows)
}

func (r *SQLiteRepository) IsSuppressed(email string) (bool, error) {
	var count int
	err := r.db.QueryRow(r.bind(`
		SELECT COUNT(*) FROM suppression_list WHERE email = ?
	`), email).Scan(&count)
	return count > 0, err
}

// AddToSuppression manually adds an email to suppression list
func (r *SQLiteRepository) AddToSuppression(email, reason string, orgID *uuid.UUID) error {
	var orgIDStr *string
	if orgID != nil {
		s := orgID.String()
		orgIDStr = &s
	}
	query := `
		INSERT OR REPLACE INTO suppression_list (email, reason, org_id, created_at)
		VALUES (?, ?, ?, ?)
	`
	if r.driver == "postgres" {
		query = `
			INSERT INTO suppression_list (email, reason, org_id, created_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(email) DO UPDATE SET reason = EXCLUDED.reason, org_id = EXCLUDED.org_id, created_at = EXCLUDED.created_at
		`
	}
	_, err := r.db.Exec(r.bind(query), email, reason, orgIDStr, time.Now())
	return err
}

// RemoveFromSuppression removes an email from suppression list
func (r *SQLiteRepository) RemoveFromSuppression(email string) error {
	_, err := r.db.Exec(r.bind(`DELETE FROM suppression_list WHERE email = ?`), email)
	return err
}

// ListSuppressed returns suppressed emails for an org
func (r *SQLiteRepository) ListSuppressed(orgID *uuid.UUID, limit int) ([]string, error) {
	var rows *sql.Rows
	var err error

	if orgID != nil {
		rows, err = r.db.Query(r.bind(`
			SELECT email FROM suppression_list WHERE org_id = ? OR org_id IS NULL ORDER BY created_at DESC LIMIT ?
		`), orgID.String(), limit)
	} else {
		rows, err = r.db.Query(r.bind(`
			SELECT email FROM suppression_list ORDER BY created_at DESC LIMIT ?
		`), limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}
	return emails, rows.Err()
}

func (r *SQLiteRepository) scanRecords(rows *sql.Rows) ([]*BounceRecord, error) {
	var records []*BounceRecord
	for rows.Next() {
		var record BounceRecord
		var idStr, orgIDStr, domainIDStr string
		var originalMsgID, diagnosticCode, remoteMTA sql.NullString

		err := rows.Scan(
			&idStr, &orgIDStr, &domainIDStr, &originalMsgID,
			&record.RecipientEmail, &record.BounceType,
			&diagnosticCode, &remoteMTA, &record.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		record.ID, _ = uuid.Parse(idStr)
		record.OrgID, _ = uuid.Parse(orgIDStr)
		record.DomainID, _ = uuid.Parse(domainIDStr)
		if originalMsgID.Valid {
			record.OriginalMsgID = originalMsgID.String
		}
		if diagnosticCode.Valid {
			record.DiagnosticCode = diagnosticCode.String
		}
		if remoteMTA.Valid {
			record.RemoteMTA = remoteMTA.String
		}

		records = append(records, &record)
	}
	return records, rows.Err()
}
