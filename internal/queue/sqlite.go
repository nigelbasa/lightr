package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SQLiteRepository implements Repository using SQLite
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new SQLite-based queue repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) migrate() error {
	_, err := r.db.Exec(`
		CREATE TABLE IF NOT EXISTS email_queue (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			domain_id TEXT NOT NULL,
			from_addr TEXT NOT NULL,
			to_addrs TEXT NOT NULL,
			subject TEXT NOT NULL,
			body TEXT NOT NULL,
			html_body TEXT,
			headers TEXT,
			status TEXT NOT NULL DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 5,
			last_error TEXT,
			next_retry DATETIME NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			delivered_at DATETIME
		);
		
		CREATE INDEX IF NOT EXISTS idx_queue_status ON email_queue(status);
		CREATE INDEX IF NOT EXISTS idx_queue_next_retry ON email_queue(next_retry);
		CREATE INDEX IF NOT EXISTS idx_queue_org_id ON email_queue(org_id);
	`)
	return err
}

func (r *SQLiteRepository) Create(msg *QueuedMessage) error {
	toJSON, _ := json.Marshal(msg.To)
	_, err := r.db.Exec(`
		INSERT INTO email_queue (
			id, org_id, domain_id, from_addr, to_addrs, subject, body, html_body,
			headers, status, attempts, max_attempts, next_retry, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		msg.ID.String(),
		msg.OrgID.String(),
		msg.DomainID.String(),
		msg.From,
		string(toJSON),
		msg.Subject,
		msg.Body,
		msg.HTMLBody,
		msg.Headers,
		string(msg.Status),
		msg.Attempts,
		msg.MaxAttempts,
		msg.NextRetry,
		msg.CreatedAt,
		msg.UpdatedAt,
	)
	return err
}

func (r *SQLiteRepository) GetPending(ctx context.Context, limit int) ([]*QueuedMessage, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, org_id, domain_id, from_addr, to_addrs, subject, body, html_body,
		       headers, status, attempts, max_attempts, last_error, next_retry,
		       created_at, updated_at, delivered_at
		FROM email_queue
		WHERE (status = 'pending' OR (status = 'retrying' AND next_retry <= datetime('now')))
		ORDER BY next_retry ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanMessages(rows)
}

func (r *SQLiteRepository) UpdateStatus(id uuid.UUID, status Status, lastError string, nextRetry *time.Time) error {
	query := `
		UPDATE email_queue
		SET status = ?, last_error = ?, updated_at = datetime('now'), attempts = attempts + 1
	`
	args := []interface{}{string(status), lastError}

	if nextRetry != nil {
		query += ", next_retry = ?"
		args = append(args, *nextRetry)
	}

	query += " WHERE id = ?"
	args = append(args, id.String())

	_, err := r.db.Exec(query, args...)
	return err
}

func (r *SQLiteRepository) MarkDelivered(id uuid.UUID) error {
	_, err := r.db.Exec(`
		UPDATE email_queue
		SET status = 'delivered', delivered_at = datetime('now'), updated_at = datetime('now')
		WHERE id = ?
	`, id.String())
	return err
}

func (r *SQLiteRepository) GetByID(id uuid.UUID) (*QueuedMessage, error) {
	row := r.db.QueryRow(`
		SELECT id, org_id, domain_id, from_addr, to_addrs, subject, body, html_body,
		       headers, status, attempts, max_attempts, last_error, next_retry,
		       created_at, updated_at, delivered_at
		FROM email_queue
		WHERE id = ?
	`, id.String())

	msg, err := r.scanMessage(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return msg, err
}

func (r *SQLiteRepository) ListByOrg(orgID uuid.UUID, status *Status, limit int) ([]*QueuedMessage, error) {
	query := `
		SELECT id, org_id, domain_id, from_addr, to_addrs, subject, body, html_body,
		       headers, status, attempts, max_attempts, last_error, next_retry,
		       created_at, updated_at, delivered_at
		FROM email_queue
		WHERE org_id = ?
	`
	args := []interface{}{orgID.String()}

	if status != nil {
		query += " AND status = ?"
		args = append(args, string(*status))
	}

	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanMessages(rows)
}

func (r *SQLiteRepository) DeleteOld(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	result, err := r.db.Exec(`
		DELETE FROM email_queue
		WHERE (status = 'delivered' OR status = 'failed')
		AND updated_at < ?
	`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *SQLiteRepository) scanMessage(row *sql.Row) (*QueuedMessage, error) {
	var msg QueuedMessage
	var idStr, orgIDStr, domainIDStr string
	var toJSON, headersJSON sql.NullString
	var statusStr string
	var lastError sql.NullString
	var deliveredAt sql.NullTime

	err := row.Scan(
		&idStr, &orgIDStr, &domainIDStr,
		&msg.From, &toJSON, &msg.Subject, &msg.Body, &msg.HTMLBody,
		&headersJSON, &statusStr, &msg.Attempts, &msg.MaxAttempts, &lastError,
		&msg.NextRetry, &msg.CreatedAt, &msg.UpdatedAt, &deliveredAt,
	)
	if err != nil {
		return nil, err
	}

	msg.ID, _ = uuid.Parse(idStr)
	msg.OrgID, _ = uuid.Parse(orgIDStr)
	msg.DomainID, _ = uuid.Parse(domainIDStr)
	msg.Status = Status(statusStr)

	if toJSON.Valid {
		json.Unmarshal([]byte(toJSON.String), &msg.To)
	}
	if headersJSON.Valid {
		msg.Headers = json.RawMessage(headersJSON.String)
	}
	if lastError.Valid {
		msg.LastError = lastError.String
	}
	if deliveredAt.Valid {
		msg.DeliveredAt = &deliveredAt.Time
	}

	return &msg, nil
}

func (r *SQLiteRepository) scanMessages(rows *sql.Rows) ([]*QueuedMessage, error) {
	var messages []*QueuedMessage

	for rows.Next() {
		var msg QueuedMessage
		var idStr, orgIDStr, domainIDStr string
		var toJSON, headersJSON sql.NullString
		var statusStr string
		var lastError sql.NullString
		var deliveredAt sql.NullTime

		err := rows.Scan(
			&idStr, &orgIDStr, &domainIDStr,
			&msg.From, &toJSON, &msg.Subject, &msg.Body, &msg.HTMLBody,
			&headersJSON, &statusStr, &msg.Attempts, &msg.MaxAttempts, &lastError,
			&msg.NextRetry, &msg.CreatedAt, &msg.UpdatedAt, &deliveredAt,
		)
		if err != nil {
			return nil, err
		}

		msg.ID, _ = uuid.Parse(idStr)
		msg.OrgID, _ = uuid.Parse(orgIDStr)
		msg.DomainID, _ = uuid.Parse(domainIDStr)
		msg.Status = Status(statusStr)

		if toJSON.Valid {
			json.Unmarshal([]byte(toJSON.String), &msg.To)
		}
		if headersJSON.Valid {
			msg.Headers = json.RawMessage(headersJSON.String)
		}
		if lastError.Valid {
			msg.LastError = lastError.String
		}
		if deliveredAt.Valid {
			msg.DeliveredAt = &deliveredAt.Time
		}

		messages = append(messages, &msg)
	}

	return messages, rows.Err()
}
