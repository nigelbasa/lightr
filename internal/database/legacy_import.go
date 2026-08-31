package database

import (
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/nigelbasa/lightr/internal/storage"
)

type LegacySQLiteImportOptions struct {
	SourceDBPath  string
	SourceDataDir string
	DestDataDir   string
}

type LegacySQLiteImportResult struct {
	Organizations int
	Domains       int
	Accounts      int
	Messages      int
	Queue         int
	BlobsCopied   int
}

func ImportLegacySQLite(opts LegacySQLiteImportOptions, dest *storage.SQLiteStore) (*LegacySQLiteImportResult, error) {
	if dest == nil {
		return nil, errors.New("destination store is required")
	}
	if opts.SourceDBPath == "" {
		return nil, errors.New("source db path is required")
	}

	src, err := sql.Open("sqlite", opts.SourceDBPath)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	if _, err := src.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		return nil, err
	}

	result := &LegacySQLiteImportResult{}
	tx, err := dest.DB().Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if result.Organizations, err = importOrganizations(src, tx); err != nil {
		return nil, err
	}
	if result.Domains, err = importDomains(src, tx); err != nil {
		return nil, err
	}
	if result.Accounts, err = importAccounts(src, tx); err != nil {
		return nil, err
	}
	if result.Messages, err = importMessages(src, tx); err != nil {
		return nil, err
	}
	if result.Queue, err = importQueue(src, tx); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	if opts.SourceDataDir != "" && opts.DestDataDir != "" {
		if result.BlobsCopied, err = copyLegacyBlobs(src, opts.SourceDataDir, opts.DestDataDir); err != nil {
			return nil, err
		}
	}

	return result, nil
}

func importOrganizations(src *sql.DB, tx *sql.Tx) (int, error) {
	if ok, err := tableExists(src, "organizations"); err != nil || !ok {
		return 0, err
	}
	rows, err := src.Query(`SELECT id, name, created_at FROM organizations`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO organizations (id, name, created_at) VALUES (?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for rows.Next() {
		var id, name string
		var createdAt interface{}
		if err := rows.Scan(&id, &name, &createdAt); err != nil {
			return 0, err
		}
		if _, err := stmt.Exec(id, name, createdAt); err != nil {
			return 0, err
		}
		count++
	}
	return count, rows.Err()
}

func importDomains(src *sql.DB, tx *sql.Tx) (int, error) {
	if ok, err := tableExists(src, "domains"); err != nil || !ok {
		return 0, err
	}
	rows, err := src.Query(`SELECT id, org_id, name, dkim_private_key, dkim_selector, webhook_url, auth_webhook_url, is_verified, created_at FROM domains`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO domains (id, org_id, name, dkim_private_key, dkim_selector, webhook_url, auth_webhook_url, is_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for rows.Next() {
		var id, orgID, name string
		var dkimPrivateKey, dkimSelector, webhookURL, authWebhookURL sql.NullString
		var isVerified interface{}
		var createdAt interface{}
		if err := rows.Scan(&id, &orgID, &name, &dkimPrivateKey, &dkimSelector, &webhookURL, &authWebhookURL, &isVerified, &createdAt); err != nil {
			return 0, err
		}
		if _, err := stmt.Exec(id, orgID, name, dkimPrivateKey.String, dkimSelector.String, webhookURL.String, authWebhookURL.String, isVerified, createdAt); err != nil {
			return 0, err
		}
		count++
	}
	return count, rows.Err()
}

func importAccounts(src *sql.DB, tx *sql.Tx) (int, error) {
	if ok, err := tableExists(src, "accounts"); err != nil || !ok {
		return 0, err
	}
	rows, err := src.Query(`SELECT id, domain_id, local_part, display_name, auth_mode, password_hash, external_id, quota_bytes, used_bytes, created_at FROM accounts`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO accounts (id, domain_id, local_part, display_name, auth_mode, password_hash, external_id, quota_bytes, used_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for rows.Next() {
		var id, domainID, localPart, authMode string
		var displayName, passwordHash, externalID sql.NullString
		var quotaBytes, usedBytes sql.NullInt64
		var createdAt interface{}
		if err := rows.Scan(&id, &domainID, &localPart, &displayName, &authMode, &passwordHash, &externalID, &quotaBytes, &usedBytes, &createdAt); err != nil {
			return 0, err
		}
		if _, err := stmt.Exec(id, domainID, localPart, displayName.String, authMode, passwordHash.String, externalID.String, quotaBytes.Int64, usedBytes.Int64, createdAt); err != nil {
			return 0, err
		}
		count++
	}
	return count, rows.Err()
}

func importMessages(src *sql.DB, tx *sql.Tx) (int, error) {
	if ok, err := tableExists(src, "messages"); err != nil || !ok {
		return 0, err
	}
	rows, err := src.Query(`SELECT id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at, deleted_at FROM messages`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO messages (id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for rows.Next() {
		var id, accountID string
		var folder, storagePath, subject, fromAddr, toAddr sql.NullString
		var sizeBytes sql.NullInt64
		var receivedAt, readAt, deletedAt interface{}
		if err := rows.Scan(&id, &accountID, &folder, &sizeBytes, &storagePath, &subject, &fromAddr, &toAddr, &receivedAt, &readAt, &deletedAt); err != nil {
			return 0, err
		}
		if _, err := stmt.Exec(id, accountID, folder.String, sizeBytes.Int64, storagePath.String, subject.String, fromAddr.String, toAddr.String, receivedAt, nullableValue(readAt), nullableValue(deletedAt)); err != nil {
			return 0, err
		}
		count++
	}
	return count, rows.Err()
}

func importQueue(src *sql.DB, tx *sql.Tx) (int, error) {
	if ok, err := tableExists(src, "email_queue"); err != nil || !ok {
		return 0, err
	}
	rows, err := src.Query(`SELECT id, org_id, domain_id, from_addr, to_addrs, subject, body, html_body, headers, status, attempts, max_attempts, last_error, next_retry, created_at, updated_at, delivered_at FROM email_queue`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO email_queue (id, org_id, domain_id, from_addr, to_addrs, subject, body, html_body, headers, status, attempts, max_attempts, last_error, next_retry, created_at, updated_at, delivered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for rows.Next() {
		var id, orgID, domainID, fromAddr, toAddrs, subject, body string
		var htmlBody, headers, lastError sql.NullString
		var status string
		var attempts, maxAttempts int
		var nextRetry, createdAt, updatedAt, deliveredAt interface{}
		if err := rows.Scan(&id, &orgID, &domainID, &fromAddr, &toAddrs, &subject, &body, &htmlBody, &headers, &status, &attempts, &maxAttempts, &lastError, &nextRetry, &createdAt, &updatedAt, &deliveredAt); err != nil {
			return 0, err
		}
		if _, err := stmt.Exec(id, orgID, domainID, fromAddr, toAddrs, subject, body, htmlBody.String, headers.String, status, attempts, maxAttempts, lastError.String, nextRetry, createdAt, updatedAt, nullableValue(deliveredAt)); err != nil {
			return 0, err
		}
		count++
	}
	return count, rows.Err()
}

func copyLegacyBlobs(src *sql.DB, sourceDataDir, destDataDir string) (int, error) {
	if ok, err := tableExists(src, "messages"); err != nil || !ok {
		return 0, err
	}
	rows, err := src.Query(`SELECT storage_path FROM messages WHERE storage_path IS NOT NULL AND storage_path != ''`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var storagePath string
		if err := rows.Scan(&storagePath); err != nil {
			return 0, err
		}
		if storagePath == "" {
			continue
		}
		found := resolveLegacyBlobPath(sourceDataDir, storagePath)
		if found == "" {
			continue
		}
		destPath := filepath.Join(destDataDir, storagePath)
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return 0, err
		}
		if err := copyFile(found, destPath); err != nil {
			return 0, err
		}
		count++
	}
	return count, rows.Err()
}

func resolveLegacyBlobPath(baseDir, storagePath string) string {
	candidates := []string{
		filepath.Join(baseDir, storagePath),
		filepath.Join(baseDir, "blobs", storagePath),
		filepath.Join(baseDir, "messages", storagePath),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func tableExists(db *sql.DB, table string) (bool, error) {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, table).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func nullableValue(v interface{}) interface{} {
	switch value := v.(type) {
	case sql.NullTime:
		if value.Valid {
			return value.Time
		}
		return nil
	case sql.NullString:
		if value.Valid {
			return value.String
		}
		return nil
	case nil:
		return nil
	default:
		return value
	}
}
