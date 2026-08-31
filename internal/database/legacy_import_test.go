package database

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/storage"
)

func TestImportLegacySQLiteCopiesDataAndBlobs(t *testing.T) {
	sourceRoot := t.TempDir()
	destRoot := t.TempDir()
	sourceDBPath := filepath.Join(sourceRoot, "legacy.db")
	destDBPath := filepath.Join(destRoot, "current.db")

	sourceDB, err := storage.NewSQLiteStore(sourceDBPath)
	if err != nil {
		t.Fatalf("failed to create source store: %v", err)
	}
	defer sourceDB.Close()

	if _, err := sourceDB.DB().Exec(`
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
	`); err != nil {
		t.Fatalf("failed to create legacy queue table: %v", err)
	}

	orgID := uuid.New().String()
	domainID := uuid.New().String()
	accountID := uuid.New().String()
	messageID := uuid.New().String()
	queueID := uuid.New().String()
	now := time.Now().UTC()
	storagePath := filepath.Join("messages", accountID, messageID+".eml")

	if _, err := sourceDB.DB().Exec(`INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)`, orgID, "Acme", now); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := sourceDB.DB().Exec(`INSERT INTO domains (id, org_id, name, dkim_private_key, dkim_selector, webhook_url, auth_webhook_url, is_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, domainID, orgID, "mail.example.com", "", "default", "", "", true, now); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if _, err := sourceDB.DB().Exec(`INSERT INTO accounts (id, domain_id, local_part, display_name, auth_mode, password_hash, external_id, quota_bytes, used_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, accountID, domainID, "user", "User", "native", "hash", "", 1024, 512, now); err != nil {
		t.Fatalf("insert account: %v", err)
	}
	if _, err := sourceDB.DB().Exec(`INSERT INTO messages (id, account_id, folder, size_bytes, storage_path, subject, "from", "to", received_at, read_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, messageID, accountID, "INBOX", 12, filepath.ToSlash(storagePath), "Hello", "from@example.com", "user@mail.example.com", now, nil, nil); err != nil {
		t.Fatalf("insert message: %v", err)
	}
	if _, err := sourceDB.DB().Exec(`INSERT INTO email_queue (id, org_id, domain_id, from_addr, to_addrs, subject, body, html_body, headers, status, attempts, max_attempts, last_error, next_retry, created_at, updated_at, delivered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, queueID, orgID, domainID, "from@example.com", `["to@example.com"]`, "Queued", "Body", "", "", "pending", 0, 5, "", now, now, now, nil); err != nil {
		t.Fatalf("insert queue: %v", err)
	}

	blobPath := filepath.Join(sourceRoot, "blobs", storagePath)
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		t.Fatalf("mkdir blob dir: %v", err)
	}
	if err := os.WriteFile(blobPath, []byte("raw email"), 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}

	destDB, err := storage.NewSQLiteStore(destDBPath)
	if err != nil {
		t.Fatalf("failed to create destination store: %v", err)
	}
	defer destDB.Close()

	if _, err := destDB.DB().Exec(`
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
	`); err != nil {
		t.Fatalf("failed to create destination queue table: %v", err)
	}

	result, err := ImportLegacySQLite(LegacySQLiteImportOptions{
		SourceDBPath:  sourceDBPath,
		SourceDataDir: sourceRoot,
		DestDataDir:   filepath.Join(destRoot, "blobs"),
	}, destDB)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	if result.Messages != 1 || result.BlobsCopied != 1 || result.Queue != 1 {
		t.Fatalf("unexpected import result: %+v", result)
	}

	var count int
	if err := destDB.DB().QueryRow(`SELECT COUNT(*) FROM messages WHERE id = ?`, messageID).Scan(&count); err != nil {
		t.Fatalf("count imported messages: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected imported message, got %d", count)
	}

	destBlobPath := filepath.Join(destRoot, "blobs", storagePath)
	data, err := os.ReadFile(destBlobPath)
	if err != nil {
		t.Fatalf("read imported blob: %v", err)
	}
	if string(data) != "raw email" {
		t.Fatalf("unexpected imported blob content: %q", string(data))
	}
}
