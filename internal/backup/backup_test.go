package backup

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Minimal schema for two safelisted tables.
	stmts := []string{
		`CREATE TABLE accounts (id TEXT PRIMARY KEY, email TEXT)`,
		`CREATE TABLE messages (id TEXT PRIMARY KEY, account_id TEXT, subject TEXT)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	return db
}

func TestBackupRoundTrip(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO accounts VALUES (?, ?)`, "a1", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO messages VALUES (?, ?, ?)`, "m1", "a1", "hello"); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "m1.eml"), []byte("raw"), 0644); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	b := New(&Config{DB: db, DataDir: dataDir, OutputDir: outDir})
	archive, err := b.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Wipe and restore.
	if _, err := db.Exec(`DELETE FROM accounts`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM messages`); err != nil {
		t.Fatal(err)
	}
	restoreDir := t.TempDir()

	r := NewRestore(db, "sqlite",restoreDir)
	result, err := r.FromFile(archive)
	if err != nil {
		t.Fatalf("FromFile: %v", err)
	}
	if result.TablesRestored < 2 {
		t.Errorf("TablesRestored=%d, want >=2", result.TablesRestored)
	}
	if result.FilesRestored != 1 {
		t.Errorf("FilesRestored=%d, want 1", result.FilesRestored)
	}

	var email string
	if err := db.QueryRow(`SELECT email FROM accounts WHERE id = ?`, "a1").Scan(&email); err != nil {
		t.Fatalf("read back account: %v", err)
	}
	if email != "alice@example.com" {
		t.Errorf("email=%q, want alice@example.com", email)
	}

	if _, err := os.Stat(filepath.Join(restoreDir, "m1.eml")); err != nil {
		t.Errorf("expected blob restored: %v", err)
	}
}

// writeTarGz builds a small backup tarball for restore-rejection tests.
func writeTarGz(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRestoreRejectsUnknownTable(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	dir := t.TempDir()
	archive := filepath.Join(dir, "bad.tar.gz")

	// Pretend table "evil" carries a row.
	rowsJSON, _ := json.Marshal([]map[string]interface{}{{"x": 1}})
	writeTarGz(t, archive, map[string][]byte{
		"db/evil.json": rowsJSON,
	})

	r := NewRestore(db, "sqlite",t.TempDir())
	result, err := r.FromFile(archive)
	if err != nil {
		t.Fatalf("FromFile: %v", err)
	}
	if result.TablesRestored != 0 {
		t.Errorf("TablesRestored=%d, want 0", result.TablesRestored)
	}
	if len(result.Errors) == 0 || !strings.Contains(strings.Join(result.Errors, "\n"), "safelist") {
		t.Errorf("expected safelist error, got %v", result.Errors)
	}
}

func TestRestoreRejectsPathTraversal(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	dir := t.TempDir()
	archive := filepath.Join(dir, "evil.tar.gz")
	dataDir := t.TempDir()

	writeTarGz(t, archive, map[string][]byte{
		"files/../escape.txt": []byte("pwned"),
	})

	r := NewRestore(db, "sqlite",dataDir)
	result, err := r.FromFile(archive)
	if err != nil {
		t.Fatalf("FromFile: %v", err)
	}
	if result.FilesRestored != 0 {
		t.Errorf("FilesRestored=%d, want 0", result.FilesRestored)
	}
	// And the escape file must not exist anywhere outside dataDir.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dataDir), "escape.txt")); err == nil {
		t.Error("traversal succeeded: escape.txt was written outside dataDir")
	}
}

func TestRestoreIgnoresExtraColumnsFromArchive(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	dir := t.TempDir()
	archive := filepath.Join(dir, "extra.tar.gz")

	// Archive row has a bogus column "; DROP TABLE accounts; --" that does
	// not exist in the live schema. It should be silently ignored.
	rowsJSON, _ := json.Marshal([]map[string]interface{}{
		{
			"id":                          "a1",
			"email":                       "alice@example.com",
			"; DROP TABLE accounts; --":   "ignored",
		},
	})
	writeTarGz(t, archive, map[string][]byte{
		"db/accounts.json": rowsJSON,
	})

	r := NewRestore(db, "sqlite",t.TempDir())
	if _, err := r.FromFile(archive); err != nil {
		t.Fatalf("FromFile: %v", err)
	}

	// accounts table must still exist
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM accounts`).Scan(&n); err != nil {
		t.Fatalf("accounts table missing: %v", err)
	}
	if n != 1 {
		t.Errorf("accounts rows=%d, want 1", n)
	}
}
