package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

func TestBindRewritesPlaceholdersForPostgres(t *testing.T) {
	store := &SQLiteStore{driver: "postgres"}
	got := store.bind(`SELECT id FROM accounts WHERE domain_id = ? AND local_part = ? LIMIT ?`)
	want := `SELECT id FROM accounts WHERE domain_id = $1 AND local_part = $2 LIMIT $3`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBindLeavesSQLiteQueriesUntouched(t *testing.T) {
	store := &SQLiteStore{driver: "sqlite"}
	query := `SELECT * FROM messages WHERE id = ?`
	if got := store.bind(query); got != query {
		t.Fatalf("expected sqlite query to stay unchanged, got %q", got)
	}
}

func TestUpdateDomainPersistsRenamedDomain(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "lightr.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer store.Close()

	org := &domain.Organization{
		ID:        uuid.New(),
		Name:      "Acme",
		CreatedAt: time.Now(),
	}
	if err := store.CreateOrg(org); err != nil {
		t.Fatalf("CreateOrg() error = %v", err)
	}

	dom := &domain.Domain{
		ID:           uuid.New(),
		OrgID:        org.ID,
		Name:         "mail.acme.test",
		MailHostname: "smtp.acme.test",
		DKIMSelector: "default",
		SpamPolicy:   "junk",
	}
	if err := store.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain() error = %v", err)
	}

	dom.Name = "mx.acme.test"
	if err := store.UpdateDomain(dom); err != nil {
		t.Fatalf("UpdateDomain() error = %v", err)
	}

	updated, err := store.GetDomainByID(dom.ID)
	if err != nil {
		t.Fatalf("GetDomainByID() error = %v", err)
	}
	if updated.Name != "mx.acme.test" {
		t.Fatalf("updated.Name = %q, want %q", updated.Name, "mx.acme.test")
	}
	if updated.MailHostname != "smtp.acme.test" {
		t.Fatalf("updated.MailHostname = %q, want %q", updated.MailHostname, "smtp.acme.test")
	}
	if _, err := store.GetDomainByName("mail.acme.test"); err == nil {
		t.Fatalf("expected old domain name lookup to fail after rename")
	}
	renamed, err := store.GetDomainByName("mx.acme.test")
	if err != nil {
		t.Fatalf("GetDomainByName(new) error = %v", err)
	}
	if renamed.ID != dom.ID {
		t.Fatalf("renamed.ID = %s, want %s", renamed.ID, dom.ID)
	}
}

func TestUpdateDomainPersistsMailHostname(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "lightr.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer store.Close()

	org := &domain.Organization{
		ID:        uuid.New(),
		Name:      "Acme",
		CreatedAt: time.Now(),
	}
	if err := store.CreateOrg(org); err != nil {
		t.Fatalf("CreateOrg() error = %v", err)
	}

	dom := &domain.Domain{
		ID:           uuid.New(),
		OrgID:        org.ID,
		Name:         "mail.acme.test",
		DKIMSelector: "default",
		SpamPolicy:   "junk",
	}
	if err := store.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain() error = %v", err)
	}

	dom.MailHostname = "mx1.acme.test"
	if err := store.UpdateDomain(dom); err != nil {
		t.Fatalf("UpdateDomain() error = %v", err)
	}

	updated, err := store.GetDomainByID(dom.ID)
	if err != nil {
		t.Fatalf("GetDomainByID() error = %v", err)
	}
	if updated.MailHostname != "mx1.acme.test" {
		t.Fatalf("updated.MailHostname = %q, want %q", updated.MailHostname, "mx1.acme.test")
	}
}

func TestQuotaIncrementsOnCreateAndDecrementsOnDelete(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "lightr.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer store.Close()

	org := &domain.Organization{ID: uuid.New(), Name: "Acme", CreatedAt: time.Now()}
	if err := store.CreateOrg(org); err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	dom := &domain.Domain{
		ID: uuid.New(), OrgID: org.ID, Name: "mail.acme.test",
		DKIMSelector: "default", SpamPolicy: "junk",
	}
	if err := store.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	acc := &domain.Account{
		ID: uuid.New(), DomainID: dom.ID, LocalPart: "ops",
		AuthMode: domain.AuthModeNative, QuotaBytes: 10000,
	}
	if err := store.CreateAccount(acc); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	msg := &domain.Message{
		ID: uuid.New(), AccountID: acc.ID, Folder: "INBOX", SizeBytes: 1234,
		StoragePath: "x.eml", ReceivedAt: time.Now(),
	}
	if err := store.CreateMessage(msg); err != nil {
		t.Fatalf("CreateMessage: %v", err)
	}

	got, err := store.GetAccountByID(acc.ID)
	if err != nil {
		t.Fatalf("GetAccountByID: %v", err)
	}
	if got.UsedBytes != 1234 {
		t.Errorf("after create UsedBytes = %d, want 1234", got.UsedBytes)
	}

	// Soft-delete the message.
	now := time.Now()
	msg.DeletedAt = &now
	if err := store.UpdateMessage(msg); err != nil {
		t.Fatalf("UpdateMessage delete: %v", err)
	}
	got, _ = store.GetAccountByID(acc.ID)
	if got.UsedBytes != 0 {
		t.Errorf("after delete UsedBytes = %d, want 0", got.UsedBytes)
	}

	// Un-delete: counter should come back.
	msg.DeletedAt = nil
	if err := store.UpdateMessage(msg); err != nil {
		t.Fatalf("UpdateMessage undelete: %v", err)
	}
	got, _ = store.GetAccountByID(acc.ID)
	if got.UsedBytes != 1234 {
		t.Errorf("after undelete UsedBytes = %d, want 1234", got.UsedBytes)
	}
}

func TestLocalBlobStorageRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	bs := NewLocalBlobStorage(dir)
	badPaths := []string{
		"../escape.eml",
		"../../etc/passwd",
		"acct/../../escape",
		"acct/../../escape.eml",
		"",
		"foo\x00bar",
	}
	for _, p := range badPaths {
		if err := bs.Put(p, []byte("x")); err == nil {
			t.Errorf("Put(%q) accepted, want rejection", p)
		}
	}
	if err := bs.Put("a/b/c.eml", []byte("ok")); err != nil {
		t.Fatalf("Put valid path: %v", err)
	}
}
