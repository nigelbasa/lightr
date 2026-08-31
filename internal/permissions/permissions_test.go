package permissions

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

func TestBindPostgresPlaceholders(t *testing.T) {
	repo := &SQLitePermissionRepository{driver: "postgres"}

	got := repo.bind("SELECT * FROM sudo_sessions WHERE user_id = ? AND expires_at > ?")
	want := "SELECT * FROM sudo_sessions WHERE user_id = $1 AND expires_at > $2"
	if got != want {
		t.Fatalf("bind() = %q, want %q", got, want)
	}
}

func TestCleanExpiredSessionsSQLite(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	repo, err := NewSQLitePermissionRepository(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}

	ctx := context.Background()
	expired := &SudoSession{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Level:       LevelAdmin,
		MFAVerified: true,
		CreatedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
		LastUsedAt:  time.Now().Add(-90 * time.Minute),
		Operations:  []string{"modify_config"},
	}
	active := &SudoSession{
		ID:          uuid.New(),
		UserID:      expired.UserID,
		Level:       LevelAdmin,
		MFAVerified: true,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		LastUsedAt:  time.Now(),
		Operations:  []string{"view_logs"},
	}

	if err := repo.CreateSession(ctx, expired); err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	if err := repo.CreateSession(ctx, active); err != nil {
		t.Fatalf("create active session: %v", err)
	}

	if err := repo.CleanExpiredSessions(ctx); err != nil {
		t.Fatalf("clean expired sessions: %v", err)
	}

	if _, err := repo.GetSession(ctx, expired.ID); err != sql.ErrNoRows {
		t.Fatalf("expired session lookup err = %v, want %v", err, sql.ErrNoRows)
	}

	got, err := repo.GetSession(ctx, active.ID)
	if err != nil {
		t.Fatalf("get active session: %v", err)
	}
	if got.ID != active.ID {
		t.Fatalf("active session ID = %s, want %s", got.ID, active.ID)
	}
}
