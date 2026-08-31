package webhooks

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

func TestBindPostgresPlaceholders(t *testing.T) {
	repo := &SQLiteWebhookRepository{driver: "postgres"}

	got := repo.bind("SELECT * FROM webhook_events WHERE status = ? AND webhook_id = ?")
	want := "SELECT * FROM webhook_events WHERE status = $1 AND webhook_id = $2"
	if got != want {
		t.Fatalf("bind() = %q, want %q", got, want)
	}
}

func TestGetRetryableEventsSQLite(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	repo, err := NewSQLiteWebhookRepository(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}

	ctx := context.Background()
	retryAt := time.Now().Add(-time.Minute)
	futureRetry := time.Now().Add(time.Hour)

	if err := repo.CreateEvent(ctx, &WebhookEvent{
		ID:        uuid.New(),
		WebhookID: uuid.New(),
		EventType: EventEmailSent,
		Payload:   map[string]interface{}{"message_id": "a"},
		Status:    StatusRetrying,
		Attempts:  1,
		NextRetry: &retryAt,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create retryable event: %v", err)
	}

	if err := repo.CreateEvent(ctx, &WebhookEvent{
		ID:        uuid.New(),
		WebhookID: uuid.New(),
		EventType: EventEmailSent,
		Payload:   map[string]interface{}{"message_id": "b"},
		Status:    StatusRetrying,
		Attempts:  1,
		NextRetry: &futureRetry,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create future event: %v", err)
	}

	events, err := repo.GetRetryableEvents(ctx, 10)
	if err != nil {
		t.Fatalf("get retryable events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if got := events[0].Payload["message_id"]; got != "a" {
		t.Fatalf("message_id = %v, want a", got)
	}
}
