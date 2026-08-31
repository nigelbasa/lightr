package apikeys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

type stubAPIKeyRepo struct {
	getByHash func(ctx context.Context, hash string) (*APIKey, error)
}

func (s stubAPIKeyRepo) Create(ctx context.Context, key *APIKey) error { return nil }
func (s stubAPIKeyRepo) Get(ctx context.Context, id uuid.UUID) (*APIKey, error) {
	return nil, ErrKeyNotFound
}
func (s stubAPIKeyRepo) GetByHash(ctx context.Context, hash string) (*APIKey, error) {
	if s.getByHash != nil {
		return s.getByHash(ctx, hash)
	}
	return nil, ErrKeyNotFound
}
func (s stubAPIKeyRepo) GetByPrefix(ctx context.Context, prefix string) ([]*APIKey, error) {
	return nil, nil
}
func (s stubAPIKeyRepo) List(ctx context.Context, orgID *uuid.UUID, limit, offset int) ([]*APIKey, error) {
	return nil, nil
}
func (s stubAPIKeyRepo) Update(ctx context.Context, key *APIKey) error  { return nil }
func (s stubAPIKeyRepo) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (s stubAPIKeyRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	return nil
}
func (s stubAPIKeyRepo) IncrementUsage(ctx context.Context, id uuid.UUID) error { return nil }
func (s stubAPIKeyRepo) ResetDailyUsage(ctx context.Context) error              { return nil }
func (s stubAPIKeyRepo) RecordUsage(ctx context.Context, record *UsageRecord) error {
	return nil
}
func (s stubAPIKeyRepo) GetUsage(ctx context.Context, keyID uuid.UUID, from, to time.Time) ([]*UsageRecord, error) {
	return nil, nil
}

func TestBindPostgresPlaceholders(t *testing.T) {
	repo := &SQLiteAPIKeyRepository{driver: "postgres"}

	got := repo.bind("SELECT * FROM api_keys WHERE id = ? AND key_hash = ?")
	want := "SELECT * FROM api_keys WHERE id = $1 AND key_hash = $2"
	if got != want {
		t.Fatalf("bind() = %q, want %q", got, want)
	}
}

func TestValidateKeyUsesFreshRepositoryState(t *testing.T) {
	secret := "ltr_test_secret_value_123456"
	hash := sha256.Sum256([]byte(secret))
	hashStr := hex.EncodeToString(hash[:])
	calls := 0

	service := NewAPIKeyService(stubAPIKeyRepo{
		getByHash: func(ctx context.Context, gotHash string) (*APIKey, error) {
			if gotHash != hashStr {
				t.Fatalf("unexpected hash lookup %q", gotHash)
			}
			calls++
			return &APIKey{
				ID:         uuid.New(),
				KeyHash:    hashStr,
				Active:     true,
				DailyLimit: 1,
				UsageToday: int64(calls - 1),
			}, nil
		},
	})

	if _, err := service.ValidateKey(context.Background(), secret); err != nil {
		t.Fatalf("first validation failed: %v", err)
	}
	if _, err := service.ValidateKey(context.Background(), secret); err != ErrKeyRateLimited {
		t.Fatalf("second validation = %v, want %v", err, ErrKeyRateLimited)
	}
	if calls != 2 {
		t.Fatalf("expected repository to be consulted twice, got %d calls", calls)
	}
}

func TestGetClientIPIgnoresForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/apikeys", nil)
	req.RemoteAddr = "198.51.100.12:8080"
	req.Header.Set("X-Forwarded-For", "203.0.113.4")
	req.Header.Set("X-Real-IP", "203.0.113.5")

	if got := getClientIP(req); got != "198.51.100.12" {
		t.Fatalf("getClientIP() = %q, want %q", got, "198.51.100.12")
	}
}
