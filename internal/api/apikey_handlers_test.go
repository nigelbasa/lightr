package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/apikeys"
	"github.com/nigelbasa/lightr/internal/domain"
	"github.com/nigelbasa/lightr/internal/storage"
)

func TestConstrainAPIKeyCreateRejectsGlobalKeyTypesForScopedActors(t *testing.T) {
	orgID := uuid.New()
	h := &Handler{}
	create := &apikeys.APIKeyCreate{Type: apikeys.KeyTypeMaster}

	err := h.constrainAPIKeyCreate(&apikeys.APIKey{
		OrganizationID: &orgID,
		Permissions:    []apikeys.Permission{apikeys.PermManageAPIKeys},
	}, create)
	if err == nil {
		t.Fatalf("expected master-key creation to be rejected for scoped actor")
	}
}

func TestConstrainAPIKeyCreateDefaultsDomainScope(t *testing.T) {
	orgID := uuid.New()
	domainID := uuid.New()

	h := &Handler{
		domainRepo: fakeDomainRepo{domain: &domain.Domain{
			ID:    domainID,
			OrgID: orgID,
			Name:  "mail.example.test",
		}},
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{}},
	}
	create := &apikeys.APIKeyCreate{Type: apikeys.KeyTypeSending}

	err := h.constrainAPIKeyCreate(&apikeys.APIKey{
		DomainID:    &domainID,
		Permissions: []apikeys.Permission{apikeys.PermManageAPIKeys},
	}, create)
	if err != nil {
		t.Fatalf("expected scope defaults, got error: %v", err)
	}
	if create.DomainID == nil || *create.DomainID != domainID {
		t.Fatalf("expected domain scope to default to actor domain")
	}
	if create.OrganizationID == nil || *create.OrganizationID != orgID {
		t.Fatalf("expected org scope to default to actor org")
	}
}

func TestFilterAccessibleAPIKeysRestrictsDomainScopedView(t *testing.T) {
	orgID := uuid.New()
	allowedDomainID := uuid.New()
	otherDomainID := uuid.New()
	accountID := uuid.New()

	h := &Handler{
		domainRepo: fakeDomainRepo{domain: &domain.Domain{
			ID:    allowedDomainID,
			OrgID: orgID,
			Name:  "mail.example.test",
		}},
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{
			accountID: {
				ID:        accountID,
				DomainID:  allowedDomainID,
				LocalPart: "alice",
				Email:     "alice@mail.example.test",
			},
		}},
	}

	keys := []*apikeys.APIKey{
		{DomainID: &allowedDomainID, Permissions: []apikeys.Permission{apikeys.PermManageAPIKeys}},
		{OrganizationID: &orgID, Permissions: []apikeys.Permission{apikeys.PermManageAPIKeys}},
		{AccountID: &accountID, Permissions: []apikeys.Permission{apikeys.PermManageAPIKeys}},
		{DomainID: &otherDomainID, Permissions: []apikeys.Permission{apikeys.PermManageAPIKeys}},
	}

	filtered := h.filterAccessibleAPIKeys(&apikeys.APIKey{
		DomainID:    &allowedDomainID,
		Permissions: []apikeys.Permission{apikeys.PermManageAPIKeys},
	}, keys)

	if len(filtered) != 2 {
		t.Fatalf("expected only same-domain keys to remain, got %d", len(filtered))
	}
	for _, key := range filtered {
		if key.OrganizationID != nil {
			t.Fatalf("expected broader org-scoped key to be filtered out")
		}
	}
}

func TestHandleCreateAPIKeyPersistsRestrictions(t *testing.T) {
	store, err := storage.NewSQLiteStore(filepath.Join(t.TempDir(), "lightr.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer store.Close()

	org := &domain.Organization{ID: uuid.New(), Name: "Acme"}
	if err := store.CreateOrg(org); err != nil {
		t.Fatalf("CreateOrg() error = %v", err)
	}
	repo, err := apikeys.NewSQLAPIKeyRepository(store.DB(), store.Driver())
	if err != nil {
		t.Fatalf("NewSQLAPIKeyRepository() error = %v", err)
	}
	handler := NewHandler(store, store, store, store, nil, nil).
		WithAPIKeyService(apikeys.NewAPIKeyService(repo))

	body := bytes.NewBufferString(`{
		"name":"api-test",
		"type":"integration",
		"org":"Acme",
		"rate_limit":25,
		"daily_limit":100,
		"allowed_ips":["198.51.100.10"],
		"allowed_domains":["example.net"],
		"expires_in":"2d"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/apikeys", body).WithContext(context.WithValue(context.Background(), apiKeyContextKey, &apikeys.APIKey{
		Permissions: []apikeys.Permission{apikeys.PermSuperAdmin},
	}))
	w := httptest.NewRecorder()

	handler.HandleCreateAPIKey(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected created, got %d body=%s", w.Code, w.Body.String())
	}
	var result apikeys.APIKeyResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Key.RateLimit != 25 {
		t.Fatalf("RateLimit = %d, want 25", result.Key.RateLimit)
	}
	if result.Key.DailyLimit != 100 {
		t.Fatalf("DailyLimit = %d, want 100", result.Key.DailyLimit)
	}
	if len(result.Key.AllowedIPs) != 1 || result.Key.AllowedIPs[0] != "198.51.100.10" {
		t.Fatalf("AllowedIPs = %#v", result.Key.AllowedIPs)
	}
	if len(result.Key.AllowedDomains) != 1 || result.Key.AllowedDomains[0] != "example.net" {
		t.Fatalf("AllowedDomains = %#v", result.Key.AllowedDomains)
	}
	if result.Key.ExpiresAt == nil {
		t.Fatalf("expected ExpiresAt to be set")
	}
}
