package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/apikeys"
	"github.com/nigelbasa/lightr/internal/domain"
)

type fakeAccountRepo struct {
	accounts map[uuid.UUID]*domain.Account
}

func (f fakeAccountRepo) CreateAccount(acc *domain.Account) error { return nil }
func (f fakeAccountRepo) GetAccountByID(id uuid.UUID) (*domain.Account, error) {
	if acc, ok := f.accounts[id]; ok {
		return acc, nil
	}
	return nil, errors.New("not found")
}
func (f fakeAccountRepo) GetAccountByEmail(email string) (*domain.Account, error) {
	for _, acc := range f.accounts {
		if acc.Email == email {
			return acc, nil
		}
	}
	return nil, errors.New("not found")
}
func (f fakeAccountRepo) GetAccountByLocalPart(domainID uuid.UUID, localPart string) (*domain.Account, error) {
	for _, acc := range f.accounts {
		if acc.DomainID == domainID && acc.LocalPart == localPart {
			return acc, nil
		}
	}
	return nil, errors.New("not found")
}
func (f fakeAccountRepo) UpdateAccount(acc *domain.Account) error { return nil }
func (f fakeAccountRepo) DeleteAccount(id uuid.UUID) error        { return nil }
func (f fakeAccountRepo) SearchByDomain(domainName, query string, limit int) ([]*domain.Account, error) {
	return nil, nil
}

func TestAuthorizeDomainWithOrgScopedKey(t *testing.T) {
	orgID := uuid.New()
	domainID := uuid.New()
	h := &Handler{
		domainRepo:  fakeDomainRepo{domain: &domain.Domain{ID: domainID, OrgID: orgID, Name: "mail.example.test"}},
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{}},
	}
	key := &apikeys.APIKey{
		OrganizationID: &orgID,
		Permissions:    []apikeys.Permission{apikeys.PermManageDomain},
	}
	req := httptest.NewRequest("GET", "/v1/domains/"+domainID.String(), nil).WithContext(context.WithValue(context.Background(), apiKeyContextKey, key))
	w := httptest.NewRecorder()

	if !h.authorizeDomain(w, req, domainID, apikeys.PermManageDomain) {
		t.Fatalf("expected org-scoped key to access domain in same org")
	}
}

func TestAuthorizeDomainRejectsWrongDomainScopedKey(t *testing.T) {
	orgID := uuid.New()
	domainID := uuid.New()
	otherDomainID := uuid.New()
	h := &Handler{
		domainRepo:  fakeDomainRepo{domain: &domain.Domain{ID: domainID, OrgID: orgID, Name: "mail.example.test"}},
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{}},
	}
	key := &apikeys.APIKey{
		DomainID:    &otherDomainID,
		Permissions: []apikeys.Permission{apikeys.PermManageDomain},
	}
	req := httptest.NewRequest("GET", "/v1/domains/"+domainID.String(), nil).WithContext(context.WithValue(context.Background(), apiKeyContextKey, key))
	w := httptest.NewRecorder()

	if h.authorizeDomain(w, req, domainID, apikeys.PermManageDomain) {
		t.Fatalf("expected mismatched domain-scoped key to be denied")
	}
}

func TestAuthorizeAccountWithAccountScopedKey(t *testing.T) {
	orgID := uuid.New()
	domainID := uuid.New()
	accountID := uuid.New()
	otherAccountID := uuid.New()
	h := &Handler{
		domainRepo: fakeDomainRepo{domain: &domain.Domain{ID: domainID, OrgID: orgID, Name: "mail.example.test"}},
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{
			accountID:      {ID: accountID, DomainID: domainID, LocalPart: "ops", Email: "ops@mail.example.test", CreatedAt: time.Now()},
			otherAccountID: {ID: otherAccountID, DomainID: domainID, LocalPart: "sales", Email: "sales@mail.example.test", CreatedAt: time.Now()},
		}},
	}
	key := &apikeys.APIKey{
		AccountID:   &accountID,
		Permissions: []apikeys.Permission{apikeys.PermReadEmail},
	}
	req := httptest.NewRequest("GET", "/v1/accounts/"+accountID.String(), nil).WithContext(context.WithValue(context.Background(), apiKeyContextKey, key))

	if !h.authorizeAccount(httptest.NewRecorder(), req, accountID, apikeys.PermReadEmail) {
		t.Fatalf("expected account-scoped key to access its own account")
	}
	if h.authorizeAccount(httptest.NewRecorder(), req, otherAccountID, apikeys.PermReadEmail) {
		t.Fatalf("expected account-scoped key to be denied for other account")
	}
}

func TestAuthorizeRejectsKeyMissingPermission(t *testing.T) {
	orgID := uuid.New()
	domainID := uuid.New()
	accountID := uuid.New()
	h := &Handler{
		domainRepo: fakeDomainRepo{domain: &domain.Domain{ID: domainID, OrgID: orgID, Name: "mail.example.test"}},
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{
			accountID: {ID: accountID, DomainID: domainID, LocalPart: "ops", CreatedAt: time.Now()},
		}},
	}
	// Key has no permissions at all — requirePermission writes 403 and
	// returns nil. The wrappers MUST return false so callers abort the
	// mutation; otherwise the 403 response is sent but the DB write still
	// happens.
	key := &apikeys.APIKey{
		AccountID:   &accountID,
		Permissions: []apikeys.Permission{}, // empty
	}
	ctx := context.WithValue(context.Background(), apiKeyContextKey, key)

	req := httptest.NewRequest("DELETE", "/v1/accounts/"+accountID.String(), nil).WithContext(ctx)
	if h.authorizeAccount(httptest.NewRecorder(), req, accountID, apikeys.PermManageUser) {
		t.Fatal("authorizeAccount returned true when permission was denied")
	}

	req = httptest.NewRequest("PATCH", "/v1/domains/"+domainID.String(), nil).WithContext(ctx)
	if h.authorizeDomain(httptest.NewRecorder(), req, domainID, apikeys.PermManageDomain) {
		t.Fatal("authorizeDomain returned true when permission was denied")
	}

	req = httptest.NewRequest("POST", "/v1/orgs", nil).WithContext(ctx)
	if h.authorizeOrg(httptest.NewRecorder(), req, orgID, apikeys.PermManageOrg) {
		t.Fatal("authorizeOrg returned true when permission was denied")
	}
}

func TestRequireGlobalPermissionRejectsScopedKey(t *testing.T) {
	orgID := uuid.New()
	key := &apikeys.APIKey{
		OrganizationID: &orgID,
		Permissions:    []apikeys.Permission{apikeys.PermManageOrg},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/orgs", nil).
		WithContext(context.WithValue(context.Background(), apiKeyContextKey, key))

	if (&Handler{}).requireGlobalPermission(httptest.NewRecorder(), req, apikeys.PermManageOrg) {
		t.Fatalf("expected scoped key to be rejected for global-only operation")
	}
}

func TestHandleSendRejectsUnknownSenderAccount(t *testing.T) {
	body := bytes.NewBufferString(`{"from":"spoof@example.net","to":"dest@example.net","subject":"Hello","text":"World"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/send", body).WithContext(context.WithValue(context.Background(), apiKeyContextKey, &apikeys.APIKey{
		Permissions: []apikeys.Permission{apikeys.PermSendEmail},
	}))
	w := httptest.NewRecorder()

	h := &Handler{
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{}},
		domainRepo:  fakeDomainRepo{},
	}
	h.HandleSend(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for unknown sender, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "sender account not found") {
		t.Fatalf("expected sender-account error, got %q", w.Body.String())
	}
}

func TestClientIPIgnoresForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/send", nil)
	req.RemoteAddr = "198.51.100.7:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Real-IP", "203.0.113.10")

	if got := clientIP(req); got != "198.51.100.7" {
		t.Fatalf("clientIP() = %q, want %q", got, "198.51.100.7")
	}
}

func TestHandleCreateAccountRejectsUnverifiedOffloadedDomain(t *testing.T) {
	orgID := uuid.New()
	domainID := uuid.New()
	body := bytes.NewBufferString(`{"domain":"mail.example.test","email":"alice@mail.example.test","auth_mode":"offloaded"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/accounts", body).WithContext(context.WithValue(context.Background(), apiKeyContextKey, &apikeys.APIKey{
		Permissions: []apikeys.Permission{apikeys.PermSuperAdmin},
	}))
	w := httptest.NewRecorder()

	h := &Handler{
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{}},
		domainRepo: fakeDomainRepo{domain: &domain.Domain{
			ID:                  domainID,
			OrgID:               orgID,
			Name:                "mail.example.test",
			AuthWebhookURL:      "https://auth.example.test/check",
			AuthWebhookVerified: false,
		}},
	}

	h.HandleCreateAccount(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(strings.ToLower(w.Body.String()), "verified") {
		t.Fatalf("expected verification error, got %q", w.Body.String())
	}
}

func TestHandleMailboxListRejectsCrossAccountAccessForAccountScopedKey(t *testing.T) {
	orgID := uuid.New()
	domainID := uuid.New()
	aliceID := uuid.New()
	bobID := uuid.New()

	h := &Handler{
		domainRepo: fakeDomainRepo{domain: &domain.Domain{
			ID:    domainID,
			OrgID: orgID,
			Name:  "mail.example.test",
		}},
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{
			aliceID: {ID: aliceID, DomainID: domainID, LocalPart: "alice", Email: "alice@mail.example.test"},
			bobID:   {ID: bobID, DomainID: domainID, LocalPart: "bob", Email: "bob@mail.example.test"},
		}},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/mailbox/messages?email=bob@mail.example.test&folder=INBOX", nil).
		WithContext(context.WithValue(context.Background(), apiKeyContextKey, &apikeys.APIKey{
			AccountID:   &aliceID,
			Permissions: []apikeys.Permission{apikeys.PermReadEmail},
		}))
	w := httptest.NewRecorder()

	h.HandleMailboxList(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleMailboxSendRejectsCrossAccountSenderForAccountScopedKey(t *testing.T) {
	orgID := uuid.New()
	domainID := uuid.New()
	aliceID := uuid.New()
	bobID := uuid.New()

	h := &Handler{
		domainRepo: fakeDomainRepo{domain: &domain.Domain{
			ID:    domainID,
			OrgID: orgID,
			Name:  "mail.example.test",
		}},
		accountRepo: fakeAccountRepo{accounts: map[uuid.UUID]*domain.Account{
			aliceID: {ID: aliceID, DomainID: domainID, LocalPart: "alice", Email: "alice@mail.example.test"},
			bobID:   {ID: bobID, DomainID: domainID, LocalPart: "bob", Email: "bob@mail.example.test"},
		}},
	}

	body := bytes.NewBufferString(`{"from":"bob@mail.example.test","to":["dest@example.net"],"subject":"Hello","text":"World"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/mailbox/send", body).
		WithContext(context.WithValue(context.Background(), apiKeyContextKey, &apikeys.APIKey{
			AccountID:   &aliceID,
			Permissions: []apikeys.Permission{apikeys.PermSendEmail},
		}))
	w := httptest.NewRecorder()

	h.HandleMailboxSend(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d body=%s", w.Code, w.Body.String())
	}
}
