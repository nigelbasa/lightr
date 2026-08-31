package smtp

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

type stubDomainRepo struct {
	domain *domain.Domain
}

func (s stubDomainRepo) CreateDomain(dom *domain.Domain) error { return nil }
func (s stubDomainRepo) GetDomainByID(id uuid.UUID) (*domain.Domain, error) {
	return s.domain, nil
}
func (s stubDomainRepo) GetDomainByName(name string) (*domain.Domain, error) {
	return s.domain, nil
}
func (s stubDomainRepo) ListDomainsByOrg(orgID uuid.UUID) ([]*domain.Domain, error) {
	return []*domain.Domain{s.domain}, nil
}
func (s stubDomainRepo) UpdateDomain(dom *domain.Domain) error { return nil }

func TestAuthenticatedSessionRejectsSpoofedMailFrom(t *testing.T) {
	domainID := uuid.New()
	s := &Session{
		backend: &Backend{
			DomainRepo: stubDomainRepo{domain: &domain.Domain{ID: domainID, Name: "mail.example.test"}},
		},
		account: &domain.Account{
			ID:       uuid.New(),
			DomainID: domainID,
			Email:    "alice@mail.example.test",
		},
	}

	if err := s.Mail("mallory@example.net", nil); err == nil {
		t.Fatalf("expected spoofed MAIL FROM to be rejected")
	}
}

func TestRewriteFromHeaderNormalizesSender(t *testing.T) {
	s := &Session{}
	raw := []byte("From: mallory@example.net\r\nSubject: hi\r\n\r\nhello")

	rewritten := string(s.rewriteFromHeader(raw, "Alice", "alice@mail.example.test"))
	if !strings.Contains(rewritten, `From: "Alice" <alice@mail.example.test>`) {
		t.Fatalf("expected rewritten From header, got %q", rewritten)
	}
	if strings.Contains(rewritten, "mallory@example.net") {
		t.Fatalf("expected original sender to be replaced, got %q", rewritten)
	}
}

func TestOutboundHostnamePrefersDomainMailHostname(t *testing.T) {
	domainID := uuid.New()
	s := &Session{
		backend: &Backend{
			DomainRepo: stubDomainRepo{domain: &domain.Domain{
				ID:           domainID,
				Name:         "mail.example.test",
				MailHostname: "mx.example.test",
			}},
			Relay: &Relay{hostname: "smtp.example.test"},
		},
	}

	if got := s.outboundHostname("alice@mail.example.test"); got != "mx.example.test" {
		t.Fatalf("outboundHostname() = %q, want %q", got, "mx.example.test")
	}
}
