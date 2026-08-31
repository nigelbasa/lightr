package api

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

type fakeOrgRepo struct {
	org *domain.Organization
}

func (f fakeOrgRepo) CreateOrg(org *domain.Organization) error              { return nil }
func (f fakeOrgRepo) GetOrgByID(id uuid.UUID) (*domain.Organization, error) { return f.org, nil }
func (f fakeOrgRepo) ListOrgs() ([]*domain.Organization, error) {
	return []*domain.Organization{f.org}, nil
}
func (f fakeOrgRepo) GetOrgByName(name string) (*domain.Organization, error) {
	if f.org != nil && f.org.Name == name {
		return f.org, nil
	}
	return nil, sql.ErrNoRows
}

type fakeDomainRepo struct {
	domain *domain.Domain
}

func (f fakeDomainRepo) CreateDomain(dom *domain.Domain) error              { return nil }
func (f fakeDomainRepo) GetDomainByID(id uuid.UUID) (*domain.Domain, error) { return f.domain, nil }
func (f fakeDomainRepo) ListDomainsByOrg(orgID uuid.UUID) ([]*domain.Domain, error) {
	return []*domain.Domain{f.domain}, nil
}
func (f fakeDomainRepo) UpdateDomain(dom *domain.Domain) error { return nil }
func (f fakeDomainRepo) GetDomainByName(name string) (*domain.Domain, error) {
	if f.domain != nil && f.domain.Name == name {
		return f.domain, nil
	}
	return nil, errors.New("not found")
}

func TestResolveOrgRefByName(t *testing.T) {
	orgID := uuid.New()
	h := &Handler{
		orgRepo: fakeOrgRepo{org: &domain.Organization{
			ID:        orgID,
			Name:      "Acme",
			CreatedAt: time.Now(),
		}},
	}

	got, err := h.resolveOrgRef("", "Acme")
	if err != nil {
		t.Fatalf("expected org resolution, got error: %v", err)
	}
	if got != orgID {
		t.Fatalf("expected %s, got %s", orgID, got)
	}
}

func TestResolveOrgRefOrDefaultUsesDefaultOrg(t *testing.T) {
	orgID := uuid.New()
	h := &Handler{
		orgRepo: fakeOrgRepo{org: &domain.Organization{
			ID:        orgID,
			Name:      domain.DefaultOrganizationName,
			CreatedAt: time.Now(),
		}},
	}

	got, err := h.resolveOrgRefOrDefault("", "")
	if err != nil {
		t.Fatalf("expected default org resolution, got error: %v", err)
	}
	if got != orgID {
		t.Fatalf("expected %s, got %s", orgID, got)
	}
}

func TestResolveDomainRefByName(t *testing.T) {
	domainID := uuid.New()
	h := &Handler{
		domainRepo: fakeDomainRepo{domain: &domain.Domain{
			ID:   domainID,
			Name: "mail.example.com",
		}},
	}

	got, err := h.resolveDomainRef("", "mail.example.com")
	if err != nil {
		t.Fatalf("expected domain resolution, got error: %v", err)
	}
	if got != domainID {
		t.Fatalf("expected %s, got %s", domainID, got)
	}
}

func TestBuildDomainDNSResponsePrefersDomainMailHostname(t *testing.T) {
	dom := &domain.Domain{
		ID:           uuid.New(),
		Name:         "example.test",
		MailHostname: "mx.example.test",
		DKIMSelector: "default",
	}
	h := &Handler{serverHostname: "smtp.example.test"}

	got, err := h.buildDomainDNSResponse(dom)
	if err != nil {
		t.Fatalf("buildDomainDNSResponse() error = %v", err)
	}
	if got.MailHostname != "mx.example.test" {
		t.Fatalf("MailHostname = %q, want %q", got.MailHostname, "mx.example.test")
	}
	if len(got.Records.MX) == 0 || got.Records.MX[0] != "10 mx.example.test" {
		t.Fatalf("MX records = %#v, want first record %q", got.Records.MX, "10 mx.example.test")
	}
}
