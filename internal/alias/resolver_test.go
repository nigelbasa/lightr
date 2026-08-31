package alias

import (
	"testing"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

func TestResolver_Resolve(t *testing.T) {
	aliasStore := &mockAliasStore{
		aliases: make(map[string]*Alias),
	}
	domainStore := &mockDomainStore{
		domains: make(map[string]*domain.Domain),
	}

	// Setup test domain
	domainID := uuid.New()
	domainStore.domains["example.com"] = &domain.Domain{
		ID:   domainID,
		Name: "example.com",
	}

	// Setup test aliases
	aliasStore.aliases["forward"] = &Alias{
		ID:           uuid.New(),
		DomainID:     domainID,
		Source:       "forward",
		Type:         AliasTypeForward,
		Destinations: []string{"user1@example.com", "user2@example.com"},
		IsActive:     true,
	}
	aliasStore.aliases["*"] = &Alias{
		ID:           uuid.New(),
		DomainID:     domainID,
		Source:       "*",
		Type:         AliasTypeCatchAll,
		Destinations: []string{"catchall@example.com"},
		IsActive:     true,
	}

	resolver := NewResolver(aliasStore, domainStore)

	tests := []struct {
		name        string
		address     string
		wantIsAlias bool
		wantType    AliasType
	}{
		{
			name:        "simple forward",
			address:     "forward@example.com",
			wantIsAlias: true,
			wantType:    AliasTypeForward,
		},
		{
			name:        "catch-all",
			address:     "unknown@example.com",
			wantIsAlias: true,
			wantType:    AliasTypeCatchAll,
		},
		{
			name:        "no alias - external domain",
			address:     "user@other.com",
			wantIsAlias: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolver.Resolve(tt.address)
			if err != nil {
				t.Errorf("Resolve() error = %v", err)
				return
			}

			if result.IsAlias != tt.wantIsAlias {
				t.Errorf("IsAlias = %v, want %v", result.IsAlias, tt.wantIsAlias)
			}

			if tt.wantIsAlias && result.AliasType != tt.wantType {
				t.Errorf("AliasType = %v, want %v", result.AliasType, tt.wantType)
			}
		})
	}
}

func TestAliasType_Values(t *testing.T) {
	tests := []struct {
		at   AliasType
		want string
	}{
		{AliasTypeForward, "forward"},
		{AliasTypeCatchAll, "catchall"},
		{AliasTypeRegex, "regex"},
		{AliasTypeBridge, "bridge"},
	}

	for _, tt := range tests {
		if string(tt.at) != tt.want {
			t.Errorf("AliasType = %v, want %v", tt.at, tt.want)
		}
	}
}

// mockAliasStore implements Repository interface for testing
type mockAliasStore struct {
	aliases map[string]*Alias
}

func (m *mockAliasStore) Create(alias *Alias) error {
	m.aliases[alias.Source] = alias
	return nil
}

func (m *mockAliasStore) GetByID(id uuid.UUID) (*Alias, error) {
	for _, a := range m.aliases {
		if a.ID == id {
			return a, nil
		}
	}
	return nil, nil
}

func (m *mockAliasStore) FindByAddress(localPart, domainID string) (*Alias, error) {
	// Direct match
	if a, ok := m.aliases[localPart]; ok && a.DomainID.String() == domainID {
		return a, nil
	}

	// Check catch-all
	if a, ok := m.aliases["*"]; ok && a.DomainID.String() == domainID {
		return a, nil
	}

	return nil, nil
}

func (m *mockAliasStore) ListByDomain(domainID uuid.UUID) ([]*Alias, error) {
	var result []*Alias
	for _, a := range m.aliases {
		if a.DomainID == domainID {
			result = append(result, a)
		}
	}
	return result, nil
}

func (m *mockAliasStore) Update(alias *Alias) error {
	m.aliases[alias.Source] = alias
	return nil
}

func (m *mockAliasStore) Delete(id uuid.UUID) error {
	for source, a := range m.aliases {
		if a.ID == id {
			delete(m.aliases, source)
			return nil
		}
	}
	return nil
}

// mockDomainStore implements domain.DomainRepository for testing
type mockDomainStore struct {
	domains map[string]*domain.Domain
}

func (m *mockDomainStore) CreateDomain(d *domain.Domain) error {
	m.domains[d.Name] = d
	return nil
}

func (m *mockDomainStore) GetDomainByName(name string) (*domain.Domain, error) {
	if d, ok := m.domains[name]; ok {
		return d, nil
	}
	return nil, nil
}

func (m *mockDomainStore) GetDomainByID(id uuid.UUID) (*domain.Domain, error) {
	for _, d := range m.domains {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, nil
}

func (m *mockDomainStore) ListDomainsByOrg(orgID uuid.UUID) ([]*domain.Domain, error) {
	return nil, nil
}

func (m *mockDomainStore) UpdateDomain(d *domain.Domain) error {
	m.domains[d.Name] = d
	return nil
}
