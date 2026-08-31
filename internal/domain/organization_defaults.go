package domain

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const DefaultOrganizationName = "default"

func IsDefaultOrganizationName(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), DefaultOrganizationName)
}

func ResolveDefaultOrganization(repo OrganizationRepository) (*Organization, error) {
	if repo == nil {
		return nil, fmt.Errorf("organization repository is required")
	}

	org, err := repo.GetOrgByName(DefaultOrganizationName)
	if err == nil {
		return org, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	org = &Organization{
		ID:        uuid.New(),
		Name:      DefaultOrganizationName,
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateOrg(org); err != nil {
		existing, getErr := repo.GetOrgByName(DefaultOrganizationName)
		if getErr == nil {
			return existing, nil
		}
		return nil, err
	}
	return org, nil
}
