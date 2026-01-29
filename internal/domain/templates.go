package domain

import (
	"time"

	"github.com/google/uuid"
)

type Template struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	Name      string    `json:"name"`
	Subject   string    `json:"subject"`
	Content   string    `json:"content"` // HTML or Text
	CreatedAt time.Time `json:"created_at"`
}

type TemplateRepository interface {
	CreateTemplate(t *Template) error
	GetTemplateByID(id uuid.UUID) (*Template, error)
	GetTemplateByName(orgID uuid.UUID, name string) (*Template, error)
	ListTemplatesByOrg(orgID uuid.UUID) ([]*Template, error)
	DeleteTemplate(id uuid.UUID) error
}
