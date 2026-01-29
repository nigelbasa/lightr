package domain

import (
	"bytes"
	"context"
	"html/template"

	"github.com/google/uuid"
)

type TemplateService struct {
	repo TemplateRepository
}

func NewTemplateService(repo TemplateRepository) *TemplateService {
	return &TemplateService{repo: repo}
}

func (s *TemplateService) Render(ctx context.Context, orgID uuid.UUID, templateName string, data interface{}) (string, string, error) {
	tmpl, err := s.repo.GetTemplateByName(orgID, templateName)
	if err != nil {
		return "", "", err
	}

	// Parse and render Subject
	subjectTmpl, err := template.New("subject").Parse(tmpl.Subject)
	if err != nil {
		return "", "", err
	}
	var subjectBuf bytes.Buffer
	if err := subjectTmpl.Execute(&subjectBuf, data); err != nil {
		return "", "", err
	}

	// Parse and render Content
	contentTmpl, err := template.New("content").Parse(tmpl.Content)
	if err != nil {
		return "", "", err
	}
	var contentBuf bytes.Buffer
	if err := contentTmpl.Execute(&contentBuf, data); err != nil {
		return "", "", err
	}

	return subjectBuf.String(), contentBuf.String(), nil
}
