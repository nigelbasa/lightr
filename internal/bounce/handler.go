package bounce

import (
	"bytes"
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
	"github.com/nigelbasa/lightr/internal/webhook"
)

// Handler processes incoming bounce emails
type Handler struct {
	parser     *Parser
	repo       *SQLiteRepository
	domainRepo domain.DomainRepository
	webhookSvc *webhook.Service
}

// NewHandler creates a new bounce handler
func NewHandler(repo *SQLiteRepository, domainRepo domain.DomainRepository, webhookSvc *webhook.Service) *Handler {
	return &Handler{
		parser:     NewParser(),
		repo:       repo,
		domainRepo: domainRepo,
		webhookSvc: webhookSvc,
	}
}

// Process handles an incoming email that might be a bounce
// Returns true if the email was identified as a bounce
func (h *Handler) Process(ctx context.Context, domainID uuid.UUID, emailData []byte) (bool, error) {
	info, err := h.parser.Parse(bytes.NewReader(emailData))
	if err != nil {
		return false, err
	}

	if info == nil {
		// Not a bounce
		return false, nil
	}

	// Get domain for org ID
	dom, err := h.domainRepo.GetDomainByID(domainID)
	if err != nil {
		return true, err
	}

	// Create bounce record
	record := &BounceRecord{
		ID:             uuid.New(),
		OrgID:          dom.OrgID,
		DomainID:       domainID,
		OriginalMsgID:  info.OriginalMsgID,
		RecipientEmail: info.OriginalTo,
		BounceType:     info.Type,
		DiagnosticCode: info.DiagnosticCode,
		RemoteMTA:      info.RemoteMTA,
		CreatedAt:      time.Now(),
	}

	if err := h.repo.Create(record); err != nil {
		log.Printf("Failed to store bounce record: %v", err)
		return true, err
	}

	log.Printf("Processed %s bounce for %s: %s", info.Type, info.OriginalTo, info.DiagnosticCode)

	// Trigger webhook if configured
	if dom.WebhookURL != "" && h.webhookSvc != nil {
		eventType := webhook.EventType("email.bounced")
		h.webhookSvc.Trigger(ctx, dom.WebhookURL, eventType, map[string]interface{}{
			"bounce_id":       record.ID.String(),
			"bounce_type":     string(info.Type),
			"recipient":       info.OriginalTo,
			"diagnostic_code": info.DiagnosticCode,
			"original_msg_id": info.OriginalMsgID,
			"remote_mta":      info.RemoteMTA,
		})
	}

	return true, nil
}

// ShouldSuppress checks if an email should be suppressed from sending
func (h *Handler) ShouldSuppress(email string) bool {
	suppressed, err := h.repo.IsSuppressed(email)
	if err != nil {
		log.Printf("Error checking suppression for %s: %v", email, err)
		return false
	}
	return suppressed
}

// GetStats returns bounce statistics for a domain
func (h *Handler) GetStats(domainID uuid.UUID, since time.Time) (*BounceStats, error) {
	dom, err := h.domainRepo.GetDomainByID(domainID)
	if err != nil {
		return nil, err
	}

	bounces, err := h.repo.ListByOrg(dom.OrgID, 1000)
	if err != nil {
		return nil, err
	}

	stats := &BounceStats{
		Since: since,
	}

	for _, b := range bounces {
		if b.CreatedAt.Before(since) {
			continue
		}
		stats.Total++
		switch b.BounceType {
		case BounceTypeHard:
			stats.Hard++
		case BounceTypeSoft:
			stats.Soft++
		case BounceTypeComplaint:
			stats.Complaints++
		}
	}

	return stats, nil
}

// BounceStats contains bounce statistics
type BounceStats struct {
	Since      time.Time `json:"since"`
	Total      int       `json:"total"`
	Hard       int       `json:"hard"`
	Soft       int       `json:"soft"`
	Complaints int       `json:"complaints"`
}
