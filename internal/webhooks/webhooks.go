package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Webhook system for analytics, bounces, delivery notifications, and email receipt

var (
	ErrWebhookNotFound    = errors.New("webhook not found")
	ErrWebhookDisabled    = errors.New("webhook disabled")
	ErrDeliveryFailed     = errors.New("webhook delivery failed")
	ErrMaxRetriesExceeded = errors.New("max retries exceeded")
	ErrInvalidSignature   = errors.New("invalid webhook signature")
)

// EventType represents a webhook event type
type EventType string

const (
	// Email lifecycle events
	EventEmailReceived  EventType = "email.received"
	EventEmailSent      EventType = "email.sent"
	EventEmailDelivered EventType = "email.delivered"
	EventEmailBounced   EventType = "email.bounced"
	EventEmailComplaint EventType = "email.complaint"
	EventEmailDeferred  EventType = "email.deferred"
	EventEmailDropped   EventType = "email.dropped"

	// Bounce types
	EventBounceHard  EventType = "bounce.hard"
	EventBounceSoft  EventType = "bounce.soft"
	EventBounceBlock EventType = "bounce.block"

	// Analytics events
	EventAnalyticsDaily   EventType = "analytics.daily"
	EventAnalyticsWeekly  EventType = "analytics.weekly"
	EventAnalyticsMonthly EventType = "analytics.monthly"

	// System events
	EventSystemHealth  EventType = "system.health"
	EventSystemAlert   EventType = "system.alert"
	EventQuotaWarning  EventType = "quota.warning"
	EventQuotaExceeded EventType = "quota.exceeded"

	// Inbound events
	EventInboundParsed   EventType = "inbound.parsed"
	EventInboundSpam     EventType = "inbound.spam"
	EventInboundRejected EventType = "inbound.rejected"
)

// Webhook represents a webhook configuration
type Webhook struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`

	// Target
	URL    string `json:"url"`
	Method string `json:"method"` // POST, PUT

	// Authentication
	Secret    string `json:"-"`         // HMAC signing secret
	AuthType  string `json:"auth_type"` // none, basic, bearer, hmac
	AuthValue string `json:"-"`         // Auth credentials

	// Events
	Events []EventType `json:"events"`

	// Filtering
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
	DomainFilter   []string   `json:"domain_filter,omitempty"`

	// Headers
	Headers map[string]string `json:"headers,omitempty"`

	// Retry settings
	MaxRetries int           `json:"max_retries"`
	RetryDelay time.Duration `json:"retry_delay"`
	Timeout    time.Duration `json:"timeout"`

	// Status
	Active       bool       `json:"active"`
	Verified     bool       `json:"verified"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	LastFailure  *time.Time `json:"last_failure,omitempty"`
	FailureCount int        `json:"failure_count"`

	// Metadata
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WebhookEvent represents an event to be delivered
type WebhookEvent struct {
	ID        uuid.UUID `json:"id"`
	WebhookID uuid.UUID `json:"webhook_id"`
	EventType EventType `json:"event_type"`

	// Payload
	Payload map[string]interface{} `json:"payload"`

	// Delivery status
	Status    DeliveryStatus `json:"status"`
	Attempts  int            `json:"attempts"`
	NextRetry *time.Time     `json:"next_retry,omitempty"`

	// Response info
	ResponseCode int    `json:"response_code,omitempty"`
	ResponseBody string `json:"response_body,omitempty"`
	Error        string `json:"error,omitempty"`

	// Timing
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	Duration    int64      `json:"duration_ms,omitempty"`
}

// DeliveryStatus represents webhook delivery status
type DeliveryStatus string

const (
	StatusPending   DeliveryStatus = "pending"
	StatusDelivered DeliveryStatus = "delivered"
	StatusFailed    DeliveryStatus = "failed"
	StatusRetrying  DeliveryStatus = "retrying"
)

// WebhookPayload is the standard payload format
type WebhookPayload struct {
	ID        string                 `json:"id"`
	Event     EventType              `json:"event"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// EmailEventPayload for email-related events
type EmailEventPayload struct {
	MessageID string            `json:"message_id"`
	From      string            `json:"from"`
	To        []string          `json:"to"`
	Subject   string            `json:"subject"`
	Timestamp time.Time         `json:"timestamp"`
	Tags      map[string]string `json:"tags,omitempty"`

	// Event-specific data
	Recipient    string `json:"recipient,omitempty"`
	BounceType   string `json:"bounce_type,omitempty"`
	BounceCode   string `json:"bounce_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	IP           string `json:"ip,omitempty"`
	LinkURL      string `json:"link_url,omitempty"`
}

// BounceEventPayload for bounce events
type BounceEventPayload struct {
	MessageID   string    `json:"message_id"`
	Recipient   string    `json:"recipient"`
	BounceType  string    `json:"bounce_type"`  // hard, soft, block
	BounceClass string    `json:"bounce_class"` // invalid, full, timeout, etc.
	DiagCode    string    `json:"diagnostic_code"`
	RemoteMTA   string    `json:"remote_mta,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// InboundEventPayload for received emails
type InboundEventPayload struct {
	MessageID   string            `json:"message_id"`
	From        string            `json:"from"`
	To          []string          `json:"to"`
	Cc          []string          `json:"cc,omitempty"`
	Subject     string            `json:"subject"`
	Date        time.Time         `json:"date"`
	TextBody    string            `json:"text_body,omitempty"`
	HTMLBody    string            `json:"html_body,omitempty"`
	Attachments []AttachmentInfo  `json:"attachments,omitempty"`
	Headers     map[string]string `json:"headers"`
	SPFResult   string            `json:"spf_result,omitempty"`
	DKIMResult  string            `json:"dkim_result,omitempty"`
	SpamScore   float64           `json:"spam_score,omitempty"`
}

// AttachmentInfo describes an email attachment
type AttachmentInfo struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	ContentID   string `json:"content_id,omitempty"`
}

// AnalyticsEventPayload for analytics events
type AnalyticsEventPayload struct {
	Period    string    `json:"period"` // daily, weekly, monthly
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`

	Sent       int64 `json:"sent"`
	Delivered  int64 `json:"delivered"`
	Bounced    int64 `json:"bounced"`
	Complaints int64 `json:"complaints"`

	DeliveryRate float64 `json:"delivery_rate"`
	BounceRate   float64 `json:"bounce_rate"`
}

// WebhookService manages webhooks
type WebhookService struct {
	repo       WebhookRepository
	httpClient *http.Client

	// Worker pool
	workerCount int
	eventQueue  chan *WebhookEvent
	stopCh      chan struct{}
	wg          sync.WaitGroup

	logger Logger
}

// WebhookRepository defines storage operations
type WebhookRepository interface {
	// Webhook CRUD
	CreateWebhook(ctx context.Context, webhook *Webhook) error
	GetWebhook(ctx context.Context, id uuid.UUID) (*Webhook, error)
	ListWebhooks(ctx context.Context, orgID *uuid.UUID) ([]*Webhook, error)
	ListWebhooksByEvent(ctx context.Context, event EventType) ([]*Webhook, error)
	UpdateWebhook(ctx context.Context, webhook *Webhook) error
	DeleteWebhook(ctx context.Context, id uuid.UUID) error

	// Event operations
	CreateEvent(ctx context.Context, event *WebhookEvent) error
	GetEvent(ctx context.Context, id uuid.UUID) (*WebhookEvent, error)
	ListEvents(ctx context.Context, webhookID uuid.UUID, limit int) ([]*WebhookEvent, error)
	UpdateEvent(ctx context.Context, event *WebhookEvent) error
	GetPendingEvents(ctx context.Context, limit int) ([]*WebhookEvent, error)
	GetRetryableEvents(ctx context.Context, limit int) ([]*WebhookEvent, error)

	// Statistics
	GetDeliveryStats(ctx context.Context, webhookID uuid.UUID, days int) (*DeliveryStats, error)
}

// DeliveryStats holds webhook delivery statistics
type DeliveryStats struct {
	Total      int64   `json:"total"`
	Delivered  int64   `json:"delivered"`
	Failed     int64   `json:"failed"`
	Pending    int64   `json:"pending"`
	AvgLatency float64 `json:"avg_latency_ms"`
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewWebhookService creates a new webhook service
func NewWebhookService(repo WebhookRepository, logger Logger) *WebhookService {
	return &WebhookService{
		repo: repo,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				// SSRF guard: refuse to connect to internal IPs even if a
				// crafted DNS record points there. This is the authoritative
				// defense — the upfront URL validator only complements it.
				DialContext: safeDialContext(),
			},
		},
		workerCount: 10,
		eventQueue:  make(chan *WebhookEvent, 1000),
		stopCh:      make(chan struct{}),
		logger:      logger,
	}
}

// Start starts the webhook delivery workers
func (s *WebhookService) Start() {
	for i := 0; i < s.workerCount; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	// Start retry processor
	s.wg.Add(1)
	go s.retryProcessor()

	s.logger.Info("webhook service started", "workers", s.workerCount)
}

// Stop stops the webhook service
func (s *WebhookService) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info("webhook service stopped")
}

// worker processes webhook events
func (s *WebhookService) worker() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			return
		case event := <-s.eventQueue:
			s.deliverEvent(event)
		}
	}
}

// retryProcessor periodically checks for events to retry
func (s *WebhookService) retryProcessor() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.processRetries()
		}
	}
}

func (s *WebhookService) processRetries() {
	ctx := context.Background()
	events, err := s.repo.GetRetryableEvents(ctx, 100)
	if err != nil {
		s.logger.Error("failed to get retryable events", "error", err)
		return
	}

	for _, event := range events {
		select {
		case s.eventQueue <- event:
		default:
			// Queue full, skip for now
		}
	}
}

// CreateWebhook creates a new webhook
func (s *WebhookService) CreateWebhook(ctx context.Context, webhook *Webhook) error {
	if err := ValidateWebhookURL(webhook.URL); err != nil {
		return err
	}
	webhook.ID = uuid.New()
	webhook.CreatedAt = time.Now()
	webhook.UpdatedAt = time.Now()

	// Set defaults
	if webhook.Method == "" {
		webhook.Method = "POST"
	}
	if webhook.MaxRetries == 0 {
		webhook.MaxRetries = 5
	}
	if webhook.RetryDelay == 0 {
		webhook.RetryDelay = 60 * time.Second
	}
	if webhook.Timeout == 0 {
		webhook.Timeout = 30 * time.Second
	}

	// Generate signing secret if HMAC auth
	if webhook.AuthType == "hmac" && webhook.Secret == "" {
		webhook.Secret = generateSecret(32)
	}

	return s.repo.CreateWebhook(ctx, webhook)
}

// DeliverOnce delivers a single event to a specific URL, bypassing the
// subscription store. Used for per-domain WebhookURL settings that aren't
// stored as Webhook subscriptions but should still benefit from the safe
// HTTP transport (SSRF guard, timeouts) and basic event auditing.
func (s *WebhookService) DeliverOnce(ctx context.Context, url string, eventType EventType, data map[string]interface{}) error {
	if url == "" {
		return nil
	}
	if err := ValidateWebhookURL(url); err != nil {
		s.logger.Error("rejecting unsafe webhook url", "url", url, "error", err)
		return err
	}
	payload := WebhookPayload{
		ID:        uuid.New().String(),
		Event:     eventType,
		Timestamp: time.Now(),
		Data:      data,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Lightr-Webhook/1.0")
	req.Header.Set("X-Event-Type", string(eventType))
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("webhook one-shot delivery failed", "url", url, "error", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Error("webhook one-shot non-2xx", "url", url, "status", resp.StatusCode)
	}
	return nil
}

// Trigger triggers a webhook event
func (s *WebhookService) Trigger(ctx context.Context, eventType EventType, data map[string]interface{}) error {
	// Find webhooks subscribed to this event
	webhooks, err := s.repo.ListWebhooksByEvent(ctx, eventType)
	if err != nil {
		return err
	}

	for _, webhook := range webhooks {
		if !webhook.Active {
			continue
		}

		// Create event
		event := &WebhookEvent{
			ID:        uuid.New(),
			WebhookID: webhook.ID,
			EventType: eventType,
			Payload:   data,
			Status:    StatusPending,
			CreatedAt: time.Now(),
		}

		if err := s.repo.CreateEvent(ctx, event); err != nil {
			s.logger.Error("failed to create webhook event", "error", err)
			continue
		}

		// Queue for delivery
		select {
		case s.eventQueue <- event:
		default:
			s.logger.Error("webhook queue full", "event_id", event.ID)
		}
	}

	return nil
}

// TriggerEmailEvent triggers an email-related webhook event
func (s *WebhookService) TriggerEmailEvent(ctx context.Context, eventType EventType, payload *EmailEventPayload) error {
	data := map[string]interface{}{
		"message_id": payload.MessageID,
		"from":       payload.From,
		"to":         payload.To,
		"subject":    payload.Subject,
		"timestamp":  payload.Timestamp,
	}

	if payload.Recipient != "" {
		data["recipient"] = payload.Recipient
	}
	if payload.BounceType != "" {
		data["bounce_type"] = payload.BounceType
	}
	if payload.ErrorMessage != "" {
		data["error_message"] = payload.ErrorMessage
	}
	if payload.UserAgent != "" {
		data["user_agent"] = payload.UserAgent
	}
	if payload.IP != "" {
		data["ip"] = payload.IP
	}
	if payload.LinkURL != "" {
		data["link_url"] = payload.LinkURL
	}
	if len(payload.Tags) > 0 {
		data["tags"] = payload.Tags
	}

	return s.Trigger(ctx, eventType, data)
}

// TriggerBounceEvent triggers a bounce webhook event
func (s *WebhookService) TriggerBounceEvent(ctx context.Context, payload *BounceEventPayload) error {
	eventType := EventEmailBounced
	switch payload.BounceType {
	case "hard":
		eventType = EventBounceHard
	case "soft":
		eventType = EventBounceSoft
	case "block":
		eventType = EventBounceBlock
	}

	data := map[string]interface{}{
		"message_id":      payload.MessageID,
		"recipient":       payload.Recipient,
		"bounce_type":     payload.BounceType,
		"bounce_class":    payload.BounceClass,
		"diagnostic_code": payload.DiagCode,
		"timestamp":       payload.Timestamp,
	}
	if payload.RemoteMTA != "" {
		data["remote_mta"] = payload.RemoteMTA
	}

	return s.Trigger(ctx, eventType, data)
}

// TriggerInboundEvent triggers an inbound email webhook event
func (s *WebhookService) TriggerInboundEvent(ctx context.Context, payload *InboundEventPayload) error {
	data := map[string]interface{}{
		"message_id": payload.MessageID,
		"from":       payload.From,
		"to":         payload.To,
		"subject":    payload.Subject,
		"date":       payload.Date,
		"headers":    payload.Headers,
	}

	if len(payload.Cc) > 0 {
		data["cc"] = payload.Cc
	}
	if payload.TextBody != "" {
		data["text_body"] = payload.TextBody
	}
	if payload.HTMLBody != "" {
		data["html_body"] = payload.HTMLBody
	}
	if len(payload.Attachments) > 0 {
		data["attachments"] = payload.Attachments
	}
	if payload.SPFResult != "" {
		data["spf_result"] = payload.SPFResult
	}
	if payload.DKIMResult != "" {
		data["dkim_result"] = payload.DKIMResult
	}
	if payload.SpamScore > 0 {
		data["spam_score"] = payload.SpamScore
	}

	return s.Trigger(ctx, EventInboundParsed, data)
}

// TriggerAnalyticsEvent triggers an analytics webhook event
func (s *WebhookService) TriggerAnalyticsEvent(ctx context.Context, payload *AnalyticsEventPayload) error {
	var eventType EventType
	switch payload.Period {
	case "daily":
		eventType = EventAnalyticsDaily
	case "weekly":
		eventType = EventAnalyticsWeekly
	case "monthly":
		eventType = EventAnalyticsMonthly
	default:
		eventType = EventAnalyticsDaily
	}

	data := map[string]interface{}{
		"period":        payload.Period,
		"start_date":    payload.StartDate,
		"end_date":      payload.EndDate,
		"sent":          payload.Sent,
		"delivered":     payload.Delivered,
		"bounced":       payload.Bounced,
		"complaints":    payload.Complaints,
		"delivery_rate": payload.DeliveryRate,
		"bounce_rate":   payload.BounceRate,
	}

	return s.Trigger(ctx, eventType, data)
}

// deliverEvent delivers a webhook event
func (s *WebhookService) deliverEvent(event *WebhookEvent) {
	ctx := context.Background()

	webhook, err := s.repo.GetWebhook(ctx, event.WebhookID)
	if err != nil {
		event.Status = StatusFailed
		event.Error = "webhook not found"
		s.repo.UpdateEvent(ctx, event)
		return
	}

	// Build payload
	payload := WebhookPayload{
		ID:        event.ID.String(),
		Event:     event.EventType,
		Timestamp: event.CreatedAt,
		Data:      event.Payload,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		event.Status = StatusFailed
		event.Error = err.Error()
		s.repo.UpdateEvent(ctx, event)
		return
	}

	// Create request
	req, err := http.NewRequest(webhook.Method, webhook.URL, bytes.NewReader(body))
	if err != nil {
		event.Status = StatusFailed
		event.Error = err.Error()
		s.repo.UpdateEvent(ctx, event)
		return
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Lightr-Webhook/1.0")
	req.Header.Set("X-Webhook-ID", webhook.ID.String())
	req.Header.Set("X-Event-ID", event.ID.String())
	req.Header.Set("X-Event-Type", string(event.EventType))

	// Add custom headers
	for k, v := range webhook.Headers {
		req.Header.Set(k, v)
	}

	// Add authentication
	s.addAuth(req, webhook, body)

	// Send request
	start := time.Now()
	resp, err := s.httpClient.Do(req)
	duration := time.Since(start)

	event.Duration = duration.Milliseconds()
	event.Attempts++

	if err != nil {
		s.handleDeliveryFailure(ctx, event, webhook, err.Error())
		return
	}
	defer resp.Body.Close()

	// Read response
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	event.ResponseCode = resp.StatusCode
	event.ResponseBody = string(respBody)

	// Check status
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		event.Status = StatusDelivered
		now := time.Now()
		event.DeliveredAt = &now

		// Update webhook success
		webhook.LastSuccess = &now
		webhook.FailureCount = 0
		s.repo.UpdateWebhook(ctx, webhook)

		s.logger.Debug("webhook delivered", "event_id", event.ID, "webhook_id", webhook.ID)
	} else {
		s.handleDeliveryFailure(ctx, event, webhook, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}

	s.repo.UpdateEvent(ctx, event)
}

func (s *WebhookService) addAuth(req *http.Request, webhook *Webhook, body []byte) {
	switch webhook.AuthType {
	case "basic":
		req.SetBasicAuth(webhook.AuthValue, webhook.Secret)

	case "bearer":
		req.Header.Set("Authorization", "Bearer "+webhook.AuthValue)

	case "hmac":
		// Sign with HMAC-SHA256
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		signaturePayload := timestamp + "." + string(body)

		mac := hmac.New(sha256.New, []byte(webhook.Secret))
		mac.Write([]byte(signaturePayload))
		signature := hex.EncodeToString(mac.Sum(nil))

		req.Header.Set("X-Webhook-Timestamp", timestamp)
		req.Header.Set("X-Webhook-Signature", "sha256="+signature)
	}
}

func (s *WebhookService) handleDeliveryFailure(ctx context.Context, event *WebhookEvent, webhook *Webhook, errMsg string) {
	event.Error = errMsg

	if event.Attempts >= webhook.MaxRetries {
		event.Status = StatusFailed
		s.logger.Error("webhook delivery failed after retries",
			"event_id", event.ID, "webhook_id", webhook.ID, "error", errMsg)
	} else {
		event.Status = StatusRetrying
		nextRetry := time.Now().Add(webhook.RetryDelay * time.Duration(event.Attempts))
		event.NextRetry = &nextRetry
		s.logger.Debug("webhook delivery retry scheduled",
			"event_id", event.ID, "attempt", event.Attempts, "next_retry", nextRetry)
	}

	// Update webhook failure stats
	now := time.Now()
	webhook.LastFailure = &now
	webhook.FailureCount++
	webhook.UpdatedAt = now
	s.repo.UpdateWebhook(ctx, webhook)
}

// VerifyWebhook sends a test event to verify webhook
func (s *WebhookService) VerifyWebhook(ctx context.Context, webhookID uuid.UUID) error {
	webhook, err := s.repo.GetWebhook(ctx, webhookID)
	if err != nil {
		return err
	}

	// Create test event
	event := &WebhookEvent{
		ID:        uuid.New(),
		WebhookID: webhook.ID,
		EventType: "webhook.test",
		Payload: map[string]interface{}{
			"message":    "This is a test webhook from Lightr",
			"webhook_id": webhook.ID.String(),
		},
		Status:    StatusPending,
		CreatedAt: time.Now(),
	}

	// Deliver synchronously
	s.deliverEvent(event)

	if event.Status == StatusDelivered {
		webhook.Verified = true
		webhook.UpdatedAt = time.Now()
		return s.repo.UpdateWebhook(ctx, webhook)
	}

	return fmt.Errorf("verification failed: %s", event.Error)
}

// GetWebhook retrieves a webhook
func (s *WebhookService) GetWebhook(ctx context.Context, id uuid.UUID) (*Webhook, error) {
	return s.repo.GetWebhook(ctx, id)
}

// ListWebhooks lists webhooks for an organization
func (s *WebhookService) ListWebhooks(ctx context.Context, orgID *uuid.UUID) ([]*Webhook, error) {
	return s.repo.ListWebhooks(ctx, orgID)
}

// UpdateWebhook updates a webhook
func (s *WebhookService) UpdateWebhook(ctx context.Context, webhook *Webhook) error {
	if err := ValidateWebhookURL(webhook.URL); err != nil {
		return err
	}
	webhook.UpdatedAt = time.Now()
	return s.repo.UpdateWebhook(ctx, webhook)
}

// DeleteWebhook deletes a webhook
func (s *WebhookService) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteWebhook(ctx, id)
}

// GetEvents retrieves webhook events
func (s *WebhookService) GetEvents(ctx context.Context, webhookID uuid.UUID, limit int) ([]*WebhookEvent, error) {
	return s.repo.ListEvents(ctx, webhookID, limit)
}

// GetDeliveryStats retrieves delivery statistics
func (s *WebhookService) GetDeliveryStats(ctx context.Context, webhookID uuid.UUID, days int) (*DeliveryStats, error) {
	return s.repo.GetDeliveryStats(ctx, webhookID, days)
}

// Helper function to generate random secret
func generateSecret(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// WebhookHandler provides HTTP endpoints for webhook management
type WebhookHandler struct {
	service *WebhookService
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(service *WebhookService) *WebhookHandler {
	return &WebhookHandler{service: service}
}

// Mount mounts webhook endpoints
func (h *WebhookHandler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /webhooks", h.handleList)
	mux.HandleFunc("POST /webhooks", h.handleCreate)
	mux.HandleFunc("GET /webhooks/{id}", h.handleGet)
	mux.HandleFunc("PUT /webhooks/{id}", h.handleUpdate)
	mux.HandleFunc("DELETE /webhooks/{id}", h.handleDelete)
	mux.HandleFunc("POST /webhooks/{id}/verify", h.handleVerify)
	mux.HandleFunc("GET /webhooks/{id}/events", h.handleEvents)
	mux.HandleFunc("GET /webhooks/{id}/stats", h.handleStats)
}

func (h *WebhookHandler) handleList(w http.ResponseWriter, r *http.Request) {
	webhooks, err := h.service.ListWebhooks(r.Context(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(webhooks)
}

func (h *WebhookHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var webhook Webhook
	if err := json.NewDecoder(r.Body).Decode(&webhook); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.service.CreateWebhook(r.Context(), &webhook); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(webhook)
}

func (h *WebhookHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	webhook, err := h.service.GetWebhook(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(webhook)
}

func (h *WebhookHandler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	webhook, err := h.service.GetWebhook(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(webhook); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.service.UpdateWebhook(r.Context(), webhook); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(webhook)
}

func (h *WebhookHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	if err := h.service.DeleteWebhook(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *WebhookHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	if err := h.service.VerifyWebhook(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "verified"})
}

func (h *WebhookHandler) handleEvents(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	events, err := h.service.GetEvents(r.Context(), id, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(events)
}

func (h *WebhookHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	stats, err := h.service.GetDeliveryStats(r.Context(), id, 30)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(stats)
}

// SQLite Repository Implementation

type SQLiteWebhookRepository struct {
	db     *sql.DB
	driver string
}

func NewSQLiteWebhookRepository(db *sql.DB) (*SQLiteWebhookRepository, error) {
	return NewSQLWebhookRepository(db, "sqlite")
}

func NewPostgresWebhookRepository(db *sql.DB) (*SQLiteWebhookRepository, error) {
	return NewSQLWebhookRepository(db, "postgres")
}

func NewSQLWebhookRepository(db *sql.DB, driver string) (*SQLiteWebhookRepository, error) {
	repo := &SQLiteWebhookRepository{db: db, driver: driver}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteWebhookRepository) bind(query string) string {
	if r.driver != "postgres" {
		return query
	}

	var out strings.Builder
	index := 1
	for _, ch := range query {
		if ch == '?' {
			out.WriteString(fmt.Sprintf("$%d", index))
			index++
			continue
		}
		out.WriteRune(ch)
	}
	return out.String()
}

func (r *SQLiteWebhookRepository) execContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return r.db.ExecContext(ctx, r.bind(query), args...)
}

func (r *SQLiteWebhookRepository) queryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, r.bind(query), args...)
}

func (r *SQLiteWebhookRepository) queryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return r.db.QueryRowContext(ctx, r.bind(query), args...)
}

func (r *SQLiteWebhookRepository) migrate() error {
	timeType := "DATETIME"
	if r.driver == "postgres" {
		timeType = "TIMESTAMP"
	}
	queries := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS webhooks (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			url TEXT NOT NULL,
			method TEXT DEFAULT 'POST',
			secret TEXT,
			auth_type TEXT DEFAULT 'none',
			auth_value TEXT,
			events TEXT NOT NULL,
			organization_id TEXT,
			domain_filter TEXT,
			headers TEXT,
			max_retries INTEGER DEFAULT 5,
			retry_delay INTEGER DEFAULT 60,
			timeout INTEGER DEFAULT 30,
			active INTEGER DEFAULT 1,
			verified INTEGER DEFAULT 0,
			last_success %s,
			last_failure %s,
			failure_count INTEGER DEFAULT 0,
			created_at %s NOT NULL,
			updated_at %s NOT NULL
		)`, timeType, timeType, timeType, timeType),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS webhook_events (
			id TEXT PRIMARY KEY,
			webhook_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload TEXT NOT NULL,
			status TEXT NOT NULL,
			attempts INTEGER DEFAULT 0,
			next_retry %s,
			response_code INTEGER,
			response_body TEXT,
			error TEXT,
			created_at %s NOT NULL,
			delivered_at %s,
			duration_ms INTEGER,
			FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
		)`, timeType, timeType, timeType),

		`CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(organization_id)`,
		`CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(active)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_events_webhook ON webhook_events(webhook_id)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON webhook_events(status)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_events_retry ON webhook_events(next_retry)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(r.bind(q)); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteWebhookRepository) CreateWebhook(ctx context.Context, webhook *Webhook) error {
	eventsJSON, _ := json.Marshal(webhook.Events)
	domainsJSON, _ := json.Marshal(webhook.DomainFilter)
	headersJSON, _ := json.Marshal(webhook.Headers)

	var orgID *string
	if webhook.OrganizationID != nil {
		s := webhook.OrganizationID.String()
		orgID = &s
	}

	_, err := r.execContext(ctx, `
		INSERT INTO webhooks (id, name, description, url, method, secret, auth_type, auth_value,
			events, organization_id, domain_filter, headers, max_retries, retry_delay, timeout,
			active, verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		webhook.ID.String(), webhook.Name, webhook.Description, webhook.URL, webhook.Method,
		webhook.Secret, webhook.AuthType, webhook.AuthValue, string(eventsJSON),
		orgID, string(domainsJSON), string(headersJSON), webhook.MaxRetries,
		int(webhook.RetryDelay.Seconds()), int(webhook.Timeout.Seconds()),
		webhook.Active, webhook.Verified, webhook.CreatedAt, webhook.UpdatedAt)

	return err
}

func (r *SQLiteWebhookRepository) GetWebhook(ctx context.Context, id uuid.UUID) (*Webhook, error) {
	var webhook Webhook
	var idStr string
	var orgID *string
	var eventsJSON, domainsJSON, headersJSON string
	var retryDelay, timeout int

	err := r.queryRowContext(ctx, `
		SELECT id, name, description, url, method, secret, auth_type, auth_value, events,
			organization_id, domain_filter, headers, max_retries, retry_delay, timeout,
			active, verified, last_success, last_failure, failure_count, created_at, updated_at
		FROM webhooks WHERE id = ?`, id.String()).Scan(
		&idStr, &webhook.Name, &webhook.Description, &webhook.URL, &webhook.Method,
		&webhook.Secret, &webhook.AuthType, &webhook.AuthValue, &eventsJSON,
		&orgID, &domainsJSON, &headersJSON, &webhook.MaxRetries, &retryDelay, &timeout,
		&webhook.Active, &webhook.Verified, &webhook.LastSuccess, &webhook.LastFailure,
		&webhook.FailureCount, &webhook.CreatedAt, &webhook.UpdatedAt)
	if err != nil {
		return nil, err
	}

	webhook.ID, _ = uuid.Parse(idStr)
	webhook.RetryDelay = time.Duration(retryDelay) * time.Second
	webhook.Timeout = time.Duration(timeout) * time.Second

	if orgID != nil {
		id, _ := uuid.Parse(*orgID)
		webhook.OrganizationID = &id
	}

	json.Unmarshal([]byte(eventsJSON), &webhook.Events)
	json.Unmarshal([]byte(domainsJSON), &webhook.DomainFilter)
	json.Unmarshal([]byte(headersJSON), &webhook.Headers)

	return &webhook, nil
}

func (r *SQLiteWebhookRepository) ListWebhooks(ctx context.Context, orgID *uuid.UUID) ([]*Webhook, error) {
	var rows *sql.Rows
	var err error

	if orgID != nil {
		rows, err = r.queryContext(ctx, `
			SELECT id, name, description, url, method, auth_type, events, organization_id,
				max_retries, active, verified, last_success, last_failure, failure_count,
				created_at, updated_at
			FROM webhooks WHERE organization_id = ? ORDER BY created_at DESC`, orgID.String())
	} else {
		rows, err = r.queryContext(ctx, `
			SELECT id, name, description, url, method, auth_type, events, organization_id,
				max_retries, active, verified, last_success, last_failure, failure_count,
				created_at, updated_at
			FROM webhooks ORDER BY created_at DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*Webhook
	for rows.Next() {
		var webhook Webhook
		var idStr string
		var org *string
		var eventsJSON string

		err := rows.Scan(&idStr, &webhook.Name, &webhook.Description, &webhook.URL, &webhook.Method,
			&webhook.AuthType, &eventsJSON, &org, &webhook.MaxRetries, &webhook.Active,
			&webhook.Verified, &webhook.LastSuccess, &webhook.LastFailure, &webhook.FailureCount,
			&webhook.CreatedAt, &webhook.UpdatedAt)
		if err != nil {
			return nil, err
		}

		webhook.ID, _ = uuid.Parse(idStr)
		json.Unmarshal([]byte(eventsJSON), &webhook.Events)

		webhooks = append(webhooks, &webhook)
	}

	return webhooks, rows.Err()
}

func (r *SQLiteWebhookRepository) ListWebhooksByEvent(ctx context.Context, event EventType) ([]*Webhook, error) {
	// SQLite JSON contains check
	rows, err := r.queryContext(ctx, `
		SELECT id, name, description, url, method, secret, auth_type, auth_value, events,
			organization_id, domain_filter, headers, max_retries, retry_delay, timeout,
			active, verified, last_success, last_failure, failure_count, created_at, updated_at
		FROM webhooks WHERE active = 1 AND events LIKE ?`, "%\""+string(event)+"\"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*Webhook
	for rows.Next() {
		var webhook Webhook
		var idStr string
		var orgID *string
		var eventsJSON, domainsJSON, headersJSON string
		var retryDelay, timeout int

		err := rows.Scan(&idStr, &webhook.Name, &webhook.Description, &webhook.URL, &webhook.Method,
			&webhook.Secret, &webhook.AuthType, &webhook.AuthValue, &eventsJSON,
			&orgID, &domainsJSON, &headersJSON, &webhook.MaxRetries, &retryDelay, &timeout,
			&webhook.Active, &webhook.Verified, &webhook.LastSuccess, &webhook.LastFailure,
			&webhook.FailureCount, &webhook.CreatedAt, &webhook.UpdatedAt)
		if err != nil {
			return nil, err
		}

		webhook.ID, _ = uuid.Parse(idStr)
		webhook.RetryDelay = time.Duration(retryDelay) * time.Second
		webhook.Timeout = time.Duration(timeout) * time.Second

		json.Unmarshal([]byte(eventsJSON), &webhook.Events)
		json.Unmarshal([]byte(domainsJSON), &webhook.DomainFilter)
		json.Unmarshal([]byte(headersJSON), &webhook.Headers)

		webhooks = append(webhooks, &webhook)
	}

	return webhooks, rows.Err()
}

func (r *SQLiteWebhookRepository) UpdateWebhook(ctx context.Context, webhook *Webhook) error {
	eventsJSON, _ := json.Marshal(webhook.Events)
	domainsJSON, _ := json.Marshal(webhook.DomainFilter)
	headersJSON, _ := json.Marshal(webhook.Headers)

	_, err := r.execContext(ctx, `
		UPDATE webhooks SET
			name = ?, description = ?, url = ?, method = ?, secret = ?, auth_type = ?,
			auth_value = ?, events = ?, domain_filter = ?, headers = ?, max_retries = ?,
			retry_delay = ?, timeout = ?, active = ?, verified = ?, last_success = ?,
			last_failure = ?, failure_count = ?, updated_at = ?
		WHERE id = ?`,
		webhook.Name, webhook.Description, webhook.URL, webhook.Method, webhook.Secret,
		webhook.AuthType, webhook.AuthValue, string(eventsJSON), string(domainsJSON),
		string(headersJSON), webhook.MaxRetries, int(webhook.RetryDelay.Seconds()),
		int(webhook.Timeout.Seconds()), webhook.Active, webhook.Verified, webhook.LastSuccess,
		webhook.LastFailure, webhook.FailureCount, webhook.UpdatedAt, webhook.ID.String())

	return err
}

func (r *SQLiteWebhookRepository) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	_, err := r.execContext(ctx, "DELETE FROM webhooks WHERE id = ?", id.String())
	return err
}

func (r *SQLiteWebhookRepository) CreateEvent(ctx context.Context, event *WebhookEvent) error {
	payloadJSON, _ := json.Marshal(event.Payload)

	_, err := r.execContext(ctx, `
		INSERT INTO webhook_events (id, webhook_id, event_type, payload, status, attempts,
			next_retry, response_code, response_body, error, created_at, delivered_at, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID.String(), event.WebhookID.String(), string(event.EventType), string(payloadJSON),
		string(event.Status), event.Attempts, event.NextRetry, event.ResponseCode,
		event.ResponseBody, event.Error, event.CreatedAt, event.DeliveredAt, event.Duration)

	return err
}

func (r *SQLiteWebhookRepository) GetEvent(ctx context.Context, id uuid.UUID) (*WebhookEvent, error) {
	var event WebhookEvent
	var idStr, webhookStr, eventType, status string
	var payloadJSON string

	err := r.queryRowContext(ctx, `
		SELECT id, webhook_id, event_type, payload, status, attempts, next_retry,
			response_code, response_body, error, created_at, delivered_at, duration_ms
		FROM webhook_events WHERE id = ?`, id.String()).Scan(
		&idStr, &webhookStr, &eventType, &payloadJSON, &status, &event.Attempts,
		&event.NextRetry, &event.ResponseCode, &event.ResponseBody, &event.Error,
		&event.CreatedAt, &event.DeliveredAt, &event.Duration)
	if err != nil {
		return nil, err
	}

	event.ID, _ = uuid.Parse(idStr)
	event.WebhookID, _ = uuid.Parse(webhookStr)
	event.EventType = EventType(eventType)
	event.Status = DeliveryStatus(status)
	json.Unmarshal([]byte(payloadJSON), &event.Payload)

	return &event, nil
}

func (r *SQLiteWebhookRepository) ListEvents(ctx context.Context, webhookID uuid.UUID, limit int) ([]*WebhookEvent, error) {
	rows, err := r.queryContext(ctx, `
		SELECT id, webhook_id, event_type, payload, status, attempts, next_retry,
			response_code, response_body, error, created_at, delivered_at, duration_ms
		FROM webhook_events WHERE webhook_id = ?
		ORDER BY created_at DESC LIMIT ?`, webhookID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*WebhookEvent
	for rows.Next() {
		var event WebhookEvent
		var idStr, webhookStr, eventType, status string
		var payloadJSON string

		err := rows.Scan(&idStr, &webhookStr, &eventType, &payloadJSON, &status, &event.Attempts,
			&event.NextRetry, &event.ResponseCode, &event.ResponseBody, &event.Error,
			&event.CreatedAt, &event.DeliveredAt, &event.Duration)
		if err != nil {
			return nil, err
		}

		event.ID, _ = uuid.Parse(idStr)
		event.WebhookID, _ = uuid.Parse(webhookStr)
		event.EventType = EventType(eventType)
		event.Status = DeliveryStatus(status)
		json.Unmarshal([]byte(payloadJSON), &event.Payload)

		events = append(events, &event)
	}

	return events, rows.Err()
}

func (r *SQLiteWebhookRepository) UpdateEvent(ctx context.Context, event *WebhookEvent) error {
	_, err := r.execContext(ctx, `
		UPDATE webhook_events SET
			status = ?, attempts = ?, next_retry = ?, response_code = ?,
			response_body = ?, error = ?, delivered_at = ?, duration_ms = ?
		WHERE id = ?`,
		string(event.Status), event.Attempts, event.NextRetry, event.ResponseCode,
		event.ResponseBody, event.Error, event.DeliveredAt, event.Duration, event.ID.String())

	return err
}

func (r *SQLiteWebhookRepository) GetPendingEvents(ctx context.Context, limit int) ([]*WebhookEvent, error) {
	return r.queryEvents(ctx, "status = ?", limit, string(StatusPending))
}

func (r *SQLiteWebhookRepository) GetRetryableEvents(ctx context.Context, limit int) ([]*WebhookEvent, error) {
	events, err := r.queryEvents(ctx, "status = ?", limit, string(StatusRetrying))
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	filtered := make([]*WebhookEvent, 0, len(events))
	for _, event := range events {
		if event.NextRetry != nil && !event.NextRetry.After(now) {
			filtered = append(filtered, event)
		}
		if len(filtered) >= limit {
			break
		}
	}

	return filtered, nil
}

func (r *SQLiteWebhookRepository) queryEvents(ctx context.Context, where string, limit int, args ...interface{}) ([]*WebhookEvent, error) {
	query := fmt.Sprintf(`
		SELECT id, webhook_id, event_type, payload, status, attempts, next_retry,
			response_code, response_body, error, created_at, delivered_at, duration_ms
		FROM webhook_events WHERE %s LIMIT ?`, where)
	args = append(args, limit)
	rows, err := r.queryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*WebhookEvent
	for rows.Next() {
		var event WebhookEvent
		var idStr, webhookStr, eventType, status string
		var payloadJSON string

		err := rows.Scan(&idStr, &webhookStr, &eventType, &payloadJSON, &status, &event.Attempts,
			&event.NextRetry, &event.ResponseCode, &event.ResponseBody, &event.Error,
			&event.CreatedAt, &event.DeliveredAt, &event.Duration)
		if err != nil {
			return nil, err
		}

		event.ID, _ = uuid.Parse(idStr)
		event.WebhookID, _ = uuid.Parse(webhookStr)
		event.EventType = EventType(eventType)
		event.Status = DeliveryStatus(status)
		json.Unmarshal([]byte(payloadJSON), &event.Payload)

		events = append(events, &event)
	}

	return events, rows.Err()
}

func (r *SQLiteWebhookRepository) GetDeliveryStats(ctx context.Context, webhookID uuid.UUID, days int) (*DeliveryStats, error) {
	var stats DeliveryStats

	since := time.Now().AddDate(0, 0, -days)

	err := r.queryRowContext(ctx, `
		SELECT 
			COUNT(*) as total,
			SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) as delivered,
			SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
			SUM(CASE WHEN status IN ('pending', 'retrying') THEN 1 ELSE 0 END) as pending,
			AVG(CASE WHEN status = 'delivered' THEN duration_ms ELSE NULL END) as avg_latency
		FROM webhook_events WHERE webhook_id = ? AND created_at >= ?`,
		webhookID.String(), since).Scan(&stats.Total, &stats.Delivered, &stats.Failed, &stats.Pending, &stats.AvgLatency)

	return &stats, err
}
