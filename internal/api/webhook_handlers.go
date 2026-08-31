package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/apikeys"
	"github.com/nigelbasa/lightr/internal/webhooks"
)

type webhookRequest struct {
	Name         string               `json:"name"`
	Description  string               `json:"description,omitempty"`
	URL          string               `json:"url"`
	Method       string               `json:"method,omitempty"`
	OrgID        string               `json:"org_id,omitempty"`
	Org          string               `json:"org,omitempty"`
	Secret       string               `json:"secret,omitempty"`
	AuthType     string               `json:"auth_type,omitempty"`
	AuthValue    string               `json:"auth_value,omitempty"`
	Events       []webhooks.EventType `json:"events,omitempty"`
	DomainFilter []string             `json:"domain_filter,omitempty"`
	Headers      map[string]string    `json:"headers,omitempty"`
	MaxRetries   int                  `json:"max_retries,omitempty"`
	RetryDelay   string               `json:"retry_delay,omitempty"`
	Timeout      string               `json:"timeout,omitempty"`
	Active       *bool                `json:"active,omitempty"`
}

func (h *Handler) HandleListWebhooks(w http.ResponseWriter, r *http.Request) {
	if h.webhookService == nil {
		http.Error(w, "webhook service unavailable", http.StatusNotImplemented)
		return
	}
	key := h.requirePermission(w, r, apikeys.PermManageWebhooks)
	if key == nil && getScopedAPIKey(r.Context()) != nil {
		return
	}
	var orgID *uuid.UUID
	if ref := firstNonEmpty(r.URL.Query().Get("org_id"), r.URL.Query().Get("org")); ref != "" {
		id, err := h.resolveOrgRef(r.URL.Query().Get("org_id"), r.URL.Query().Get("org"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !h.authorizeOrg(w, r, id, apikeys.PermManageWebhooks) {
			return
		}
		orgID = &id
	} else if key != nil && !hasGlobalAccess(key) {
		if scopedOrgID := h.apiKeyScopeOrgID(key); scopedOrgID != nil {
			orgID = scopedOrgID
		}
	}
	items, err := h.webhookService.ListWebhooks(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filtered := make([]*webhooks.Webhook, 0, len(items))
	for _, item := range items {
		if key == nil || hasGlobalAccess(key) || item.OrganizationID == nil {
			filtered = append(filtered, item)
			continue
		}
		if scopedOrgID := h.apiKeyScopeOrgID(key); scopedOrgID != nil && *scopedOrgID == *item.OrganizationID {
			filtered = append(filtered, item)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filtered)
}

func (h *Handler) HandleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	if h.webhookService == nil {
		http.Error(w, "webhook service unavailable", http.StatusNotImplemented)
		return
	}
	key := h.requirePermission(w, r, apikeys.PermManageWebhooks)
	if key == nil && getScopedAPIKey(r.Context()) != nil {
		return
	}
	var req webhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.URL) == "" {
		http.Error(w, "name and url are required", http.StatusBadRequest)
		return
	}
	var orgID *uuid.UUID
	if ref := firstNonEmpty(req.OrgID, req.Org); ref != "" {
		id, err := h.resolveOrgRef(req.OrgID, req.Org)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !h.authorizeOrg(w, r, id, apikeys.PermManageWebhooks) {
			return
		}
		orgID = &id
	} else if key != nil && !hasGlobalAccess(key) {
		scopedOrgID := h.apiKeyScopeOrgID(key)
		if scopedOrgID == nil {
			http.Error(w, "scope denied", http.StatusForbidden)
			return
		}
		orgID = scopedOrgID
	}
	retryDelay, err := parseDurationOrDefault(req.RetryDelay, 60*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	timeout, err := parseDurationOrDefault(req.Timeout, 30*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	item := &webhooks.Webhook{
		Name:           req.Name,
		Description:    req.Description,
		URL:            req.URL,
		Method:         strings.ToUpper(firstNonEmpty(req.Method, http.MethodPost)),
		Secret:         req.Secret,
		AuthType:       strings.ToLower(req.AuthType),
		AuthValue:      req.AuthValue,
		Events:         req.Events,
		OrganizationID: orgID,
		DomainFilter:   req.DomainFilter,
		Headers:        req.Headers,
		MaxRetries:     req.MaxRetries,
		RetryDelay:     retryDelay,
		Timeout:        timeout,
		Active:         req.Active == nil || *req.Active,
	}
	if err := h.webhookService.CreateWebhook(r.Context(), item); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(item)
}

func (h *Handler) HandleGetWebhook(w http.ResponseWriter, r *http.Request) {
	item, ok := h.authorizedWebhook(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

func (h *Handler) HandleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	item, ok := h.authorizedWebhook(w, r)
	if !ok {
		return
	}
	var req webhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name != "" {
		item.Name = req.Name
	}
	if req.Description != "" {
		item.Description = req.Description
	}
	if req.URL != "" {
		item.URL = req.URL
	}
	if req.Method != "" {
		item.Method = strings.ToUpper(req.Method)
	}
	if req.Secret != "" {
		item.Secret = req.Secret
	}
	if req.AuthType != "" {
		item.AuthType = strings.ToLower(req.AuthType)
	}
	if req.AuthValue != "" {
		item.AuthValue = req.AuthValue
	}
	if req.Events != nil {
		item.Events = req.Events
	}
	if req.DomainFilter != nil {
		item.DomainFilter = req.DomainFilter
	}
	if req.Headers != nil {
		item.Headers = req.Headers
	}
	if req.MaxRetries > 0 {
		item.MaxRetries = req.MaxRetries
	}
	if req.RetryDelay != "" {
		dur, err := time.ParseDuration(req.RetryDelay)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		item.RetryDelay = dur
	}
	if req.Timeout != "" {
		dur, err := time.ParseDuration(req.Timeout)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		item.Timeout = dur
	}
	if req.Active != nil {
		item.Active = *req.Active
	}
	if err := h.webhookService.UpdateWebhook(r.Context(), item); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

func (h *Handler) HandleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	item, ok := h.authorizedWebhook(w, r)
	if !ok {
		return
	}
	if err := h.webhookService.DeleteWebhook(r.Context(), item.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleVerifyWebhook(w http.ResponseWriter, r *http.Request) {
	item, ok := h.authorizedWebhook(w, r)
	if !ok {
		return
	}
	if err := h.webhookService.VerifyWebhook(r.Context(), item.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "verified"})
}

func (h *Handler) HandleListWebhookEvents(w http.ResponseWriter, r *http.Request) {
	item, ok := h.authorizedWebhook(w, r)
	if !ok {
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := parsePositiveInt(raw); err == nil {
			limit = parsed
		}
	}
	events, err := h.webhookService.GetEvents(r.Context(), item.ID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (h *Handler) HandleWebhookStats(w http.ResponseWriter, r *http.Request) {
	item, ok := h.authorizedWebhook(w, r)
	if !ok {
		return
	}
	days := 7
	if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
		if parsed, err := parsePositiveInt(raw); err == nil {
			days = parsed
		}
	}
	stats, err := h.webhookService.GetDeliveryStats(r.Context(), item.ID, days)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *Handler) authorizedWebhook(w http.ResponseWriter, r *http.Request) (*webhooks.Webhook, bool) {
	if h.webhookService == nil {
		http.Error(w, "webhook service unavailable", http.StatusNotImplemented)
		return nil, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return nil, false
	}
	item, err := h.webhookService.GetWebhook(r.Context(), id)
	if err != nil {
		http.Error(w, "webhook not found", http.StatusNotFound)
		return nil, false
	}
	if item.OrganizationID != nil {
		if !h.authorizeOrg(w, r, *item.OrganizationID, apikeys.PermManageWebhooks) {
			return nil, false
		}
		return item, true
	}
	if !h.requireGlobalPermission(w, r, apikeys.PermManageWebhooks) {
		return nil, false
	}
	return item, true
}

func parseDurationOrDefault(raw string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	return time.ParseDuration(raw)
}

func parsePositiveInt(raw string) (int, error) {
	var value int
	_, err := fmt.Sscanf(raw, "%d", &value)
	if err != nil {
		return 0, err
	}
	if value <= 0 {
		return 0, errors.New("value must be positive")
	}
	return value, nil
}
