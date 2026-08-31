package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/alias"
	"github.com/nigelbasa/lightr/internal/apikeys"
)

type aliasRequest struct {
	DomainID     string          `json:"domain_id,omitempty"`
	Domain       string          `json:"domain,omitempty"`
	Source       string          `json:"source"`
	Destinations []string        `json:"destinations"`
	Type         alias.AliasType `json:"type"`
	IsActive     *bool           `json:"is_active,omitempty"`
}

type aliasUpdateRequest struct {
	Source       *string          `json:"source,omitempty"`
	Destinations *[]string        `json:"destinations,omitempty"`
	Type         *alias.AliasType `json:"type,omitempty"`
	IsActive     *bool            `json:"is_active,omitempty"`
}

func (h *Handler) HandleListAliases(w http.ResponseWriter, r *http.Request) {
	if h.aliasRepo == nil {
		http.Error(w, "alias repository unavailable", http.StatusNotImplemented)
		return
	}
	domID, err := h.resolveDomainRef(r.URL.Query().Get("domain_id"), r.URL.Query().Get("domain"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !h.authorizeDomain(w, r, domID, apikeys.PermManageDomain) {
		return
	}
	items, err := h.aliasRepo.ListByDomain(domID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func (h *Handler) HandleCreateAlias(w http.ResponseWriter, r *http.Request) {
	if h.aliasRepo == nil {
		http.Error(w, "alias repository unavailable", http.StatusNotImplemented)
		return
	}
	var req aliasRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	domID, err := h.resolveDomainRef(req.DomainID, req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !h.authorizeDomain(w, r, domID, apikeys.PermManageDomain) {
		return
	}
	source := strings.TrimSpace(req.Source)
	if source == "" || len(req.Destinations) == 0 {
		http.Error(w, "source and destinations are required", http.StatusBadRequest)
		return
	}
	item := &alias.Alias{
		ID:           uuid.New(),
		DomainID:     domID,
		Source:       source,
		Destinations: trimAliasDestinations(req.Destinations),
		Type:         firstAliasType(req.Type),
		IsActive:     req.IsActive == nil || *req.IsActive,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if item.Type == alias.AliasTypeBridge {
		if _, err := h.accountRepo.GetAccountByLocalPart(domID, item.Source); err != nil {
			http.Error(w, "bridge alias source must match an existing mailbox local-part", http.StatusBadRequest)
			return
		}
	}
	if err := h.aliasRepo.Create(item); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(item)
}

func (h *Handler) HandleUpdateAlias(w http.ResponseWriter, r *http.Request) {
	if h.aliasRepo == nil {
		http.Error(w, "alias repository unavailable", http.StatusNotImplemented)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	item, err := h.aliasRepo.GetByID(id)
	if err != nil {
		http.Error(w, "alias not found", http.StatusNotFound)
		return
	}
	if !h.authorizeDomain(w, r, item.DomainID, apikeys.PermManageDomain) {
		return
	}
	var req aliasUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Source != nil {
		item.Source = strings.TrimSpace(*req.Source)
	}
	if req.Destinations != nil {
		item.Destinations = trimAliasDestinations(*req.Destinations)
	}
	if req.Type != nil {
		item.Type = *req.Type
	}
	if req.IsActive != nil {
		item.IsActive = *req.IsActive
	}
	if item.Type == alias.AliasTypeBridge {
		if _, err := h.accountRepo.GetAccountByLocalPart(item.DomainID, item.Source); err != nil {
			http.Error(w, "bridge alias source must match an existing mailbox local-part", http.StatusBadRequest)
			return
		}
	}
	if err := h.aliasRepo.Update(item); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

func (h *Handler) HandleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	if h.aliasRepo == nil {
		http.Error(w, "alias repository unavailable", http.StatusNotImplemented)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	item, err := h.aliasRepo.GetByID(id)
	if err != nil {
		http.Error(w, "alias not found", http.StatusNotFound)
		return
	}
	if !h.authorizeDomain(w, r, item.DomainID, apikeys.PermManageDomain) {
		return
	}
	if err := h.aliasRepo.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func trimAliasDestinations(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func firstAliasType(value alias.AliasType) alias.AliasType {
	if value == "" {
		return alias.AliasTypeForward
	}
	return value
}
