package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
	"github.com/nigelbasa/lightr/internal/smtp"
	"golang.org/x/crypto/bcrypt"
)

// APIKeyMiddleware validates API key from Authorization header
func APIKeyMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Support "Bearer <key>" or just "<key>"
		key := strings.TrimPrefix(auth, "Bearer ")
		if key != apiKey {
			http.Error(w, "invalid API key", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type Handler struct {
	accountRepo  domain.AccountRepository
	domainRepo   domain.DomainRepository
	orgRepo      domain.OrganizationRepository
	messageRepo  domain.MessageRepository
	templateRepo domain.TemplateRepository
	trackingRepo domain.TrackingEventRepository
	relay        *smtp.Relay
}

func NewHandler(
	accRepo domain.AccountRepository,
	domRepo domain.DomainRepository,
	orgRepo domain.OrganizationRepository,
	msgRepo domain.MessageRepository,
	tmplRepo domain.TemplateRepository,
	trackRepo domain.TrackingEventRepository,
	relay *smtp.Relay,
) *Handler {
	return &Handler{
		accountRepo:  accRepo,
		domainRepo:   domRepo,
		orgRepo:      orgRepo,
		messageRepo:  msgRepo,
		templateRepo: tmplRepo,
		trackingRepo: trackRepo,
		relay:        relay,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Health
	mux.HandleFunc("GET /health", h.HandleHealth)

	// Organizations
	mux.HandleFunc("GET /v1/orgs", h.HandleListOrgs)
	mux.HandleFunc("POST /v1/orgs", h.HandleCreateOrg)
	mux.HandleFunc("GET /v1/orgs/{id}", h.HandleGetOrg)

	// Domains
	mux.HandleFunc("GET /v1/orgs/{org_id}/domains", h.HandleListDomains)
	mux.HandleFunc("POST /v1/domains", h.HandleCreateDomain)
	mux.HandleFunc("GET /v1/domains/{id}", h.HandleGetDomain)

	// Accounts
	mux.HandleFunc("POST /v1/accounts", h.HandleCreateAccount)
	mux.HandleFunc("GET /v1/accounts/{id}", h.HandleGetAccount)
	mux.HandleFunc("DELETE /v1/accounts/{id}", h.HandleDeleteAccount)

	// Messages
	mux.HandleFunc("GET /v1/accounts/{account_id}/messages", h.HandleListMessages)
	mux.HandleFunc("GET /v1/messages/{id}", h.HandleGetMessage)

	// Templates
	mux.HandleFunc("POST /v1/templates", h.HandleCreateTemplate)
	mux.HandleFunc("GET /v1/orgs/{org_id}/templates", h.HandleListTemplates)
	mux.HandleFunc("GET /v1/templates/{org_id}/{name}", h.HandleGetTemplate)

	// Send
	mux.HandleFunc("POST /v1/send", h.HandleSend)

	// Stats
	mux.HandleFunc("GET /v1/messages/{id}/tracking", h.HandleGetTrackingStats)
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type CreateDomainRequest struct {
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
}

func (h *Handler) HandleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req CreateDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	orgID, err := uuid.Parse(req.OrgID)
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	dom := &domain.Domain{
		ID:           uuid.New(),
		OrgID:        orgID,
		Name:         req.Name,
		DKIMSelector: "default", // default selector
		IsVerified:   false,
	}

	if err := h.domainRepo.CreateDomain(dom); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dom)
}

type CreateAccountRequest struct {
	DomainID   string `json:"domain_id"`
	LocalPart  string `json:"local_part"`
	AuthMode   string `json:"auth_mode"`
	Password   string `json:"password,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
	QuotaBytes int64  `json:"quota_bytes"`
}

func (h *Handler) HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	domID, err := uuid.Parse(req.DomainID)
	if err != nil {
		http.Error(w, "invalid domain_id", http.StatusBadRequest)
		return
	}

	acc := &domain.Account{
		ID:         uuid.New(),
		DomainID:   domID,
		LocalPart:  req.LocalPart,
		AuthMode:   domain.AuthMode(req.AuthMode),
		ExternalID: req.ExternalID,
		QuotaBytes: req.QuotaBytes,
	}

	// Handle password hashing for native auth
	if acc.AuthMode == domain.AuthModeNative && req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
			return
		}
		acc.PasswordHash = string(hash)
	}

	if err := h.accountRepo.CreateAccount(acc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(acc)
}

func (h *Handler) HandleGetAccount(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	acc, err := h.accountRepo.GetAccountByID(id)
	if err != nil {
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(acc)
}

type SendRequest struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html,omitempty"`
}

func (h *Handler) HandleSend(w http.ResponseWriter, r *http.Request) {
	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Basic RFC822 message construction (very simple for now)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", req.From, req.To, req.Subject, req.Text)

	if err := h.relay.Send(r.Context(), req.From, []string{req.To}, []byte(msg)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
}

// Organization handlers

func (h *Handler) HandleListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.orgRepo.ListOrgs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orgs)
}

type CreateOrgRequest struct {
	Name        string `json:"name"`
	BillingTier string `json:"billing_tier"`
}

func (h *Handler) HandleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var req CreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	org := &domain.Organization{
		ID:          uuid.New(),
		Name:        req.Name,
		BillingTier: req.BillingTier,
	}
	if org.BillingTier == "" {
		org.BillingTier = "free"
	}

	if err := h.orgRepo.CreateOrg(org); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(org)
}

func (h *Handler) HandleGetOrg(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	org, err := h.orgRepo.GetOrgByID(id)
	if err != nil {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(org)
}

// Domain handlers

func (h *Handler) HandleListDomains(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	domains, err := h.domainRepo.ListDomainsByOrg(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

func (h *Handler) HandleGetDomain(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	dom, err := h.domainRepo.GetDomainByID(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dom)
}

// Account handlers

func (h *Handler) HandleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	if err := h.accountRepo.DeleteAccount(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Message handlers

func (h *Handler) HandleListMessages(w http.ResponseWriter, r *http.Request) {
	accountID, err := uuid.Parse(r.PathValue("account_id"))
	if err != nil {
		http.Error(w, "invalid account_id", http.StatusBadRequest)
		return
	}

	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "INBOX"
	}

	messages, err := h.messageRepo.ListByAccount(accountID, folder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func (h *Handler) HandleGetMessage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	msg, err := h.messageRepo.GetMessageByID(id)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

// Template handlers

type CreateTemplateRequest struct {
	OrgID   string `json:"org_id"`
	Name    string `json:"name"`
	Subject string `json:"subject"`
	Content string `json:"content"`
}

func (h *Handler) HandleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req CreateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	orgID, err := uuid.Parse(req.OrgID)
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	tmpl := &domain.Template{
		ID:      uuid.New(),
		OrgID:   orgID,
		Name:    req.Name,
		Subject: req.Subject,
		Content: req.Content,
	}

	if err := h.templateRepo.CreateTemplate(tmpl); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tmpl)
}

func (h *Handler) HandleListTemplates(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	templates, err := h.templateRepo.ListTemplatesByOrg(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

func (h *Handler) HandleGetTemplate(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")

	tmpl, err := h.templateRepo.GetTemplateByName(orgID, name)
	if err != nil {
		http.Error(w, "template not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tmpl)
}

// Tracking stats

func (h *Handler) HandleGetTrackingStats(w http.ResponseWriter, r *http.Request) {
	msgID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	events, err := h.trackingRepo.GetTrackingEventsByMessage(msgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Aggregate stats
	stats := struct {
		Opens  int                     `json:"opens"`
		Clicks int                     `json:"clicks"`
		Events []*domain.TrackingEvent `json:"events"`
	}{
		Events: events,
	}

	for _, e := range events {
		switch e.EventType {
		case "open":
			stats.Opens++
		case "click":
			stats.Clicks++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
