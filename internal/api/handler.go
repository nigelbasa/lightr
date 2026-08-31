package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/alias"
	"github.com/nigelbasa/lightr/internal/apikeys"
	"github.com/nigelbasa/lightr/internal/domain"
	"github.com/nigelbasa/lightr/internal/smtp"
	"github.com/nigelbasa/lightr/internal/spam"
	"github.com/nigelbasa/lightr/internal/webhooks"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	accountRepo    domain.AccountRepository
	domainRepo     domain.DomainRepository
	orgRepo        domain.OrganizationRepository
	messageRepo    domain.MessageRepository
	blobStorage    domain.BlobStorage
	relay          *smtp.Relay
	apikeyService  *apikeys.APIKeyService
	aliasRepo      alias.Repository
	webhookService *webhooks.WebhookService
	serverHostname string
}

func NewHandler(
	accRepo domain.AccountRepository,
	domRepo domain.DomainRepository,
	orgRepo domain.OrganizationRepository,
	msgRepo domain.MessageRepository,
	blobStorage domain.BlobStorage,
	relay *smtp.Relay,
) *Handler {
	return &Handler{
		accountRepo: accRepo,
		domainRepo:  domRepo,
		orgRepo:     orgRepo,
		messageRepo: msgRepo,
		blobStorage: blobStorage,
		relay:       relay,
	}
}

func (h *Handler) WithAPIKeyService(service *apikeys.APIKeyService) *Handler {
	h.apikeyService = service
	return h
}

func (h *Handler) WithAliasRepo(repo alias.Repository) *Handler {
	h.aliasRepo = repo
	return h
}

func (h *Handler) WithWebhookService(service *webhooks.WebhookService) *Handler {
	h.webhookService = service
	return h
}

func (h *Handler) WithServerHostname(hostname string) *Handler {
	h.serverHostname = strings.TrimSpace(hostname)
	return h
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Health
	mux.HandleFunc("GET /health", h.HandleHealth)

	// Organizations
	mux.HandleFunc("GET /v1/orgs", h.HandleListOrgs)
	mux.HandleFunc("POST /v1/orgs", h.HandleCreateOrg)
	mux.HandleFunc("GET /v1/orgs/{id}", h.HandleGetOrg)
	mux.HandleFunc("GET /v1/apikeys", h.HandleListAPIKeys)
	mux.HandleFunc("POST /v1/apikeys", h.HandleCreateAPIKey)
	mux.HandleFunc("POST /v1/apikeys/{id}/rotate", h.HandleRotateAPIKey)
	mux.HandleFunc("POST /v1/apikeys/{id}/revoke", h.HandleRevokeAPIKey)
	mux.HandleFunc("DELETE /v1/apikeys/{id}", h.HandleDeleteAPIKey)

	// Domains
	mux.HandleFunc("GET /v1/domains", h.HandleListDomains)
	mux.HandleFunc("GET /v1/orgs/{org_id}/domains", h.HandleListDomains)
	mux.HandleFunc("POST /v1/domains", h.HandleCreateDomain)
	mux.HandleFunc("GET /v1/domains/{id}", h.HandleGetDomain)
	mux.HandleFunc("PATCH /v1/domains/{id}", h.HandleUpdateDomain)
	mux.HandleFunc("DELETE /v1/domains/{id}", h.HandleDeleteDomain)
	mux.HandleFunc("GET /v1/domains/{id}/dns", h.HandleGetDomainDNS)
	mux.HandleFunc("POST /v1/domains/{id}/verify", h.HandleVerifyDomain)
	mux.HandleFunc("POST /v1/domains/{id}/auth-webhook/verify", h.HandleVerifyDomainAuthWebhook)
	mux.HandleFunc("POST /v1/domains/{id}/auth-webhook/rotate-secret", h.HandleRotateDomainAuthWebhookSecret)

	// Accounts
	mux.HandleFunc("GET /v1/accounts", h.HandleListAccounts)
	mux.HandleFunc("POST /v1/accounts", h.HandleCreateAccount)
	mux.HandleFunc("GET /v1/accounts/{id}", h.HandleGetAccount)
	mux.HandleFunc("PATCH /v1/accounts/{id}", h.HandleUpdateAccount)
	mux.HandleFunc("DELETE /v1/accounts/{id}", h.HandleDeleteAccount)

	// Aliases
	mux.HandleFunc("GET /v1/aliases", h.HandleListAliases)
	mux.HandleFunc("POST /v1/aliases", h.HandleCreateAlias)
	mux.HandleFunc("PATCH /v1/aliases/{id}", h.HandleUpdateAlias)
	mux.HandleFunc("DELETE /v1/aliases/{id}", h.HandleDeleteAlias)

	// Messages
	mux.HandleFunc("GET /v1/accounts/{account_id}/messages", h.HandleListMessages)
	mux.HandleFunc("GET /v1/messages/{id}", h.HandleGetMessage)

	// Convenience endpoints (by email address)
	mux.HandleFunc("GET /v1/mailbox", h.HandleGetMailbox)                                              // ?email=user@domain.com
	mux.HandleFunc("GET /v1/mailbox/messages", h.HandleMailboxList)                                    // ?email=user@domain.com&folder=INBOX
	mux.HandleFunc("GET /v1/mailbox/messages/{id}", h.HandleMailboxGetMessage)                         // Get full message with body
	mux.HandleFunc("PATCH /v1/mailbox/messages/{id}", h.HandleMailboxMarkMessage)                      // Mark read/unread
	mux.HandleFunc("GET /v1/mailbox/messages/{id}/attachments/{att_id}", h.HandleMailboxGetAttachment) // Get attachment data
	mux.HandleFunc("GET /v1/mailbox/folders", h.HandleMailboxFolders)
	mux.HandleFunc("POST /v1/mailbox/send", h.HandleMailboxSend)
	mux.HandleFunc("GET /v1/mailbox/contacts", h.HandleMailboxContacts)       // Contact autocomplete
	mux.HandleFunc("PATCH /v1/mailbox/account", h.HandleUpdateMailboxAccount) // Update display name etc

	// Webhooks
	mux.HandleFunc("GET /v1/webhooks", h.HandleListWebhooks)
	mux.HandleFunc("POST /v1/webhooks", h.HandleCreateWebhook)
	mux.HandleFunc("GET /v1/webhooks/{id}", h.HandleGetWebhook)
	mux.HandleFunc("PATCH /v1/webhooks/{id}", h.HandleUpdateWebhook)
	mux.HandleFunc("DELETE /v1/webhooks/{id}", h.HandleDeleteWebhook)
	mux.HandleFunc("POST /v1/webhooks/{id}/verify", h.HandleVerifyWebhook)
	mux.HandleFunc("GET /v1/webhooks/{id}/events", h.HandleListWebhookEvents)
	mux.HandleFunc("GET /v1/webhooks/{id}/stats", h.HandleWebhookStats)

	// Send
	mux.HandleFunc("POST /v1/send", h.HandleSend)
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type CreateDomainRequest struct {
	OrgID              string `json:"org_id,omitempty"`
	Org                string `json:"org,omitempty"`
	Name               string `json:"name"`
	MailHostname       string `json:"mail_hostname,omitempty"`
	DKIMSelector       string `json:"dkim_selector,omitempty"`
	DKIMPrivateKey     string `json:"dkim_private_key,omitempty"`
	WebhookURL         string `json:"webhook_url,omitempty"`
	AuthWebhookURL     string `json:"auth_webhook_url,omitempty"`
	TLSCertFile        string `json:"tls_cert_file,omitempty"`
	TLSKeyFile         string `json:"tls_key_file,omitempty"`
	RelayEnabled       *bool  `json:"relay_enabled,omitempty"`
	RelayHost          string `json:"relay_host,omitempty"`
	RelayPort          int    `json:"relay_port,omitempty"`
	RelayUsername      string `json:"relay_username,omitempty"`
	RelayPassword      string `json:"relay_password,omitempty"`
	RelayUseTLS        *bool  `json:"relay_use_tls,omitempty"`
	RelayTLSSkipVerify *bool  `json:"relay_tls_skip_verify,omitempty"`
	SpamPolicy         string `json:"spam_policy,omitempty"`
	Verified           *bool  `json:"verified,omitempty"`
}

func (h *Handler) HandleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req CreateDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	orgID, err := h.resolveOrgRefOrDefault(req.OrgID, req.Org)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !h.authorizeOrg(w, r, orgID, apikeys.PermManageDomain) {
		return
	}

	dom := &domain.Domain{
		ID:                 uuid.New(),
		OrgID:              orgID,
		Name:               req.Name,
		MailHostname:       req.MailHostname,
		DKIMSelector:       firstNonEmpty(req.DKIMSelector, "default"),
		DKIMPrivateKey:     req.DKIMPrivateKey,
		WebhookURL:         req.WebhookURL,
		AuthWebhookURL:     req.AuthWebhookURL,
		TLSCertFile:        req.TLSCertFile,
		TLSKeyFile:         req.TLSKeyFile,
		RelayEnabled:       req.RelayEnabled != nil && *req.RelayEnabled,
		RelayHost:          req.RelayHost,
		RelayPort:          req.RelayPort,
		RelayUsername:      req.RelayUsername,
		RelayPassword:      req.RelayPassword,
		RelayUseTLS:        req.RelayUseTLS != nil && *req.RelayUseTLS,
		RelayTLSSkipVerify: req.RelayTLSSkipVerify != nil && *req.RelayTLSSkipVerify,
		SpamPolicy:         firstNonEmpty(req.SpamPolicy, "junk"),
		IsVerified:         req.Verified != nil && *req.Verified,
	}
	if strings.TrimSpace(dom.DKIMPrivateKey) == "" {
		keyPair, err := smtp.GenerateDKIMKey(2048, dom.DKIMSelector)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		dom.DKIMPrivateKey = keyPair.PrivateKeyPEM
	}
	if err := domain.EnsureAuthWebhookSecret(dom); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(dom.AuthWebhookURL) == "" {
		domain.ResetAuthWebhookVerification(dom)
	}

	if err := h.domainRepo.CreateDomain(dom); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dom)
}

type CreateAccountRequest struct {
	DomainID    string `json:"domain_id,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Email       string `json:"email,omitempty"`
	LocalPart   string `json:"local_part,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	AuthMode    string `json:"auth_mode"`
	Password    string `json:"password,omitempty"`
	ExternalID  string `json:"external_id,omitempty"`
	QuotaBytes  int64  `json:"quota_bytes"`
}

func (h *Handler) HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	domID, err := h.resolveDomainRef(req.DomainID, req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !h.authorizeDomain(w, r, domID, apikeys.PermManageUser) {
		return
	}

	localPart := req.LocalPart
	if localPart == "" && req.Email != "" {
		parts := strings.Split(req.Email, "@")
		if len(parts) != 2 {
			http.Error(w, "invalid email", http.StatusBadRequest)
			return
		}
		localPart = parts[0]
	}
	if localPart == "" {
		http.Error(w, "local_part or email is required", http.StatusBadRequest)
		return
	}

	acc := &domain.Account{
		ID:          uuid.New(),
		DomainID:    domID,
		LocalPart:   localPart,
		DisplayName: req.DisplayName,
		AuthMode:    domain.AuthMode(firstNonEmpty(strings.ToLower(req.AuthMode), string(domain.AuthModeNative))),
		ExternalID:  req.ExternalID,
		QuotaBytes:  req.QuotaBytes,
	}
	dom, err := h.domainRepo.GetDomainByID(domID)
	if err != nil {
		http.Error(w, "domain not found", http.StatusBadRequest)
		return
	}
	if err := domain.ValidateAccountAuthMode(dom, acc.AuthMode); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if acc.AuthMode == domain.AuthModeNative && strings.TrimSpace(req.Password) == "" {
		http.Error(w, "password is required for native accounts", http.StatusBadRequest)
		return
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
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermManageUser) {
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
	if h.requirePermission(w, r, apikeys.PermSendEmail) == nil {
		return
	}
	if strings.TrimSpace(req.From) == "" || strings.TrimSpace(req.To) == "" {
		http.Error(w, "from and to are required", http.StatusBadRequest)
		return
	}
	acc, err := h.getAccountByEmail(req.From)
	if err != nil {
		http.Error(w, "sender account not found", http.StatusForbidden)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermSendEmail) {
		return
	}
	dom, err := h.domainRepo.GetDomainByID(acc.DomainID)
	if err != nil {
		http.Error(w, "sender domain not found", http.StatusForbidden)
		return
	}

	// Basic RFC822 message construction (very simple for now)
	fromDomain := strings.Split(req.From, "@")[1]
	mailHost := domain.EffectiveMailHostname(dom, h.serverHostname)
	msgID := fmt.Sprintf("<%s@%s>", uuid.NewString(), fromDomain)
	msg := fmt.Sprintf("Message-ID: %s\r\nFrom: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nUser-Agent: Lightr API\r\nX-Mailer: Lightr\r\nX-Lightr-Mailed-By: %s\r\n\r\n%s",
		msgID, req.From, req.To, req.Subject, time.Now().Format(time.RFC1123Z), mailHost, req.Text)

	if err := h.relay.Send(r.Context(), req.From, []string{req.To}, []byte(msg)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
}

// Organization handlers

func (h *Handler) HandleListOrgs(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalPermission(w, r, apikeys.PermManageOrg) {
		return
	}
	orgs, err := h.orgRepo.ListOrgs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !strings.EqualFold(r.URL.Query().Get("include_default"), "true") {
		orgs = h.filterVisibleOrganizations(orgs)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orgs)
}

type CreateOrgRequest struct {
	Name string `json:"name"`
}

func (h *Handler) HandleCreateOrg(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalPermission(w, r, apikeys.PermManageOrg) {
		return
	}
	var req CreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if domain.IsDefaultOrganizationName(req.Name) {
		http.Error(w, "default organization name is reserved", http.StatusConflict)
		return
	}

	org := &domain.Organization{
		ID:   uuid.New(),
		Name: req.Name,
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
	if !h.authorizeOrg(w, r, org.ID, apikeys.PermManageOrg) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(org)
}

// Domain handlers

func (h *Handler) HandleListDomains(w http.ResponseWriter, r *http.Request) {
	key := h.requirePermission(w, r, apikeys.PermManageDomain)
	if key == nil && getScopedAPIKey(r.Context()) != nil {
		return
	}

	orgIDRef := strings.TrimSpace(r.PathValue("org_id"))
	if orgIDRef == "" {
		orgIDRef = strings.TrimSpace(r.URL.Query().Get("org_id"))
	}
	orgNameRef := strings.TrimSpace(r.URL.Query().Get("org"))

	var (
		domains []*domain.Domain
		err     error
	)
	if orgIDRef != "" || orgNameRef != "" {
		orgID, resolveErr := h.resolveOrgRef(orgIDRef, orgNameRef)
		if resolveErr != nil {
			http.Error(w, resolveErr.Error(), http.StatusBadRequest)
			return
		}
		if !h.authorizeOrg(w, r, orgID, apikeys.PermManageDomain) {
			return
		}
		domains, err = h.domainRepo.ListDomainsByOrg(orgID)
	} else {
		domains, err = h.listAccessibleDomains(key)
	}
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
	if !h.authorizeDomain(w, r, dom.ID, apikeys.PermManageDomain) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dom)
}

func (h *Handler) HandleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if !h.authorizeDomain(w, r, id, apikeys.PermManageDomain) {
		return
	}
	dom, err := h.domainRepo.GetDomainByID(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}
	var req CreateDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name != "" {
		dom.Name = req.Name
	}
	if req.MailHostname != "" {
		dom.MailHostname = req.MailHostname
	}
	if req.DKIMSelector != "" {
		dom.DKIMSelector = req.DKIMSelector
	}
	if req.DKIMPrivateKey != "" {
		dom.DKIMPrivateKey = req.DKIMPrivateKey
	}
	if req.WebhookURL != "" {
		dom.WebhookURL = req.WebhookURL
	}
	if req.AuthWebhookURL != "" {
		if !strings.EqualFold(dom.AuthWebhookURL, req.AuthWebhookURL) {
			domain.ResetAuthWebhookVerification(dom)
		}
		dom.AuthWebhookURL = req.AuthWebhookURL
		if err := domain.EnsureAuthWebhookSecret(dom); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if req.TLSCertFile != "" {
		dom.TLSCertFile = req.TLSCertFile
	}
	if req.TLSKeyFile != "" {
		dom.TLSKeyFile = req.TLSKeyFile
	}
	if req.RelayEnabled != nil {
		dom.RelayEnabled = *req.RelayEnabled
	}
	if req.RelayHost != "" {
		dom.RelayHost = req.RelayHost
	}
	if req.RelayPort != 0 {
		dom.RelayPort = req.RelayPort
	}
	if req.RelayUsername != "" {
		dom.RelayUsername = req.RelayUsername
	}
	if req.RelayPassword != "" {
		dom.RelayPassword = req.RelayPassword
	}
	if req.RelayUseTLS != nil {
		dom.RelayUseTLS = *req.RelayUseTLS
	}
	if req.RelayTLSSkipVerify != nil {
		dom.RelayTLSSkipVerify = *req.RelayTLSSkipVerify
	}
	if req.SpamPolicy != "" {
		dom.SpamPolicy = req.SpamPolicy
	}
	if req.Verified != nil {
		dom.IsVerified = *req.Verified
	}
	if dom.DKIMSelector == "" {
		dom.DKIMSelector = "default"
	}
	if strings.TrimSpace(dom.DKIMPrivateKey) == "" {
		keyPair, err := smtp.GenerateDKIMKey(2048, dom.DKIMSelector)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		dom.DKIMPrivateKey = keyPair.PrivateKeyPEM
	}
	if err := h.domainRepo.UpdateDomain(dom); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	if !h.authorizeAccount(w, r, id, apikeys.PermManageUser) {
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
	if !h.authorizeAccount(w, r, accountID, apikeys.PermReadEmail) {
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
	if !h.authorizeAccount(w, r, msg.AccountID, apikeys.PermReadEmail) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

// Convenience handlers for email-address-based access

// getAccountByEmail resolves email to account
func (h *Handler) getAccountByEmail(email string) (*domain.Account, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format")
	}
	localPart, domainName := parts[0], parts[1]

	dom, err := h.domainRepo.GetDomainByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("domain not found: %s (err: %v)", domainName, err)
	}

	acc, err := h.accountRepo.GetAccountByLocalPart(dom.ID, localPart)
	if err != nil {
		return nil, fmt.Errorf("account not found: %s (domain_id: %s, err: %v)", email, dom.ID, err)
	}

	return acc, nil
}

// HandleGetMailbox returns account info by email
func (h *Handler) HandleGetMailbox(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermManageMailbox) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":           acc.ID,
		"email":        email,
		"display_name": acc.DisplayName,
		"auth_mode":    acc.AuthMode,
		"quota":        acc.QuotaBytes,
		"used":         acc.UsedBytes,
		"created_at":   acc.CreatedAt,
	})
}

// HandleMailboxList returns messages for an email address
func (h *Handler) HandleMailboxList(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required", http.StatusBadRequest)
		return
	}

	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "INBOX"
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermReadEmail) {
		return
	}

	messages, err := h.messageRepo.ListByAccount(acc.ID, folder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return in a standard format
	result := make([]map[string]interface{}, len(messages))
	for i, msg := range messages {
		metadata := h.messageMetadata(msg)
		result[i] = map[string]interface{}{
			"id":                  msg.ID,
			"from":                msg.From,
			"to":                  msg.To,
			"subject":             msg.Subject,
			"date":                msg.ReceivedAt,
			"read":                msg.ReadAt != nil,
			"folder":              msg.Folder,
			"size":                msg.SizeBytes,
			"preview":             msg.Subject, // We can add a preview field later
			"spam_status":         metadata["X-Spam-Status"],
			"spam_score":          metadata["X-Spam-Score"],
			"mailed_by":           metadata["X-Lightr-Mailed-By"],
			"signed_by":           metadata["X-Lightr-Signed-By"],
			"remote_ip":           metadata["X-Lightr-Remote-IP"],
			"auth_results":        metadata["Authentication-Results"],
			"received_spf":        metadata["Received-SPF"],
			"message_id":          firstNonEmpty(metadata["Message-ID"], metadata["Message-Id"]),
			"return_path":         metadata["Return-Path"],
			"spam_reasons":        metadata["X-Lightr-Spam-Reasons"],
			"dnsbl_hits":          metadata["X-Lightr-DNSBL-Hits"],
			"user_classification": metadata["X-Lightr-User-Classification"],
			"reply_to":            metadata["Reply-To"],
			"sender":              metadata["Sender"],
			"arc_seal":            metadata["ARC-Seal"],
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"messages": result,
		"total":    len(messages),
		"folder":   folder,
	})
}

// HandleMailboxGetMessage returns a single message with parsed body
// Requires email query param for IDOR protection
func (h *Handler) HandleMailboxGetMessage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	// IDOR Protection: Require email and verify ownership
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required for authorization", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, "account not found", http.StatusForbidden)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermReadEmail) {
		return
	}

	msg, err := h.messageRepo.GetMessageByID(id)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}

	// Verify the message belongs to this account
	if msg.AccountID != acc.ID {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	// Get message body from storage and parse it
	var parsedMsg *ParsedMessage
	if msg.StoragePath != "" && h.blobStorage != nil {
		data, err := h.blobStorage.Get(msg.StoragePath)
		if err == nil {
			parsedMsg, _ = ParseRFC822Message(data)
		}
	}

	// Fallback to empty parsed message if parsing failed
	if parsedMsg == nil {
		parsedMsg = &ParsedMessage{
			Text:        "",
			HTML:        "",
			Attachments: []AttachmentMeta{},
		}
	}

	// Extract CC and BCC from raw headers if available
	var cc, bcc string
	metadata := map[string]string{}
	if msg.StoragePath != "" && h.blobStorage != nil {
		data, err := h.blobStorage.Get(msg.StoragePath)
		if err == nil {
			if mailMsg, err := mail.ReadMessage(bytes.NewReader(data)); err == nil {
				cc = mailMsg.Header.Get("Cc")
				bcc = mailMsg.Header.Get("Bcc")
			}
			metadata = spam.HeaderMetadata(data)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          msg.ID,
		"from":        msg.From,
		"to":          msg.To,
		"cc":          cc,
		"bcc":         bcc,
		"subject":     msg.Subject,
		"date":        msg.ReceivedAt,
		"read":        msg.ReadAt != nil,
		"folder":      msg.Folder,
		"size":        msg.SizeBytes,
		"text":        parsedMsg.Text,
		"html":        parsedMsg.HTML,
		"attachments": parsedMsg.Attachments,
		"metadata": map[string]interface{}{
			"authentication_results": metadata["Authentication-Results"],
			"spam_score":             metadata["X-Spam-Score"],
			"spam_status":            metadata["X-Spam-Status"],
			"spam_reasons":           metadata["X-Lightr-Spam-Reasons"],
			"mailed_by":              metadata["X-Lightr-Mailed-By"],
			"signed_by":              metadata["X-Lightr-Signed-By"],
			"remote_ip":              metadata["X-Lightr-Remote-IP"],
			"date_header":            metadata["Date"],
			"message_id":             firstNonEmpty(metadata["Message-ID"], metadata["Message-Id"]),
			"return_path":            metadata["Return-Path"],
			"received_spf":           metadata["Received-SPF"],
			"dkim_signature":         metadata["DKIM-Signature"],
			"dnsbl_hits":             metadata["X-Lightr-DNSBL-Hits"],
			"external_spam_source":   metadata["X-Lightr-External-Spam-Source"],
			"external_spam_score":    metadata["X-Lightr-External-Spam-Score"],
			"user_classification":    metadata["X-Lightr-User-Classification"],
			"reply_to":               metadata["Reply-To"],
			"sender":                 metadata["Sender"],
			"arc_seal":               metadata["ARC-Seal"],
			"arc_message_signature":  metadata["ARC-Message-Signature"],
			"arc_authentication":     metadata["ARC-Authentication-Results"],
		},
	})
}

func (h *Handler) messageMetadata(msg *domain.Message) map[string]string {
	if msg == nil || msg.StoragePath == "" || h.blobStorage == nil {
		return map[string]string{}
	}
	data, err := h.blobStorage.Get(msg.StoragePath)
	if err != nil {
		return map[string]string{}
	}
	return spam.HeaderMetadata(data)
}

// HandleMailboxFolders returns standard mailbox folders
func (h *Handler) HandleMailboxFolders(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermReadEmail) {
		return
	}

	// Get message counts per folder
	folders := []string{"INBOX", "Sent", "Drafts", "Trash", "Junk", "Quarantine"}
	result := make([]map[string]interface{}, len(folders))

	for i, folder := range folders {
		msgs, _ := h.messageRepo.ListByAccount(acc.ID, folder)
		unread := 0
		for _, m := range msgs {
			if m.ReadAt == nil {
				unread++
			}
		}
		result[i] = map[string]interface{}{
			"name":   folder,
			"path":   folder,
			"total":  len(msgs),
			"unread": unread,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mailboxes": result,
	})
}

// HandleMailboxGetAttachment returns attachment data by ID
// Requires email query param for IDOR protection
func (h *Handler) HandleMailboxGetAttachment(w http.ResponseWriter, r *http.Request) {
	msgID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid message id", http.StatusBadRequest)
		return
	}

	attID := r.PathValue("att_id")
	if attID == "" {
		http.Error(w, "attachment id required", http.StatusBadRequest)
		return
	}

	// IDOR Protection: Require email and verify ownership
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required for authorization", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, "account not found", http.StatusForbidden)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermReadEmail) {
		return
	}

	msg, err := h.messageRepo.GetMessageByID(msgID)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}

	// Verify the message belongs to this account
	if msg.AccountID != acc.ID {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	// Parse the message to get attachments
	if msg.StoragePath == "" || h.blobStorage == nil {
		http.Error(w, "message content not available", http.StatusNotFound)
		return
	}

	data, err := h.blobStorage.Get(msg.StoragePath)
	if err != nil {
		http.Error(w, "failed to retrieve message", http.StatusInternalServerError)
		return
	}

	_, attachments := ParseRFC822Message(data)

	// Find the requested attachment by ID
	for _, att := range attachments {
		if att.Meta.ID == attID {
			// Set appropriate headers
			w.Header().Set("Content-Type", att.Meta.ContentType)
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, att.Meta.Filename))
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(att.Data)))
			w.Write(att.Data)
			return
		}
	}

	http.Error(w, "attachment not found", http.StatusNotFound)
}

// HandleMailboxSend sends an email on behalf of a user
func (h *Handler) HandleMailboxSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From        string   `json:"from"`
		To          []string `json:"to"`
		Cc          []string `json:"cc,omitempty"`
		Bcc         []string `json:"bcc,omitempty"`
		Subject     string   `json:"subject"`
		Text        string   `json:"text"`
		HTML        string   `json:"html,omitempty"`
		Attachments []struct {
			Filename    string `json:"filename"`
			ContentType string `json:"content_type"`
			Data        string `json:"data"` // Base64 encoded
		} `json:"attachments,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify sender account exists
	acc, err := h.getAccountByEmail(req.From)
	if err != nil {
		http.Error(w, "sender account not found", http.StatusForbidden)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermSendEmail) {
		return
	}
	dom, err := h.domainRepo.GetDomainByID(acc.DomainID)
	if err != nil {
		http.Error(w, "sender domain not found", http.StatusForbidden)
		return
	}

	// Build message - BCC recipients get the email but are not in headers
	// Handle nil slices safely
	allRecipients := make([]string, 0, len(req.To)+len(req.Cc)+len(req.Bcc))
	allRecipients = append(allRecipients, req.To...)
	if len(req.Cc) > 0 {
		allRecipients = append(allRecipients, req.Cc...)
	}
	if len(req.Bcc) > 0 {
		allRecipients = append(allRecipients, req.Bcc...)
	}

	now := time.Now()
	boundary := fmt.Sprintf("----=_Part_%s", uuid.New().String()[:8])
	msgID := uuid.New().String()
	mailHost := domain.EffectiveMailHostname(dom, h.serverHostname)

	var msgBuilder strings.Builder

	// Headers (BCC is NOT included in headers - that's how BCC works)
	msgBuilder.WriteString(fmt.Sprintf("Message-ID: <%s@%s>\r\n", msgID, strings.Split(req.From, "@")[1]))
	msgBuilder.WriteString(fmt.Sprintf("From: %s\r\n", req.From))
	msgBuilder.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(req.To, ", ")))
	if len(req.Cc) > 0 {
		msgBuilder.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(req.Cc, ", ")))
	}
	msgBuilder.WriteString(fmt.Sprintf("Subject: %s\r\n", req.Subject))
	msgBuilder.WriteString(fmt.Sprintf("Date: %s\r\n", now.Format(time.RFC1123Z)))
	msgBuilder.WriteString("MIME-Version: 1.0\r\n")
	msgBuilder.WriteString("User-Agent: Lightr Mailbox API\r\n")
	msgBuilder.WriteString("X-Mailer: Lightr\r\n")
	msgBuilder.WriteString(fmt.Sprintf("X-Lightr-Mailed-By: %s\r\n", mailHost))

	if len(req.Attachments) > 0 {
		msgBuilder.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
		msgBuilder.WriteString("\r\n")

		// Text body part
		msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msgBuilder.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		msgBuilder.WriteString("Content-Transfer-Encoding: 7bit\r\n")
		msgBuilder.WriteString("\r\n")
		msgBuilder.WriteString(req.Text)
		msgBuilder.WriteString("\r\n")

		// Attachment parts
		for _, att := range req.Attachments {
			msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			contentType := att.ContentType
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			msgBuilder.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", contentType, att.Filename))
			msgBuilder.WriteString("Content-Transfer-Encoding: base64\r\n")
			msgBuilder.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", att.Filename))
			msgBuilder.WriteString("\r\n")
			msgBuilder.WriteString(att.Data)
			msgBuilder.WriteString("\r\n")
		}

		msgBuilder.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		msgBuilder.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		msgBuilder.WriteString("\r\n")
		msgBuilder.WriteString(req.Text)
	}

	msg := msgBuilder.String()

	if err := h.relay.Send(r.Context(), req.From, allRecipients, []byte(msg)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Save to Sent folder
	sentMsg := &domain.Message{
		ID:         uuid.New(),
		AccountID:  acc.ID,
		Folder:     "Sent",
		Subject:    req.Subject,
		From:       req.From,
		To:         strings.Join(req.To, ", "),
		SizeBytes:  int64(len(msg)),
		ReceivedAt: now,
		ReadAt:     &now, // Sent messages are marked as read
	}

	// Store the raw message
	storagePath := fmt.Sprintf("messages/%s/%s.eml", acc.ID, sentMsg.ID)
	if h.blobStorage != nil {
		if err := h.blobStorage.Put(storagePath, []byte(msg)); err == nil {
			sentMsg.StoragePath = storagePath
		}
	}

	// Save to database
	if err := h.messageRepo.CreateMessage(sentMsg); err != nil {
		// Don't fail the request, just log
		log.Printf("Warning: failed to save sent message: %v", err)
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Email queued for delivery",
	})
}

// HandleMailboxContacts provides contact autocomplete for compose
func (h *Handler) HandleMailboxContacts(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	query := r.URL.Query().Get("q")

	if email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}

	// Verify account exists
	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, "account not found", http.StatusForbidden)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermReadEmail) {
		return
	}

	var contacts []domain.Contact

	// Search accounts in the same domain (colleagues) if query provided
	if query != "" {
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			domainName := parts[1]
			domainAccounts, err := h.accountRepo.SearchByDomain(domainName, query, 10)
			if err == nil {
				for _, da := range domainAccounts {
					if da.Email != email { // Exclude self
						name := da.DisplayName
						if name == "" {
							name = da.LocalPart
						}
						contacts = append(contacts, domain.Contact{
							Email:       da.Email,
							DisplayName: name,
						})
					}
				}
			}
		}
	}

	// Also search recipients from previously sent messages
	sentMessages, err := h.messageRepo.ListByAccount(acc.ID, "Sent")
	if err == nil {
		recipientCount := make(map[string]int)
		for _, msg := range sentMessages {
			// Parse the "To" field which might have multiple recipients
			recipients := strings.Split(msg.To, ",")
			for _, r := range recipients {
				r = strings.TrimSpace(r)
				// Extract email from "Name <email>" format
				if idx := strings.Index(r, "<"); idx != -1 {
					end := strings.Index(r, ">")
					if end > idx {
						r = r[idx+1 : end]
					}
				}
				r = strings.ToLower(strings.TrimSpace(r))
				if r != "" && r != email && (query == "" || strings.Contains(r, strings.ToLower(query))) {
					recipientCount[r]++
				}
			}
		}

		// Add to contacts, avoiding duplicates
		existingEmails := make(map[string]bool)
		for _, c := range contacts {
			existingEmails[strings.ToLower(c.Email)] = true
		}

		for emailAddr, count := range recipientCount {
			if !existingEmails[emailAddr] {
				contacts = append(contacts, domain.Contact{
					Email:        emailAddr,
					ContactCount: count,
				})
				existingEmails[emailAddr] = true
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contacts)
}

// HandleMailboxMarkMessage marks a message as read or unread
// Requires email in body for IDOR protection
func (h *Handler) HandleMailboxMarkMessage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var req struct {
		Email  string `json:"email"`
		Read   bool   `json:"read"`
		Folder string `json:"folder,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// IDOR Protection: Require email and verify ownership
	if req.Email == "" {
		http.Error(w, "email required for authorization", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(req.Email)
	if err != nil {
		http.Error(w, "account not found", http.StatusForbidden)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermManageMailbox) {
		return
	}

	msg, err := h.messageRepo.GetMessageByID(id)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}

	// Verify the message belongs to this account
	if msg.AccountID != acc.ID {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	if req.Read {
		now := time.Now()
		msg.ReadAt = &now
	} else {
		msg.ReadAt = nil
	}
	oldFolder := msg.Folder
	if req.Folder != "" {
		msg.Folder = req.Folder
		if err := h.applyMailboxTraining(r.Context(), msg, oldFolder, req.Folder); err != nil {
			log.Printf("mailbox training failed for %s: %v", msg.ID, err)
		}
	}

	if err := h.messageRepo.UpdateMessage(msg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"read":    req.Read,
		"folder":  msg.Folder,
	})
}

func (h *Handler) applyMailboxTraining(ctx context.Context, msg *domain.Message, oldFolder, newFolder string) error {
	if msg == nil || h.blobStorage == nil || msg.StoragePath == "" {
		return nil
	}
	wasJunk := strings.EqualFold(strings.TrimSpace(oldFolder), "Junk") || strings.EqualFold(strings.TrimSpace(oldFolder), "Spam")
	isJunk := strings.EqualFold(strings.TrimSpace(newFolder), "Junk") || strings.EqualFold(strings.TrimSpace(newFolder), "Spam")
	if wasJunk == isJunk {
		return h.rewriteClassificationHeaders(msg, newFolder)
	}

	raw, err := h.blobStorage.Get(msg.StoragePath)
	if err != nil {
		return err
	}
	senderEmail, senderDomain := spam.SenderIdentity(raw, msg.From)
	if learner, ok := h.messageRepo.(interface {
		RecordFeedback(ctx context.Context, senderEmail, senderDomain string, isSpam bool) error
	}); ok {
		if err := learner.RecordFeedback(ctx, senderEmail, senderDomain, isJunk); err != nil {
			return err
		}
	}
	return h.rewriteClassificationHeaders(msg, newFolder)
}

func (h *Handler) rewriteClassificationHeaders(msg *domain.Message, folder string) error {
	if msg == nil || h.blobStorage == nil || msg.StoragePath == "" {
		return nil
	}
	raw, err := h.blobStorage.Get(msg.StoragePath)
	if err != nil {
		return err
	}
	updated := spam.ApplyUserClassification(raw, folder)
	return h.blobStorage.Put(msg.StoragePath, updated)
}

// HandleUpdateMailboxAccount updates account display name etc
func (h *Handler) HandleUpdateMailboxAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(req.Email)
	if err != nil {
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}
	if !h.authorizeAccount(w, r, acc.ID, apikeys.PermManageMailbox) {
		return
	}

	acc.DisplayName = req.DisplayName
	acc.UpdatedAt = time.Now()

	if err := h.accountRepo.UpdateAccount(acc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"display_name": acc.DisplayName,
	})
}

func (h *Handler) resolveOrgRef(idRef, nameRef string) (uuid.UUID, error) {
	if idRef != "" {
		id, err := uuid.Parse(idRef)
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid org_id")
		}
		return id, nil
	}
	if nameRef == "" {
		return uuid.Nil, fmt.Errorf("org_id or org is required")
	}
	org, err := h.orgRepo.GetOrgByName(nameRef)
	if err != nil {
		return uuid.Nil, fmt.Errorf("organization not found")
	}
	return org.ID, nil
}

func (h *Handler) resolveOrgRefOrDefault(idRef, nameRef string) (uuid.UUID, error) {
	if firstNonEmpty(idRef, nameRef) == "" {
		org, err := domain.ResolveDefaultOrganization(h.orgRepo)
		if err != nil {
			return uuid.Nil, fmt.Errorf("default organization unavailable")
		}
		return org.ID, nil
	}
	return h.resolveOrgRef(idRef, nameRef)
}

func (h *Handler) resolveDomainRef(idRef, nameRef string) (uuid.UUID, error) {
	if idRef != "" {
		id, err := uuid.Parse(idRef)
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid domain_id")
		}
		return id, nil
	}
	if nameRef == "" {
		return uuid.Nil, fmt.Errorf("domain_id or domain is required")
	}
	dom, err := h.domainRepo.GetDomainByName(nameRef)
	if err != nil {
		return uuid.Nil, fmt.Errorf("domain not found")
	}
	return dom.ID, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (h *Handler) filterVisibleOrganizations(orgs []*domain.Organization) []*domain.Organization {
	filtered := make([]*domain.Organization, 0, len(orgs))
	for _, org := range orgs {
		if org != nil && !domain.IsDefaultOrganizationName(org.Name) {
			filtered = append(filtered, org)
		}
	}
	return filtered
}

func (h *Handler) listAllDomains() ([]*domain.Domain, error) {
	orgs, err := h.orgRepo.ListOrgs()
	if err != nil {
		return nil, err
	}
	var domains []*domain.Domain
	for _, org := range orgs {
		items, err := h.domainRepo.ListDomainsByOrg(org.ID)
		if err != nil {
			return nil, err
		}
		domains = append(domains, items...)
	}
	return domains, nil
}

func (h *Handler) listAccessibleDomains(key *apikeys.APIKey) ([]*domain.Domain, error) {
	if key == nil || hasGlobalAccess(key) {
		return h.listAllDomains()
	}
	if accountID := keyAccountID(key); accountID != nil {
		acc, err := h.accountRepo.GetAccountByID(*accountID)
		if err != nil {
			return nil, err
		}
		dom, err := h.domainRepo.GetDomainByID(acc.DomainID)
		if err != nil {
			return nil, err
		}
		return []*domain.Domain{dom}, nil
	}
	if key.DomainID != nil {
		dom, err := h.domainRepo.GetDomainByID(*key.DomainID)
		if err != nil {
			return nil, err
		}
		return []*domain.Domain{dom}, nil
	}
	if key.OrganizationID != nil {
		return h.domainRepo.ListDomainsByOrg(*key.OrganizationID)
	}
	return []*domain.Domain{}, nil
}
