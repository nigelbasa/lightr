package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/apikeys"
	iauth "github.com/nigelbasa/lightr/internal/auth"
	"github.com/nigelbasa/lightr/internal/domain"
	"github.com/nigelbasa/lightr/internal/smtp"
	"golang.org/x/crypto/bcrypt"
)

type accountUpdateRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Password    *string `json:"password,omitempty"`
	QuotaBytes  *int64  `json:"quota_bytes,omitempty"`
	AuthMode    *string `json:"auth_mode,omitempty"`
	ExternalID  *string `json:"external_id,omitempty"`
}

type domainDNSResponse struct {
	Domain       string                  `json:"domain"`
	MailHostname string                  `json:"mail_hostname"`
	Records      *domain.DNSRecords      `json:"records"`
	Verification *domain.DNSVerification `json:"verification"`
}

func (h *Handler) HandleListAccounts(w http.ResponseWriter, r *http.Request) {
	key := h.requirePermission(w, r, apikeys.PermManageUser)
	if key == nil && getScopedAPIKey(r.Context()) != nil {
		return
	}

	var domains []*domain.Domain
	if ref := firstNonEmpty(r.URL.Query().Get("domain_id"), r.URL.Query().Get("domain")); ref != "" {
		domID, err := h.resolveDomainRef(r.URL.Query().Get("domain_id"), r.URL.Query().Get("domain"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !h.authorizeDomain(w, r, domID, apikeys.PermManageUser) {
			return
		}
		dom, err := h.domainRepo.GetDomainByID(domID)
		if err != nil {
			http.Error(w, "domain not found", http.StatusNotFound)
			return
		}
		domains = []*domain.Domain{dom}
	} else if ref := firstNonEmpty(r.URL.Query().Get("org_id"), r.URL.Query().Get("org")); ref != "" {
		orgID, err := h.resolveOrgRef(r.URL.Query().Get("org_id"), r.URL.Query().Get("org"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !h.authorizeOrg(w, r, orgID, apikeys.PermManageUser) {
			return
		}
		items, err := h.domainRepo.ListDomainsByOrg(orgID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		domains = items
	} else {
		items, err := h.listAccessibleDomains(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		domains = items
	}

	lister, ok := h.accountRepo.(interface {
		ListAccountsByDomain(uuid.UUID) ([]*domain.Account, error)
	})
	if !ok {
		http.Error(w, "account listing unavailable", http.StatusNotImplemented)
		return
	}

	var accounts []*domain.Account
	for _, dom := range domains {
		items, err := lister.ListAccountsByDomain(dom.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, acc := range items {
			acc.Email = accountEmailForDomain(acc, dom.Name)
		}
		accounts = append(accounts, items...)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(accounts)
}

func (h *Handler) HandleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if !h.authorizeAccount(w, r, id, apikeys.PermManageUser) {
		return
	}
	acc, err := h.accountRepo.GetAccountByID(id)
	if err != nil {
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}
	dom, err := h.domainRepo.GetDomainByID(acc.DomainID)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}

	var req accountUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.DisplayName != nil {
		acc.DisplayName = *req.DisplayName
	}
	if req.QuotaBytes != nil {
		acc.QuotaBytes = *req.QuotaBytes
	}
	if req.AuthMode != nil {
		acc.AuthMode = domain.AuthMode(strings.ToLower(strings.TrimSpace(*req.AuthMode)))
		if err := domain.ValidateAccountAuthMode(dom, acc.AuthMode); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if acc.AuthMode == domain.AuthModeNative && strings.TrimSpace(acc.PasswordHash) == "" && req.Password == nil {
			http.Error(w, "password is required when switching to native auth", http.StatusBadRequest)
			return
		}
	}
	if req.ExternalID != nil {
		acc.ExternalID = *req.ExternalID
	}
	if req.Password != nil {
		if acc.AuthMode != domain.AuthModeNative {
			http.Error(w, "password updates are only valid for native accounts", http.StatusBadRequest)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
			return
		}
		acc.PasswordHash = string(hash)
	}
	if err := h.accountRepo.UpdateAccount(acc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	acc.Email = accountEmailForDomain(acc, dom.Name)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(acc)
}

func (h *Handler) HandleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if !h.authorizeDomain(w, r, id, apikeys.PermManageDomain) {
		return
	}
	deleter, ok := h.domainRepo.(interface {
		DeleteDomain(uuid.UUID) error
	})
	if !ok {
		http.Error(w, "domain deletion unavailable", http.StatusNotImplemented)
		return
	}
	if err := deleter.DeleteDomain(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleGetDomainDNS(w http.ResponseWriter, r *http.Request) {
	response, ok := h.domainDNSResponseForRequest(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) HandleVerifyDomain(w http.ResponseWriter, r *http.Request) {
	dom, response, ok := h.domainDNSStateForMutation(w, r)
	if !ok {
		return
	}
	if !(response.Verification.MX && response.Verification.SPF && response.Verification.DKIM && response.Verification.DMARC) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(response)
		return
	}
	dom.IsVerified = true
	if err := h.domainRepo.UpdateDomain(dom); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) HandleVerifyDomainAuthWebhook(w http.ResponseWriter, r *http.Request) {
	dom, ok := h.mutableDomainFromRequest(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(dom.AuthWebhookURL) == "" {
		http.Error(w, "auth webhook URL is not configured", http.StatusBadRequest)
		return
	}
	if err := domain.EnsureAuthWebhookSecret(dom); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := iauth.VerifyDomainAuthWebhook(r.Context(), dom.AuthWebhookURL, dom.AuthWebhookSecret, dom.Name); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	domain.MarkAuthWebhookVerified(dom)
	if err := h.domainRepo.UpdateDomain(dom); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":                   dom.Name,
		"auth_webhook_verified":    dom.AuthWebhookVerified,
		"auth_webhook_verified_at": dom.AuthWebhookVerifiedAt,
	})
}

func (h *Handler) HandleRotateDomainAuthWebhookSecret(w http.ResponseWriter, r *http.Request) {
	dom, ok := h.mutableDomainFromRequest(w, r)
	if !ok {
		return
	}
	secret, err := domain.GenerateAuthWebhookSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dom.AuthWebhookSecret = secret
	domain.ResetAuthWebhookVerification(dom)
	if err := h.domainRepo.UpdateDomain(dom); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":                   dom.Name,
		"auth_webhook_secret":      secret,
		"auth_webhook_verified":    dom.AuthWebhookVerified,
		"auth_webhook_verified_at": dom.AuthWebhookVerifiedAt,
	})
}

func (h *Handler) domainDNSResponseForRequest(w http.ResponseWriter, r *http.Request) (*domainDNSResponse, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return nil, false
	}
	if !h.authorizeDomain(w, r, id, apikeys.PermManageDomain) {
		return nil, false
	}
	dom, err := h.domainRepo.GetDomainByID(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return nil, false
	}
	response, err := h.buildDomainDNSResponse(dom)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	return response, true
}

func (h *Handler) domainDNSStateForMutation(w http.ResponseWriter, r *http.Request) (*domain.Domain, *domainDNSResponse, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return nil, nil, false
	}
	if !h.authorizeDomain(w, r, id, apikeys.PermManageDomain) {
		return nil, nil, false
	}
	dom, err := h.domainRepo.GetDomainByID(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return nil, nil, false
	}
	response, err := h.buildDomainDNSResponse(dom)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, nil, false
	}
	return dom, response, true
}

func (h *Handler) mutableDomainFromRequest(w http.ResponseWriter, r *http.Request) (*domain.Domain, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return nil, false
	}
	if !h.authorizeDomain(w, r, id, apikeys.PermManageDomain) {
		return nil, false
	}
	dom, err := h.domainRepo.GetDomainByID(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return nil, false
	}
	return dom, true
}

func (h *Handler) buildDomainDNSResponse(dom *domain.Domain) (*domainDNSResponse, error) {
	selector := firstNonEmpty(dom.DKIMSelector, "default")
	publicKeyBytes, err := publicKeyBytesForDomain(dom)
	if err != nil {
		return nil, err
	}
	hostname := domain.EffectiveMailHostname(dom, h.serverHostname)
	return &domainDNSResponse{
		Domain:       dom.Name,
		MailHostname: hostname,
		Records:      domain.GenerateRecommendedDNS(dom.Name, hostname, selector, publicKeyBytes),
		Verification: domain.VerifyRecommendedDNS(dom.Name, hostname, selector, publicKeyBytes),
	}, nil
}

func publicKeyBytesForDomain(dom *domain.Domain) ([]byte, error) {
	if dom == nil || strings.TrimSpace(dom.DKIMPrivateKey) == "" {
		return nil, nil
	}
	return smtp.DKIMPublicKeyBytesFromPrivateKey(dom.DKIMPrivateKey)
}

func accountEmailForDomain(acc *domain.Account, domainName string) string {
	if acc == nil {
		return ""
	}
	if strings.TrimSpace(acc.Email) != "" {
		return acc.Email
	}
	return fmt.Sprintf("%s@%s", acc.LocalPart, domainName)
}
