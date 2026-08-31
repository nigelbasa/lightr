package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/apikeys"
)

type createAPIKeyRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	Type           string   `json:"type"`
	OrgID          string   `json:"org_id,omitempty"`
	Org            string   `json:"org,omitempty"`
	DomainID       string   `json:"domain_id,omitempty"`
	Domain         string   `json:"domain,omitempty"`
	AccountID      string   `json:"account_id,omitempty"`
	Account        string   `json:"account,omitempty"`
	ExpiresIn      string   `json:"expires_in,omitempty"`
	RateLimit      int      `json:"rate_limit,omitempty"`
	DailyLimit     int      `json:"daily_limit,omitempty"`
	AllowedIPs     []string `json:"allowed_ips,omitempty"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
}

func (h *Handler) HandleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	if h.apikeyService == nil {
		http.Error(w, "api key service unavailable", http.StatusNotImplemented)
		return
	}
	key := h.requirePermission(w, r, apikeys.PermManageAPIKeys)
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
		if !h.authorizeOrg(w, r, id, apikeys.PermManageAPIKeys) {
			return
		}
		orgID = &id
	} else if scopedOrgID := h.apiKeyScopeOrgID(key); scopedOrgID != nil && !hasGlobalAccess(key) {
		orgID = scopedOrgID
	}

	keys, err := h.apikeyService.List(r.Context(), orgID, 100, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	keys = h.filterAccessibleAPIKeys(key, keys)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func (h *Handler) HandleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	if h.apikeyService == nil {
		http.Error(w, "api key service unavailable", http.StatusNotImplemented)
		return
	}
	actor := h.requirePermission(w, r, apikeys.PermManageAPIKeys)
	if actor == nil && getScopedAPIKey(r.Context()) != nil {
		return
	}

	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	create := &apikeys.APIKeyCreate{
		Name:           req.Name,
		Description:    req.Description,
		Type:           apikeys.KeyType(req.Type),
		RateLimit:      req.RateLimit,
		DailyLimit:     req.DailyLimit,
		AllowedIPs:     req.AllowedIPs,
		AllowedDomains: req.AllowedDomains,
	}
	if !isSupportedAPIKeyType(create.Type) {
		http.Error(w, "invalid api key type", http.StatusBadRequest)
		return
	}

	if orgID, err := h.resolveOptionalOrg(req.OrgID, req.Org); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if orgID != nil {
		if !h.authorizeOrg(w, r, *orgID, apikeys.PermManageAPIKeys) {
			return
		}
		create.OrganizationID = orgID
	}

	if domainID, err := h.resolveOptionalDomain(req.DomainID, req.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if domainID != nil {
		if !h.authorizeDomain(w, r, *domainID, apikeys.PermManageAPIKeys) {
			return
		}
		create.DomainID = domainID
		dom, _ := h.domainRepo.GetDomainByID(*domainID)
		if dom != nil && create.OrganizationID == nil {
			create.OrganizationID = &dom.OrgID
		}
	}

	if accountID, err := h.resolveOptionalAccount(req.AccountID, req.Account); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if accountID != nil {
		if !h.authorizeAccount(w, r, *accountID, apikeys.PermManageAPIKeys) {
			return
		}
		create.AccountID = accountID
		create.UserID = accountID
		acc, _ := h.accountRepo.GetAccountByID(*accountID)
		if acc != nil {
			if create.DomainID == nil {
				create.DomainID = &acc.DomainID
			}
			if create.OrganizationID == nil {
				if dom, err := h.domainRepo.GetDomainByID(acc.DomainID); err == nil {
					create.OrganizationID = &dom.OrgID
				}
			}
		}
	}

	if err := h.constrainAPIKeyCreate(actor, create); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if strings.TrimSpace(req.ExpiresIn) != "" {
		expiry, err := parseAPIExpiryDuration(req.ExpiresIn)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		create.ExpiresIn = expiry
	}

	result, err := h.apikeyService.GenerateKey(r.Context(), create)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

func parseAPIExpiryDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return 0, nil
	}
	if strings.HasSuffix(raw, "d") {
		daysRaw := strings.TrimSuffix(raw, "d")
		var days int
		if _, err := fmt.Sscanf(daysRaw, "%d", &days); err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid expires_in")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(raw)
}

func (h *Handler) HandleRotateAPIKey(w http.ResponseWriter, r *http.Request) {
	if h.apikeyService == nil {
		http.Error(w, "api key service unavailable", http.StatusNotImplemented)
		return
	}
	target, actor, ok := h.getAccessibleAPIKeyTarget(w, r, apikeys.PermManageAPIKeys)
	if !ok {
		return
	}
	if actor != nil && !h.apiKeyAccessible(actor, target) {
		http.Error(w, "scope denied", http.StatusForbidden)
		return
	}
	result, err := h.apikeyService.RotateKey(r.Context(), target.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) HandleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if h.apikeyService == nil {
		http.Error(w, "api key service unavailable", http.StatusNotImplemented)
		return
	}
	target, actor, ok := h.getAccessibleAPIKeyTarget(w, r, apikeys.PermManageAPIKeys)
	if !ok {
		return
	}
	if actor != nil && !h.apiKeyAccessible(actor, target) {
		http.Error(w, "scope denied", http.StatusForbidden)
		return
	}
	if err := h.apikeyService.RevokeKey(r.Context(), target.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if h.apikeyService == nil {
		http.Error(w, "api key service unavailable", http.StatusNotImplemented)
		return
	}
	target, actor, ok := h.getAccessibleAPIKeyTarget(w, r, apikeys.PermManageAPIKeys)
	if !ok {
		return
	}
	if actor != nil && !h.apiKeyAccessible(actor, target) {
		http.Error(w, "scope denied", http.StatusForbidden)
		return
	}
	if err := h.apikeyService.Delete(r.Context(), target.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getAccessibleAPIKeyTarget(w http.ResponseWriter, r *http.Request, permission apikeys.Permission) (*apikeys.APIKey, *apikeys.APIKey, bool) {
	actor := h.requirePermission(w, r, permission)
	if actor == nil && getScopedAPIKey(r.Context()) != nil {
		return nil, nil, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return nil, nil, false
	}
	target, err := h.apikeyService.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "api key not found", http.StatusNotFound)
		return nil, nil, false
	}
	return target, actor, true
}

func (h *Handler) resolveOptionalOrg(idRef, nameRef string) (*uuid.UUID, error) {
	if firstNonEmpty(idRef, nameRef) == "" {
		return nil, nil
	}
	id, err := h.resolveOrgRef(idRef, nameRef)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func (h *Handler) resolveOptionalDomain(idRef, nameRef string) (*uuid.UUID, error) {
	if firstNonEmpty(idRef, nameRef) == "" {
		return nil, nil
	}
	id, err := h.resolveDomainRef(idRef, nameRef)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func (h *Handler) resolveOptionalAccount(idRef, emailRef string) (*uuid.UUID, error) {
	if firstNonEmpty(idRef, emailRef) == "" {
		return nil, nil
	}
	if idRef != "" {
		id, err := uuid.Parse(idRef)
		if err != nil {
			return nil, err
		}
		return &id, nil
	}
	acc, err := h.getAccountByEmail(emailRef)
	if err != nil {
		return nil, err
	}
	return &acc.ID, nil
}

func isSupportedAPIKeyType(keyType apikeys.KeyType) bool {
	switch keyType {
	case apikeys.KeyTypeMaster,
		apikeys.KeyTypeAdmin,
		apikeys.KeyTypeOrg,
		apikeys.KeyTypeDomain,
		apikeys.KeyTypeAccount,
		apikeys.KeyTypeSending,
		apikeys.KeyTypeReceiving,
		apikeys.KeyTypeReadOnly,
		apikeys.KeyTypeWebhook,
		apikeys.KeyTypeIntegration:
		return true
	default:
		return false
	}
}

func isScopedAPIKeyType(keyType apikeys.KeyType) bool {
	switch keyType {
	case apikeys.KeyTypeOrg,
		apikeys.KeyTypeDomain,
		apikeys.KeyTypeAccount,
		apikeys.KeyTypeSending,
		apikeys.KeyTypeReceiving,
		apikeys.KeyTypeReadOnly,
		apikeys.KeyTypeWebhook,
		apikeys.KeyTypeIntegration:
		return true
	default:
		return false
	}
}

func allowedScopedKeyTypeForActor(actor *apikeys.APIKey, keyType apikeys.KeyType) bool {
	switch {
	case actor == nil || hasGlobalAccess(actor):
		return true
	case keyAccountID(actor) != nil:
		switch keyType {
		case apikeys.KeyTypeAccount,
			apikeys.KeyTypeSending,
			apikeys.KeyTypeReceiving,
			apikeys.KeyTypeReadOnly,
			apikeys.KeyTypeIntegration:
			return true
		default:
			return false
		}
	case actor.DomainID != nil:
		switch keyType {
		case apikeys.KeyTypeDomain,
			apikeys.KeyTypeAccount,
			apikeys.KeyTypeSending,
			apikeys.KeyTypeReceiving,
			apikeys.KeyTypeReadOnly,
			apikeys.KeyTypeWebhook,
			apikeys.KeyTypeIntegration:
			return true
		default:
			return false
		}
	case actor.OrganizationID != nil:
		switch keyType {
		case apikeys.KeyTypeOrg,
			apikeys.KeyTypeDomain,
			apikeys.KeyTypeAccount,
			apikeys.KeyTypeSending,
			apikeys.KeyTypeReceiving,
			apikeys.KeyTypeReadOnly,
			apikeys.KeyTypeWebhook,
			apikeys.KeyTypeIntegration:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func (h *Handler) constrainAPIKeyCreate(actor *apikeys.APIKey, create *apikeys.APIKeyCreate) error {
	if actor == nil || hasGlobalAccess(actor) {
		return nil
	}
	if !isScopedAPIKeyType(create.Type) {
		return fmt.Errorf("requested key type requires global administrator privileges")
	}
	if !allowedScopedKeyTypeForActor(actor, create.Type) {
		return fmt.Errorf("requested key type exceeds caller scope")
	}

	if accountID := keyAccountID(actor); accountID != nil {
		acc, err := h.accountRepo.GetAccountByID(*accountID)
		if err != nil {
			return fmt.Errorf("actor account not found")
		}
		dom, err := h.domainRepo.GetDomainByID(acc.DomainID)
		if err != nil {
			return fmt.Errorf("actor domain not found")
		}
		if create.AccountID == nil {
			create.AccountID = accountID
		}
		if *create.AccountID != *accountID {
			return fmt.Errorf("account-scoped keys can only create keys for the same account")
		}
		if create.DomainID == nil {
			create.DomainID = &acc.DomainID
		}
		if *create.DomainID != acc.DomainID {
			return fmt.Errorf("account-scoped keys cannot escape their domain")
		}
		if create.OrganizationID == nil {
			create.OrganizationID = &dom.OrgID
		}
		if *create.OrganizationID != dom.OrgID {
			return fmt.Errorf("account-scoped keys cannot escape their organization")
		}
		create.UserID = create.AccountID
		return nil
	}

	if actor.DomainID != nil {
		dom, err := h.domainRepo.GetDomainByID(*actor.DomainID)
		if err != nil {
			return fmt.Errorf("actor domain not found")
		}
		if create.AccountID != nil {
			acc, err := h.accountRepo.GetAccountByID(*create.AccountID)
			if err != nil {
				return fmt.Errorf("account not found")
			}
			if acc.DomainID != *actor.DomainID {
				return fmt.Errorf("domain-scoped keys can only create account keys in the same domain")
			}
			if create.DomainID == nil {
				create.DomainID = &acc.DomainID
			}
			create.UserID = create.AccountID
		}
		if create.DomainID == nil {
			create.DomainID = actor.DomainID
		}
		if *create.DomainID != *actor.DomainID {
			return fmt.Errorf("domain-scoped keys cannot escape their domain")
		}
		if create.OrganizationID == nil {
			create.OrganizationID = &dom.OrgID
		}
		if *create.OrganizationID != dom.OrgID {
			return fmt.Errorf("domain-scoped keys cannot escape their organization")
		}
		return nil
	}

	if actor.OrganizationID != nil {
		if create.AccountID != nil {
			acc, err := h.accountRepo.GetAccountByID(*create.AccountID)
			if err != nil {
				return fmt.Errorf("account not found")
			}
			dom, err := h.domainRepo.GetDomainByID(acc.DomainID)
			if err != nil {
				return fmt.Errorf("account domain not found")
			}
			if dom.OrgID != *actor.OrganizationID {
				return fmt.Errorf("organization-scoped keys can only create account keys in the same organization")
			}
			if create.DomainID == nil {
				create.DomainID = &acc.DomainID
			}
			create.UserID = create.AccountID
		}
		if create.DomainID != nil {
			dom, err := h.domainRepo.GetDomainByID(*create.DomainID)
			if err != nil {
				return fmt.Errorf("domain not found")
			}
			if dom.OrgID != *actor.OrganizationID {
				return fmt.Errorf("organization-scoped keys can only create domain keys in the same organization")
			}
		}
		if create.OrganizationID == nil {
			create.OrganizationID = actor.OrganizationID
		}
		if *create.OrganizationID != *actor.OrganizationID {
			return fmt.Errorf("organization-scoped keys cannot escape their organization")
		}
		return nil
	}

	return fmt.Errorf("scoped key is missing scope")
}

func (h *Handler) apiKeyScopeOrgID(key *apikeys.APIKey) *uuid.UUID {
	if key == nil {
		return nil
	}
	if key.OrganizationID != nil {
		return key.OrganizationID
	}
	if key.DomainID != nil {
		dom, err := h.domainRepo.GetDomainByID(*key.DomainID)
		if err != nil {
			return nil
		}
		return &dom.OrgID
	}
	if accountID := keyAccountID(key); accountID != nil {
		acc, err := h.accountRepo.GetAccountByID(*accountID)
		if err != nil {
			return nil
		}
		dom, err := h.domainRepo.GetDomainByID(acc.DomainID)
		if err != nil {
			return nil
		}
		return &dom.OrgID
	}
	return nil
}

func (h *Handler) filterAccessibleAPIKeys(actor *apikeys.APIKey, keys []*apikeys.APIKey) []*apikeys.APIKey {
	if actor == nil || hasGlobalAccess(actor) {
		return keys
	}
	filtered := make([]*apikeys.APIKey, 0, len(keys))
	for _, key := range keys {
		if h.apiKeyAccessible(actor, key) {
			filtered = append(filtered, key)
		}
	}
	return filtered
}

func (h *Handler) apiKeyAccessible(actor *apikeys.APIKey, target *apikeys.APIKey) bool {
	if actor == nil || target == nil {
		return false
	}
	if hasGlobalAccess(actor) {
		return true
	}
	if hasGlobalAccess(target) {
		return false
	}

	if accountID := keyAccountID(actor); accountID != nil {
		targetAccountID := keyAccountID(target)
		return targetAccountID != nil && *targetAccountID == *accountID
	}

	if actor.DomainID != nil {
		if targetAccountID := keyAccountID(target); targetAccountID != nil {
			acc, err := h.accountRepo.GetAccountByID(*targetAccountID)
			return err == nil && acc.DomainID == *actor.DomainID
		}
		return target.DomainID != nil && *target.DomainID == *actor.DomainID
	}

	if actor.OrganizationID != nil {
		if targetAccountID := keyAccountID(target); targetAccountID != nil {
			acc, err := h.accountRepo.GetAccountByID(*targetAccountID)
			if err != nil {
				return false
			}
			dom, err := h.domainRepo.GetDomainByID(acc.DomainID)
			return err == nil && dom.OrgID == *actor.OrganizationID
		}
		if target.DomainID != nil {
			dom, err := h.domainRepo.GetDomainByID(*target.DomainID)
			return err == nil && dom.OrgID == *actor.OrganizationID
		}
		return target.OrganizationID != nil && *target.OrganizationID == *actor.OrganizationID
	}

	return false
}
