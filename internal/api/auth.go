package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/apikeys"
)

func APIKeyAuthMiddleware(bootstrapKey string, service *apikeys.APIKeyService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		secret := extractAPISecret(r)
		if secret == "" {
			http.Error(w, "API key required", http.StatusUnauthorized)
			return
		}

		var key *apikeys.APIKey
		var err error
		if bootstrapKey != "" && secret == bootstrapKey {
			key = apikeys.BootstrapKey(secret)
		} else {
			if service == nil {
				http.Error(w, "API key service unavailable", http.StatusUnauthorized)
				return
			}
			key, err = service.ValidateKey(r.Context(), secret)
			if err != nil {
				status := http.StatusUnauthorized
				if err == apikeys.ErrKeyRateLimited {
					status = http.StatusTooManyRequests
				}
				http.Error(w, err.Error(), status)
				return
			}
			if err := service.ValidateIP(key, clientIP(r)); err != nil {
				http.Error(w, "IP not allowed", http.StatusForbidden)
				return
			}
		}

		ctx := context.WithValue(r.Context(), apiKeyContextKey, key)
		if service == nil || key == nil || key.ID == uuid.Nil {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r.WithContext(ctx))
		usageCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		service.RecordUsage(usageCtx, key, r, wrapped.status, time.Since(start))
	})
}

type contextKey string

const apiKeyContextKey contextKey = "scoped_api_key"

func getScopedAPIKey(ctx context.Context) *apikeys.APIKey {
	if key, ok := ctx.Value(apiKeyContextKey).(*apikeys.APIKey); ok {
		return key
	}
	return apikeys.GetAPIKey(ctx)
}

func (h *Handler) requirePermission(w http.ResponseWriter, r *http.Request, permission apikeys.Permission) *apikeys.APIKey {
	key := getScopedAPIKey(r.Context())
	if key == nil {
		return nil
	}
	if hasPermission(key, permission) {
		return key
	}
	http.Error(w, "permission denied", http.StatusForbidden)
	return nil
}

func (h *Handler) requireGlobalPermission(w http.ResponseWriter, r *http.Request, permission apikeys.Permission) bool {
	key := getScopedAPIKey(r.Context())
	if key == nil {
		return true
	}
	if !hasPermission(key, permission) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return false
	}
	if !hasGlobalAccess(key) {
		http.Error(w, "scope denied", http.StatusForbidden)
		return false
	}
	return true
}

func (h *Handler) authorizeOrg(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, permission apikeys.Permission) bool {
	key := h.requirePermission(w, r, permission)
	if key == nil {
		// requirePermission has already written the 403/401 response.
		return false
	}
	if hasGlobalAccess(key) {
		return true
	}
	if key.OrganizationID != nil && *key.OrganizationID == orgID {
		return true
	}
	if key.DomainID != nil {
		dom, err := h.domainRepo.GetDomainByID(*key.DomainID)
		if err == nil && dom.OrgID == orgID {
			return true
		}
	}
	if accountID := keyAccountID(key); accountID != nil {
		if acc, err := h.accountRepo.GetAccountByID(*accountID); err == nil {
			if dom, err := h.domainRepo.GetDomainByID(acc.DomainID); err == nil && dom.OrgID == orgID {
				return true
			}
		}
	}
	http.Error(w, "scope denied", http.StatusForbidden)
	return false
}

func (h *Handler) authorizeDomain(w http.ResponseWriter, r *http.Request, domainID uuid.UUID, permission apikeys.Permission) bool {
	key := h.requirePermission(w, r, permission)
	if key == nil {
		return false
	}
	if hasGlobalAccess(key) {
		return true
	}
	if key.DomainID != nil && *key.DomainID == domainID {
		return true
	}
	dom, err := h.domainRepo.GetDomainByID(domainID)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return false
	}
	if key.OrganizationID != nil && *key.OrganizationID == dom.OrgID {
		return true
	}
	if accountID := keyAccountID(key); accountID != nil {
		if acc, err := h.accountRepo.GetAccountByID(*accountID); err == nil && acc.DomainID == domainID {
			return true
		}
	}
	http.Error(w, "scope denied", http.StatusForbidden)
	return false
}

func (h *Handler) authorizeAccount(w http.ResponseWriter, r *http.Request, accountID uuid.UUID, permission apikeys.Permission) bool {
	key := h.requirePermission(w, r, permission)
	if key == nil {
		return false
	}
	if hasGlobalAccess(key) {
		return true
	}
	if scopedAccountID := keyAccountID(key); scopedAccountID != nil && *scopedAccountID == accountID {
		return true
	}
	acc, err := h.accountRepo.GetAccountByID(accountID)
	if err != nil {
		http.Error(w, "account not found", http.StatusNotFound)
		return false
	}
	if key.DomainID != nil && *key.DomainID == acc.DomainID {
		return true
	}
	if key.OrganizationID != nil {
		dom, err := h.domainRepo.GetDomainByID(acc.DomainID)
		if err == nil && dom.OrgID == *key.OrganizationID {
			return true
		}
	}
	http.Error(w, "scope denied", http.StatusForbidden)
	return false
}

func hasPermission(key *apikeys.APIKey, permission apikeys.Permission) bool {
	if key == nil {
		return true
	}
	for _, item := range key.Permissions {
		if item == apikeys.PermSuperAdmin || item == permission {
			return true
		}
	}
	return false
}

func hasGlobalAccess(key *apikeys.APIKey) bool {
	return key != nil && hasPermission(key, apikeys.PermSuperAdmin)
}

func keyAccountID(key *apikeys.APIKey) *uuid.UUID {
	if key == nil {
		return nil
	}
	if key.AccountID != nil {
		return key.AccountID
	}
	return key.UserID
}

func extractAPISecret(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	if authHeader != "" {
		return authHeader
	}
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}
	return r.URL.Query().Get("api_key")
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.Trim(strings.TrimSpace(r.RemoteAddr), "[]")
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
