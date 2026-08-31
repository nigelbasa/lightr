package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/nigelbasa/lightr/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	accountRepo domain.AccountRepository
	domainRepo  domain.DomainRepository
	offloader   domain.AuthOffloader
}

func NewService(repo domain.AccountRepository, offloader domain.AuthOffloader) *Service {
	return &Service{
		accountRepo: repo,
		offloader:   offloader,
	}
}

// WithDomainRepo sets the domain repository for webhook URL lookup
func (s *Service) WithDomainRepo(repo domain.DomainRepository) *Service {
	s.domainRepo = repo
	return s
}

func (s *Service) Authenticate(ctx context.Context, username, password string) (*domain.Account, error) {
	acc, err := s.accountRepo.GetAccountByEmail(username)
	if err != nil {
		return nil, err
	}

	switch acc.AuthMode {
	case domain.AuthModeNative:
		if err := bcrypt.CompareHashAndPassword([]byte(acc.PasswordHash), []byte(password)); err != nil {
			return nil, errors.New("invalid credentials")
		}
		return acc, nil
	case domain.AuthModeOffloaded:
		// Try domain-specific auth webhook first
		if s.domainRepo != nil {
			dom, err := s.domainRepo.GetDomainByID(acc.DomainID)
			if err == nil && dom.AuthWebhookURL != "" {
				if !dom.AuthWebhookVerified {
					return nil, errors.New("auth webhook is not verified for this domain")
				}
				log.Printf("Auth: Using auth webhook URL for domain %s: %s", dom.Name, dom.AuthWebhookURL)
				offloader := NewHTTPOffloader(dom.AuthWebhookURL).WithSecret(dom.AuthWebhookSecret)
				authResult, err := offloader.OffloadAuth(ctx, username, password)
				if err != nil {
					return nil, err
				}
				// Update account with display name from webhook if provided
				if authResult != nil && authResult.DisplayName != "" {
					acc.DisplayName = authResult.DisplayName
				}
				return acc, nil
			}
		}

		// Fall back to global offloader
		if s.offloader == nil {
			return nil, errors.New("auth offloader not configured")
		}
		authResult, err := s.offloader.OffloadAuth(ctx, username, password)
		if err != nil {
			return nil, err
		}
		// Update account with display name from webhook if provided
		if authResult != nil && authResult.DisplayName != "" {
			acc.DisplayName = authResult.DisplayName
		}
		return acc, nil
	default:
		return nil, fmt.Errorf("unsupported auth mode: %s", acc.AuthMode)
	}
}

type HTTPOffloader struct {
	hookURL       string
	webhookSecret string
	httpClient    *http.Client
}

func NewHTTPOffloader(hookURL string) *HTTPOffloader {
	return &HTTPOffloader{
		hookURL: hookURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// WithSecret sets the webhook secret for authentication
func (h *HTTPOffloader) WithSecret(secret string) *HTTPOffloader {
	h.webhookSecret = secret
	return h
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type verifyRequest struct {
	Type      string `json:"type"`
	Domain    string `json:"domain"`
	Challenge string `json:"challenge"`
	Timestamp string `json:"timestamp"`
}

type authResponse struct {
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Verified    bool   `json:"verified,omitempty"`
	Challenge   string `json:"challenge,omitempty"`
}

func (h *HTTPOffloader) OffloadAuth(ctx context.Context, username, password string) (*domain.AuthResult, error) {
	reqBody, _ := json.Marshal(authRequest{Username: username, Password: password})
	req, err := http.NewRequestWithContext(ctx, "POST", h.hookURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Add webhook secret header if configured
	if h.webhookSecret != "" {
		req.Header.Set("X-Lightr-Webhook-Secret", h.webhookSecret)
	}

	log.Printf("Auth offload: POST %s for user %s", h.hookURL, username)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Printf("Auth offload: HTTP error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Auth offload: HTTP status %d", resp.StatusCode)
		return nil, fmt.Errorf("auth offload failed with status: %d", resp.StatusCode)
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		log.Printf("Auth offload: Failed to decode response: %v", err)
		return nil, err
	}

	if !authResp.Success {
		errMsg := authResp.Error
		if errMsg == "" {
			errMsg = "authentication failed"
		}
		log.Printf("Auth offload: Auth failed for %s: %s", username, errMsg)
		return nil, errors.New(errMsg)
	}

	log.Printf("Auth offload: Success for %s (display_name: %s)", username, authResp.DisplayName)

	// Return auth result with user info from webhook
	return &domain.AuthResult{
		UserID:      authResp.UserID,
		Email:       authResp.Email,
		DisplayName: authResp.DisplayName,
	}, nil
}

func VerifyDomainAuthWebhook(ctx context.Context, hookURL, secret, domainName string) error {
	challenge := fmt.Sprintf("lightr-%d", time.Now().UnixNano())
	reqBody, _ := json.Marshal(verifyRequest{
		Type:      "verify",
		Domain:    domainName,
		Challenge: challenge,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hookURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Lightr-Webhook-Secret", secret)
	}
	req.Header.Set("X-Lightr-Webhook-Mode", "verify")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("verification webhook returned status %d", resp.StatusCode)
	}

	var out authResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Verified || out.Success {
		if out.Challenge == "" || out.Challenge == challenge {
			return nil
		}
	}
	return errors.New("verification webhook did not confirm challenge")
}
