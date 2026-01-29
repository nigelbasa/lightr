package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nigelbasa/lightr/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	accountRepo domain.AccountRepository
	offloader   domain.AuthOffloader
}

func NewService(repo domain.AccountRepository, offloader domain.AuthOffloader) *Service {
	return &Service{
		accountRepo: repo,
		offloader:   offloader,
	}
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
		if s.offloader == nil {
			return nil, errors.New("auth offloader not configured")
		}
		return s.offloader.OffloadAuth(ctx, username, password)
	default:
		return nil, fmt.Errorf("unsupported auth mode: %s", acc.AuthMode)
	}
}

type HTTPOffloader struct {
	hookURL    string
	httpClient *http.Client
}

func NewHTTPOffloader(hookURL string) *HTTPOffloader {
	return &HTTPOffloader{
		hookURL: hookURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	// Could include user metadata to sync back
}

func (h *HTTPOffloader) OffloadAuth(ctx context.Context, username, password string) (*domain.Account, error) {
	reqBody, _ := json.Marshal(authRequest{Username: username, Password: password})
	req, err := http.NewRequestWithContext(ctx, "POST", h.hookURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth offload failed with status: %d", resp.StatusCode)
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	if !authResp.Success {
		return nil, errors.New(authResp.Error)
	}

	// In a real implementation, we might want to return the local account
	// or create a transient one.
	return nil, errors.New("not fully implemented: account sync from offload")
}
