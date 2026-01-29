package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuth2Offloader implements Offloader for OAuth2/OIDC auth
type OAuth2Offloader struct {
	config     *ProviderConfig
	oauth2Cfg  *OAuth2Config
	client     *http.Client
	stateStore *StateStore
}

// StateStore manages OAuth2 state tokens
type StateStore struct {
	mu     sync.RWMutex
	states map[string]*OAuthState
}

// OAuthState represents an OAuth2 authorization state
type OAuthState struct {
	State       string
	Nonce       string
	RedirectURI string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Extra       map[string]string
}

// NewStateStore creates a new state store
func NewStateStore() *StateStore {
	store := &StateStore{
		states: make(map[string]*OAuthState),
	}
	// Start cleanup goroutine
	go store.cleanup()
	return store
}

func (s *StateStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for state, data := range s.states {
			if now.After(data.ExpiresAt) {
				delete(s.states, state)
			}
		}
		s.mu.Unlock()
	}
}

func (s *StateStore) Create(redirectURI string, extra map[string]string) (*OAuthState, error) {
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, err
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}

	state := &OAuthState{
		State:       base64.URLEncoding.EncodeToString(stateBytes),
		Nonce:       base64.URLEncoding.EncodeToString(nonceBytes),
		RedirectURI: redirectURI,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Extra:       extra,
	}

	s.mu.Lock()
	s.states[state.State] = state
	s.mu.Unlock()

	return state, nil
}

func (s *StateStore) Validate(state string) (*OAuthState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.states[state]
	if !ok {
		return nil, false
	}

	if time.Now().After(data.ExpiresAt) {
		delete(s.states, state)
		return nil, false
	}

	delete(s.states, state)
	return data, true
}

// NewOAuth2Offloader creates a new OAuth2/OIDC offloader
func NewOAuth2Offloader(config *ProviderConfig) (*OAuth2Offloader, error) {
	var oauth2Cfg OAuth2Config
	if err := json.Unmarshal(config.Config, &oauth2Cfg); err != nil {
		return nil, fmt.Errorf("invalid OAuth2 config: %w", err)
	}

	// Set defaults
	if oauth2Cfg.EmailField == "" {
		oauth2Cfg.EmailField = "email"
	}
	if oauth2Cfg.NameField == "" {
		oauth2Cfg.NameField = "name"
	}
	if len(oauth2Cfg.Scopes) == 0 {
		oauth2Cfg.Scopes = []string{"openid", "email", "profile"}
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &OAuth2Offloader{
		config:     config,
		oauth2Cfg:  &oauth2Cfg,
		client:     client,
		stateStore: NewStateStore(),
	}, nil
}

// GetAuthorizationURL returns the URL to redirect users for authorization
func (o *OAuth2Offloader) GetAuthorizationURL(redirectURI string, extra map[string]string) (string, error) {
	state, err := o.stateStore.Create(redirectURI, extra)
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Set("client_id", o.oauth2Cfg.ClientID)
	params.Set("redirect_uri", o.oauth2Cfg.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(o.oauth2Cfg.Scopes, " "))
	params.Set("state", state.State)

	// OIDC specific
	if o.config.Provider == ProviderOIDC {
		params.Set("nonce", state.Nonce)
	}

	// Google hosted domain restriction
	if o.oauth2Cfg.HostedDomain != "" {
		params.Set("hd", o.oauth2Cfg.HostedDomain)
	}

	return o.oauth2Cfg.AuthURL + "?" + params.Encode(), nil
}

// ExchangeCode exchanges an authorization code for tokens
func (o *OAuth2Offloader) ExchangeCode(ctx context.Context, code, state string) (*OffloadResult, error) {
	// Validate state
	stateData, valid := o.stateStore.Validate(state)
	if !valid {
		return nil, errors.New("invalid or expired state")
	}

	// Exchange code for token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", o.oauth2Cfg.RedirectURL)
	data.Set("client_id", o.oauth2Cfg.ClientID)
	data.Set("client_secret", o.oauth2Cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", o.oauth2Cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Get user info
	result, err := o.getUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, err
	}

	result.AccessToken = tokenResp.AccessToken
	result.RefreshToken = tokenResp.RefreshToken
	if tokenResp.ExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		result.ExpiresAt = &expiresAt
	}

	// Include state extra data
	if stateData.Extra != nil {
		result.Attributes = stateData.Extra
	}

	return result, nil
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (o *OAuth2Offloader) getUserInfo(ctx context.Context, accessToken string) (*OffloadResult, error) {
	if o.oauth2Cfg.UserInfoURL == "" {
		return nil, errors.New("userinfo URL not configured")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", o.oauth2Cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", string(body))
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo: %w", err)
	}

	result := &OffloadResult{
		Success:      true,
		ProviderData: body,
	}

	// Extract email
	if email, ok := getNestedValue(userInfo, o.oauth2Cfg.EmailField).(string); ok {
		result.Email = email
	}

	// Extract name
	if name, ok := getNestedValue(userInfo, o.oauth2Cfg.NameField).(string); ok {
		result.DisplayName = name
	}

	// Extract user ID
	if sub, ok := userInfo["sub"].(string); ok {
		result.UserID = sub
	}

	// Extract groups
	if o.oauth2Cfg.GroupsField != "" {
		if groups, ok := getNestedValue(userInfo, o.oauth2Cfg.GroupsField).([]interface{}); ok {
			for _, g := range groups {
				if gs, ok := g.(string); ok {
					result.Groups = append(result.Groups, gs)
				}
			}
		}
	}

	// Verify email domain if restricted
	if o.oauth2Cfg.HostedDomain != "" && result.Email != "" {
		domain := extractAuthDomain(result.Email)
		if domain != o.oauth2Cfg.HostedDomain {
			result.Success = false
			result.Error = "email domain not allowed"
		}
	}

	return result, nil
}

// Authenticate for OAuth2 doesn't make sense with username/password
// This would only work if using Resource Owner Password Credentials grant
func (o *OAuth2Offloader) Authenticate(ctx context.Context, username, password string) (*OffloadResult, error) {
	// Resource Owner Password Credentials Grant (if token URL supports it)
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)
	data.Set("client_id", o.oauth2Cfg.ClientID)
	data.Set("client_secret", o.oauth2Cfg.ClientSecret)
	data.Set("scope", strings.Join(o.oauth2Cfg.Scopes, " "))

	req, err := http.NewRequestWithContext(ctx, "POST", o.oauth2Cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		json.Unmarshal(body, &errResp)
		return &OffloadResult{
			Success:   false,
			Error:     errResp.ErrorDescription,
			ErrorCode: errResp.Error,
		}, nil
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Get user info
	result, err := o.getUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, err
	}

	result.AccessToken = tokenResp.AccessToken
	result.RefreshToken = tokenResp.RefreshToken

	return result, nil
}

func (o *OAuth2Offloader) ValidateToken(ctx context.Context, token string) (*OffloadResult, error) {
	return o.getUserInfo(ctx, token)
}

func (o *OAuth2Offloader) RefreshToken(ctx context.Context, refreshToken string) (*OffloadResult, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", o.oauth2Cfg.ClientID)
	data.Set("client_secret", o.oauth2Cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", o.oauth2Cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed: %s", string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	result, err := o.getUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, err
	}

	result.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		result.RefreshToken = tokenResp.RefreshToken
	} else {
		result.RefreshToken = refreshToken // Keep old refresh token if not returned
	}

	return result, nil
}

func (o *OAuth2Offloader) GetProviderType() AuthProvider {
	if o.config.Provider == ProviderOIDC {
		return ProviderOIDC
	}
	return ProviderOAuth2
}

func (o *OAuth2Offloader) Close() error {
	return nil
}

// Pre-configured OAuth2 providers

// GoogleOAuth2Config returns config for Google OAuth2
func GoogleOAuth2Config(clientID, clientSecret, redirectURL string) *OAuth2Config {
	return &OAuth2Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
		RedirectURL:  redirectURL,
		Issuer:       "https://accounts.google.com",
		EmailField:   "email",
		NameField:    "name",
	}
}

// MicrosoftOAuth2Config returns config for Microsoft/Azure AD OAuth2
func MicrosoftOAuth2Config(clientID, clientSecret, tenantID, redirectURL string) *OAuth2Config {
	base := "https://login.microsoftonline.com/" + tenantID
	return &OAuth2Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      base + "/oauth2/v2.0/authorize",
		TokenURL:     base + "/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/oidc/userinfo",
		Scopes:       []string{"openid", "email", "profile", "User.Read"},
		RedirectURL:  redirectURL,
		Issuer:       base + "/v2.0",
		EmailField:   "email",
		NameField:    "name",
		GroupsField:  "groups",
	}
}

// GitHubOAuth2Config returns config for GitHub OAuth2
func GitHubOAuth2Config(clientID, clientSecret, redirectURL string) *OAuth2Config {
	return &OAuth2Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		Scopes:       []string{"user:email"},
		RedirectURL:  redirectURL,
		EmailField:   "email",
		NameField:    "name",
	}
}

// OktaOAuth2Config returns config for Okta OAuth2
func OktaOAuth2Config(clientID, clientSecret, domain, redirectURL string) *OAuth2Config {
	base := "https://" + domain
	return &OAuth2Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      base + "/oauth2/v1/authorize",
		TokenURL:     base + "/oauth2/v1/token",
		UserInfoURL:  base + "/oauth2/v1/userinfo",
		JWKSURL:      base + "/oauth2/v1/keys",
		Scopes:       []string{"openid", "email", "profile", "groups"},
		RedirectURL:  redirectURL,
		Issuer:       base,
		EmailField:   "email",
		NameField:    "name",
		GroupsField:  "groups",
	}
}

// Auth0OAuth2Config returns config for Auth0 OAuth2
func Auth0OAuth2Config(clientID, clientSecret, domain, redirectURL string) *OAuth2Config {
	base := "https://" + domain
	return &OAuth2Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      base + "/authorize",
		TokenURL:     base + "/oauth/token",
		UserInfoURL:  base + "/userinfo",
		JWKSURL:      base + "/.well-known/jwks.json",
		Scopes:       []string{"openid", "email", "profile"},
		RedirectURL:  redirectURL,
		Issuer:       base + "/",
		EmailField:   "email",
		NameField:    "name",
	}
}

// KeycloakOAuth2Config returns config for Keycloak OAuth2
func KeycloakOAuth2Config(clientID, clientSecret, serverURL, realm, redirectURL string) *OAuth2Config {
	base := serverURL + "/realms/" + realm + "/protocol/openid-connect"
	return &OAuth2Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      base + "/auth",
		TokenURL:     base + "/token",
		UserInfoURL:  base + "/userinfo",
		JWKSURL:      base + "/certs",
		Scopes:       []string{"openid", "email", "profile"},
		RedirectURL:  redirectURL,
		Issuer:       serverURL + "/realms/" + realm,
		EmailField:   "email",
		NameField:    "name",
		GroupsField:  "groups",
	}
}
