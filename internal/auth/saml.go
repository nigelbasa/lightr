package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SAMLOffloader implements Offloader for SAML auth
type SAMLOffloader struct {
	config   *ProviderConfig
	samlCfg  *SAMLConfig
	idpCert  *x509.Certificate
}

// SAMLAssertion represents a parsed SAML assertion
type SAMLAssertion struct {
	XMLName      xml.Name       `xml:"Assertion"`
	ID           string         `xml:"ID,attr"`
	IssueInstant time.Time      `xml:"IssueInstant,attr"`
	Issuer       string         `xml:"Issuer"`
	Subject      SAMLSubject    `xml:"Subject"`
	Conditions   SAMLConditions `xml:"Conditions"`
	Attributes   []SAMLAttribute `xml:"AttributeStatement>Attribute"`
}

// SAMLSubject represents the subject in a SAML assertion
type SAMLSubject struct {
	NameID            string             `xml:"NameID"`
	SubjectConfirmation SAMLSubjectConfirmation `xml:"SubjectConfirmation"`
}

// SAMLSubjectConfirmation represents subject confirmation
type SAMLSubjectConfirmation struct {
	Method string `xml:"Method,attr"`
	Data   struct {
		NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
		Recipient    string    `xml:"Recipient,attr"`
	} `xml:"SubjectConfirmationData"`
}

// SAMLConditions represents validity conditions
type SAMLConditions struct {
	NotBefore    time.Time `xml:"NotBefore,attr"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
	Audience     string    `xml:"AudienceRestriction>Audience"`
}

// SAMLAttribute represents an attribute in the assertion
type SAMLAttribute struct {
	Name         string   `xml:"Name,attr"`
	NameFormat   string   `xml:"NameFormat,attr"`
	Values       []string `xml:"AttributeValue"`
}

// SAMLResponse represents a SAML response
type SAMLResponse struct {
	XMLName      xml.Name       `xml:"Response"`
	ID           string         `xml:"ID,attr"`
	Destination  string         `xml:"Destination,attr"`
	IssueInstant time.Time      `xml:"IssueInstant,attr"`
	Status       SAMLStatus     `xml:"Status"`
	Assertion    *SAMLAssertion `xml:"Assertion"`
}

// SAMLStatus represents the status of a SAML response
type SAMLStatus struct {
	StatusCode struct {
		Value string `xml:"Value,attr"`
	} `xml:"StatusCode"`
	StatusMessage string `xml:"StatusMessage"`
}

// NewSAMLOffloader creates a new SAML offloader
func NewSAMLOffloader(config *ProviderConfig) (*SAMLOffloader, error) {
	var samlCfg SAMLConfig
	if err := json.Unmarshal(config.Config, &samlCfg); err != nil {
		return nil, fmt.Errorf("invalid SAML config: %w", err)
	}

	// Set defaults
	if samlCfg.EmailAttr == "" {
		samlCfg.EmailAttr = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	}
	if samlCfg.DisplayNameAttr == "" {
		samlCfg.DisplayNameAttr = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
	}
	if samlCfg.GroupsAttr == "" {
		samlCfg.GroupsAttr = "http://schemas.xmlsoap.org/claims/Group"
	}

	// Parse IdP certificate
	var idpCert *x509.Certificate
	if samlCfg.Certificate != "" {
		certPEM := samlCfg.Certificate
		if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
			// Assume it's base64 encoded DER
			certDER, err := base64.StdEncoding.DecodeString(certPEM)
			if err != nil {
				return nil, fmt.Errorf("failed to decode certificate: %w", err)
			}
			idpCert, err = x509.ParseCertificate(certDER)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
		}
	}

	return &SAMLOffloader{
		config:  config,
		samlCfg: &samlCfg,
		idpCert: idpCert,
	}, nil
}

// GetLoginURL returns the SAML login URL (SSO URL with AuthnRequest)
func (s *SAMLOffloader) GetLoginURL(relayState string) (string, error) {
	// Build AuthnRequest
	authnRequest := fmt.Sprintf(`
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_lightr_%d"
    Version="2.0"
    IssueInstant="%s"
    Destination="%s"
    AssertionConsumerServiceURL="%s"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>%s</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>`,
		time.Now().UnixNano(),
		time.Now().UTC().Format(time.RFC3339),
		s.samlCfg.SSOURL,
		s.samlCfg.ACSPath,
		s.samlCfg.EntityID,
	)

	// Compress and encode
	encoded := base64.StdEncoding.EncodeToString([]byte(authnRequest))

	// Build redirect URL
	params := url.Values{}
	params.Set("SAMLRequest", encoded)
	if relayState != "" {
		params.Set("RelayState", relayState)
	}

	return s.samlCfg.SSOURL + "?" + params.Encode(), nil
}

// ProcessResponse processes a SAML response from the IdP
func (s *SAMLOffloader) ProcessResponse(ctx context.Context, samlResponse, relayState string) (*OffloadResult, error) {
	// Decode response
	responseXML, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAML response: %w", err)
	}

	// Parse response
	var response SAMLResponse
	if err := xml.Unmarshal(responseXML, &response); err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Check status
	if !strings.HasSuffix(response.Status.StatusCode.Value, ":Success") {
		return &OffloadResult{
			Success:   false,
			Error:     response.Status.StatusMessage,
			ErrorCode: response.Status.StatusCode.Value,
		}, nil
	}

	// Validate assertion
	if response.Assertion == nil {
		return nil, errors.New("SAML response contains no assertion")
	}

	assertion := response.Assertion

	// Validate time conditions
	now := time.Now()
	if !assertion.Conditions.NotBefore.IsZero() && now.Before(assertion.Conditions.NotBefore) {
		return nil, errors.New("assertion not yet valid")
	}
	if !assertion.Conditions.NotOnOrAfter.IsZero() && now.After(assertion.Conditions.NotOnOrAfter) {
		return nil, errors.New("assertion has expired")
	}

	// Validate audience if configured
	if s.samlCfg.EntityID != "" && assertion.Conditions.Audience != "" {
		if assertion.Conditions.Audience != s.samlCfg.EntityID {
			return nil, fmt.Errorf("invalid audience: expected %s, got %s", s.samlCfg.EntityID, assertion.Conditions.Audience)
		}
	}

	// TODO: Signature validation would go here using s.idpCert
	// This requires crypto/xmldsig or similar library

	// Extract user attributes
	result := &OffloadResult{
		Success:      true,
		UserID:       assertion.Subject.NameID,
		Email:        assertion.Subject.NameID, // Default to NameID
		ProviderData: responseXML,
	}

	// Parse attributes
	attrs := make(map[string][]string)
	for _, attr := range assertion.Attributes {
		attrs[attr.Name] = attr.Values
	}

	// Extract email
	if emails, ok := attrs[s.samlCfg.EmailAttr]; ok && len(emails) > 0 {
		result.Email = emails[0]
	}

	// Extract display name
	if names, ok := attrs[s.samlCfg.DisplayNameAttr]; ok && len(names) > 0 {
		result.DisplayName = names[0]
	}

	// Extract groups
	if groups, ok := attrs[s.samlCfg.GroupsAttr]; ok {
		result.Groups = groups
	}

	// Set expiry
	if !assertion.Conditions.NotOnOrAfter.IsZero() {
		result.ExpiresAt = &assertion.Conditions.NotOnOrAfter
	}

	return result, nil
}

// Authenticate for SAML doesn't work with username/password
// SAML is browser-based only
func (s *SAMLOffloader) Authenticate(ctx context.Context, username, password string) (*OffloadResult, error) {
	return nil, errors.New("SAML does not support direct username/password authentication - use browser-based flow")
}

func (s *SAMLOffloader) ValidateToken(ctx context.Context, token string) (*OffloadResult, error) {
	return nil, errors.New("SAML does not support token validation")
}

func (s *SAMLOffloader) RefreshToken(ctx context.Context, refreshToken string) (*OffloadResult, error) {
	return nil, errors.New("SAML does not support token refresh")
}

func (s *SAMLOffloader) GetProviderType() AuthProvider {
	return ProviderSAML
}

func (s *SAMLOffloader) Close() error {
	return nil
}

// GetMetadata returns the SAML SP metadata
func (s *SAMLOffloader) GetMetadata() string {
	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="%s">
    <md:SPSSODescriptor
        AuthnRequestsSigned="%t"
        WantAssertionsSigned="%t"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="%s"
            index="0"
            isDefault="true"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>`,
		s.samlCfg.EntityID,
		s.samlCfg.SignRequests,
		s.samlCfg.WantAssertionsSigned,
		s.samlCfg.ACSPath,
	)
	return metadata
}

// SAMLHandler provides HTTP handlers for SAML endpoints
type SAMLHandler struct {
	offloader *SAMLOffloader
	manager   *OffloadManager
	config    *ProviderConfig
}

// NewSAMLHandler creates a new SAML HTTP handler
func NewSAMLHandler(offloader *SAMLOffloader, manager *OffloadManager, config *ProviderConfig) *SAMLHandler {
	return &SAMLHandler{
		offloader: offloader,
		manager:   manager,
		config:    config,
	}
}

// ServeMetadata serves the SP metadata
func (h *SAMLHandler) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(h.offloader.GetMetadata()))
}

// HandleLogin initiates SAML login
func (h *SAMLHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	relayState := r.URL.Query().Get("RelayState")
	if relayState == "" {
		relayState = r.URL.Query().Get("redirect")
	}

	loginURL, err := h.offloader.GetLoginURL(relayState)
	if err != nil {
		http.Error(w, "Failed to generate login URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, loginURL, http.StatusFound)
}

// HandleACS handles the Assertion Consumer Service (ACS) callback
func (h *SAMLHandler) HandleACS(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	samlResponse := r.FormValue("SAMLResponse")
	relayState := r.FormValue("RelayState")

	if samlResponse == "" {
		http.Error(w, "Missing SAMLResponse", http.StatusBadRequest)
		return
	}

	result, err := h.offloader.ProcessResponse(r.Context(), samlResponse, relayState)
	if err != nil {
		http.Error(w, "Failed to process SAML response: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if !result.Success {
		http.Error(w, "Authentication failed: "+result.Error, http.StatusUnauthorized)
		return
	}

	// At this point, you would:
	// 1. Create a session for the user
	// 2. Provision/update account if auto_provision is enabled
	// 3. Redirect to the application with a session cookie

	// For now, return JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// HandleSLO handles Single Logout
func (h *SAMLHandler) HandleSLO(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement Single Logout
	http.Error(w, "SLO not implemented", http.StatusNotImplemented)
}
