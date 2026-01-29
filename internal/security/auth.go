package security

import (
	"context"
	"log"
	"net"
)

// AuthResult contains the results of email authentication checks
type AuthResult struct {
	SPF   SPFAuthResult
	DKIM  []DKIMAuthResult
	DMARC DMARCAuthResult
}

// SPFAuthResult contains SPF check details
type SPFAuthResult struct {
	Result SPFResult `json:"result"`
	Domain string    `json:"domain"`
	Reason string    `json:"reason"`
}

// DMARCAuthResult contains DMARC check details
type DMARCAuthResult struct {
	Result      DMARCResult `json:"result"`
	Policy      DMARCPolicy `json:"policy"`
	SPFAligned  bool        `json:"spf_aligned"`
	DKIMAligned bool        `json:"dkim_aligned"`
	Reason      string      `json:"reason"`
}

// Authenticator performs SPF, DKIM, and DMARC checks
type Authenticator struct {
	spf   *SPFChecker
	dmarc *DMARCChecker
}

// NewAuthenticator creates a new email authenticator
func NewAuthenticator() *Authenticator {
	return &Authenticator{
		spf:   NewSPFChecker(),
		dmarc: NewDMARCChecker(),
	}
}

// AuthenticateInput contains information for authenticating an email
type AuthenticateInput struct {
	ClientIP      net.IP           // IP of the sending server
	HeloDomain    string           // HELO/EHLO domain
	MailFrom      string           // MAIL FROM address
	FromHeader    string           // From: header domain
	DKIMResults   []DKIMAuthResult // DKIM verification results (from go-msgauth)
}

// Authenticate performs full email authentication
func (a *Authenticator) Authenticate(ctx context.Context, input *AuthenticateInput) *AuthResult {
	result := &AuthResult{
		DKIM: input.DKIMResults,
	}

	// Extract domains
	mailFromDomain := extractDomain(input.MailFrom)
	fromDomain := extractDomain(input.FromHeader)

	// SPF Check
	spfResult, spfReason := a.spf.Check(ctx, input.ClientIP, mailFromDomain, input.HeloDomain)
	result.SPF = SPFAuthResult{
		Result: spfResult,
		Domain: mailFromDomain,
		Reason: spfReason,
	}

	// DMARC Check
	dmarcInput := &DMARCCheckInput{
		FromDomain:  fromDomain,
		MailFrom:    mailFromDomain,
		ClientIP:    input.ClientIP,
		DKIMResults: input.DKIMResults,
		SPFResult:   spfResult,
		SPFDomain:   mailFromDomain,
	}

	dmarcResult := a.dmarc.Check(ctx, dmarcInput)
	result.DMARC = DMARCAuthResult{
		Result:      dmarcResult.Result,
		Policy:      dmarcResult.Policy,
		SPFAligned:  dmarcResult.SPFAligned,
		DKIMAligned: dmarcResult.DKIMAligned,
		Reason:      dmarcResult.Reason,
	}

	return result
}

// ShouldReject determines if an email should be rejected based on auth results
func (a *Authenticator) ShouldReject(result *AuthResult) bool {
	// Reject if DMARC fails with reject policy
	if result.DMARC.Result == DMARCFail && result.DMARC.Policy == DMARCPolicyReject {
		return true
	}
	return false
}

// ShouldQuarantine determines if an email should be quarantined
func (a *Authenticator) ShouldQuarantine(result *AuthResult) bool {
	// Quarantine if DMARC fails with quarantine policy
	if result.DMARC.Result == DMARCFail && result.DMARC.Policy == DMARCPolicyQuarantine {
		return true
	}
	// Also quarantine on SPF hard fail even without DMARC
	if result.SPF.Result == SPFFail && result.DMARC.Result == DMARCNone {
		return true
	}
	return false
}

// GetAuthResultsHeader returns Authentication-Results header value
func (a *Authenticator) GetAuthResultsHeader(hostname string, result *AuthResult) string {
	header := hostname + ";"

	// SPF result
	header += " spf=" + string(result.SPF.Result)
	if result.SPF.Domain != "" {
		header += " smtp.mailfrom=" + result.SPF.Domain
	}
	header += ";"

	// DKIM results
	for _, dkim := range result.DKIM {
		if dkim.Pass {
			header += " dkim=pass"
		} else {
			header += " dkim=fail"
		}
		header += " header.d=" + dkim.Domain + ";"
	}

	// DMARC result
	header += " dmarc=" + string(result.DMARC.Result)
	if result.DMARC.Policy != DMARCPolicyNone {
		header += " policy=" + string(result.DMARC.Policy)
	}

	return header
}

func extractDomain(email string) string {
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			return email[i+1:]
		}
	}
	return email
}

// LogAuthResult logs authentication results
func LogAuthResult(result *AuthResult, from string) {
	log.Printf("Auth results for %s: SPF=%s DMARC=%s (policy=%s, spf_aligned=%v, dkim_aligned=%v)",
		from,
		result.SPF.Result,
		result.DMARC.Result,
		result.DMARC.Policy,
		result.DMARC.SPFAligned,
		result.DMARC.DKIMAligned,
	)
}
