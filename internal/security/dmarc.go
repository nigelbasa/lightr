package security

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// DMARCResult represents the result of a DMARC check
type DMARCResult string

const (
	DMARCPass      DMARCResult = "pass"
	DMARCFail      DMARCResult = "fail"
	DMARCNone      DMARCResult = "none"
	DMARCTempError DMARCResult = "temperror"
	DMARCPermError DMARCResult = "permerror"
)

// DMARCPolicy represents the policy from a DMARC record
type DMARCPolicy string

const (
	DMARCPolicyNone       DMARCPolicy = "none"
	DMARCPolicyQuarantine DMARCPolicy = "quarantine"
	DMARCPolicyReject     DMARCPolicy = "reject"
)

// DMARCRecord represents a parsed DMARC record
type DMARCRecord struct {
	Version            string      // v=
	Policy             DMARCPolicy // p=
	SubdomainPolicy    DMARCPolicy // sp=
	Percentage         int         // pct= (0-100)
	ReportAggregate    []string    // rua=
	ReportForensic     []string    // ruf=
	ADKIM              string      // adkim= (r=relaxed, s=strict)
	ASPF               string      // aspf= (r=relaxed, s=strict)
	ReportFormat       string      // rf=
	ReportInterval     int         // ri= (seconds)
	FailureOptions     string      // fo=
}

// DMARCChecker validates DMARC records
type DMARCChecker struct {
	spfChecker *SPFChecker
}

// NewDMARCChecker creates a new DMARC checker
func NewDMARCChecker() *DMARCChecker {
	return &DMARCChecker{
		spfChecker: NewSPFChecker(),
	}
}

// DMARCCheckInput contains all the information needed for a DMARC check
type DMARCCheckInput struct {
	FromDomain    string    // Domain from the From header
	MailFrom      string    // Domain from MAIL FROM (envelope sender)
	ClientIP      net.IP    // IP of sending server
	DKIMResults   []DKIMAuthResult // Results from DKIM verification
	SPFResult     SPFResult // Result from SPF check (optional, will check if empty)
	SPFDomain     string    // Domain used for SPF check
}

// DKIMAuthResult represents a DKIM authentication result
type DKIMAuthResult struct {
	Domain string
	Pass   bool
}

// DMARCCheckResult contains the full result of a DMARC check
type DMARCCheckResult struct {
	Result       DMARCResult
	Policy       DMARCPolicy
	Record       *DMARCRecord
	SPFAligned   bool
	DKIMAligned  bool
	Reason       string
}

// Check performs DMARC validation
func (c *DMARCChecker) Check(ctx context.Context, input *DMARCCheckInput) *DMARCCheckResult {
	result := &DMARCCheckResult{
		Result: DMARCNone,
		Policy: DMARCPolicyNone,
	}

	if input.FromDomain == "" {
		result.Reason = "no From domain"
		return result
	}

	// Look up DMARC record
	record, err := c.lookupDMARC(ctx, input.FromDomain)
	if err != nil {
		if isTemporaryError(err) {
			result.Result = DMARCTempError
			result.Reason = err.Error()
		} else {
			result.Result = DMARCNone
			result.Reason = "no DMARC record"
		}
		return result
	}

	result.Record = record
	result.Policy = record.Policy

	// Check SPF alignment
	if input.SPFResult == "" {
		// Perform SPF check
		input.SPFResult, _ = c.spfChecker.Check(ctx, input.ClientIP, input.MailFrom, "")
		input.SPFDomain = input.MailFrom
	}

	if input.SPFResult == SPFPass {
		result.SPFAligned = c.checkAlignment(input.FromDomain, input.SPFDomain, record.ASPF)
	}

	// Check DKIM alignment
	for _, dkim := range input.DKIMResults {
		if dkim.Pass {
			if c.checkAlignment(input.FromDomain, dkim.Domain, record.ADKIM) {
				result.DKIMAligned = true
				break
			}
		}
	}

	// DMARC passes if either SPF or DKIM is aligned
	if result.SPFAligned || result.DKIMAligned {
		result.Result = DMARCPass
		result.Reason = "aligned authentication"
	} else {
		result.Result = DMARCFail
		if len(input.DKIMResults) == 0 && input.SPFResult != SPFPass {
			result.Reason = "no aligned authentication (SPF and DKIM both failed)"
		} else if !result.SPFAligned && input.SPFResult == SPFPass {
			result.Reason = "SPF passed but not aligned"
		} else if !result.DKIMAligned && len(input.DKIMResults) > 0 {
			result.Reason = "DKIM passed but not aligned"
		} else {
			result.Reason = "no aligned authentication"
		}
	}

	return result
}

func (c *DMARCChecker) lookupDMARC(ctx context.Context, domain string) (*DMARCRecord, error) {
	// Try _dmarc.domain first
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.DefaultResolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		// Try organizational domain (remove one subdomain level)
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			orgDomain := strings.Join(parts[len(parts)-2:], ".")
			dmarcDomain = "_dmarc." + orgDomain
			txtRecords, err = net.DefaultResolver.LookupTXT(ctx, dmarcDomain)
		}
		if err != nil {
			return nil, err
		}
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			return c.parseDMARC(txt)
		}
	}

	return nil, fmt.Errorf("no DMARC record found")
}

func (c *DMARCChecker) parseDMARC(record string) (*DMARCRecord, error) {
	dmarc := &DMARCRecord{
		Policy:          DMARCPolicyNone,
		SubdomainPolicy: DMARCPolicyNone,
		Percentage:      100,
		ADKIM:           "r", // relaxed default
		ASPF:            "r", // relaxed default
		ReportInterval:  86400,
	}

	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "v":
			dmarc.Version = value
		case "p":
			dmarc.Policy = DMARCPolicy(value)
		case "sp":
			dmarc.SubdomainPolicy = DMARCPolicy(value)
		case "pct":
			fmt.Sscanf(value, "%d", &dmarc.Percentage)
		case "rua":
			dmarc.ReportAggregate = strings.Split(value, ",")
		case "ruf":
			dmarc.ReportForensic = strings.Split(value, ",")
		case "adkim":
			dmarc.ADKIM = value
		case "aspf":
			dmarc.ASPF = value
		case "rf":
			dmarc.ReportFormat = value
		case "ri":
			fmt.Sscanf(value, "%d", &dmarc.ReportInterval)
		case "fo":
			dmarc.FailureOptions = value
		}
	}

	if dmarc.SubdomainPolicy == DMARCPolicyNone && dmarc.Policy != DMARCPolicyNone {
		dmarc.SubdomainPolicy = dmarc.Policy
	}

	return dmarc, nil
}

func (c *DMARCChecker) checkAlignment(fromDomain, authDomain, mode string) bool {
	fromDomain = strings.ToLower(fromDomain)
	authDomain = strings.ToLower(authDomain)

	if mode == "s" {
		// Strict: exact match required
		return fromDomain == authDomain
	}

	// Relaxed: organizational domain must match
	fromOrg := getOrgDomain(fromDomain)
	authOrg := getOrgDomain(authDomain)
	return fromOrg == authOrg
}

// getOrgDomain extracts the organizational domain (e.g., example.com from mail.example.com)
// This is a simplified version - a proper implementation would use the Public Suffix List
func getOrgDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	// Simple heuristic: take last two parts
	// This doesn't handle co.uk, com.au etc properly
	return strings.Join(parts[len(parts)-2:], ".")
}
