package security

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// SPFResult represents the result of an SPF check
type SPFResult string

const (
	SPFPass      SPFResult = "pass"
	SPFFail      SPFResult = "fail"
	SPFSoftFail  SPFResult = "softfail"
	SPFNeutral   SPFResult = "neutral"
	SPFNone      SPFResult = "none"
	SPFTempError SPFResult = "temperror"
	SPFPermError SPFResult = "permerror"
)

// SPFChecker validates SPF records
type SPFChecker struct {
	lookupLimit int
}

// NewSPFChecker creates a new SPF checker
func NewSPFChecker() *SPFChecker {
	return &SPFChecker{
		lookupLimit: 10, // RFC 7208 limit
	}
}

// Check performs SPF validation
// ip: the IP address of the sending server
// domain: the domain from the MAIL FROM
// helo: the HELO/EHLO domain
func (c *SPFChecker) Check(ctx context.Context, ip net.IP, domain, helo string) (SPFResult, string) {
	if domain == "" {
		domain = helo
	}
	if domain == "" {
		return SPFNone, "no domain specified"
	}

	// Look up SPF record
	record, err := c.lookupSPF(ctx, domain)
	if err != nil {
		if isTemporaryError(err) {
			return SPFTempError, err.Error()
		}
		return SPFNone, "no SPF record found"
	}

	// Parse and evaluate
	return c.evaluate(ctx, record, ip, domain, 0)
}

func (c *SPFChecker) lookupSPF(ctx context.Context, domain string) (string, error) {
	txtRecords, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		return "", err
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1 ") || txt == "v=spf1" {
			return txt, nil
		}
	}

	return "", fmt.Errorf("no SPF record")
}

func (c *SPFChecker) evaluate(ctx context.Context, record string, ip net.IP, domain string, depth int) (SPFResult, string) {
	if depth > c.lookupLimit {
		return SPFPermError, "too many DNS lookups"
	}

	// Parse mechanisms
	parts := strings.Fields(record)
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "v=spf1") {
		return SPFPermError, "invalid SPF record"
	}

	for _, part := range parts[1:] {
		// Skip modifiers (redirect=, exp=)
		if strings.Contains(part, "=") && !strings.HasPrefix(part, "+") &&
			!strings.HasPrefix(part, "-") && !strings.HasPrefix(part, "~") &&
			!strings.HasPrefix(part, "?") {

			if strings.HasPrefix(part, "redirect=") {
				redirectDomain := strings.TrimPrefix(part, "redirect=")
				newRecord, err := c.lookupSPF(ctx, redirectDomain)
				if err != nil {
					return SPFPermError, "redirect lookup failed"
				}
				return c.evaluate(ctx, newRecord, ip, redirectDomain, depth+1)
			}
			continue
		}

		result, match := c.checkMechanism(ctx, part, ip, domain, depth)
		if match {
			return result, part
		}
	}

	// Default result is neutral
	return SPFNeutral, "no mechanism matched"
}

func (c *SPFChecker) checkMechanism(ctx context.Context, mechanism string, ip net.IP, domain string, depth int) (SPFResult, bool) {
	// Parse qualifier
	qualifier := SPFPass
	mech := mechanism

	switch mechanism[0] {
	case '+':
		qualifier = SPFPass
		mech = mechanism[1:]
	case '-':
		qualifier = SPFFail
		mech = mechanism[1:]
	case '~':
		qualifier = SPFSoftFail
		mech = mechanism[1:]
	case '?':
		qualifier = SPFNeutral
		mech = mechanism[1:]
	}

	// Check mechanism type
	switch {
	case mech == "all":
		return qualifier, true

	case strings.HasPrefix(mech, "ip4:"):
		cidr := strings.TrimPrefix(mech, "ip4:")
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return SPFPermError, false
		}
		if network.Contains(ip) {
			return qualifier, true
		}

	case strings.HasPrefix(mech, "ip6:"):
		cidr := strings.TrimPrefix(mech, "ip6:")
		if !strings.Contains(cidr, "/") {
			cidr += "/128"
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return SPFPermError, false
		}
		if network.Contains(ip) {
			return qualifier, true
		}

	case mech == "a" || strings.HasPrefix(mech, "a:") || strings.HasPrefix(mech, "a/"):
		targetDomain := domain
		cidrLen := ""
		if strings.HasPrefix(mech, "a:") {
			rest := strings.TrimPrefix(mech, "a:")
			if idx := strings.Index(rest, "/"); idx > 0 {
				targetDomain = rest[:idx]
				cidrLen = rest[idx:]
			} else {
				targetDomain = rest
			}
		} else if strings.HasPrefix(mech, "a/") {
			cidrLen = strings.TrimPrefix(mech, "a")
		}
		if c.checkA(ctx, ip, targetDomain, cidrLen) {
			return qualifier, true
		}

	case mech == "mx" || strings.HasPrefix(mech, "mx:") || strings.HasPrefix(mech, "mx/"):
		targetDomain := domain
		cidrLen := ""
		if strings.HasPrefix(mech, "mx:") {
			rest := strings.TrimPrefix(mech, "mx:")
			if idx := strings.Index(rest, "/"); idx > 0 {
				targetDomain = rest[:idx]
				cidrLen = rest[idx:]
			} else {
				targetDomain = rest
			}
		} else if strings.HasPrefix(mech, "mx/") {
			cidrLen = strings.TrimPrefix(mech, "mx")
		}
		if c.checkMX(ctx, ip, targetDomain, cidrLen) {
			return qualifier, true
		}

	case strings.HasPrefix(mech, "include:"):
		includeDomain := strings.TrimPrefix(mech, "include:")
		includeRecord, err := c.lookupSPF(ctx, includeDomain)
		if err != nil {
			return SPFPermError, false
		}
		result, _ := c.evaluate(ctx, includeRecord, ip, includeDomain, depth+1)
		if result == SPFPass {
			return qualifier, true
		}

	case strings.HasPrefix(mech, "exists:"):
		existsDomain := strings.TrimPrefix(mech, "exists:")
		existsDomain = strings.ReplaceAll(existsDomain, "%{i}", ip.String())
		existsDomain = strings.ReplaceAll(existsDomain, "%{d}", domain)
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", existsDomain)
		if err == nil && len(ips) > 0 {
			return qualifier, true
		}
	}

	return SPFNeutral, false
}

func (c *SPFChecker) checkA(ctx context.Context, ip net.IP, domain, cidrLen string) bool {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return false
	}

	for _, addr := range ips {
		if cidrLen == "" {
			if addr.Equal(ip) {
				return true
			}
		} else {
			cidr := addr.String() + cidrLen
			_, network, err := net.ParseCIDR(cidr)
			if err == nil && network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (c *SPFChecker) checkMX(ctx context.Context, ip net.IP, domain, cidrLen string) bool {
	mxRecords, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return false
	}

	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		if c.checkA(ctx, ip, host, cidrLen) {
			return true
		}
	}
	return false
}

func isTemporaryError(err error) bool {
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.Temporary()
	}
	return false
}
