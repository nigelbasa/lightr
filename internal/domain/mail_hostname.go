package domain

import "strings"

// EffectiveMailHostname resolves the public mail hostname for a domain.
// Domain-specific configuration wins, then the server-wide hostname, then
// a conventional mail.<domain> fallback for self-hosted setups.
func EffectiveMailHostname(dom *Domain, serverHostname string) string {
	if dom != nil {
		if host := strings.TrimSpace(dom.MailHostname); host != "" {
			return host
		}
	}
	if host := strings.TrimSpace(serverHostname); host != "" {
		return host
	}
	if dom != nil {
		if name := strings.TrimSpace(dom.Name); name != "" {
			return "mail." + name
		}
	}
	return "localhost"
}
