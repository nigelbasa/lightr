package webhooks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
)

// ErrBlockedAddress is returned when a webhook URL resolves to an address in a
// reserved range. It is exported so callers can detect SSRF rejections.
var ErrBlockedAddress = errors.New("webhook target resolves to a blocked address")

// ValidateWebhookURL performs an upfront SSRF check on a webhook destination.
// The dial-time check in safeDialContext is the authoritative defense (it
// handles DNS rebinding), but this gives callers a clear synchronous error at
// configuration time.
func ValidateWebhookURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("webhook url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid webhook url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("webhook url must use http or https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("webhook url is missing a host")
	}
	if isBlockedHostname(host) {
		return ErrBlockedAddress
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
		return ErrBlockedAddress
	}
	// If the host is a name, best-effort resolve and reject if any candidate
	// is in a blocked range. The dial-time guard re-checks at connect time.
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err == nil {
			for _, ip := range ips {
				if isBlockedIP(ip) {
					return ErrBlockedAddress
				}
			}
		}
	}
	return nil
}

// safeDialContext returns a DialContext that re-validates the resolved IP for
// every connection. This is the authoritative SSRF guard — it stops DNS
// rebinding attacks that bypass the upfront URL validation by returning a
// public IP at registration and a private IP at delivery time.
func safeDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if isBlockedHostname(host) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedAddress, host)
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		var firstErr error
		for _, ip := range ips {
			if isBlockedIP(ip) {
				firstErr = fmt.Errorf("%w: %s -> %s", ErrBlockedAddress, host, ip)
				continue
			}
			conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if derr == nil {
				return conn, nil
			}
			// Move on to the next IP rather than leak resolver state.
			if firstErr == nil {
				firstErr = derr
			}
			// Don't retry on hard syscall failures unrelated to the address.
			var se *net.OpError
			if errors.As(derr, &se) {
				var sce syscall.Errno
				if errors.As(se.Err, &sce) {
					if sce == syscall.EACCES || sce == syscall.EPERM {
						return nil, derr
					}
				}
			}
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("no usable address for %s", host)
		}
		return nil, firstErr
	}
}

// isBlockedHostname rejects literal localhost-style names. We do this before
// resolution to avoid resolver-specific behavior.
func isBlockedHostname(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "localhost.", "ip6-localhost", "ip6-loopback":
		return true
	}
	return false
}

// isBlockedIP returns true for any IP in a reserved or private range that a
// webhook should never reach. We default-deny on internal address space.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// RFC1918
		if ip4[0] == 10 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// CGNAT (RFC6598)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		// 169.254/16 link-local (already covered by IsLinkLocalUnicast but
		// belt-and-braces — IMDS 169.254.169.254 is the canonical SSRF target).
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 0.0.0.0/8 — "this network"
		if ip4[0] == 0 {
			return true
		}
		// 127.0.0.0/8 (loopback handled above, but Go's IsLoopback may miss
		// some forms on certain platforms)
		if ip4[0] == 127 {
			return true
		}
		return false
	}
	// IPv6: block private and ULA ranges
	// fc00::/7 — unique local
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:a.b.c.d) — re-check as IPv4
	if v4 := ip.To4(); v4 != nil {
		return isBlockedIP(v4)
	}
	return false
}
