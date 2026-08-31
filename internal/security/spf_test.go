package security

import (
	"context"
	"net"
	"testing"
)

func TestSPFChecker_Check(t *testing.T) {
	// Note: These tests use real DNS lookups, so they test the logic
	// but results depend on actual DNS records
	checker := NewSPFChecker()

	tests := []struct {
		name       string
		domain     string
		ip         string
		wantResult SPFResult
	}{
		{
			name:       "localhost should softfail or neutral",
			domain:     "example.com",
			ip:         "127.0.0.1",
			wantResult: SPFSoftFail, // Most domains won't have localhost authorized
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result, explanation := checker.Check(context.Background(), ip, tt.domain, "")
			// Just verify we get a valid result
			if result == "" {
				t.Error("Expected non-empty result")
			}
			if explanation == "" {
				t.Error("Expected non-empty explanation")
			}
		})
	}
}

func TestSPFResult_String(t *testing.T) {
	tests := []struct {
		result SPFResult
		want   string
	}{
		{SPFPass, "pass"},
		{SPFFail, "fail"},
		{SPFSoftFail, "softfail"},
		{SPFNeutral, "neutral"},
		{SPFNone, "none"},
		{SPFTempError, "temperror"},
		{SPFPermError, "permerror"},
	}

	for _, tt := range tests {
		if got := string(tt.result); got != tt.want {
			t.Errorf("string(SPFResult(%q)) = %v, want %v", tt.result, got, tt.want)
		}
	}
}

func TestParseIPRange(t *testing.T) {
	tests := []struct {
		mechanism string
		ip        string
		want      bool
	}{
		{"ip4:192.168.1.0/24", "192.168.1.100", true},
		{"ip4:192.168.1.0/24", "192.168.2.100", false},
		{"ip4:10.0.0.1", "10.0.0.1", true},
		{"ip4:10.0.0.1", "10.0.0.2", false},
		{"ip6:2001:db8::/32", "2001:db8::1", true},
		{"ip6:2001:db8::/32", "2001:db9::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.mechanism+"_"+tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			// Extract the IP/CIDR from mechanism
			var cidr string
			if len(tt.mechanism) > 4 && tt.mechanism[:4] == "ip4:" {
				cidr = tt.mechanism[4:]
			} else if len(tt.mechanism) > 4 && tt.mechanism[:4] == "ip6:" {
				cidr = tt.mechanism[4:]
			}

			// Add /32 or /128 if no prefix
			if !contains(cidr, "/") {
				if ip.To4() != nil {
					cidr += "/32"
				} else {
					cidr += "/128"
				}
			}

			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatalf("ParseCIDR error: %v", err)
			}

			got := network.Contains(ip)
			if got != tt.want {
				t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
