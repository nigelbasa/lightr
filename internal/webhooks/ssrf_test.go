package webhooks

import (
	"net"
	"testing"
)

func TestValidateWebhookURLRejectsBlocked(t *testing.T) {
	cases := []string{
		"",
		"not a url",
		"file:///etc/passwd",
		"gopher://internal/",
		"ftp://example.com/",
		"http://",
		"http://127.0.0.1/",
		"http://127.0.0.1:8080/path",
		"http://localhost/admin",
		"http://[::1]/",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/",
		"http://192.168.1.1/",
		"http://172.16.5.5/",
		"http://172.31.99.99/",
		"http://100.64.1.1/",
		"http://0.0.0.0/",
	}
	for _, u := range cases {
		if err := ValidateWebhookURL(u); err == nil {
			t.Errorf("ValidateWebhookURL(%q) accepted, want rejection", u)
		}
	}
}

func TestValidateWebhookURLAcceptsPublic(t *testing.T) {
	cases := []string{
		"https://example.com/hook",
		"http://93.184.216.34/",            // example.com public IP
		"https://hooks.example.com:8443/h",
	}
	for _, u := range cases {
		if err := ValidateWebhookURL(u); err != nil {
			t.Errorf("ValidateWebhookURL(%q) rejected: %v", u, err)
		}
	}
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"127.255.255.254",
		"10.0.0.5",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.169.254",
		"100.64.1.1",
		"0.0.0.0",
		"::1",
		"fc00::1",
		"fd12:3456:789a::1",
		"fe80::1",
		"224.0.0.1",
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if !isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%s) = false, want true", s)
		}
	}

	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
		"2606:4700:4700::1111",
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%s) = true, want false", s)
		}
	}
}

func TestIsBlockedHostname(t *testing.T) {
	for _, h := range []string{"localhost", "LOCALHOST", "localhost.", "ip6-localhost"} {
		if !isBlockedHostname(h) {
			t.Errorf("isBlockedHostname(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"example.com", "api.example.com", ""} {
		if isBlockedHostname(h) {
			t.Errorf("isBlockedHostname(%q) = true, want false", h)
		}
	}
}
