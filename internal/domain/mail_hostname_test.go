package domain

import "testing"

func TestEffectiveMailHostnamePrefersDomainOverride(t *testing.T) {
	dom := &Domain{Name: "example.test", MailHostname: "mx.example.test"}
	if got := EffectiveMailHostname(dom, "smtp.example.test"); got != "mx.example.test" {
		t.Fatalf("EffectiveMailHostname() = %q, want %q", got, "mx.example.test")
	}
}

func TestEffectiveMailHostnameFallsBackToServerHostname(t *testing.T) {
	dom := &Domain{Name: "example.test"}
	if got := EffectiveMailHostname(dom, "smtp.example.test"); got != "smtp.example.test" {
		t.Fatalf("EffectiveMailHostname() = %q, want %q", got, "smtp.example.test")
	}
}

func TestEffectiveMailHostnameFallsBackToMailSubdomain(t *testing.T) {
	dom := &Domain{Name: "example.test"}
	if got := EffectiveMailHostname(dom, ""); got != "mail.example.test" {
		t.Fatalf("EffectiveMailHostname() = %q, want %q", got, "mail.example.test")
	}
}
