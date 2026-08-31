package spam

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nigelbasa/lightr/internal/security"
)

type fakeSPFChecker struct {
	result security.SPFResult
}

func (f fakeSPFChecker) Check(ctx context.Context, ip net.IP, domain, helo string) (security.SPFResult, string) {
	return f.result, ""
}

type fakeResolver struct {
	hits map[string][]string
}

func (f fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if values, ok := f.hits[host]; ok {
		return values, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host}
}

func TestAnalyzerDNSBLAndExternalScanner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":2.4,"action":"add header","symbols":{"BAYES_SPAM":{"description":"Bayes says spam","score":2.4}}}`))
	}))
	defer server.Close()

	analyzer := NewAnalyzerWithConfig(Config{
		SuspiciousThreshold: 2.0,
		JunkThreshold:       4.0,
		DNSBLZones:          []string{"zen.example.test"},
		Timeout:             2 * time.Second,
	}).
		WithSPFChecker(fakeSPFChecker{result: security.SPFFail}).
		WithResolver(fakeResolver{
			hits: map[string][]string{
				"2.0.0.127.zen.example.test": {"127.0.0.2"},
			},
		}).
		WithExternalScanner(NewRspamdScanner(server.URL, "", 2*time.Second))

	raw := []byte("From: Fraud Desk <alerts@example.net>\r\n" +
		"Reply-To: payout@other.test\r\n" +
		"To: user@mail.example.test\r\n" +
		"Subject: Urgent action\r\n" +
		"\r\n" +
		"click here for crypto investment lottery winner https://bad.example/claim\r\n")

	report := analyzer.Analyze(context.Background(), raw, "bounce@example.net", net.ParseIP("127.0.0.2"), "mx.example.net", "lightr")
	if report == nil {
		t.Fatal("expected report")
	}
	if report.Verdict != VerdictSpam {
		t.Fatalf("expected spam verdict, got %s score=%.2f reasons=%v", report.Verdict, report.SpamScore, report.Reasons)
	}
	if len(report.DNSBLHits) != 1 || report.DNSBLHits[0] != "zen.example.test" {
		t.Fatalf("expected dnsbl hit, got %#v", report.DNSBLHits)
	}
	if report.ExternalSource != "rspamd" {
		t.Fatalf("expected rspamd source, got %q", report.ExternalSource)
	}
	if report.AuthResults == "" {
		t.Fatal("expected authentication-results")
	}
	annotated := Annotate(raw, report)
	metadata := HeaderMetadata(annotated)
	if metadata["X-Lightr-DNSBL-Hits"] == "" {
		t.Fatalf("expected dnsbl metadata, got %#v", metadata)
	}
	if metadata["X-Lightr-External-Spam-Source"] != "rspamd" {
		t.Fatalf("expected external source metadata, got %#v", metadata)
	}
}

func TestAnalyzerCleanMessageMetadata(t *testing.T) {
	analyzer := NewAnalyzerWithConfig(Config{
		SuspiciousThreshold: 2.0,
		JunkThreshold:       4.0,
	}).WithSPFChecker(fakeSPFChecker{result: security.SPFPass})

	raw := []byte("From: sender@example.net\r\n" +
		"To: user@mail.example.test\r\n" +
		"Subject: Hello\r\n" +
		"Date: Mon, 04 May 2026 10:00:00 +0000\r\n" +
		"Message-ID: <abc@example.net>\r\n" +
		"\r\n" +
		"hello there\r\n")

	report := analyzer.Analyze(context.Background(), raw, "sender@example.net", net.ParseIP("127.0.0.1"), "mail.example.net", "lightr")
	if report.Verdict != VerdictClean {
		t.Fatalf("expected clean verdict, got %s score=%.2f reasons=%v", report.Verdict, report.SpamScore, report.Reasons)
	}
	annotated := string(Annotate(raw, report))
	if !strings.Contains(annotated, "Authentication-Results:") {
		t.Fatalf("expected auth headers in annotation, got %s", annotated)
	}
	if strings.Contains(annotated, "X-Lightr-DNSBL-Hits:") {
		t.Fatalf("did not expect dnsbl header in clean annotation")
	}
}
