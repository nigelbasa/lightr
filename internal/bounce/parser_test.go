package bounce

import (
	"strings"
	"testing"
)

func TestParser_Parse_DSN(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name             string
		email            string
		wantType         BounceType
		wantOriginalTo   string
		wantDiagnostic   string
	}{
		{
			name: "hard bounce - user unknown",
			email: `From: MAILER-DAEMON@example.com
Subject: Delivery Status Notification
Content-Type: multipart/report; report-type=delivery-status; boundary="boundary"

--boundary
Content-Type: text/plain

Mail delivery failed.

--boundary
Content-Type: message/delivery-status

Final-Recipient: rfc822;user@example.com
Action: failed
Status: 5.1.1
Diagnostic-Code: smtp; 550 User unknown

--boundary--
`,
			wantType:       BounceTypeHard,
			wantOriginalTo: "user@example.com",
			wantDiagnostic: "550 User unknown",
		},
		{
			name: "soft bounce - mailbox full",
			email: `From: postmaster@example.com
Subject: Mail Delivery Failure
Content-Type: multipart/report; report-type=delivery-status; boundary="b"

--b
Content-Type: message/delivery-status

Final-Recipient: rfc822;test@example.org
Action: delayed
Status: 4.2.2
Diagnostic-Code: smtp; 452 Mailbox full

--b--
`,
			wantType:       BounceTypeSoft,
			wantOriginalTo: "test@example.org",
			wantDiagnostic: "452 Mailbox full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(strings.NewReader(tt.email))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			if result.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", result.Type, tt.wantType)
			}
			if result.OriginalTo != tt.wantOriginalTo {
				t.Errorf("OriginalTo = %v, want %v", result.OriginalTo, tt.wantOriginalTo)
			}
			if tt.wantDiagnostic != "" && !strings.Contains(result.DiagnosticCode, tt.wantDiagnostic) {
				t.Errorf("DiagnosticCode = %v, want to contain %v", result.DiagnosticCode, tt.wantDiagnostic)
			}
		})
	}
}

func TestParser_Parse_Generic(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name      string
		email     string
		wantType  BounceType
		wantMatch bool
	}{
		{
			name: "generic bounce - user unknown",
			email: `From: postmaster@mail.example.com
Subject: Undelivered Mail Returned to Sender

This is the mail delivery agent.
550 5.1.1 <invalid@example.com>: Recipient address rejected: User unknown
`,
			wantType:  BounceTypeHard,
			wantMatch: true,
		},
		{
			name: "generic bounce - mailbox full",
			email: `From: mailer-daemon@example.com
Subject: Delivery failure

The recipient's mailbox is full.
452 4.2.2 Mailbox full
`,
			wantType:  BounceTypeSoft,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(strings.NewReader(tt.email))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			if result == nil {
				t.Fatal("Parse() returned nil result")
			}

			if tt.wantMatch {
				if result.Type != tt.wantType {
					t.Errorf("Type = %v, want %v", result.Type, tt.wantType)
				}
			} else {
				if result.Type != BounceTypeUnknown {
					t.Errorf("Expected non-bounce, got Type = %v", result.Type)
				}
			}
		})
	}
}
