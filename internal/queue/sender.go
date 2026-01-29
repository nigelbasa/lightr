package queue

import (
	"bytes"
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/nigelbasa/lightr/internal/smtp"
)

// RelaySender implements Sender using the SMTP relay
type RelaySender struct {
	relay *smtp.Relay
}

// NewRelaySender creates a sender that uses the SMTP relay
func NewRelaySender(relay *smtp.Relay) *RelaySender {
	return &RelaySender{relay: relay}
}

// Send sends the queued message via the relay
func (s *RelaySender) Send(ctx context.Context, msg *QueuedMessage) error {
	// Build RFC 5322 email message
	var buf bytes.Buffer

	// Extract domain from sender for DKIM
	parts := strings.Split(msg.From, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid from address: %s", msg.From)
	}
	senderDomain := parts[1]

	// Date header
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))

	// From header
	buf.WriteString(fmt.Sprintf("From: %s\r\n", msg.From))

	// To header
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(msg.To, ", ")))

	// Subject header
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))

	// Message-ID
	msgID := fmt.Sprintf("<%s@%s>", msg.ID.String(), senderDomain)
	buf.WriteString(fmt.Sprintf("Message-ID: %s\r\n", msgID))

	// MIME headers
	if msg.HTMLBody != "" {
		// Multipart message
		boundary := fmt.Sprintf("=_%s", msg.ID.String()[:8])
		buf.WriteString("MIME-Version: 1.0\r\n")
		buf.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
		buf.WriteString("\r\n")

		// Plain text part
		buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(msg.Body)
		buf.WriteString("\r\n")

		// HTML part
		buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(msg.HTMLBody)
		buf.WriteString("\r\n")

		// End boundary
		buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Simple text message
		buf.WriteString("MIME-Version: 1.0\r\n")
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(msg.Body)
	}

	// Parse recipients to get addresses
	var rcptTo []string
	for _, to := range msg.To {
		addr, err := mail.ParseAddress(to)
		if err != nil {
			rcptTo = append(rcptTo, to)
		} else {
			rcptTo = append(rcptTo, addr.Address)
		}
	}

	// Parse sender
	from := msg.From
	if addr, err := mail.ParseAddress(msg.From); err == nil {
		from = addr.Address
	}

	// Send via relay
	return s.relay.Send(ctx, from, rcptTo, buf.Bytes())
}
