package smtp

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

type Relay struct {
	dkimSigners map[string]*DKIMSigner // domain -> signer
}

func NewRelay() *Relay {
	return &Relay{
		dkimSigners: make(map[string]*DKIMSigner),
	}
}

// AddDKIMSigner registers a DKIM signer for a specific domain
func (r *Relay) AddDKIMSigner(domain, selector, privateKeyPEM string) error {
	signer, err := NewDKIMSigner(domain, selector, privateKeyPEM)
	if err != nil {
		return err
	}
	r.dkimSigners[domain] = signer
	return nil
}

// Send delivers email to one or more recipients
// It groups recipients by domain and sends to each domain's MX server
func (r *Relay) Send(ctx context.Context, from string, to []string, data []byte) error {
	// 1. Extract domain from 'from' address for DKIM signing
	fromParts := strings.Split(from, "@")
	if len(fromParts) == 2 {
		fromDomain := fromParts[1]
		if signer, ok := r.dkimSigners[fromDomain]; ok {
			signedData, err := signer.Sign(data)
			if err == nil {
				data = signedData
			}
			// If signing fails, we continue with unsigned data
		}
	}

	// 2. Group recipients by domain
	byDomain := make(map[string][]string)
	for _, rcpt := range to {
		parts := strings.Split(rcpt, "@")
		if len(parts) != 2 {
			return fmt.Errorf("invalid recipient email: %s", rcpt)
		}
		domain := parts[1]
		byDomain[domain] = append(byDomain[domain], rcpt)
	}

	// 3. Send to each domain
	var errors []string
	for domain, recipients := range byDomain {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := r.sendToDomain(ctx, from, domain, recipients, data); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", domain, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("delivery failures: %s", strings.Join(errors, "; "))
	}

	return nil
}

// SendSingle delivers email to a single recipient (backwards compatibility)
func (r *Relay) SendSingle(from, to string, data []byte) error {
	return r.Send(context.Background(), from, []string{to}, data)
}

func (r *Relay) sendToDomain(ctx context.Context, from, domain string, recipients []string, data []byte) error {
	// Lookup MX records
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("mx lookup failed: %v", err)
	}
	if len(mxRecords) == 0 {
		return fmt.Errorf("no mx records found")
	}

	// Try sending to MX servers in priority order
	var lastErr error
	for _, mx := range mxRecords {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		mxHost := strings.TrimSuffix(mx.Host, ".")
		err := smtp.SendMail(mxHost+":25", nil, from, recipients, data)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("all MX servers failed: %v", lastErr)
}
