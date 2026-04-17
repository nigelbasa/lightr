package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type Relay struct {
	dkimSigners map[string]*DKIMSigner // domain -> signer
	hostname    string                  // HELO/EHLO hostname
}

func NewRelay() *Relay {
	return &Relay{
		dkimSigners: make(map[string]*DKIMSigner),
		hostname:    "localhost",
	}
}

// WithHostname sets the HELO/EHLO hostname for outbound connections
func (r *Relay) WithHostname(hostname string) *Relay {
	r.hostname = hostname
	return r
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
	log.Printf("Relay: sending email from %s to %v (size: %d bytes)", from, to, len(data))
	
	// 1. Extract domain from 'from' address for DKIM signing
	fromParts := strings.Split(from, "@")
	if len(fromParts) == 2 {
		fromDomain := fromParts[1]
		if signer, ok := r.dkimSigners[fromDomain]; ok {
			signedData, err := signer.Sign(data)
			if err == nil {
				data = signedData
				log.Printf("Relay: DKIM signed for domain %s", fromDomain)
			} else {
				log.Printf("Relay: DKIM signing failed for %s: %v", fromDomain, err)
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
			log.Printf("Relay: failed to send to %s: %v", domain, err)
			errors = append(errors, fmt.Sprintf("%s: %v", domain, err))
		} else {
			log.Printf("Relay: successfully sent to %v at %s", recipients, domain)
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

	log.Printf("Relay: found %d MX records for %s", len(mxRecords), domain)

	// Try sending to MX servers in priority order
	var lastErr error
	for _, mx := range mxRecords {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		mxHost := strings.TrimSuffix(mx.Host, ".")
		log.Printf("Relay: trying MX %s (priority %d) for %s", mxHost, mx.Pref, domain)
		
		err := r.sendToMX(mxHost, from, recipients, data)
		if err == nil {
			return nil
		}
		log.Printf("Relay: MX %s failed: %v", mxHost, err)
		lastErr = err
	}

	return fmt.Errorf("all MX servers failed: %v", lastErr)
}

// sendToMX sends email to a specific MX server with proper timeout and TLS support
func (r *Relay) sendToMX(mxHost, from string, recipients []string, data []byte) error {
	// Create a connection with timeout
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	
	conn, err := dialer.Dial("tcp", mxHost+":25")
	if err != nil {
		return fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()
	
	// Set read/write deadlines for large messages
	deadline := time.Now().Add(5 * time.Minute)
	conn.SetDeadline(deadline)
	
	client, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		return fmt.Errorf("client creation failed: %v", err)
	}
	defer client.Close()
	
	// Send proper HELO/EHLO with our hostname
	if err := client.Hello(r.hostname); err != nil {
		return fmt.Errorf("HELO failed: %v", err)
	}
	
	// Try STARTTLS if available
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{
			ServerName: mxHost,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			log.Printf("Relay: STARTTLS failed for %s: %v (continuing without TLS)", mxHost, err)
		}
	}
	
	// Send the email
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}
	
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO %s failed: %v", rcpt, err)
		}
	}
	
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %v", err)
	}
	
	_, err = wc.Write(data)
	if err != nil {
		wc.Close()
		return fmt.Errorf("data write failed: %v", err)
	}
	
	if err := wc.Close(); err != nil {
		return fmt.Errorf("data close failed: %v", err)
	}
	
	return client.Quit()
}
