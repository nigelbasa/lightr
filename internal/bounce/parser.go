package bounce

import (
	"bufio"
	"bytes"
	"io"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BounceType indicates the type of bounce
type BounceType string

const (
	BounceTypeHard      BounceType = "hard"      // Permanent failure (invalid address)
	BounceTypeSoft      BounceType = "soft"      // Temporary failure (mailbox full, server down)
	BounceTypeComplaint BounceType = "complaint" // Spam complaint (FBL)
	BounceTypeUnknown   BounceType = "unknown"
)

// BounceInfo contains parsed bounce information
type BounceInfo struct {
	Type            BounceType
	OriginalTo      string    // Original recipient that bounced
	OriginalFrom    string    // Original sender
	OriginalMsgID   string    // Original Message-ID if available
	DiagnosticCode  string    // SMTP diagnostic code (e.g., "550 5.1.1")
	BounceMessage   string    // Human-readable bounce reason
	RemoteMTA       string    // Remote MTA that rejected
	ReportingMTA    string    // MTA that generated the DSN
	ReceivedAt      time.Time
}

// Parser handles bounce email parsing
type Parser struct {
	// Patterns for detecting bounce emails
	hardBouncePatterns []*regexp.Regexp
	softBouncePatterns []*regexp.Regexp
}

// NewParser creates a new bounce parser
func NewParser() *Parser {
	return &Parser{
		hardBouncePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)user unknown`),
			regexp.MustCompile(`(?i)no such user`),
			regexp.MustCompile(`(?i)does not exist`),
			regexp.MustCompile(`(?i)invalid (recipient|address|mailbox)`),
			regexp.MustCompile(`(?i)address rejected`),
			regexp.MustCompile(`(?i)unknown user`),
			regexp.MustCompile(`(?i)mailbox not found`),
			regexp.MustCompile(`(?i)recipient rejected`),
			regexp.MustCompile(`(?i)550[\s\-]5\.1\.1`), // Invalid mailbox
			regexp.MustCompile(`(?i)550[\s\-]5\.1\.2`), // Invalid domain
			regexp.MustCompile(`(?i)551`),              // User not local
			regexp.MustCompile(`(?i)552`),              // Mailbox full (treat as hard after retries)
			regexp.MustCompile(`(?i)553`),              // Invalid mailbox name
			regexp.MustCompile(`(?i)554`),              // Transaction failed
		},
		softBouncePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)mailbox full`),
			regexp.MustCompile(`(?i)quota exceeded`),
			regexp.MustCompile(`(?i)over quota`),
			regexp.MustCompile(`(?i)temporarily`),
			regexp.MustCompile(`(?i)try again later`),
			regexp.MustCompile(`(?i)service unavailable`),
			regexp.MustCompile(`(?i)connection timed out`),
			regexp.MustCompile(`(?i)too many connections`),
			regexp.MustCompile(`(?i)rate limit`),
			regexp.MustCompile(`(?i)450[\s\-]`),
			regexp.MustCompile(`(?i)451[\s\-]`),
			regexp.MustCompile(`(?i)452[\s\-]`),
		},
	}
}

// Parse analyzes an email and extracts bounce information if it's a bounce
func (p *Parser) Parse(r io.Reader) (*BounceInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	info := &BounceInfo{
		Type:       BounceTypeUnknown,
		ReceivedAt: time.Now(),
	}

	// Check if this is a DSN (RFC 3464)
	contentType := msg.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/report") &&
		strings.Contains(contentType, "delivery-status") {
		return p.parseDSN(data, msg, info)
	}

	// Check common bounce indicators in headers
	if p.isBounceFromHeaders(msg) {
		return p.parseGenericBounce(data, msg, info)
	}

	// Check body for bounce patterns
	if p.isBounceFromBody(data) {
		return p.parseGenericBounce(data, msg, info)
	}

	return nil, nil // Not a bounce
}

func (p *Parser) isBounceFromHeaders(msg *mail.Message) bool {
	// Check From address
	from := strings.ToLower(msg.Header.Get("From"))
	bounceFroms := []string{
		"mailer-daemon@",
		"postmaster@",
		"mail-daemon@",
		"noreply@",
	}
	for _, bf := range bounceFroms {
		if strings.Contains(from, bf) {
			return true
		}
	}

	// Check Subject
	subject := strings.ToLower(msg.Header.Get("Subject"))
	bounceSubjects := []string{
		"delivery status",
		"undeliverable",
		"undelivered",
		"mail delivery failed",
		"returned mail",
		"delivery failure",
		"delivery failed",
		"mail system error",
		"failure notice",
	}
	for _, bs := range bounceSubjects {
		if strings.Contains(subject, bs) {
			return true
		}
	}

	// Check Auto-Submitted header
	autoSubmitted := strings.ToLower(msg.Header.Get("Auto-Submitted"))
	if autoSubmitted == "auto-replied" || autoSubmitted == "auto-generated" {
		return true
	}

	return false
}

func (p *Parser) isBounceFromBody(data []byte) bool {
	body := strings.ToLower(string(data))
	for _, pat := range p.hardBouncePatterns {
		if pat.MatchString(body) {
			return true
		}
	}
	for _, pat := range p.softBouncePatterns {
		if pat.MatchString(body) {
			return true
		}
	}
	return false
}

func (p *Parser) parseDSN(data []byte, msg *mail.Message, info *BounceInfo) (*BounceInfo, error) {
	// Parse multipart to extract delivery-status part
	body := string(data)

	// Extract Original-Recipient or Final-Recipient
	if match := regexp.MustCompile(`(?i)(?:Original|Final)-Recipient:\s*(?:rfc822;)?\s*(\S+)`).FindStringSubmatch(body); len(match) > 1 {
		info.OriginalTo = strings.TrimSpace(match[1])
	}

	// Extract Diagnostic-Code
	if match := regexp.MustCompile(`(?i)Diagnostic-Code:\s*(?:smtp;)?\s*(.+)`).FindStringSubmatch(body); len(match) > 1 {
		info.DiagnosticCode = strings.TrimSpace(match[1])
	}

	// Extract Remote-MTA
	if match := regexp.MustCompile(`(?i)Remote-MTA:\s*(?:dns;)?\s*(\S+)`).FindStringSubmatch(body); len(match) > 1 {
		info.RemoteMTA = strings.TrimSpace(match[1])
	}

	// Extract Reporting-MTA
	if match := regexp.MustCompile(`(?i)Reporting-MTA:\s*(?:dns;)?\s*(\S+)`).FindStringSubmatch(body); len(match) > 1 {
		info.ReportingMTA = strings.TrimSpace(match[1])
	}

	// Extract Action (failed, delayed, etc.)
	action := ""
	if match := regexp.MustCompile(`(?i)Action:\s*(\S+)`).FindStringSubmatch(body); len(match) > 1 {
		action = strings.ToLower(strings.TrimSpace(match[1]))
	}

	// Extract Status code
	status := ""
	if match := regexp.MustCompile(`(?i)Status:\s*(\d\.\d+\.\d+)`).FindStringSubmatch(body); len(match) > 1 {
		status = match[1]
	}

	// Determine bounce type from status code
	info.Type = p.classifyDSNStatus(status, action, info.DiagnosticCode)

	// Try to extract original Message-ID from attached message
	if match := regexp.MustCompile(`(?i)Message-ID:\s*<([^>]+)>`).FindStringSubmatch(body); len(match) > 1 {
		info.OriginalMsgID = match[1]
	}

	return info, nil
}

func (p *Parser) classifyDSNStatus(status, action, diagnostic string) BounceType {
	// RFC 3463 status codes
	if strings.HasPrefix(status, "5.") {
		// 5.x.x = Permanent failure
		switch {
		case strings.HasPrefix(status, "5.1."): // Addressing status
			return BounceTypeHard
		case strings.HasPrefix(status, "5.2."): // Mailbox status
			return BounceTypeHard
		case strings.HasPrefix(status, "5.3."): // Mail system status
			return BounceTypeHard
		case strings.HasPrefix(status, "5.7."): // Security/policy
			return BounceTypeHard
		default:
			return BounceTypeHard
		}
	} else if strings.HasPrefix(status, "4.") {
		// 4.x.x = Temporary failure
		return BounceTypeSoft
	}

	// Check action
	if action == "failed" {
		return BounceTypeHard
	} else if action == "delayed" {
		return BounceTypeSoft
	}

	// Fall back to pattern matching on diagnostic
	for _, pat := range p.hardBouncePatterns {
		if pat.MatchString(diagnostic) {
			return BounceTypeHard
		}
	}
	for _, pat := range p.softBouncePatterns {
		if pat.MatchString(diagnostic) {
			return BounceTypeSoft
		}
	}

	return BounceTypeUnknown
}

func (p *Parser) parseGenericBounce(data []byte, msg *mail.Message, info *BounceInfo) (*BounceInfo, error) {
	body := string(data)

	// Try to find original recipient
	emailRegex := regexp.MustCompile(`[\w.+-]+@[\w.-]+\.\w+`)
	emails := emailRegex.FindAllString(body, -1)
	
	// Look for "To:" pattern in quoted headers
	if match := regexp.MustCompile(`(?i)(?:Original |X-Failed-Recipients?:\s*)([^\s<>]+@[^\s<>]+)`).FindStringSubmatch(body); len(match) > 1 {
		info.OriginalTo = match[1]
	} else if len(emails) > 0 {
		// Use first email that's not the bounce sender
		from := msg.Header.Get("From")
		for _, email := range emails {
			if !strings.Contains(from, email) {
				info.OriginalTo = email
				break
			}
		}
	}

	// Extract diagnostic from body
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		for _, pat := range p.hardBouncePatterns {
			if pat.MatchString(line) {
				info.DiagnosticCode = strings.TrimSpace(line)
				info.Type = BounceTypeHard
				return info, nil
			}
		}
		for _, pat := range p.softBouncePatterns {
			if pat.MatchString(line) {
				info.DiagnosticCode = strings.TrimSpace(line)
				info.Type = BounceTypeSoft
				return info, nil
			}
		}
	}

	// Default to soft if we couldn't determine
	if info.Type == BounceTypeUnknown {
		info.Type = BounceTypeSoft
	}

	return info, nil
}

// BounceRecord represents a bounce stored in the database
type BounceRecord struct {
	ID             uuid.UUID
	OrgID          uuid.UUID
	DomainID       uuid.UUID
	OriginalMsgID  string
	RecipientEmail string
	BounceType     BounceType
	DiagnosticCode string
	RemoteMTA      string
	CreatedAt      time.Time
}

// Repository defines storage operations for bounces
type Repository interface {
	// Create stores a new bounce record
	Create(record *BounceRecord) error

	// GetByRecipient returns bounce history for an email address
	GetByRecipient(email string) ([]*BounceRecord, error)

	// CountByRecipient returns bounce count for an email
	CountByRecipient(email string, bounceType BounceType, since time.Time) (int, error)

	// ListByOrg returns bounces for an organization
	ListByOrg(orgID uuid.UUID, limit int) ([]*BounceRecord, error)

	// IsSuppressed checks if an email should be suppressed due to bounces
	IsSuppressed(email string) (bool, error)
}
