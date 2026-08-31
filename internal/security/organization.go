package security

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TrustLevel indicates how much an email sender can be trusted
type TrustLevel string

const (
	TrustInternal   TrustLevel = "internal"   // Same organization
	TrustPartner    TrustLevel = "partner"    // Known partner organization
	TrustVerified   TrustLevel = "verified"   // Verified external sender
	TrustExternal   TrustLevel = "external"   // Unknown external sender
	TrustSuspicious TrustLevel = "suspicious" // Potentially malicious
)

// Warning represents a security warning to display in email clients
type Warning struct {
	Type     WarningType `json:"type"`
	Severity Severity    `json:"severity"`
	Title    string      `json:"title"`
	Message  string      `json:"message"`
	Details  string      `json:"details,omitempty"`
}

// WarningType identifies the warning category
type WarningType string

const (
	WarningExternalSender   WarningType = "external_sender"
	WarningFirstTimeContact WarningType = "first_time_contact"
	WarningSpoofingAttempt  WarningType = "spoofing_attempt"
	WarningDomainSimilarity WarningType = "domain_similarity"
	WarningReplyToMismatch  WarningType = "reply_to_mismatch"
	WarningDisplayNameSpoof WarningType = "display_name_spoof"
	WarningAuthFailure      WarningType = "auth_failure"
	WarningSuspiciousLinks  WarningType = "suspicious_links"
	WarningAttachmentRisk   WarningType = "attachment_risk"
	WarningImpersonation    WarningType = "impersonation"
)

// Severity indicates warning importance
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Organization represents a known organization
type Organization struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Domains    []string   `json:"domains"`
	TrustLevel TrustLevel `json:"trust_level"`
	LogoURL    string     `json:"logo_url,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// OrgRecognizer identifies organizations and generates warnings
type OrgRecognizer struct {
	repo            OrgRepository
	internalDomains []string
	vipNames        []string // Names that should never come from external
}

// Contact represents a recorded email contact
type Contact struct {
	Email        string    `json:"email"`
	ContactCount int       `json:"contact_count"`
	LastContact  time.Time `json:"last_contact"`
}

// OrgRepository stores organization data
type OrgRepository interface {
	GetByDomain(domain string) (*Organization, error)
	GetByID(id uuid.UUID) (*Organization, error)
	Create(org *Organization) error
	Update(org *Organization) error
	List() ([]*Organization, error)
	RecordContact(senderEmail, recipientEmail string) error
	IsFirstContact(senderEmail, recipientEmail string) (bool, error)
	SearchContacts(senderEmail, query string, limit int) ([]Contact, error)
}

// RecognizerConfig holds configuration
type RecognizerConfig struct {
	InternalDomains []string // Organization's own domains
	VIPNames        []string // Executive/VIP names to protect from spoofing
}

// NewOrgRecognizer creates an organization recognizer
func NewOrgRecognizer(repo OrgRepository, cfg *RecognizerConfig) *OrgRecognizer {
	return &OrgRecognizer{
		repo:            repo,
		internalDomains: cfg.InternalDomains,
		vipNames:        cfg.VIPNames,
	}
}

// EmailContext contains email metadata for analysis
type EmailContext struct {
	From           string
	FromName       string // Display name
	ReplyTo        string
	To             []string
	Subject        string
	MessageID      string
	SPFResult      string
	DKIMResult     string
	DMARCResult    string
	SenderIP       net.IP
	Links          []string // URLs in body
	HasAttachments bool
}

// AnalysisResult contains organization recognition results
type AnalysisResult struct {
	SenderOrg   *Organization
	TrustLevel  TrustLevel
	Warnings    []Warning
	Headers     map[string]string // Headers to add to email
	ShouldBlock bool
	BlockReason string
}

// Analyze examines an email for organization and security indicators
func (r *OrgRecognizer) Analyze(ctx *EmailContext, recipientEmail string) (*AnalysisResult, error) {
	result := &AnalysisResult{
		TrustLevel: TrustExternal,
		Headers:    make(map[string]string),
	}

	senderDomain := extractOrgDomain(ctx.From)
	if senderDomain == "" {
		return result, nil
	}

	// Check if sender is internal
	if r.isInternalDomain(senderDomain) {
		result.TrustLevel = TrustInternal

		// Internal sender but auth failed? Big red flag!
		if ctx.SPFResult == "fail" || ctx.DMARCResult == "fail" {
			result.Warnings = append(result.Warnings, Warning{
				Type:     WarningSpoofingAttempt,
				Severity: SeverityCritical,
				Title:    "Possible Internal Spoofing",
				Message:  "This email claims to be from your organization but failed authentication checks.",
				Details:  fmt.Sprintf("SPF: %s, DMARC: %s", ctx.SPFResult, ctx.DMARCResult),
			})
			result.TrustLevel = TrustSuspicious
		}
	} else {
		// External sender
		result.Warnings = append(result.Warnings, Warning{
			Type:     WarningExternalSender,
			Severity: SeverityInfo,
			Title:    "External Sender",
			Message:  fmt.Sprintf("This email is from outside your organization (%s).", senderDomain),
		})

		// Check if known organization
		org, _ := r.repo.GetByDomain(senderDomain)
		if org != nil {
			result.SenderOrg = org
			result.TrustLevel = org.TrustLevel
		}

		// Check for first-time contact
		isFirst, _ := r.repo.IsFirstContact(ctx.From, recipientEmail)
		if isFirst {
			result.Warnings = append(result.Warnings, Warning{
				Type:     WarningFirstTimeContact,
				Severity: SeverityWarning,
				Title:    "First-Time Sender",
				Message:  "You've never received email from this sender before.",
			})
		}
	}

	// Check for display name spoofing
	if warning := r.checkDisplayNameSpoof(ctx.FromName, senderDomain); warning != nil {
		result.Warnings = append(result.Warnings, *warning)
		result.TrustLevel = TrustSuspicious
	}

	// Check for domain similarity attacks
	if warning := r.checkDomainSimilarity(senderDomain); warning != nil {
		result.Warnings = append(result.Warnings, *warning)
		result.TrustLevel = TrustSuspicious
	}

	// Check Reply-To mismatch
	if ctx.ReplyTo != "" && ctx.ReplyTo != ctx.From {
		replyToDomain := extractOrgDomain(ctx.ReplyTo)
		if replyToDomain != senderDomain {
			result.Warnings = append(result.Warnings, Warning{
				Type:     WarningReplyToMismatch,
				Severity: SeverityWarning,
				Title:    "Reply Address Mismatch",
				Message:  fmt.Sprintf("Replies will go to a different address: %s", ctx.ReplyTo),
			})
		}
	}

	// Check authentication results
	if ctx.SPFResult == "fail" || ctx.DMARCResult == "fail" {
		result.Warnings = append(result.Warnings, Warning{
			Type:     WarningAuthFailure,
			Severity: SeverityWarning,
			Title:    "Email Authentication Failed",
			Message:  "This email did not pass security verification.",
			Details:  fmt.Sprintf("SPF: %s, DKIM: %s, DMARC: %s", ctx.SPFResult, ctx.DKIMResult, ctx.DMARCResult),
		})
	}

	// Check for VIP impersonation
	if warning := r.checkVIPImpersonation(ctx.FromName, senderDomain); warning != nil {
		result.Warnings = append(result.Warnings, *warning)
		result.TrustLevel = TrustSuspicious
	}

	// Add headers for client display
	result.Headers["X-Org-Trust-Level"] = string(result.TrustLevel)
	if result.SenderOrg != nil {
		result.Headers["X-Org-Sender-Name"] = result.SenderOrg.Name
		if result.SenderOrg.LogoURL != "" {
			result.Headers["X-Org-Sender-Logo"] = result.SenderOrg.LogoURL
		}
	}
	if len(result.Warnings) > 0 {
		result.Headers["X-Org-Warning-Count"] = fmt.Sprintf("%d", len(result.Warnings))
		// Add most severe warning
		maxSeverity := SeverityInfo
		var primaryWarning *Warning
		for i := range result.Warnings {
			w := &result.Warnings[i]
			if compareSeverity(w.Severity, maxSeverity) > 0 {
				maxSeverity = w.Severity
				primaryWarning = w
			}
		}
		if primaryWarning != nil {
			result.Headers["X-Org-Primary-Warning"] = primaryWarning.Title
		}
	}

	// Record contact for future reference
	if result.TrustLevel != TrustSuspicious {
		r.repo.RecordContact(ctx.From, recipientEmail)
	}

	return result, nil
}

func (r *OrgRecognizer) isInternalDomain(domain string) bool {
	domain = strings.ToLower(domain)
	for _, d := range r.internalDomains {
		if strings.ToLower(d) == domain {
			return true
		}
	}
	return false
}

func (r *OrgRecognizer) checkDisplayNameSpoof(displayName, senderDomain string) *Warning {
	if displayName == "" {
		return nil
	}

	displayName = strings.ToLower(displayName)

	// Check if display name contains an email address (common spoof technique)
	if strings.Contains(displayName, "@") {
		fakeDomain := extractOrgDomain(displayName)
		if fakeDomain != "" && fakeDomain != senderDomain {
			return &Warning{
				Type:     WarningDisplayNameSpoof,
				Severity: SeverityCritical,
				Title:    "Display Name Spoofing Detected",
				Message:  fmt.Sprintf("The display name contains a different email address than the actual sender."),
				Details:  fmt.Sprintf("Display: %s, Actual domain: %s", displayName, senderDomain),
			}
		}
	}

	// Check if display name impersonates internal domain
	for _, internal := range r.internalDomains {
		if strings.Contains(displayName, strings.ToLower(internal)) {
			return &Warning{
				Type:     WarningDisplayNameSpoof,
				Severity: SeverityWarning,
				Title:    "Suspicious Display Name",
				Message:  "The sender's display name references your organization but comes from an external address.",
			}
		}
	}

	return nil
}

func (r *OrgRecognizer) checkDomainSimilarity(senderDomain string) *Warning {
	senderDomain = strings.ToLower(senderDomain)

	for _, internal := range r.internalDomains {
		internal = strings.ToLower(internal)

		// Skip if same domain
		if senderDomain == internal {
			continue
		}

		// Check for common typosquatting patterns
		similarity := calculateSimilarity(senderDomain, internal)
		if similarity > 0.8 && similarity < 1.0 {
			return &Warning{
				Type:     WarningDomainSimilarity,
				Severity: SeverityCritical,
				Title:    "Suspicious Domain Detected",
				Message:  fmt.Sprintf("The sender's domain '%s' is very similar to '%s'.", senderDomain, internal),
				Details:  "This could be an attempt to impersonate your organization.",
			}
		}

		// Check for common tricks
		if isSuspiciousSimilar(senderDomain, internal) {
			return &Warning{
				Type:     WarningDomainSimilarity,
				Severity: SeverityCritical,
				Title:    "Potential Domain Spoofing",
				Message:  fmt.Sprintf("The domain '%s' may be impersonating '%s'.", senderDomain, internal),
			}
		}
	}

	return nil
}

func (r *OrgRecognizer) checkVIPImpersonation(displayName, senderDomain string) *Warning {
	if displayName == "" {
		return nil
	}

	displayName = strings.ToLower(displayName)

	for _, vipName := range r.vipNames {
		vipName = strings.ToLower(vipName)
		if strings.Contains(displayName, vipName) {
			// Check if from internal domain
			if !r.isInternalDomain(senderDomain) {
				return &Warning{
					Type:     WarningImpersonation,
					Severity: SeverityCritical,
					Title:    "Executive Impersonation Detected",
					Message:  fmt.Sprintf("This email appears to impersonate a known person (%s) but comes from an external source.", vipName),
					Details:  "Do not trust requests for money transfers, password resets, or sensitive information.",
				}
			}
		}
	}

	return nil
}

func extractOrgDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

func calculateSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}

	// Levenshtein distance based similarity
	distance := levenshteinDistance(a, b)
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}

	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - float64(distance)/float64(maxLen)
}

func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := 0; j <= len(b); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}

	return matrix[len(a)][len(b)]
}

func min(nums ...int) int {
	m := nums[0]
	for _, n := range nums[1:] {
		if n < m {
			m = n
		}
	}
	return m
}

func isSuspiciousSimilar(suspect, legitimate string) bool {
	// Remove TLD for comparison
	suspectBase := strings.Split(suspect, ".")[0]
	legitBase := strings.Split(legitimate, ".")[0]

	// Common substitution attacks
	substitutions := map[string][]string{
		"o": {"0"},
		"i": {"1", "l"},
		"l": {"1", "i"},
		"e": {"3"},
		"a": {"@", "4"},
		"s": {"5", "$"},
		"g": {"9", "q"},
	}

	// Check if only differs by common substitutions
	if len(suspectBase) == len(legitBase) {
		diffs := 0
		for i := 0; i < len(suspectBase); i++ {
			if suspectBase[i] != legitBase[i] {
				diffs++
				// Check if it's a known substitution
				legitChar := string(legitBase[i])
				suspectChar := string(suspectBase[i])
				if subs, ok := substitutions[legitChar]; ok {
					for _, sub := range subs {
						if sub == suspectChar {
							// This is a substitution attack
							return true
						}
					}
				}
			}
		}
		// Single character difference is suspicious
		if diffs == 1 {
			return true
		}
	}

	// Check for added/removed characters
	if abs(len(suspectBase)-len(legitBase)) == 1 {
		// Check if it's just one added/removed character
		longer, shorter := suspectBase, legitBase
		if len(legitBase) > len(suspectBase) {
			longer, shorter = legitBase, suspectBase
		}

		for i := 0; i < len(longer); i++ {
			modified := longer[:i] + longer[i+1:]
			if modified == shorter {
				return true
			}
		}
	}

	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func compareSeverity(a, b Severity) int {
	order := map[Severity]int{
		SeverityInfo:     0,
		SeverityWarning:  1,
		SeverityCritical: 2,
	}
	return order[a] - order[b]
}

// SQLiteOrgRepository implements OrgRepository
type SQLiteOrgRepository struct {
	db     *sql.DB
	driver string
}

// NewSQLiteOrgRepository creates a new org repository
func NewSQLiteOrgRepository(db *sql.DB) (*SQLiteOrgRepository, error) {
	return NewSQLOrgRepository(db, "sqlite")
}

func NewPostgresOrgRepository(db *sql.DB) (*SQLiteOrgRepository, error) {
	return NewSQLOrgRepository(db, "postgres")
}

func NewSQLOrgRepository(db *sql.DB, driver string) (*SQLiteOrgRepository, error) {
	repo := &SQLiteOrgRepository{db: db, driver: driver}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteOrgRepository) bind(query string) string {
	if r.driver != "postgres" {
		return query
	}

	var out strings.Builder
	index := 1
	for _, ch := range query {
		if ch == '?' {
			out.WriteString(fmt.Sprintf("$%d", index))
			index++
			continue
		}
		out.WriteRune(ch)
	}
	return out.String()
}

func (r *SQLiteOrgRepository) migrate() error {
	_, err := r.db.Exec(r.bind(`
		CREATE TABLE IF NOT EXISTS known_organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			domains TEXT NOT NULL,
			trust_level TEXT DEFAULT 'external',
			logo_url TEXT,
			verified_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_orgs_domains ON known_organizations(domains);

		CREATE TABLE IF NOT EXISTS sender_contacts (
			sender_email TEXT NOT NULL,
			recipient_email TEXT NOT NULL,
			first_contact DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_contact DATETIME DEFAULT CURRENT_TIMESTAMP,
			contact_count INTEGER DEFAULT 1,
			PRIMARY KEY (sender_email, recipient_email)
		);
		CREATE INDEX IF NOT EXISTS idx_contacts_recipient ON sender_contacts(recipient_email);
	`))
	return err
}

func (r *SQLiteOrgRepository) GetByDomain(domain string) (*Organization, error) {
	row := r.db.QueryRow(r.bind(`
		SELECT id, name, domains, trust_level, logo_url, verified_at, created_at, updated_at
		FROM known_organizations WHERE domains LIKE ?
	`), "%"+domain+"%")
	return r.scanOrg(row)
}

func (r *SQLiteOrgRepository) GetByID(id uuid.UUID) (*Organization, error) {
	row := r.db.QueryRow(r.bind(`
		SELECT id, name, domains, trust_level, logo_url, verified_at, created_at, updated_at
		FROM known_organizations WHERE id = ?
	`), id.String())
	return r.scanOrg(row)
}

func (r *SQLiteOrgRepository) Create(org *Organization) error {
	if org.ID == uuid.Nil {
		org.ID = uuid.New()
	}
	org.CreatedAt = time.Now()
	org.UpdatedAt = time.Now()

	domains := strings.Join(org.Domains, ",")
	_, err := r.db.Exec(r.bind(`
		INSERT INTO known_organizations (id, name, domains, trust_level, logo_url, verified_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`), org.ID.String(), org.Name, domains, org.TrustLevel, org.LogoURL, org.VerifiedAt, org.CreatedAt, org.UpdatedAt)
	return err
}

func (r *SQLiteOrgRepository) Update(org *Organization) error {
	org.UpdatedAt = time.Now()
	domains := strings.Join(org.Domains, ",")
	_, err := r.db.Exec(r.bind(`
		UPDATE known_organizations SET name = ?, domains = ?, trust_level = ?, logo_url = ?, verified_at = ?, updated_at = ?
		WHERE id = ?
	`), org.Name, domains, org.TrustLevel, org.LogoURL, org.VerifiedAt, org.UpdatedAt, org.ID.String())
	return err
}

func (r *SQLiteOrgRepository) List() ([]*Organization, error) {
	rows, err := r.db.Query(r.bind(`SELECT id, name, domains, trust_level, logo_url, verified_at, created_at, updated_at FROM known_organizations ORDER BY name`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []*Organization
	for rows.Next() {
		org, err := r.scanOrgRow(rows)
		if err != nil {
			return nil, err
		}
		orgs = append(orgs, org)
	}
	return orgs, nil
}

func (r *SQLiteOrgRepository) RecordContact(senderEmail, recipientEmail string) error {
	_, err := r.db.Exec(r.bind(`
		INSERT INTO sender_contacts (sender_email, recipient_email)
		VALUES (?, ?)
		ON CONFLICT (sender_email, recipient_email) DO UPDATE SET
			last_contact = CURRENT_TIMESTAMP,
			contact_count = contact_count + 1
	`), strings.ToLower(senderEmail), strings.ToLower(recipientEmail))
	return err
}

func (r *SQLiteOrgRepository) IsFirstContact(senderEmail, recipientEmail string) (bool, error) {
	var count int
	err := r.db.QueryRow(r.bind(`
		SELECT contact_count FROM sender_contacts
		WHERE sender_email = ? AND recipient_email = ?
	`), strings.ToLower(senderEmail), strings.ToLower(recipientEmail)).Scan(&count)

	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

// SearchContacts searches for contacts a user has interacted with
func (r *SQLiteOrgRepository) SearchContacts(senderEmail, query string, limit int) ([]Contact, error) {
	if limit <= 0 {
		limit = 10
	}

	// Search for contacts where this sender has sent emails, ordered by frequency
	rows, err := r.db.Query(r.bind(`
		SELECT recipient_email, contact_count, last_contact
		FROM sender_contacts
		WHERE sender_email = ? AND recipient_email LIKE ?
		ORDER BY contact_count DESC, last_contact DESC
		LIMIT ?
	`), strings.ToLower(senderEmail), "%"+strings.ToLower(query)+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var c Contact
		if err := rows.Scan(&c.Email, &c.ContactCount, &c.LastContact); err != nil {
			return nil, err
		}
		contacts = append(contacts, c)
	}

	return contacts, rows.Err()
}

func (r *SQLiteOrgRepository) scanOrg(row *sql.Row) (*Organization, error) {
	var org Organization
	var idStr, domains string
	var verifiedAt sql.NullTime
	var logoURL sql.NullString

	err := row.Scan(&idStr, &org.Name, &domains, &org.TrustLevel, &logoURL, &verifiedAt, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, err
	}

	org.ID, _ = uuid.Parse(idStr)
	org.Domains = strings.Split(domains, ",")
	if logoURL.Valid {
		org.LogoURL = logoURL.String
	}
	if verifiedAt.Valid {
		org.VerifiedAt = &verifiedAt.Time
	}

	return &org, nil
}

func (r *SQLiteOrgRepository) scanOrgRow(rows *sql.Rows) (*Organization, error) {
	var org Organization
	var idStr, domains string
	var verifiedAt sql.NullTime
	var logoURL sql.NullString

	err := rows.Scan(&idStr, &org.Name, &domains, &org.TrustLevel, &logoURL, &verifiedAt, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, err
	}

	org.ID, _ = uuid.Parse(idStr)
	org.Domains = strings.Split(domains, ",")
	if logoURL.Valid {
		org.LogoURL = logoURL.String
	}
	if verifiedAt.Valid {
		org.VerifiedAt = &verifiedAt.Time
	}

	return &org, nil
}
