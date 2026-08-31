package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/alias"
	"github.com/nigelbasa/lightr/internal/domain"
	imapbackend "github.com/nigelbasa/lightr/internal/imap"
	"github.com/nigelbasa/lightr/internal/spam"
	"github.com/nigelbasa/lightr/internal/webhooks"
)

// LoginAuthenticator is a callback function for LOGIN auth
type LoginAuthenticator func(username, password string) error

// loginServer is a SASL server for LOGIN mechanism
type loginServer struct {
	authenticate LoginAuthenticator
	username     string
	step         int
}

func newLoginServer(auth LoginAuthenticator) sasl.Server {
	return &loginServer{authenticate: auth}
}

func (s *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.step {
	case 0:
		// Initial - send "Username:" challenge
		s.step++
		return []byte("Username:"), false, nil
	case 1:
		// Received username - send "Password:" challenge
		s.username = string(response)
		s.step++
		return []byte("Password:"), false, nil
	case 2:
		// Received password - authenticate
		password := string(response)
		err := s.authenticate(s.username, password)
		return nil, true, err
	}
	return nil, false, sasl.ErrUnexpectedClientResponse
}

type Server struct {
	addr            string
	submissionAddr  string
	domain          string
	backend         *Backend
	tlsConfig       *tls.Config
	allowInsecure   bool
	maxRecipients   int
	maxMessageBytes int64
}

func NewServer(addr string, backend *Backend) *Server {
	return &Server{
		addr:            addr,
		backend:         backend,
		domain:          "localhost",
		maxRecipients:   50,
		maxMessageBytes: 25 * 1024 * 1024, // 25MB matches Gmail/Outlook
	}
}

// WithLimits sets envelope-level limits enforced by the SMTP server.
// Zero or negative values fall back to the constructor defaults.
func (s *Server) WithLimits(maxRecipients int, maxMessageBytes int64) {
	if maxRecipients > 0 {
		s.maxRecipients = maxRecipients
	}
	if maxMessageBytes > 0 {
		s.maxMessageBytes = maxMessageBytes
	}
}

// WithDomain sets the SMTP server domain name
func (s *Server) WithDomain(domain string) {
	s.domain = domain
}

// WithSubmissionAddr sets the submission port (587)
func (s *Server) WithSubmissionAddr(addr string) {
	s.submissionAddr = addr
}

// WithAllowInsecureAuth controls whether AUTH is permitted without TLS.
func (s *Server) WithAllowInsecureAuth(allow bool) {
	s.allowInsecure = allow
}

// WithTLS configures TLS support for STARTTLS
func (s *Server) WithTLS(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	s.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return nil
}

// WithTLSMultiDomain configures TLS with SNI support for multiple domains
func (s *Server) WithTLSMultiDomain(defaultCert, defaultKey string, domainCerts map[string]tls.Certificate) error {
	defaultCertPair, err := tls.LoadX509KeyPair(defaultCert, defaultKey)
	if err != nil {
		return err
	}
	s.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{defaultCertPair},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cert, ok := domainCerts[info.ServerName]; ok {
				log.Printf("SNI: Using certificate for %s", info.ServerName)
				return &cert, nil
			}
			log.Printf("SNI: Using default certificate for %s", info.ServerName)
			return &defaultCertPair, nil
		},
		MinVersion: tls.VersionTLS12,
	}
	return nil
}

func (s *Server) Start() error {
	srv := smtp.NewServer(s.backend)
	srv.Addr = s.addr
	srv.Domain = s.domain
	srv.WriteTimeout = 5 * time.Minute // Allow 5 minutes for large attachments
	srv.ReadTimeout = 5 * time.Minute  // Allow 5 minutes for large attachments
	srv.MaxRecipients = s.maxRecipients
	srv.MaxMessageBytes = s.maxMessageBytes

	if s.tlsConfig != nil {
		srv.TLSConfig = s.tlsConfig
		srv.AllowInsecureAuth = false
		log.Printf("Starting SMTP server at %s with STARTTLS (domain: %s)", s.addr, s.domain)
	} else {
		srv.AllowInsecureAuth = s.allowInsecure
		if s.allowInsecure {
			log.Printf("Starting SMTP server at %s (insecure auth enabled)", s.addr)
		} else {
			log.Printf("Starting SMTP server at %s without SMTP AUTH until TLS is configured", s.addr)
		}
	}

	return srv.ListenAndServe()
}

// StartSubmission starts the submission server on port 587
func (s *Server) StartSubmission() error {
	if s.submissionAddr == "" {
		return nil
	}

	srv := smtp.NewServer(s.backend)
	srv.Addr = s.submissionAddr
	srv.Domain = s.domain
	srv.WriteTimeout = 5 * time.Minute // Allow 5 minutes for large attachments
	srv.ReadTimeout = 5 * time.Minute  // Allow 5 minutes for large attachments
	srv.MaxRecipients = s.maxRecipients
	srv.MaxMessageBytes = s.maxMessageBytes

	if s.tlsConfig != nil {
		srv.TLSConfig = s.tlsConfig
		srv.AllowInsecureAuth = false
		log.Printf("Starting SMTP submission server at %s with STARTTLS (domain: %s)", s.submissionAddr, s.domain)
	} else {
		srv.AllowInsecureAuth = s.allowInsecure
		if s.allowInsecure {
			log.Printf("Starting SMTP submission server at %s (insecure auth enabled)", s.submissionAddr)
		} else {
			log.Printf("Starting SMTP submission server at %s without SMTP AUTH until TLS is configured", s.submissionAddr)
		}
	}

	return srv.ListenAndServe()
}

type Backend struct {
	AccountRepo      domain.AccountRepository
	DomainRepo       domain.DomainRepository
	BlobStorage      domain.BlobStorage
	MessageRepo      domain.MessageRepository
	AuthService      domain.AuthService
	AliasRepo        *alias.SQLiteRepository
	SpamAnalyzer     *spam.Analyzer
	WebhookService   *webhooks.WebhookService
	GlobalWebhookURL string // Global webhook URL from config
	Relay            *Relay

	// IPLimiter throttles per-IP envelope-from operations. Nil disables.
	IPLimiter SMTPThrottle
	// SendLimiter throttles per-account and per-domain send rate from
	// authenticated submission. Nil disables.
	SendLimiter SendThrottle
	// SuppressionList, if set, is consulted on inbound to reject envelopes
	// whose return-path is on the suppression list.
	SuppressionList SuppressionChecker
	// OrganizationHostname identifies "our" domains for the X-Lightr-External
	// header. If empty, the marker is skipped.
	OrgDomainResolver OrgDomainResolver
}

// SMTPThrottle gates per-IP envelope operations.
type SMTPThrottle interface {
	AllowSMTP(ip string) bool
}

// SendThrottle gates submission by account/domain.
type SendThrottle interface {
	AllowSend(accountID, domainID uuid.UUID) bool
}

// SuppressionChecker reports whether a sender is on the suppression list.
type SuppressionChecker interface {
	IsSuppressed(email string) bool
}

// OrgDomainResolver reports whether a domain belongs to the same organization
// as the recipient's domain. Used to mark cross-org mail with X-Lightr-External.
type OrgDomainResolver interface {
	SameOrg(recipientDomainID uuid.UUID, senderDomain string) bool
}

func (bkd *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{backend: bkd, conn: c}, nil
}

type Session struct {
	backend *Backend
	conn    *smtp.Conn
	account *domain.Account
	from    string
	to      []string
}

// AuthMechanisms returns the list of supported authentication mechanisms
func (s *Session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

// Auth handles authentication using SASL
func (s *Session) Auth(mech string) (sasl.Server, error) {
	log.Printf("SMTP Auth: mechanism=%s", mech)
	authCallback := func(username, password string) error {
		log.Printf("SMTP Auth: attempting auth for user=%s", username)
		acc, err := s.backend.AuthService.Authenticate(context.Background(), username, password)
		if err != nil {
			log.Printf("SMTP Auth: auth failed for user=%s: %v", username, err)
			return smtp.ErrAuthFailed
		}
		log.Printf("SMTP Auth: auth succeeded for user=%s", username)
		s.account = acc
		return nil
	}

	switch mech {
	case sasl.Login:
		return newLoginServer(authCallback), nil
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return authCallback(username, password)
		}), nil
	default:
		return nil, smtp.ErrAuthUnsupported
	}
}

func (s *Session) AuthPlain(username, password string) error {
	acc, err := s.backend.AuthService.Authenticate(context.Background(), username, password)
	if err != nil {
		return err
	}
	s.account = acc
	return nil
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	// Unauthenticated (inbound) MAIL is rate-limited per remote IP so a
	// flood from one source can't drown the server.
	if s.account == nil && s.backend.IPLimiter != nil {
		if ip := s.remoteIP(); ip != nil && !s.backend.IPLimiter.AllowSMTP(ip.String()) {
			return &smtp.SMTPError{
				Code:         421,
				EnhancedCode: smtp.EnhancedCode{4, 7, 0},
				Message:      "rate limit exceeded, please retry later",
			}
		}
	}

	// Inbound suppression: refuse mail from a return-path on the bounce
	// suppression list. Cheap reject at MAIL time saves bandwidth.
	if s.account == nil && s.backend.SuppressionList != nil {
		if from != "" && s.backend.SuppressionList.IsSuppressed(from) {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "sender is on suppression list",
			}
		}
	}

	if s.account != nil {
		sender, err := s.authenticatedSender()
		if err != nil {
			return err
		}
		if !strings.EqualFold(normalizeMailboxAddress(from), sender) {
			return fmt.Errorf("authenticated user may only send as %s", sender)
		}
		// Authenticated submission also has its own send rate limit so a
		// compromised account can't be used as a spam cannon.
		if s.backend.SendLimiter != nil {
			if !s.backend.SendLimiter.AllowSend(s.account.ID, s.account.DomainID) {
				return &smtp.SMTPError{
					Code:         421,
					EnhancedCode: smtp.EnhancedCode{4, 7, 0},
					Message:      "send rate limit exceeded",
				}
			}
		}
		s.from = sender
		return nil
	}
	s.from = from
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// Authenticated submission can target anywhere — no early reject.
	if s.account != nil {
		s.to = append(s.to, to)
		return nil
	}
	// Inbound mail: only accept recipients we actually host. Validating at
	// RCPT time means senders get an immediate 550 instead of a silent
	// black hole at DATA time, matching what Gmail/Outlook do.
	if err := s.backend.validateInboundRcpt(to); err != nil {
		return err
	}
	s.to = append(s.to, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	// Parse MIME headers
	msg, err := mail.ReadMessage(strings.NewReader(string(data)))
	var subject, fromHeader, toHeader string
	if err == nil {
		subject = msg.Header.Get("Subject")
		fromHeader = msg.Header.Get("From")
		toHeader = msg.Header.Get("To")
	}

	// Fall back to envelope data if headers missing
	if fromHeader == "" {
		fromHeader = s.from
	}
	if toHeader == "" && len(s.to) > 0 {
		toHeader = strings.Join(s.to, ", ")
	}

	// If authenticated (submission), this is outgoing mail - queue for delivery
	if s.account != nil {
		sender, err := s.authenticatedSender()
		if err != nil {
			return err
		}
		s.from = sender
		data = s.prepareAuthenticatedMessage(data, s.account.DisplayName, sender)
		fromHeader = formatFromHeaderValue(s.account.DisplayName, sender)
		if s.backend.Relay != nil {
			if dom, err := s.backend.DomainRepo.GetDomainByID(s.account.DomainID); err == nil {
				if dom.RelayEnabled && dom.RelayHost != "" {
					s.backend.Relay.SetDomainRoute(dom.Name, RelayRoute{
						Host:          dom.RelayHost,
						Port:          dom.RelayPort,
						Username:      dom.RelayUsername,
						Password:      dom.RelayPassword,
						UseTLS:        dom.RelayUseTLS,
						TLSSkipVerify: dom.RelayTLSSkipVerify,
					})
				} else {
					s.backend.Relay.RemoveDomainRoute(dom.Name)
				}
			}
		}

		localRecipients, remoteRecipients := s.backend.partitionRecipients(s.to)
		for _, rcpt := range localRecipients {
			if err := s.backend.deliverToLocalRecipient(s.from, rcpt, subject, fromHeader, toHeader, data, nil); err != nil {
				log.Printf("Failed to locally deliver mail to %s: %v", rcpt, err)
			}
		}
		if len(remoteRecipients) > 0 {
			relayCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			err := s.backend.Relay.Send(relayCtx, s.from, remoteRecipients, data)
			cancel()
			if err != nil {
				log.Printf("Failed to relay mail to %v: %v", remoteRecipients, err)
				return err
			}
		}
		return nil
	}

	// Incoming mail - deliver to local recipients
	analyzer := s.backend.SpamAnalyzer
	if analyzer == nil {
		analyzer = spam.NewAnalyzer()
	}
	spamCtx, spamCancel := context.WithTimeout(context.Background(), 30*time.Second)
	analysis := analyzer.Analyze(spamCtx, data, s.from, s.remoteIP(), s.heloName(), "lightr")
	spamCancel()
	var delivered int
	var lastErr error
	for _, rcpt := range s.to {
		if err := s.backend.deliverToLocalRecipient(s.from, rcpt, subject, fromHeader, toHeader, data, analysis); err != nil {
			log.Printf("Failed to deliver mail from %s to %s: %v", s.from, rcpt, err)
			lastErr = err
			continue
		}
		delivered++
		log.Printf("Delivered mail from %s to %s", s.from, rcpt)
	}
	if delivered == 0 && lastErr != nil {
		return lastErr
	}

	return nil
}

func (s *Session) remoteIP() net.IP {
	if s.conn == nil || s.conn.Conn() == nil {
		return nil
	}
	if addr, ok := s.conn.Conn().RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP
	}
	host, _, err := net.SplitHostPort(s.conn.Conn().RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func (s *Session) heloName() string {
	if s.conn == nil {
		return ""
	}
	return s.conn.Hostname()
}

func (s *Session) authenticatedSender() (string, error) {
	if s.account == nil {
		return "", nil
	}
	dom, err := s.backend.DomainRepo.GetDomainByID(s.account.DomainID)
	if err != nil {
		return "", fmt.Errorf("resolve authenticated sender domain: %w", err)
	}
	return normalizeMailboxAddress(accountAddress(s.account, dom.Name)), nil
}

func (bkd *Backend) partitionRecipients(recipients []string) (local []string, remote []string) {
	for _, rcpt := range recipients {
		if bkd.isLocalRecipient(rcpt) {
			local = append(local, rcpt)
			continue
		}
		remote = append(remote, rcpt)
	}
	return local, remote
}

func (bkd *Backend) isLocalRecipient(email string) bool {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	_, err := bkd.DomainRepo.GetDomainByName(parts[1])
	return err == nil
}

func (bkd *Backend) deliverToLocalRecipient(envelopeFrom, rcpt, subject, fromHeader, toHeader string, data []byte, analysis *spam.Report) error {
	parts := strings.SplitN(rcpt, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient email: %s", rcpt)
	}
	localPart := parts[0]
	domainName := parts[1]

	dom, err := bkd.DomainRepo.GetDomainByName(domainName)
	if err != nil {
		return fmt.Errorf("domain not found for %s: %w", rcpt, err)
	}

	if route := bkd.lookupReplyRoute(localPart); route != nil {
		return bkd.handleBridgeReply(route, subject, data)
	}

	acc, err := bkd.AccountRepo.GetAccountByLocalPart(dom.ID, localPart)
	if err != nil {
		if bkd.AliasRepo != nil {
			aliased, aliasErr := bkd.AliasRepo.FindByAddress(localPart, dom.ID.String())
			if aliasErr == nil && aliased != nil && aliased.IsActive {
				return bkd.handleDirectAlias(aliased, envelopeFrom, data)
			}
		}
		return fmt.Errorf("account not found for %s: %w", rcpt, err)
	}

	annotatedData := data
	folder := "INBOX"
	if analysis != nil {
		annotatedData = spam.Annotate(data, analysis)
		var rejected bool
		folder, rejected = applySpamPolicy(dom, analysis)
		if rejected {
			return fmt.Errorf("message rejected by spam policy for domain %s", dom.Name)
		}
	}

	msgID := uuid.New()
	storagePath := msgID.String() + ".eml"
	if err := bkd.BlobStorage.Put(storagePath, annotatedData); err != nil {
		return fmt.Errorf("store blob for %s: %w", rcpt, err)
	}

	domainMsg := &domain.Message{
		ID:          msgID,
		AccountID:   acc.ID,
		Folder:      folder,
		SizeBytes:   int64(len(annotatedData)),
		StoragePath: storagePath,
		Subject:     subject,
		From:        firstHeaderValue(fromHeader, envelopeFrom),
		To:          firstHeaderValue(toHeader, rcpt),
		ReceivedAt:  time.Now(),
	}
	if err := bkd.MessageRepo.CreateMessage(domainMsg); err != nil {
		return fmt.Errorf("create message for %s: %w", rcpt, err)
	}

	msgs, _ := bkd.MessageRepo.ListByAccount(acc.ID, folder)
	imapbackend.GetIdleNotifier().NotifyNewMail(acc.ID, uint32(len(msgs)))

	webhookURL := dom.WebhookURL
	if webhookURL == "" {
		webhookURL = bkd.GlobalWebhookURL
	}
	if bkd.WebhookService != nil {
		payload := map[string]interface{}{
			"message_id": domainMsg.ID,
			"account_id": acc.ID,
			"email":      rcpt,
			"from":       domainMsg.From,
			"subject":    subject,
			"received":   domainMsg.ReceivedAt,
			"folder":     folder,
		}
		if analysis != nil {
			payload["spam_score"] = analysis.SpamScore
			payload["spam_verdict"] = analysis.Verdict
			payload["spf_result"] = analysis.SPFResult
			payload["dkim_result"] = analysis.DKIMResult
			payload["dmarc_result"] = analysis.DMARCResult
			payload["mailed_by"] = analysis.MailedBy
			payload["signed_by"] = analysis.SignedBy
			payload["remote_ip"] = analysis.RemoteIP
			payload["reasons"] = analysis.Reasons
		}
		// Fan out to API-registered subscribers.
		bkd.WebhookService.Trigger(context.Background(), webhooks.EventEmailReceived, payload)
		// And to the legacy per-domain / global URL, if configured.
		if webhookURL != "" {
			bkd.WebhookService.DeliverOnce(context.Background(), webhookURL, webhooks.EventEmailReceived, payload)
		}
	}
	if bkd.AliasRepo != nil {
		if bridgeAlias, aliasErr := bkd.AliasRepo.FindByAddress(localPart, dom.ID.String()); aliasErr == nil && bridgeAlias != nil && bridgeAlias.IsActive && bridgeAlias.Type == alias.AliasTypeBridge {
			if err := bkd.mirrorBridgeMessage(acc, dom, bridgeAlias, envelopeFrom, subject, fromHeader, toHeader, data); err != nil {
				log.Printf("Failed to mirror bridged mail for %s: %v", rcpt, err)
			}
		}
	}
	return nil
}

func applySpamPolicy(dom *domain.Domain, analysis *spam.Report) (string, bool) {
	if analysis == nil {
		return "INBOX", false
	}
	if analysis.Verdict != spam.VerdictSpam {
		return "INBOX", false
	}
	switch strings.ToLower(strings.TrimSpace(firstHeaderValue(dom.SpamPolicy, "junk"))) {
	case "accept", "mark":
		return "INBOX", false
	case "quarantine":
		return "Quarantine", false
	case "reject":
		return "", true
	case "junk", "spam":
		fallthrough
	default:
		return "Junk", false
	}
}

func (bkd *Backend) lookupReplyRoute(localPart string) *alias.ReplyRoute {
	if bkd.AliasRepo == nil {
		return nil
	}
	token := extractBridgeToken(localPart)
	if token == "" {
		return nil
	}
	route, err := bkd.AliasRepo.GetReplyRoute(token)
	if err != nil {
		return nil
	}
	return route
}

func extractBridgeToken(localPart string) string {
	idx := strings.Index(localPart, "--ltr-")
	if idx == -1 {
		return ""
	}
	token := strings.TrimSpace(localPart[idx+len("--ltr-"):])
	if token == "" {
		return ""
	}
	return token
}

func (bkd *Backend) handleDirectAlias(aliased *alias.Alias, envelopeFrom string, data []byte) error {
	if len(aliased.Destinations) == 0 {
		return nil
	}
	switch aliased.Type {
	case alias.AliasTypeForward, alias.AliasTypeCatchAll, alias.AliasTypeRegex:
		return bkd.Relay.Send(context.Background(), envelopeFrom, aliased.Destinations, data)
	default:
		return fmt.Errorf("unsupported alias type %s", aliased.Type)
	}
}

func (bkd *Backend) mirrorBridgeMessage(acc *domain.Account, dom *domain.Domain, bridgeAlias *alias.Alias, envelopeFrom, subject, fromHeader, toHeader string, data []byte) error {
	if len(bridgeAlias.Destinations) == 0 {
		return nil
	}
	accountEmail := accountAddress(acc, dom.Name)
	token := uuid.NewString()
	replyAddr := fmt.Sprintf("%s--ltr-%s@%s", bridgeAlias.Source, token, dom.Name)
	route := &alias.ReplyRoute{
		Token:              token,
		AliasID:            bridgeAlias.ID,
		AccountID:          acc.ID,
		LocalAddress:       accountEmail,
		BridgeDestinations: bridgeAlias.Destinations,
		OriginalFrom:       normalizeAddress(firstHeaderValue(fromHeader, envelopeFrom)),
		OriginalTo:         toHeader,
		OriginalCc:         topLevelHeader(data, "Cc"),
		CreatedAt:          time.Now(),
	}
	if err := bkd.AliasRepo.CreateReplyRoute(route); err != nil {
		return err
	}

	mirrored := buildBridgeMirrorMessage(accountEmail, bridgeAlias.Destinations, replyAddr, route, subject, data)
	bkd.syncRelayRoute(dom)
	return bkd.Relay.Send(context.Background(), accountEmail, bridgeAlias.Destinations, mirrored)
}

func (bkd *Backend) handleBridgeReply(route *alias.ReplyRoute, fallbackSubject string, data []byte) error {
	toRecipients, ccRecipients, subject, outbound := buildBridgeReplyMessage(route, fallbackSubject, data)
	allRecipients := append([]string{}, toRecipients...)
	allRecipients = append(allRecipients, ccRecipients...)
	if len(allRecipients) == 0 {
		allRecipients = append(allRecipients, route.OriginalFrom)
	}
	bkd.syncRelayRouteByAddress(route.LocalAddress)
	if err := bkd.Relay.Send(context.Background(), route.LocalAddress, allRecipients, outbound); err != nil {
		return err
	}

	acc, err := bkd.AccountRepo.GetAccountByID(route.AccountID)
	if err != nil {
		return nil
	}
	msgID := uuid.New()
	storagePath := msgID.String() + ".eml"
	if err := bkd.BlobStorage.Put(storagePath, outbound); err != nil {
		return nil
	}
	now := time.Now()
	sentMsg := &domain.Message{
		ID:          msgID,
		AccountID:   acc.ID,
		Folder:      "Sent",
		SizeBytes:   int64(len(outbound)),
		StoragePath: storagePath,
		Subject:     subject,
		From:        route.LocalAddress,
		To:          strings.Join(toRecipients, ", "),
		ReceivedAt:  now,
		ReadAt:      &now,
	}
	_ = bkd.MessageRepo.CreateMessage(sentMsg)
	return nil
}

func buildBridgeMirrorMessage(accountEmail string, bridgeDestinations []string, replyAddr string, route *alias.ReplyRoute, subject string, original []byte) []byte {
	var body strings.Builder
	body.WriteString("This message was mirrored by lightr mailbox bridge.\r\n\r\n")
	body.WriteString(fmt.Sprintf("Original From: %s\r\n", route.OriginalFrom))
	if route.OriginalTo != "" {
		body.WriteString(fmt.Sprintf("Original To: %s\r\n", route.OriginalTo))
	}
	if route.OriginalCc != "" {
		body.WriteString(fmt.Sprintf("Original Cc: %s\r\n", route.OriginalCc))
	}
	body.WriteString("\r\nReply to this email and lightr will route it back through your mailbox.\r\n\r\n")
	preview := extractMessagePreview(original)
	if preview != "" {
		body.WriteString(preview)
		body.WriteString("\r\n")
	}

	boundary := "ltr-bridge-" + uuid.NewString()[:8]
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("Message-ID: <%s@%s>\r\n", uuid.NewString(), strings.Split(accountEmail, "@")[1]))
	msg.WriteString(fmt.Sprintf("From: %s\r\n", formatBridgeDisplay(route.OriginalFrom, accountEmail)))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", route.OriginalFrom))
	msg.WriteString(fmt.Sprintf("Reply-To: %s\r\n", replyAddr))
	if route.OriginalFrom != "" {
		msg.WriteString(fmt.Sprintf("X-Lightr-Original-From: %s\r\n", route.OriginalFrom))
	}
	if route.OriginalCc != "" {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", route.OriginalCc))
	}
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	msg.WriteString(body.String())
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: message/rfc822; name=\"original.eml\"\r\n")
	msg.WriteString("Content-Disposition: attachment; filename=\"original.eml\"\r\n\r\n")
	msg.Write(original)
	if !bytes.HasSuffix(original, []byte("\r\n")) {
		msg.WriteString("\r\n")
	}
	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	return []byte(msg.String())
}

func buildBridgeReplyMessage(route *alias.ReplyRoute, fallbackSubject string, raw []byte) ([]string, []string, string, []byte) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		subject := firstHeaderValue(fallbackSubject, "Re: bridged message")
		outbound := minimalReplyMessage(route.LocalAddress, []string{route.OriginalFrom}, nil, subject, raw)
		return []string{route.OriginalFrom}, nil, subject, outbound
	}
	body, _ := io.ReadAll(msg.Body)
	subject := firstHeaderValue(msg.Header.Get("Subject"), fallbackSubject, "Re: bridged message")

	filteredTo := filterReplyRecipients(append(parseAddressList(msg.Header.Get("To")), parseAddressList(msg.Header.Get("Cc"))...), route)
	toRecipients := []string{}
	ccRecipients := []string{}
	if len(filteredTo) == 0 {
		toRecipients = append(toRecipients, route.OriginalFrom)
	} else {
		toRecipients = append(toRecipients, filteredTo[0])
		if len(filteredTo) > 1 {
			ccRecipients = append(ccRecipients, filteredTo[1:]...)
		}
	}

	header := make(textproto.MIMEHeader)
	header.Set("Message-ID", fmt.Sprintf("<%s@%s>", uuid.NewString(), strings.Split(route.LocalAddress, "@")[1]))
	header.Set("From", rewriteFromHeaderValue(msg.Header.Get("From"), route.LocalAddress))
	header.Set("To", strings.Join(toRecipients, ", "))
	if len(ccRecipients) > 0 {
		header.Set("Cc", strings.Join(ccRecipients, ", "))
	}
	header.Set("Subject", subject)
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	copyHeaderIfPresent(header, msg.Header, "MIME-Version")
	copyHeaderIfPresent(header, msg.Header, "Content-Type")
	copyHeaderIfPresent(header, msg.Header, "Content-Transfer-Encoding")
	copyHeaderIfPresent(header, msg.Header, "In-Reply-To")
	copyHeaderIfPresent(header, msg.Header, "References")

	var rebuilt bytes.Buffer
	writeHeaders(&rebuilt, header)
	rebuilt.WriteString("\r\n")
	rebuilt.Write(body)
	return toRecipients, ccRecipients, subject, rebuilt.Bytes()
}

func minimalReplyMessage(from string, to, cc []string, subject string, raw []byte) []byte {
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("Message-ID: <%s@%s>\r\n", uuid.NewString(), strings.Split(from, "@")[1]))
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	if len(cc) > 0 {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(cc, ", ")))
	}
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	msg.Write(raw)
	return []byte(msg.String())
}

func filterReplyRecipients(candidates []string, route *alias.ReplyRoute) []string {
	seen := map[string]bool{}
	excluded := map[string]bool{
		strings.ToLower(route.LocalAddress): true,
		strings.ToLower(strings.Split(route.LocalAddress, "@")[0] + "--ltr-" + route.Token + "@" + strings.Split(route.LocalAddress, "@")[1]): true,
	}
	for _, dest := range route.BridgeDestinations {
		excluded[strings.ToLower(strings.TrimSpace(dest))] = true
	}
	var out []string
	for _, candidate := range candidates {
		normalized := strings.ToLower(strings.TrimSpace(candidate))
		if normalized == "" || excluded[normalized] || seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, strings.TrimSpace(candidate))
	}
	return out
}

func parseAddressList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	addrs, err := mail.ParseAddressList(raw)
	if err == nil {
		out := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			out = append(out, addr.Address)
		}
		return out
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if addr, err := mail.ParseAddress(raw); err == nil {
		return addr.Address
	}
	return raw
}

func rewriteFromHeaderValue(rawFrom, fallbackAddress string) string {
	if rawFrom == "" {
		return fallbackAddress
	}
	if addr, err := mail.ParseAddress(rawFrom); err == nil {
		if addr.Name != "" {
			return (&mail.Address{Name: addr.Name, Address: fallbackAddress}).String()
		}
	}
	return fallbackAddress
}

func formatBridgeDisplay(originalFrom, accountEmail string) string {
	if addr, err := mail.ParseAddress(originalFrom); err == nil {
		name := addr.Name
		if name == "" {
			name = addr.Address
		}
		return (&mail.Address{Name: name + " via lightr", Address: accountEmail}).String()
	}
	return (&mail.Address{Name: "Bridged message via lightr", Address: accountEmail}).String()
}

func extractMessagePreview(raw []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return string(raw)
	}
	contentType := strings.ToLower(msg.Header.Get("Content-Type"))
	body, _ := io.ReadAll(msg.Body)
	if strings.Contains(contentType, "multipart/") {
		return "Open the attached original.eml for the full message and attachments."
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 4000 {
		text = text[:4000]
	}
	return text
}

func topLevelHeader(raw []byte, name string) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	return msg.Header.Get(name)
}

func copyHeaderIfPresent(dst textproto.MIMEHeader, src mail.Header, key string) {
	if value := src.Get(key); value != "" {
		dst.Set(key, value)
	}
}

func writeHeaders(buf *bytes.Buffer, header textproto.MIMEHeader) {
	order := []string{"Message-ID", "From", "To", "Cc", "Subject", "Date", "MIME-Version", "Content-Type", "Content-Transfer-Encoding", "In-Reply-To", "References"}
	written := map[string]bool{}
	for _, key := range order {
		if value := header.Get(key); value != "" {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
			written[key] = true
		}
	}
	for key, values := range header {
		if written[key] {
			continue
		}
		for _, value := range values {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		}
	}
}

func accountAddress(acc *domain.Account, domainName string) string {
	if acc.Email != "" {
		return acc.Email
	}
	return acc.LocalPart + "@" + domainName
}

func (bkd *Backend) syncRelayRouteByAddress(email string) {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return
	}
	dom, err := bkd.DomainRepo.GetDomainByName(parts[1])
	if err != nil {
		return
	}
	bkd.syncRelayRoute(dom)
}

func (bkd *Backend) syncRelayRoute(dom *domain.Domain) {
	if bkd.Relay == nil || dom == nil {
		return
	}
	if dom.RelayEnabled && dom.RelayHost != "" {
		bkd.Relay.SetDomainRoute(dom.Name, RelayRoute{
			Host:          dom.RelayHost,
			Port:          dom.RelayPort,
			Username:      dom.RelayUsername,
			Password:      dom.RelayPassword,
			UseTLS:        dom.RelayUseTLS,
			TLSSkipVerify: dom.RelayTLSSkipVerify,
		})
		return
	}
	bkd.Relay.RemoveDomainRoute(dom.Name)
}

func firstHeaderValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// rewriteFromHeader rewrites the From header to include the display name
func (s *Session) rewriteFromHeader(data []byte, displayName, email string) []byte {
	content := string(data)

	// Build the new From header with display name
	newFromHeader := "From: " + formatFromHeaderValue(displayName, email)

	// Find and replace the From header
	// Handle various formats: From: email, From: <email>, From: "Name" <email>
	lines := strings.Split(content, "\r\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "from:") {
			lines[i] = newFromHeader
			log.Printf("Rewrote From header: %s -> %s", line, newFromHeader)
			replaced = true
			break
		}
		// Empty line means end of headers
		if line == "" {
			break
		}
	}
	if !replaced {
		insertAt := len(lines)
		for i, line := range lines {
			if line == "" {
				insertAt = i
				break
			}
		}
		lines = append(lines[:insertAt], append([]string{newFromHeader}, lines[insertAt:]...)...)
	}

	return []byte(strings.Join(lines, "\r\n"))
}

func (s *Session) prepareAuthenticatedMessage(data []byte, displayName, email string) []byte {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return s.injectSubmissionHeaders(s.rewriteFromHeader(data, displayName, email), email)
	}
	body, _ := io.ReadAll(msg.Body)
	header := make(textproto.MIMEHeader)
	for key, values := range msg.Header {
		for _, value := range values {
			header.Add(key, value)
		}
	}
	header.Set("From", formatFromHeaderValue(displayName, email))
	if header.Get("Message-ID") == "" {
		header.Set("Message-ID", fmt.Sprintf("<%s@%s>", uuid.NewString(), strings.Split(email, "@")[1]))
	}
	if header.Get("Date") == "" {
		header.Set("Date", time.Now().Format(time.RFC1123Z))
	}
	if header.Get("MIME-Version") == "" {
		header.Set("MIME-Version", "1.0")
	}
	if header.Get("User-Agent") == "" {
		header.Set("User-Agent", "Lightr SMTP")
	}
	if header.Get("X-Mailer") == "" {
		header.Set("X-Mailer", "Lightr")
	}
	if header.Get("X-Lightr-Mailed-By") == "" {
		header.Set("X-Lightr-Mailed-By", s.outboundHostname(email))
	}

	var rebuilt bytes.Buffer
	writeHeaders(&rebuilt, header)
	rebuilt.WriteString("\r\n")
	rebuilt.Write(body)
	return rebuilt.Bytes()
}

func (s *Session) injectSubmissionHeaders(data []byte, email string) []byte {
	lines := strings.Split(string(data), "\r\n")
	insertAt := len(lines)
	for i, line := range lines {
		if line == "" {
			insertAt = i
			break
		}
	}
	headers := []string{}
	if topLevelHeader(data, "Message-ID") == "" {
		headers = append(headers, fmt.Sprintf("Message-ID: <%s@%s>", uuid.NewString(), strings.Split(email, "@")[1]))
	}
	if topLevelHeader(data, "Date") == "" {
		headers = append(headers, fmt.Sprintf("Date: %s", time.Now().Format(time.RFC1123Z)))
	}
	if topLevelHeader(data, "MIME-Version") == "" {
		headers = append(headers, "MIME-Version: 1.0")
	}
	if topLevelHeader(data, "User-Agent") == "" {
		headers = append(headers, "User-Agent: Lightr SMTP")
	}
	if topLevelHeader(data, "X-Mailer") == "" {
		headers = append(headers, "X-Mailer: Lightr")
	}
	if topLevelHeader(data, "X-Lightr-Mailed-By") == "" {
		headers = append(headers, "X-Lightr-Mailed-By: "+s.outboundHostname(email))
	}
	if len(headers) == 0 {
		return data
	}
	lines = append(lines[:insertAt], append(headers, lines[insertAt:]...)...)
	return []byte(strings.Join(lines, "\r\n"))
}

func (s *Session) outboundHostname(email string) string {
	serverHostname := ""
	if s != nil && s.backend != nil && s.backend.Relay != nil {
		serverHostname = s.backend.Relay.hostname
	}
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		if s != nil && s.backend != nil && s.backend.DomainRepo != nil {
			if dom, err := s.backend.DomainRepo.GetDomainByName(parts[1]); err == nil {
				return domain.EffectiveMailHostname(dom, serverHostname)
			}
		}
		if strings.TrimSpace(serverHostname) != "" {
			return strings.TrimSpace(serverHostname)
		}
		return parts[1]
	}
	return "localhost"
}

func formatFromHeaderValue(displayName, email string) string {
	if strings.TrimSpace(displayName) == "" {
		return email
	}
	safeDisplayName := strings.ReplaceAll(displayName, `"`, `'`)
	return fmt.Sprintf("\"%s\" <%s>", safeDisplayName, email)
}

func normalizeMailboxAddress(address string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(address), "<>"))
}

func (s *Session) Reset() {
	s.account = nil
	s.from = ""
	s.to = nil
}

func (s *Session) Logout() error {
	return nil
}
