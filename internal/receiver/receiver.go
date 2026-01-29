package receiver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// REST and SMTP receivers for incoming email

// ReceiverType defines the type of receiver
type ReceiverType string

const (
	ReceiverSMTP    ReceiverType = "smtp"
	ReceiverREST    ReceiverType = "rest"
	ReceiverWebhook ReceiverType = "webhook"
)

// InboundEmail represents a received email
type InboundEmail struct {
	ID           uuid.UUID          `json:"id"`
	ReceiverID   uuid.UUID          `json:"receiver_id"`
	ReceiverType ReceiverType       `json:"receiver_type"`
	
	// Envelope
	MailFrom     string             `json:"mail_from"`
	RcptTo       []string           `json:"rcpt_to"`
	
	// Parsed headers
	From         string             `json:"from"`
	To           []string           `json:"to"`
	Cc           []string           `json:"cc,omitempty"`
	Bcc          []string           `json:"bcc,omitempty"`
	Subject      string             `json:"subject"`
	Date         time.Time          `json:"date"`
	MessageID    string             `json:"message_id"`
	InReplyTo    string             `json:"in_reply_to,omitempty"`
	References   []string           `json:"references,omitempty"`
	
	// Content
	TextBody     string             `json:"text_body,omitempty"`
	HTMLBody     string             `json:"html_body,omitempty"`
	Attachments  []Attachment       `json:"attachments,omitempty"`
	RawMessage   []byte             `json:"-"`
	
	// Headers
	Headers      map[string]string  `json:"headers"`
	
	// Authentication results
	SPFResult    string             `json:"spf_result,omitempty"`
	DKIMResult   string             `json:"dkim_result,omitempty"`
	DMARCResult  string             `json:"dmarc_result,omitempty"`
	
	// Spam analysis
	SpamScore    float64            `json:"spam_score"`
	SpamStatus   string             `json:"spam_status"`
	
	// Source info
	RemoteIP     string             `json:"remote_ip"`
	RemoteHost   string             `json:"remote_host,omitempty"`
	TLSVersion   string             `json:"tls_version,omitempty"`
	TLSCipher    string             `json:"tls_cipher,omitempty"`
	
	// Processing
	Status       string             `json:"status"` // pending, processed, rejected, deferred
	Error        string             `json:"error,omitempty"`
	
	ReceivedAt   time.Time          `json:"received_at"`
	ProcessedAt  *time.Time         `json:"processed_at,omitempty"`
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	ContentID   string `json:"content_id,omitempty"`
	Size        int64  `json:"size"`
	Data        []byte `json:"-"`
	URL         string `json:"url,omitempty"` // If stored externally
}

// ReceiverConfig configures a receiver endpoint
type ReceiverConfig struct {
	ID             uuid.UUID          `json:"id"`
	Name           string             `json:"name"`
	Type           ReceiverType       `json:"type"`
	
	// Network
	Address        string             `json:"address"`
	Port           int                `json:"port"`
	
	// TLS
	TLSEnabled     bool               `json:"tls_enabled"`
	TLSCertFile    string             `json:"tls_cert_file,omitempty"`
	TLSKeyFile     string             `json:"tls_key_file,omitempty"`
	TLSMinVersion  string             `json:"tls_min_version,omitempty"`
	
	// SMTP specific
	Hostname       string             `json:"hostname,omitempty"`
	MaxMessageSize int64              `json:"max_message_size"`
	MaxRecipients  int                `json:"max_recipients"`
	RequireAuth    bool               `json:"require_auth"`
	AllowRelay     bool               `json:"allow_relay"`
	
	// REST specific
	APIKeyRequired bool               `json:"api_key_required"`
	RateLimit      int                `json:"rate_limit"` // per minute
	
	// Domains to accept
	AcceptDomains  []string           `json:"accept_domains,omitempty"`
	RejectDomains  []string           `json:"reject_domains,omitempty"`
	
	// Handlers
	OnReceive      string             `json:"on_receive,omitempty"` // webhook URL
	
	Active         bool               `json:"active"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

// SMTPReceiver handles incoming SMTP connections
type SMTPReceiver struct {
	config    *ReceiverConfig
	listener  net.Listener
	tlsConfig *tls.Config
	
	handler   EmailHandler
	logger    Logger
	
	connections sync.WaitGroup
	stopCh      chan struct{}
}

// EmailHandler processes received emails
type EmailHandler interface {
	HandleInbound(ctx context.Context, email *InboundEmail) error
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewSMTPReceiver creates a new SMTP receiver
func NewSMTPReceiver(config *ReceiverConfig, handler EmailHandler, logger Logger) (*SMTPReceiver, error) {
	r := &SMTPReceiver{
		config:  config,
		handler: handler,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
	
	// Set defaults
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = 25 * 1024 * 1024 // 25MB
	}
	if config.MaxRecipients == 0 {
		config.MaxRecipients = 100
	}
	if config.Hostname == "" {
		config.Hostname = "localhost"
	}
	
	// Setup TLS if enabled
	if config.TLSEnabled && config.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS cert: %w", err)
		}
		r.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}
	
	return r, nil
}

// Start starts the SMTP receiver
func (r *SMTPReceiver) Start() error {
	addr := fmt.Sprintf("%s:%d", r.config.Address, r.config.Port)
	
	var err error
	if r.tlsConfig != nil {
		r.listener, err = tls.Listen("tcp", addr, r.tlsConfig)
	} else {
		r.listener, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return err
	}
	
	r.logger.Info("SMTP receiver started", "address", addr)
	
	go r.acceptLoop()
	return nil
}

// Stop stops the SMTP receiver
func (r *SMTPReceiver) Stop() error {
	close(r.stopCh)
	if r.listener != nil {
		r.listener.Close()
	}
	r.connections.Wait()
	return nil
}

func (r *SMTPReceiver) acceptLoop() {
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}
		
		conn, err := r.listener.Accept()
		if err != nil {
			select {
			case <-r.stopCh:
				return
			default:
				r.logger.Error("accept error", "error", err)
				continue
			}
		}
		
		r.connections.Add(1)
		go r.handleConnection(conn)
	}
}

func (r *SMTPReceiver) handleConnection(conn net.Conn) {
	defer r.connections.Done()
	defer conn.Close()
	
	session := &smtpSession{
		conn:     conn,
		receiver: r,
		state:    stateGreeting,
	}
	
	session.run()
}

// SMTP session states
type smtpState int

const (
	stateGreeting smtpState = iota
	stateReady
	stateMail
	stateRcpt
	stateData
	stateQuit
)

type smtpSession struct {
	conn      net.Conn
	receiver  *SMTPReceiver
	reader    *bufio.Reader
	writer    *bufio.Writer
	
	state     smtpState
	
	// Transaction state
	mailFrom  string
	rcptTo    []string
	data      bytes.Buffer
	
	// TLS state
	tls       bool
}

func (s *smtpSession) run() {
	s.reader = bufio.NewReader(s.conn)
	s.writer = bufio.NewWriter(s.conn)
	
	// Send greeting
	s.writeLine("220 %s ESMTP Lightr", s.receiver.config.Hostname)
	s.state = stateReady
	
	for s.state != stateQuit {
		line, err := s.readLine()
		if err != nil {
			return
		}
		
		s.handleCommand(line)
	}
}

func (s *smtpSession) handleCommand(line string) {
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])
	var arg string
	if len(parts) > 1 {
		arg = parts[1]
	}
	
	switch cmd {
	case "HELO":
		s.handleHELO(arg)
	case "EHLO":
		s.handleEHLO(arg)
	case "MAIL":
		s.handleMAIL(arg)
	case "RCPT":
		s.handleRCPT(arg)
	case "DATA":
		s.handleDATA()
	case "RSET":
		s.handleRSET()
	case "NOOP":
		s.writeLine("250 OK")
	case "QUIT":
		s.writeLine("221 Bye")
		s.state = stateQuit
	case "STARTTLS":
		s.handleSTARTTLS()
	case "AUTH":
		s.handleAUTH(arg)
	default:
		s.writeLine("502 Command not implemented")
	}
}

func (s *smtpSession) handleHELO(arg string) {
	s.writeLine("250 %s", s.receiver.config.Hostname)
	s.state = stateReady
}

func (s *smtpSession) handleEHLO(arg string) {
	s.writeLine("250-%s", s.receiver.config.Hostname)
	s.writeLine("250-SIZE %d", s.receiver.config.MaxMessageSize)
	s.writeLine("250-8BITMIME")
	s.writeLine("250-PIPELINING")
	if s.receiver.tlsConfig != nil && !s.tls {
		s.writeLine("250-STARTTLS")
	}
	if s.receiver.config.RequireAuth {
		s.writeLine("250-AUTH PLAIN LOGIN")
	}
	s.writeLine("250 ENHANCEDSTATUSCODES")
	s.state = stateReady
}

func (s *smtpSession) handleMAIL(arg string) {
	if s.state != stateReady {
		s.writeLine("503 Bad sequence of commands")
		return
	}
	
	// Parse MAIL FROM:<address>
	arg = strings.TrimPrefix(strings.ToUpper(arg), "FROM:")
	arg = strings.Trim(arg, "<> ")
	
	// Extract address
	addr, _ := strings.CutPrefix(strings.TrimSpace(arg), "<")
	addr, _, _ = strings.Cut(addr, ">")
	
	s.mailFrom = addr
	s.rcptTo = nil
	s.data.Reset()
	
	s.writeLine("250 2.1.0 OK")
	s.state = stateMail
}

func (s *smtpSession) handleRCPT(arg string) {
	if s.state != stateMail && s.state != stateRcpt {
		s.writeLine("503 Bad sequence of commands")
		return
	}
	
	if len(s.rcptTo) >= s.receiver.config.MaxRecipients {
		s.writeLine("452 4.5.3 Too many recipients")
		return
	}
	
	// Parse RCPT TO:<address>
	arg = strings.TrimPrefix(strings.ToUpper(arg), "TO:")
	arg = strings.Trim(arg, "<> ")
	
	addr, _ := strings.CutPrefix(strings.TrimSpace(arg), "<")
	addr, _, _ = strings.Cut(addr, ">")
	
	// Check if we accept this domain
	if !s.receiver.acceptsDomain(addr) {
		s.writeLine("550 5.1.1 Recipient not accepted")
		return
	}
	
	s.rcptTo = append(s.rcptTo, addr)
	s.writeLine("250 2.1.5 OK")
	s.state = stateRcpt
}

func (s *smtpSession) handleDATA() {
	if s.state != stateRcpt || len(s.rcptTo) == 0 {
		s.writeLine("503 Bad sequence of commands")
		return
	}
	
	s.writeLine("354 Start mail input; end with <CRLF>.<CRLF>")
	
	// Read data until terminator
	for {
		line, err := s.readLine()
		if err != nil {
			return
		}
		
		if line == "." {
			break
		}
		
		// Remove dot-stuffing
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		
		// Check size
		if int64(s.data.Len()+len(line)+2) > s.receiver.config.MaxMessageSize {
			s.writeLine("552 5.3.4 Message too big")
			s.state = stateReady
			return
		}
		
		s.data.WriteString(line)
		s.data.WriteString("\r\n")
	}
	
	// Process the email
	if err := s.processEmail(); err != nil {
		s.receiver.logger.Error("failed to process email", "error", err)
		s.writeLine("451 4.3.0 Temporary failure")
	} else {
		s.writeLine("250 2.0.0 OK")
	}
	
	s.state = stateReady
}

func (s *smtpSession) processEmail() error {
	// Parse the email
	msg, err := mail.ReadMessage(bytes.NewReader(s.data.Bytes()))
	if err != nil {
		return err
	}
	
	// Build inbound email
	remoteAddr := s.conn.RemoteAddr().(*net.TCPAddr)
	
	email := &InboundEmail{
		ID:           uuid.New(),
		ReceiverID:   s.receiver.config.ID,
		ReceiverType: ReceiverSMTP,
		MailFrom:     s.mailFrom,
		RcptTo:       s.rcptTo,
		Headers:      make(map[string]string),
		RawMessage:   s.data.Bytes(),
		RemoteIP:     remoteAddr.IP.String(),
		Status:       "pending",
		ReceivedAt:   time.Now(),
	}
	
	// Extract headers
	for key, values := range msg.Header {
		email.Headers[key] = strings.Join(values, ", ")
	}
	
	email.From = msg.Header.Get("From")
	email.Subject = msg.Header.Get("Subject")
	email.MessageID = msg.Header.Get("Message-ID")
	email.InReplyTo = msg.Header.Get("In-Reply-To")
	
	// Parse To
	if toAddrs, err := msg.Header.AddressList("To"); err == nil {
		for _, addr := range toAddrs {
			email.To = append(email.To, addr.Address)
		}
	}
	
	// Parse Cc
	if ccAddrs, err := msg.Header.AddressList("Cc"); err == nil {
		for _, addr := range ccAddrs {
			email.Cc = append(email.Cc, addr.Address)
		}
	}
	
	// Parse date
	if date, err := msg.Header.Date(); err == nil {
		email.Date = date
	} else {
		email.Date = time.Now()
	}
	
	// Read body
	body, _ := io.ReadAll(msg.Body)
	email.TextBody = string(body) // Simplified - would need MIME parsing
	
	// TLS info
	if s.tls {
		if tlsConn, ok := s.conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			email.TLSVersion = tlsVersionString(state.Version)
			email.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
		}
	}
	
	// Handle the email
	return s.receiver.handler.HandleInbound(context.Background(), email)
}

func (s *smtpSession) handleRSET() {
	s.mailFrom = ""
	s.rcptTo = nil
	s.data.Reset()
	s.writeLine("250 OK")
	s.state = stateReady
}

func (s *smtpSession) handleSTARTTLS() {
	if s.tls || s.receiver.tlsConfig == nil {
		s.writeLine("503 TLS not available")
		return
	}
	
	s.writeLine("220 Ready to start TLS")
	
	tlsConn := tls.Server(s.conn, s.receiver.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		s.receiver.logger.Error("TLS handshake failed", "error", err)
		return
	}
	
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.tls = true
	s.state = stateReady
}

func (s *smtpSession) handleAUTH(arg string) {
	// Simplified AUTH - would need proper implementation
	s.writeLine("235 2.7.0 Authentication successful")
}

func (s *smtpSession) readLine() (string, error) {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (s *smtpSession) writeLine(format string, args ...interface{}) {
	fmt.Fprintf(s.writer, format+"\r\n", args...)
	s.writer.Flush()
}

func (r *SMTPReceiver) acceptsDomain(addr string) bool {
	parts := strings.Split(addr, "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])
	
	// Check reject list first
	for _, d := range r.config.RejectDomains {
		if strings.ToLower(d) == domain {
			return false
		}
	}
	
	// If accept list is empty, accept all
	if len(r.config.AcceptDomains) == 0 {
		return true
	}
	
	// Check accept list
	for _, d := range r.config.AcceptDomains {
		if strings.ToLower(d) == domain {
			return true
		}
	}
	
	return false
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

// RESTReceiver handles incoming REST API requests
type RESTReceiver struct {
	config   *ReceiverConfig
	handler  EmailHandler
	server   *http.Server
	logger   Logger
}

// NewRESTReceiver creates a new REST receiver
func NewRESTReceiver(config *ReceiverConfig, handler EmailHandler, logger Logger) *RESTReceiver {
	return &RESTReceiver{
		config:  config,
		handler: handler,
		logger:  logger,
	}
}

// Start starts the REST receiver
func (r *RESTReceiver) Start() error {
	mux := http.NewServeMux()
	
	// Mount endpoints
	mux.HandleFunc("POST /v1/inbound", r.handleInbound)
	mux.HandleFunc("POST /v1/inbound/mime", r.handleInboundMIME)
	mux.HandleFunc("GET /v1/health", r.handleHealth)
	
	addr := fmt.Sprintf("%s:%d", r.config.Address, r.config.Port)
	
	r.server = &http.Server{
		Addr:         addr,
		Handler:      r.middleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	r.logger.Info("REST receiver started", "address", addr)
	
	go func() {
		var err error
		if r.config.TLSEnabled {
			err = r.server.ListenAndServeTLS(r.config.TLSCertFile, r.config.TLSKeyFile)
		} else {
			err = r.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			r.logger.Error("REST receiver error", "error", err)
		}
	}()
	
	return nil
}

// Stop stops the REST receiver
func (r *RESTReceiver) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return r.server.Shutdown(ctx)
}

func (r *RESTReceiver) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// API key validation
		if r.config.APIKeyRequired {
			apiKey := req.Header.Get("X-API-Key")
			if apiKey == "" {
				apiKey = req.Header.Get("Authorization")
				apiKey = strings.TrimPrefix(apiKey, "Bearer ")
			}
			
			if apiKey == "" {
				http.Error(w, "API key required", http.StatusUnauthorized)
				return
			}
			
			// Would validate API key here
		}
		
		next.ServeHTTP(w, req)
	})
}

// InboundRequest is the JSON payload for inbound emails
type InboundRequest struct {
	From        string            `json:"from"`
	To          []string          `json:"to"`
	Cc          []string          `json:"cc,omitempty"`
	Subject     string            `json:"subject"`
	TextBody    string            `json:"text_body,omitempty"`
	HTMLBody    string            `json:"html_body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Attachments []AttachmentReq   `json:"attachments,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type AttachmentReq struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     string `json:"content"` // base64 encoded
}

func (r *RESTReceiver) handleInbound(w http.ResponseWriter, req *http.Request) {
	var inReq InboundRequest
	if err := json.NewDecoder(req.Body).Decode(&inReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	// Build inbound email
	email := &InboundEmail{
		ID:           uuid.New(),
		ReceiverID:   r.config.ID,
		ReceiverType: ReceiverREST,
		From:         inReq.From,
		To:           inReq.To,
		Cc:           inReq.Cc,
		Subject:      inReq.Subject,
		TextBody:     inReq.TextBody,
		HTMLBody:     inReq.HTMLBody,
		Headers:      inReq.Headers,
		MailFrom:     inReq.From,
		RcptTo:       inReq.To,
		Date:         time.Now(),
		MessageID:    fmt.Sprintf("<%s@%s>", uuid.New().String(), r.config.Hostname),
		RemoteIP:     getClientIP(req),
		Status:       "pending",
		ReceivedAt:   time.Now(),
	}
	
	// Handle email
	if err := r.handler.HandleInbound(req.Context(), email); err != nil {
		r.logger.Error("failed to handle inbound email", "error", err)
		http.Error(w, "Processing failed", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":     email.ID.String(),
		"status": "accepted",
	})
}

func (r *RESTReceiver) handleInboundMIME(w http.ResponseWriter, req *http.Request) {
	// Read raw MIME message
	body, err := io.ReadAll(io.LimitReader(req.Body, r.config.MaxMessageSize))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	// Parse MIME
	msg, err := mail.ReadMessage(bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Invalid MIME message", http.StatusBadRequest)
		return
	}
	
	email := &InboundEmail{
		ID:           uuid.New(),
		ReceiverID:   r.config.ID,
		ReceiverType: ReceiverREST,
		RawMessage:   body,
		Headers:      make(map[string]string),
		RemoteIP:     getClientIP(req),
		Status:       "pending",
		ReceivedAt:   time.Now(),
	}
	
	// Extract headers
	for key, values := range msg.Header {
		email.Headers[key] = strings.Join(values, ", ")
	}
	
	email.From = msg.Header.Get("From")
	email.Subject = msg.Header.Get("Subject")
	email.MessageID = msg.Header.Get("Message-ID")
	
	if toAddrs, err := msg.Header.AddressList("To"); err == nil {
		for _, addr := range toAddrs {
			email.To = append(email.To, addr.Address)
			email.RcptTo = append(email.RcptTo, addr.Address)
		}
	}
	
	if fromAddrs, err := msg.Header.AddressList("From"); err == nil && len(fromAddrs) > 0 {
		email.MailFrom = fromAddrs[0].Address
	}
	
	if date, err := msg.Header.Date(); err == nil {
		email.Date = date
	}
	
	// Read body
	bodyContent, _ := io.ReadAll(msg.Body)
	email.TextBody = string(bodyContent)
	
	// Handle email
	if err := r.handler.HandleInbound(req.Context(), email); err != nil {
		http.Error(w, "Processing failed", http.StatusInternalServerError)
		return
	}
	
	json.NewEncoder(w).Encode(map[string]string{
		"id":     email.ID.String(),
		"status": "accepted",
	})
}

func (r *RESTReceiver) handleHealth(w http.ResponseWriter, req *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}

// ReceiverManager manages multiple receivers
type ReceiverManager struct {
	repo      ReceiverRepository
	receivers map[uuid.UUID]interface{} // SMTPReceiver or RESTReceiver
	handler   EmailHandler
	logger    Logger
	mu        sync.RWMutex
}

// ReceiverRepository defines storage operations
type ReceiverRepository interface {
	Create(ctx context.Context, config *ReceiverConfig) error
	Get(ctx context.Context, id uuid.UUID) (*ReceiverConfig, error)
	List(ctx context.Context) ([]*ReceiverConfig, error)
	Update(ctx context.Context, config *ReceiverConfig) error
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Inbound emails
	SaveInbound(ctx context.Context, email *InboundEmail) error
	GetInbound(ctx context.Context, id uuid.UUID) (*InboundEmail, error)
	ListInbound(ctx context.Context, limit, offset int) ([]*InboundEmail, error)
	UpdateInboundStatus(ctx context.Context, id uuid.UUID, status string) error
}

// NewReceiverManager creates a new receiver manager
func NewReceiverManager(repo ReceiverRepository, handler EmailHandler, logger Logger) *ReceiverManager {
	return &ReceiverManager{
		repo:      repo,
		receivers: make(map[uuid.UUID]interface{}),
		handler:   handler,
		logger:    logger,
	}
}

// Start starts all configured receivers
func (m *ReceiverManager) Start(ctx context.Context) error {
	configs, err := m.repo.List(ctx)
	if err != nil {
		return err
	}
	
	for _, config := range configs {
		if !config.Active {
			continue
		}
		
		if err := m.startReceiver(config); err != nil {
			m.logger.Error("failed to start receiver", "id", config.ID, "error", err)
		}
	}
	
	return nil
}

// Stop stops all receivers
func (m *ReceiverManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for id, receiver := range m.receivers {
		switch r := receiver.(type) {
		case *SMTPReceiver:
			r.Stop()
		case *RESTReceiver:
			r.Stop()
		}
		delete(m.receivers, id)
	}
}

func (m *ReceiverManager) startReceiver(config *ReceiverConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	switch config.Type {
	case ReceiverSMTP:
		receiver, err := NewSMTPReceiver(config, m.handler, m.logger)
		if err != nil {
			return err
		}
		if err := receiver.Start(); err != nil {
			return err
		}
		m.receivers[config.ID] = receiver
		
	case ReceiverREST:
		receiver := NewRESTReceiver(config, m.handler, m.logger)
		if err := receiver.Start(); err != nil {
			return err
		}
		m.receivers[config.ID] = receiver
	}
	
	return nil
}

// SQLite Repository Implementation

type SQLiteReceiverRepository struct {
	db *sql.DB
}

func NewSQLiteReceiverRepository(db *sql.DB) (*SQLiteReceiverRepository, error) {
	repo := &SQLiteReceiverRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteReceiverRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS receiver_configs (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			address TEXT NOT NULL,
			port INTEGER NOT NULL,
			tls_enabled INTEGER DEFAULT 0,
			tls_cert_file TEXT,
			tls_key_file TEXT,
			hostname TEXT,
			max_message_size INTEGER DEFAULT 26214400,
			max_recipients INTEGER DEFAULT 100,
			require_auth INTEGER DEFAULT 0,
			allow_relay INTEGER DEFAULT 0,
			api_key_required INTEGER DEFAULT 0,
			rate_limit INTEGER DEFAULT 1000,
			accept_domains TEXT,
			reject_domains TEXT,
			on_receive TEXT,
			active INTEGER DEFAULT 1,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		
		`CREATE TABLE IF NOT EXISTS inbound_emails (
			id TEXT PRIMARY KEY,
			receiver_id TEXT NOT NULL,
			receiver_type TEXT NOT NULL,
			mail_from TEXT,
			rcpt_to TEXT,
			from_addr TEXT,
			to_addrs TEXT,
			cc_addrs TEXT,
			subject TEXT,
			date DATETIME,
			message_id TEXT,
			in_reply_to TEXT,
			text_body TEXT,
			html_body TEXT,
			headers TEXT,
			spf_result TEXT,
			dkim_result TEXT,
			dmarc_result TEXT,
			spam_score REAL DEFAULT 0,
			spam_status TEXT,
			remote_ip TEXT,
			remote_host TEXT,
			tls_version TEXT,
			tls_cipher TEXT,
			status TEXT NOT NULL,
			error TEXT,
			received_at DATETIME NOT NULL,
			processed_at DATETIME,
			FOREIGN KEY (receiver_id) REFERENCES receiver_configs(id)
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_inbound_receiver ON inbound_emails(receiver_id)`,
		`CREATE INDEX IF NOT EXISTS idx_inbound_status ON inbound_emails(status)`,
		`CREATE INDEX IF NOT EXISTS idx_inbound_received ON inbound_emails(received_at)`,
	}
	
	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteReceiverRepository) Create(ctx context.Context, config *ReceiverConfig) error {
	acceptJSON, _ := json.Marshal(config.AcceptDomains)
	rejectJSON, _ := json.Marshal(config.RejectDomains)
	
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO receiver_configs (id, name, type, address, port, tls_enabled, tls_cert_file,
			tls_key_file, hostname, max_message_size, max_recipients, require_auth, allow_relay,
			api_key_required, rate_limit, accept_domains, reject_domains, on_receive, active,
			created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		config.ID.String(), config.Name, string(config.Type), config.Address, config.Port,
		config.TLSEnabled, config.TLSCertFile, config.TLSKeyFile, config.Hostname,
		config.MaxMessageSize, config.MaxRecipients, config.RequireAuth, config.AllowRelay,
		config.APIKeyRequired, config.RateLimit, string(acceptJSON), string(rejectJSON),
		config.OnReceive, config.Active, config.CreatedAt, config.UpdatedAt)
	
	return err
}

func (r *SQLiteReceiverRepository) Get(ctx context.Context, id uuid.UUID) (*ReceiverConfig, error) {
	var config ReceiverConfig
	var idStr, recType string
	var acceptJSON, rejectJSON string
	
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, type, address, port, tls_enabled, tls_cert_file, tls_key_file,
			hostname, max_message_size, max_recipients, require_auth, allow_relay,
			api_key_required, rate_limit, accept_domains, reject_domains, on_receive,
			active, created_at, updated_at
		FROM receiver_configs WHERE id = ?`, id.String()).Scan(
		&idStr, &config.Name, &recType, &config.Address, &config.Port,
		&config.TLSEnabled, &config.TLSCertFile, &config.TLSKeyFile, &config.Hostname,
		&config.MaxMessageSize, &config.MaxRecipients, &config.RequireAuth, &config.AllowRelay,
		&config.APIKeyRequired, &config.RateLimit, &acceptJSON, &rejectJSON,
		&config.OnReceive, &config.Active, &config.CreatedAt, &config.UpdatedAt)
	if err != nil {
		return nil, err
	}
	
	config.ID, _ = uuid.Parse(idStr)
	config.Type = ReceiverType(recType)
	json.Unmarshal([]byte(acceptJSON), &config.AcceptDomains)
	json.Unmarshal([]byte(rejectJSON), &config.RejectDomains)
	
	return &config, nil
}

func (r *SQLiteReceiverRepository) List(ctx context.Context) ([]*ReceiverConfig, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, type, address, port, tls_enabled, tls_cert_file, tls_key_file,
			hostname, max_message_size, max_recipients, require_auth, allow_relay,
			api_key_required, rate_limit, accept_domains, reject_domains, on_receive,
			active, created_at, updated_at
		FROM receiver_configs ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var configs []*ReceiverConfig
	for rows.Next() {
		var config ReceiverConfig
		var idStr, recType string
		var acceptJSON, rejectJSON string
		
		err := rows.Scan(&idStr, &config.Name, &recType, &config.Address, &config.Port,
			&config.TLSEnabled, &config.TLSCertFile, &config.TLSKeyFile, &config.Hostname,
			&config.MaxMessageSize, &config.MaxRecipients, &config.RequireAuth, &config.AllowRelay,
			&config.APIKeyRequired, &config.RateLimit, &acceptJSON, &rejectJSON,
			&config.OnReceive, &config.Active, &config.CreatedAt, &config.UpdatedAt)
		if err != nil {
			return nil, err
		}
		
		config.ID, _ = uuid.Parse(idStr)
		config.Type = ReceiverType(recType)
		json.Unmarshal([]byte(acceptJSON), &config.AcceptDomains)
		json.Unmarshal([]byte(rejectJSON), &config.RejectDomains)
		
		configs = append(configs, &config)
	}
	
	return configs, rows.Err()
}

func (r *SQLiteReceiverRepository) Update(ctx context.Context, config *ReceiverConfig) error {
	acceptJSON, _ := json.Marshal(config.AcceptDomains)
	rejectJSON, _ := json.Marshal(config.RejectDomains)
	
	_, err := r.db.ExecContext(ctx, `
		UPDATE receiver_configs SET
			name = ?, type = ?, address = ?, port = ?, tls_enabled = ?, tls_cert_file = ?,
			tls_key_file = ?, hostname = ?, max_message_size = ?, max_recipients = ?,
			require_auth = ?, allow_relay = ?, api_key_required = ?, rate_limit = ?,
			accept_domains = ?, reject_domains = ?, on_receive = ?, active = ?, updated_at = ?
		WHERE id = ?`,
		config.Name, string(config.Type), config.Address, config.Port, config.TLSEnabled,
		config.TLSCertFile, config.TLSKeyFile, config.Hostname, config.MaxMessageSize,
		config.MaxRecipients, config.RequireAuth, config.AllowRelay, config.APIKeyRequired,
		config.RateLimit, string(acceptJSON), string(rejectJSON), config.OnReceive,
		config.Active, config.UpdatedAt, config.ID.String())
	
	return err
}

func (r *SQLiteReceiverRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM receiver_configs WHERE id = ?", id.String())
	return err
}

func (r *SQLiteReceiverRepository) SaveInbound(ctx context.Context, email *InboundEmail) error {
	rcptJSON, _ := json.Marshal(email.RcptTo)
	toJSON, _ := json.Marshal(email.To)
	ccJSON, _ := json.Marshal(email.Cc)
	headersJSON, _ := json.Marshal(email.Headers)
	
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO inbound_emails (id, receiver_id, receiver_type, mail_from, rcpt_to,
			from_addr, to_addrs, cc_addrs, subject, date, message_id, in_reply_to,
			text_body, html_body, headers, spf_result, dkim_result, dmarc_result,
			spam_score, spam_status, remote_ip, remote_host, tls_version, tls_cipher,
			status, error, received_at, processed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		email.ID.String(), email.ReceiverID.String(), string(email.ReceiverType),
		email.MailFrom, string(rcptJSON), email.From, string(toJSON), string(ccJSON),
		email.Subject, email.Date, email.MessageID, email.InReplyTo, email.TextBody,
		email.HTMLBody, string(headersJSON), email.SPFResult, email.DKIMResult,
		email.DMARCResult, email.SpamScore, email.SpamStatus, email.RemoteIP,
		email.RemoteHost, email.TLSVersion, email.TLSCipher, email.Status,
		email.Error, email.ReceivedAt, email.ProcessedAt)
	
	return err
}

func (r *SQLiteReceiverRepository) GetInbound(ctx context.Context, id uuid.UUID) (*InboundEmail, error) {
	var email InboundEmail
	var idStr, receiverStr, recType string
	var rcptJSON, toJSON, ccJSON, headersJSON string
	
	err := r.db.QueryRowContext(ctx, `
		SELECT id, receiver_id, receiver_type, mail_from, rcpt_to, from_addr, to_addrs,
			cc_addrs, subject, date, message_id, in_reply_to, text_body, html_body,
			headers, spf_result, dkim_result, dmarc_result, spam_score, spam_status,
			remote_ip, remote_host, tls_version, tls_cipher, status, error,
			received_at, processed_at
		FROM inbound_emails WHERE id = ?`, id.String()).Scan(
		&idStr, &receiverStr, &recType, &email.MailFrom, &rcptJSON, &email.From,
		&toJSON, &ccJSON, &email.Subject, &email.Date, &email.MessageID, &email.InReplyTo,
		&email.TextBody, &email.HTMLBody, &headersJSON, &email.SPFResult, &email.DKIMResult,
		&email.DMARCResult, &email.SpamScore, &email.SpamStatus, &email.RemoteIP,
		&email.RemoteHost, &email.TLSVersion, &email.TLSCipher, &email.Status,
		&email.Error, &email.ReceivedAt, &email.ProcessedAt)
	if err != nil {
		return nil, err
	}
	
	email.ID, _ = uuid.Parse(idStr)
	email.ReceiverID, _ = uuid.Parse(receiverStr)
	email.ReceiverType = ReceiverType(recType)
	json.Unmarshal([]byte(rcptJSON), &email.RcptTo)
	json.Unmarshal([]byte(toJSON), &email.To)
	json.Unmarshal([]byte(ccJSON), &email.Cc)
	json.Unmarshal([]byte(headersJSON), &email.Headers)
	
	return &email, nil
}

func (r *SQLiteReceiverRepository) ListInbound(ctx context.Context, limit, offset int) ([]*InboundEmail, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, receiver_id, receiver_type, mail_from, from_addr, subject, date,
			status, spam_score, remote_ip, received_at
		FROM inbound_emails ORDER BY received_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var emails []*InboundEmail
	for rows.Next() {
		var email InboundEmail
		var idStr, receiverStr, recType string
		
		err := rows.Scan(&idStr, &receiverStr, &recType, &email.MailFrom, &email.From,
			&email.Subject, &email.Date, &email.Status, &email.SpamScore, &email.RemoteIP,
			&email.ReceivedAt)
		if err != nil {
			return nil, err
		}
		
		email.ID, _ = uuid.Parse(idStr)
		email.ReceiverID, _ = uuid.Parse(receiverStr)
		email.ReceiverType = ReceiverType(recType)
		
		emails = append(emails, &email)
	}
	
	return emails, rows.Err()
}

func (r *SQLiteReceiverRepository) UpdateInboundStatus(ctx context.Context, id uuid.UUID, status string) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx,
		"UPDATE inbound_emails SET status = ?, processed_at = ? WHERE id = ?",
		status, now, id.String())
	return err
}
