package smtp

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
	imapbackend "github.com/nigelbasa/lightr/internal/imap"
	"github.com/nigelbasa/lightr/internal/webhook"
)

type Server struct {
	addr           string
	submissionAddr string
	backend        *Backend
	tlsConfig      *tls.Config
}

func NewServer(addr string, backend *Backend) *Server {
	return &Server{
		addr:    addr,
		backend: backend,
	}
}

// WithSubmissionAddr sets the submission port (587)
func (s *Server) WithSubmissionAddr(addr string) {
	s.submissionAddr = addr
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

func (s *Server) Start() error {
	srv := smtp.NewServer(s.backend)
	srv.Addr = s.addr
	srv.Domain = "localhost"
	srv.WriteTimeout = 5 * time.Minute  // Allow 5 minutes for large attachments
	srv.ReadTimeout = 5 * time.Minute   // Allow 5 minutes for large attachments
	srv.MaxRecipients = 50
	srv.MaxMessageBytes = 50 * 1024 * 1024 // 50MB max message size

	if s.tlsConfig != nil {
		srv.TLSConfig = s.tlsConfig
		srv.AllowInsecureAuth = false
		log.Printf("Starting SMTP server at %s with STARTTLS", s.addr)
	} else {
		srv.AllowInsecureAuth = true
		log.Printf("Starting SMTP server at %s (insecure)", s.addr)
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
	srv.Domain = "localhost"
	srv.WriteTimeout = 5 * time.Minute  // Allow 5 minutes for large attachments
	srv.ReadTimeout = 5 * time.Minute   // Allow 5 minutes for large attachments
	srv.MaxRecipients = 50
	srv.MaxMessageBytes = 50 * 1024 * 1024 // 50MB max message size

	if s.tlsConfig != nil {
		srv.TLSConfig = s.tlsConfig
		srv.AllowInsecureAuth = false
		log.Printf("Starting SMTP submission server at %s with STARTTLS", s.submissionAddr)
	} else {
		srv.AllowInsecureAuth = true
		log.Printf("Starting SMTP submission server at %s (insecure)", s.submissionAddr)
	}

	return srv.ListenAndServe()
}

type Backend struct {
	AccountRepo    domain.AccountRepository
	DomainRepo     domain.DomainRepository
	BlobStorage    domain.BlobStorage
	MessageRepo    domain.MessageRepository
	AuthService    domain.AuthService
	WebhookService *webhook.Service
	Relay          *Relay
}

func (bkd *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{backend: bkd}, nil
}

type Session struct {
	backend *Backend
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
	return sasl.NewPlainServer(func(identity, username, password string) error {
		acc, err := s.backend.AuthService.Authenticate(context.Background(), username, password)
		if err != nil {
			return smtp.ErrAuthFailed
		}
		s.account = acc
		return nil
	}), nil
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
	s.from = from
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
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
		// Outgoing mail - queue for external delivery
		for _, rcpt := range s.to {
			if err := s.backend.Relay.Send(context.Background(), s.from, []string{rcpt}, data); err != nil {
				log.Printf("Failed to queue mail to %s: %v", rcpt, err)
			}
		}
		return nil
	}

	// Incoming mail - deliver to local recipients
	for _, rcpt := range s.to {
		// Parse recipient email to find local account
		parts := strings.SplitN(rcpt, "@", 2)
		if len(parts) != 2 {
			continue
		}
		localPart := parts[0]
		domainName := parts[1]

		// Look up the domain
		dom, err := s.backend.DomainRepo.GetDomainByName(domainName)
		if err != nil {
			log.Printf("Domain not found for %s: %v", rcpt, err)
			continue
		}

		// Look up the account
		acc, err := s.backend.AccountRepo.GetAccountByLocalPart(dom.ID, localPart)
		if err != nil {
			log.Printf("Account not found for %s: %v", rcpt, err)
			continue
		}

		// Store the message for this recipient
		msgID := uuid.New()
		storagePath := msgID.String() + ".eml"

		if err := s.backend.BlobStorage.Put(storagePath, data); err != nil {
			log.Printf("Failed to store blob for %s: %v", rcpt, err)
			continue
		}

		domainMsg := &domain.Message{
			ID:          msgID,
			AccountID:   acc.ID,
			Folder:      "INBOX",
			SizeBytes:   int64(len(data)),
			StoragePath: storagePath,
			Subject:     subject,
			From:        fromHeader,
			To:          toHeader,
			ReceivedAt:  time.Now(),
		}

		if err := s.backend.MessageRepo.CreateMessage(domainMsg); err != nil {
			log.Printf("Failed to create message for %s: %v", rcpt, err)
			continue
		}

		// Notify IDLE sessions about new mail
		msgs, _ := s.backend.MessageRepo.ListByAccount(acc.ID, "INBOX")
		imapbackend.GetIdleNotifier().NotifyNewMail(acc.ID, uint32(len(msgs)))

		// Trigger webhook
		if dom.WebhookURL != "" {
			s.backend.WebhookService.Trigger(context.Background(), dom.WebhookURL, webhook.EventEmailReceived, domainMsg)
		}

		log.Printf("Delivered mail from %s to %s", s.from, rcpt)
	}

	return nil
}

func (s *Session) Reset() {
	s.account = nil
	s.from = ""
	s.to = nil
}

func (s *Session) Logout() error {
	return nil
}
