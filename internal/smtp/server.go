package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
	"github.com/nigelbasa/lightr/internal/webhook"
)

type Server struct {
	addr      string
	backend   *Backend
	tlsConfig *tls.Config
}

func NewServer(addr string, backend *Backend) *Server {
	return &Server{
		addr:    addr,
		backend: backend,
	}
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
	srv.WriteTimeout = 10 * time.Second
	srv.ReadTimeout = 10 * time.Second
	srv.MaxRecipients = 50

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

type Backend struct {
	AccountRepo    domain.AccountRepository
	DomainRepo     domain.DomainRepository
	BlobStorage    domain.BlobStorage
	MessageRepo    domain.MessageRepository
	AuthService    domain.AuthService
	WebhookService *webhook.Service
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
	if s.account == nil {
		return errors.New("authentication required")
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	// Parse MIME headers
	msg, err := mail.ReadMessage(strings.NewReader(string(data)))
	var subject, from, to string
	if err == nil {
		subject = msg.Header.Get("Subject")
		from = msg.Header.Get("From")
		to = msg.Header.Get("To")
	}

	// Fall back to envelope data if headers missing
	if from == "" {
		from = s.from
	}
	if to == "" && len(s.to) > 0 {
		to = strings.Join(s.to, ", ")
	}

	msgID := uuid.New()
	storagePath := msgID.String() + ".eml"

	// Store blob
	if err := s.backend.BlobStorage.Put(storagePath, data); err != nil {
		return err
	}

	// Store metadata
	domainMsg := &domain.Message{
		ID:          msgID,
		AccountID:   s.account.ID,
		Folder:      "INBOX",
		SizeBytes:   int64(len(data)),
		StoragePath: storagePath,
		Subject:     subject,
		From:        from,
		To:          to,
		ReceivedAt:  time.Now(),
	}

	if err := s.backend.MessageRepo.CreateMessage(domainMsg); err != nil {
		return err
	}

	// Trigger webhook
	dom, err := s.backend.DomainRepo.GetDomainByID(s.account.DomainID)
	if err == nil && dom.WebhookURL != "" {
		s.backend.WebhookService.Trigger(context.Background(), dom.WebhookURL, webhook.EventEmailReceived, domainMsg)
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
