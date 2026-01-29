package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

// Backend provides the session factory for IMAP connections
type Backend struct {
	AccountRepo domain.AccountRepository
	DomainRepo  domain.DomainRepository
	MessageRepo domain.MessageRepository
	BlobStorage domain.BlobStorage
	AuthService domain.AuthService
}

// NewSession creates a new IMAP session for an incoming connection
func (bkd *Backend) NewSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	return &Session{
		backend:  bkd,
		conn:     conn,
		selected: "",
	}, nil, nil
}

// Session implements imapserver.Session
type Session struct {
	backend  *Backend
	conn     *imapserver.Conn
	account  *domain.Account
	domainID uuid.UUID
	selected string
	mu       sync.Mutex
}

func (s *Session) Close() error {
	return nil
}

func (s *Session) Login(username, password string) error {
	acc, err := s.backend.AuthService.Authenticate(context.Background(), username, password)
	if err != nil {
		return imapserver.ErrAuthFailed
	}
	s.account = acc
	s.domainID = acc.DomainID
	return nil
}

func (s *Session) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	if s.account == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	s.mu.Lock()
	s.selected = mailbox
	s.mu.Unlock()

	msgs, err := s.backend.MessageRepo.ListByAccount(s.account.ID, mailbox)
	if err != nil {
		return nil, err
	}

	numMessages := uint32(len(msgs))
	var uidNext imap.UID = 1
	if numMessages > 0 {
		uidNext = imap.UID(numMessages + 1)
	}

	return &imap.SelectData{
		Flags:          []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft},
		PermanentFlags: []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft, "\\*"},
		NumMessages:    numMessages,
		UIDNext:        uidNext,
		UIDValidity:    1,
	}, nil
}

func (s *Session) Create(mailbox string, options *imap.CreateOptions) error {
	// Folders are implicit based on message storage - just accept
	return nil
}

func (s *Session) Delete(mailbox string) error {
	return nil
}

func (s *Session) Rename(mailbox, newName string, options *imap.RenameOptions) error {
	return nil
}

func (s *Session) Subscribe(mailbox string) error {
	return nil
}

func (s *Session) Unsubscribe(mailbox string) error {
	return nil
}

func (s *Session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	// Standard mailboxes
	mailboxes := []string{"INBOX", "Sent", "Drafts", "Trash", "Junk"}

	for _, mb := range mailboxes {
		match := false
		for _, pattern := range patterns {
			if matchMailbox(mb, ref, pattern) {
				match = true
				break
			}
		}
		if !match && len(patterns) > 0 {
			continue
		}

		data := &imap.ListData{
			Mailbox: mb,
			Delim:   '/',
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
	}
	return nil
}

func matchMailbox(name, ref, pattern string) bool {
	full := ref + pattern
	if full == "*" || full == "%" {
		return true
	}
	if strings.Contains(full, "*") {
		prefix := strings.Split(full, "*")[0]
		return strings.HasPrefix(name, prefix)
	}
	if strings.Contains(full, "%") {
		prefix := strings.Split(full, "%")[0]
		return strings.HasPrefix(name, prefix) && !strings.Contains(name[len(prefix):], "/")
	}
	return name == full
}

func (s *Session) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if s.account == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	msgs, err := s.backend.MessageRepo.ListByAccount(s.account.ID, mailbox)
	if err != nil {
		return nil, err
	}

	numMessages := uint32(len(msgs))
	unseen := uint32(0)
	for _, msg := range msgs {
		if msg.ReadAt == nil {
			unseen++
		}
	}

	var uidNext imap.UID = 1
	if numMessages > 0 {
		uidNext = imap.UID(numMessages + 1)
	}

	return &imap.StatusData{
		Mailbox:     mailbox,
		NumMessages: &numMessages,
		UIDNext:     uidNext,
		UIDValidity: 1,
		NumUnseen:   &unseen,
	}, nil
}

func (s *Session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	if s.account == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	// Read the message content
	data := make([]byte, r.Size())
	if _, err := r.Read(data); err != nil {
		return nil, err
	}

	msgID := uuid.New()
	storagePath := fmt.Sprintf("%s/%s/%s.eml", s.account.ID, mailbox, msgID)

	if err := s.backend.BlobStorage.Put(storagePath, data); err != nil {
		return nil, err
	}

	msg := &domain.Message{
		ID:          msgID,
		AccountID:   s.account.ID,
		Folder:      mailbox,
		SizeBytes:   int64(len(data)),
		StoragePath: storagePath,
		Subject:     "", // Would need to parse from data
		From:        "",
		To:          "",
		ReceivedAt:  time.Now(),
	}

	if err := s.backend.MessageRepo.CreateMessage(msg); err != nil {
		return nil, err
	}

	return &imap.AppendData{
		UID:         1, // Simplified
		UIDValidity: 1,
	}, nil
}

func (s *Session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	return nil
}

func (s *Session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	<-stop
	return nil
}

func (s *Session) Unselect() error {
	s.mu.Lock()
	s.selected = ""
	s.mu.Unlock()
	return nil
}

func (s *Session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	// Mark messages as deleted in DB
	return nil
}

func (s *Session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	if s.account == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	s.mu.Lock()
	mailbox := s.selected
	s.mu.Unlock()

	if mailbox == "" {
		return nil, fmt.Errorf("no mailbox selected")
	}

	msgs, err := s.backend.MessageRepo.ListByAccount(s.account.ID, mailbox)
	if err != nil {
		return nil, err
	}

	// Simple search - return all message UIDs
	var uids []imap.UID
	for i := range msgs {
		uids = append(uids, imap.UID(i+1))
	}

	uidSet := imap.UIDSetNum(uids...)
	return &imap.SearchData{
		All: uidSet,
	}, nil
}

func (s *Session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	if s.account == nil {
		return fmt.Errorf("not authenticated")
	}

	s.mu.Lock()
	mailbox := s.selected
	s.mu.Unlock()

	if mailbox == "" {
		return fmt.Errorf("no mailbox selected")
	}

	msgs, err := s.backend.MessageRepo.ListByAccount(s.account.ID, mailbox)
	if err != nil {
		return err
	}

	for i, msg := range msgs {
		seqNum := uint32(i + 1)
		uid := imap.UID(i + 1)

		// Check if this message is in the requested set
		inSet := false
		switch set := numSet.(type) {
		case imap.SeqSet:
			inSet = set.Contains(seqNum)
		case *imap.SeqSet:
			inSet = set.Contains(seqNum)
		case imap.UIDSet:
			inSet = set.Contains(uid)
		case *imap.UIDSet:
			inSet = set.Contains(uid)
		default:
			// Fallback - assume all messages
			inSet = true
		}
		if !inSet {
			continue
		}

		respWriter := w.CreateMessage(seqNum)

		// Write UID
		respWriter.WriteUID(uid)

		// Write envelope if requested
		if options.Envelope {
			respWriter.WriteEnvelope(&imap.Envelope{
				Date:    msg.ReceivedAt,
				Subject: msg.Subject,
				From:    parseAddressList(msg.From),
				To:      parseAddressList(msg.To),
			})
		}

		// Write flags
		if options.Flags {
			flags := []imap.Flag{}
			if msg.ReadAt != nil {
				flags = append(flags, imap.FlagSeen)
			}
			respWriter.WriteFlags(flags)
		}

		// Write body if requested
		for _, section := range options.BodySection {
			data, err := s.backend.BlobStorage.Get(msg.StoragePath)
			if err != nil {
				continue
			}
			bw := respWriter.WriteBodySection(section, int64(len(data)))
			bw.Write(data)
			bw.Close()
		}

		if err := respWriter.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (s *Session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	// Update message flags
	return nil
}

func (s *Session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	return &imap.CopyData{
		UIDValidity: 1,
	}, nil
}

func parseAddressList(addr string) []imap.Address {
	if addr == "" {
		return nil
	}
	// Simple parse - just extract email
	parts := strings.Split(addr, "@")
	if len(parts) != 2 {
		return []imap.Address{{Mailbox: addr, Host: ""}}
	}
	return []imap.Address{{Mailbox: parts[0], Host: parts[1]}}
}

// Server wraps the IMAP server
type Server struct {
	addr      string
	backend   *Backend
	tlsConfig *tls.Config
}

// NewServer creates a new IMAP server
func NewServer(addr string, backend *Backend) *Server {
	return &Server{
		addr:    addr,
		backend: backend,
	}
}

// WithTLS configures TLS support for IMAPS
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

// Start starts the IMAP server
func (s *Server) Start() error {
	opts := &imapserver.Options{
		NewSession: s.backend.NewSession,
		Caps:       imap.CapSet{imap.CapIMAP4rev1: {}},
		TLSConfig:  s.tlsConfig,
	}

	if s.tlsConfig != nil {
		opts.InsecureAuth = false
		log.Printf("Starting IMAP server at %s with TLS", s.addr)
	} else {
		opts.InsecureAuth = true
		log.Printf("Starting IMAP server at %s (insecure)", s.addr)
	}

	srv := imapserver.New(opts)
	return srv.ListenAndServe(s.addr)
}
