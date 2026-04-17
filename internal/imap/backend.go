package imap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

// IdleNotifier manages IDLE connections and notifications
type IdleNotifier struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID][]chan uint32 // accountID -> list of IDLE channels
}

var globalIdleNotifier = &IdleNotifier{
	sessions: make(map[uuid.UUID][]chan uint32),
}

// RegisterIdle registers an IDLE session for notifications
func (n *IdleNotifier) RegisterIdle(accountID uuid.UUID, ch chan uint32) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sessions[accountID] = append(n.sessions[accountID], ch)
}

// UnregisterIdle removes an IDLE session
func (n *IdleNotifier) UnregisterIdle(accountID uuid.UUID, ch chan uint32) {
	n.mu.Lock()
	defer n.mu.Unlock()
	channels := n.sessions[accountID]
	for i, c := range channels {
		if c == ch {
			n.sessions[accountID] = append(channels[:i], channels[i+1:]...)
			break
		}
	}
}

// NotifyNewMail notifies all IDLE sessions for an account of new mail
func (n *IdleNotifier) NotifyNewMail(accountID uuid.UUID, msgCount uint32) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, ch := range n.sessions[accountID] {
		select {
		case ch <- msgCount:
		default:
			// Channel full, skip
		}
	}
}

// GetIdleNotifier returns the global IDLE notifier
func GetIdleNotifier() *IdleNotifier {
	return globalIdleNotifier
}

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
	if s.account == nil {
		return fmt.Errorf("not authenticated")
	}

	log.Printf("IDLE: client started IDLE for account %s", s.account.ID)

	// Create notification channel
	notifyCh := make(chan uint32, 10)
	globalIdleNotifier.RegisterIdle(s.account.ID, notifyCh)
	defer func() {
		globalIdleNotifier.UnregisterIdle(s.account.ID, notifyCh)
		log.Printf("IDLE: client ended IDLE for account %s", s.account.ID)
	}()

	for {
		select {
		case <-stop:
			return nil
		case msgCount := <-notifyCh:
			// New mail arrived - notify client
			log.Printf("IDLE: notifying account %s of new mail (count: %d)", s.account.ID, msgCount)
			if err := w.WriteNumMessages(msgCount); err != nil {
				return err
			}
		}
	}
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
	// Comprehensive logging of what client is requesting
	log.Printf("FETCH: request received - NumSet=%v Envelope=%v Flags=%v InternalDate=%v RFC822Size=%v UID=%v BodyStructure=%v BodySections=%d",
		numSet, options.Envelope, options.Flags, options.InternalDate, options.RFC822Size, options.UID, options.BodyStructure != nil, len(options.BodySection))

	// Log each body section requested
	for i, section := range options.BodySection {
		log.Printf("FETCH: BodySection[%d] - Part=%v Specifier=%v Peek=%v HeaderFields=%v", i, section.Part, section.Specifier, section.Peek, section.HeaderFields)
	}

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

		// Write internal date
		if options.InternalDate {
			respWriter.WriteInternalDate(msg.ReceivedAt)
		}

		// Write RFC822 size
		if options.RFC822Size {
			respWriter.WriteRFC822Size(msg.SizeBytes)
		}

		// Write body structure if requested
		if options.BodyStructure != nil {
			data, err := s.backend.BlobStorage.Get(msg.StoragePath)
			if err == nil {
				// Normalize CRLF before building BODYSTRUCTURE so sizes are correct
				data = normalizeCRLF(data)
				bs := buildBodyStructure(data, options.BodyStructure.Extended)
				log.Printf("FETCH: Returning BODYSTRUCTURE for msg %d - Extended=%v Type=%T", seqNum, options.BodyStructure.Extended, bs)
				respWriter.WriteBodyStructure(bs)
			} else {
				log.Printf("FETCH: Failed to get blob for BODYSTRUCTURE: %v", err)
			}
		}

		// Write body if requested
		for _, section := range options.BodySection {
			log.Printf("FETCH: section requested - Part=%v Specifier=%v Peek=%v", section.Part, section.Specifier, section.Peek)

			data, err := s.backend.BlobStorage.Get(msg.StoragePath)
			if err != nil {
				log.Printf("Failed to read message body: %v", err)
				continue
			}

			// Normalize CRLF line endings (RFC 5322 requirement)
			data = normalizeCRLF(data)

			// Mark as read when body is fetched (unless PEEK)
			if !section.Peek && msg.ReadAt == nil {
				now := time.Now()
				msg.ReadAt = &now
				s.backend.MessageRepo.UpdateMessage(msg)
			}

			// Handle different section specifiers
			var bodyData []byte

			// First check if a specific part is requested (e.g., BODY[1], BODY[2], BODY[1.MIME])
			if len(section.Part) > 0 {
				log.Printf("FETCH: Part check - Specifier=%q PartSpecifierMIME=%q Match=%v", section.Specifier, imap.PartSpecifierMIME, section.Specifier == imap.PartSpecifierMIME)
				// Handle MIME specifier for parts (BODY[1.MIME], BODY[2.MIME], etc.)
				if section.Specifier == imap.PartSpecifierMIME {
					// Return MIME headers for the specific part
					bodyData = extractMessagePartMIME(data, section.Part)
					log.Printf("FETCH: extracted part %v MIME headers, length=%d", section.Part, len(bodyData))
				} else if section.Specifier == imap.PartSpecifierHeader {
					// Return headers for the specific part
					bodyData = extractMessagePartHeaders(data, section.Part)
					log.Printf("FETCH: extracted part %v headers, length=%d", section.Part, len(bodyData))
				} else if section.Specifier == imap.PartSpecifierText {
					// Return text content (body without headers) for the specific part
					partData := extractMessagePartDecoded(data, section.Part)
					// For message/rfc822 parts, strip headers
					idx := strings.Index(string(partData), "\r\n\r\n")
					if idx != -1 {
						bodyData = partData[idx+4:]
					} else {
						idx = strings.Index(string(partData), "\n\n")
						if idx != -1 {
							bodyData = partData[idx+2:]
						} else {
							bodyData = partData
						}
					}
					log.Printf("FETCH: extracted part %v text, length=%d", section.Part, len(bodyData))
				} else {
					// Extract the specific part body content from the multipart message
					// Use decoded version for text parts
					bodyData = extractMessagePartDecoded(data, section.Part)
					log.Printf("FETCH: extracted part %v, length=%d", section.Part, len(bodyData))
				}
			} else {
				switch section.Specifier {
				case imap.PartSpecifierText:
					// Return only the body (after headers)
					// Find the blank line separating headers from body
					idx := strings.Index(string(data), "\r\n\r\n")
					if idx == -1 {
						idx = strings.Index(string(data), "\n\n")
						if idx != -1 {
							bodyData = data[idx+2:]
						} else {
							bodyData = data
						}
					} else {
						bodyData = data[idx+4:]
					}
					log.Printf("FETCH: TEXT specifier, body length=%d", len(bodyData))
				case imap.PartSpecifierHeader:
					// Return only the headers
					idx := strings.Index(string(data), "\r\n\r\n")
					if idx == -1 {
						idx = strings.Index(string(data), "\n\n")
						if idx != -1 {
							bodyData = data[:idx+2]
						} else {
							bodyData = data
						}
					} else {
						bodyData = data[:idx+4]
					}
					log.Printf("FETCH: HEADER specifier, header length=%d", len(bodyData))
				default:
					// Return full message for BODY[] or other specifiers
					bodyData = data
					log.Printf("FETCH: full message, length=%d", len(bodyData))
				}
			}

			bw := respWriter.WriteBodySection(section, int64(len(bodyData)))
			bw.Write(bodyData)
			bw.Close()
		}

		if err := respWriter.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (s *Session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
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
			inSet = true
		}
		if !inSet {
			continue
		}

		// Process flag changes
		for _, flag := range flags.Flags {
			if flag == imap.FlagSeen {
				switch flags.Op {
				case imap.StoreFlagsAdd:
					if msg.ReadAt == nil {
						now := time.Now()
						msg.ReadAt = &now
						s.backend.MessageRepo.UpdateMessage(msg)
					}
				case imap.StoreFlagsDel:
					if msg.ReadAt != nil {
						msg.ReadAt = nil
						s.backend.MessageRepo.UpdateMessage(msg)
					}
				case imap.StoreFlagsSet:
					now := time.Now()
					msg.ReadAt = &now
					s.backend.MessageRepo.UpdateMessage(msg)
				}
			}
			if flag == imap.FlagDeleted {
				if flags.Op == imap.StoreFlagsAdd || flags.Op == imap.StoreFlagsSet {
					now := time.Now()
					msg.DeletedAt = &now
					s.backend.MessageRepo.UpdateMessage(msg)
				}
			}
		}

		// Write response if not silent
		if !flags.Silent {
			respWriter := w.CreateMessage(seqNum)
			respWriter.WriteUID(uid)

			currentFlags := []imap.Flag{}
			if msg.ReadAt != nil {
				currentFlags = append(currentFlags, imap.FlagSeen)
			}
			if msg.DeletedAt != nil {
				currentFlags = append(currentFlags, imap.FlagDeleted)
			}
			respWriter.WriteFlags(currentFlags)
			respWriter.Close()
		}
	}

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

	// Try to parse as RFC 5322 address (e.g., "Display Name <email@example.com>")
	// or simple email (e.g., "email@example.com")
	addr = strings.TrimSpace(addr)

	var name, mailbox, host string

	// Check for "Name <email>" format
	if idx := strings.Index(addr, "<"); idx != -1 {
		name = strings.TrimSpace(addr[:idx])
		name = strings.Trim(name, "\"") // Remove quotes if present

		endIdx := strings.Index(addr, ">")
		if endIdx == -1 {
			endIdx = len(addr)
		}
		email := strings.TrimSpace(addr[idx+1 : endIdx])

		parts := strings.SplitN(email, "@", 2)
		if len(parts) == 2 {
			mailbox = parts[0]
			host = parts[1]
		} else {
			mailbox = email
		}
	} else {
		// Simple email format
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) == 2 {
			mailbox = parts[0]
			host = parts[1]
		} else {
			mailbox = addr
		}
	}

	return []imap.Address{{
		Name:    name,
		Mailbox: mailbox,
		Host:    host,
	}}
}

// normalizeCRLF ensures all line endings are CRLF as per RFC 5322
func normalizeCRLF(data []byte) []byte {
	// First convert any \r\n to \n, then convert all \n to \r\n
	// This handles mixed line endings properly
	result := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	result = bytes.ReplaceAll(result, []byte("\r"), []byte("\n"))
	result = bytes.ReplaceAll(result, []byte("\n"), []byte("\r\n"))
	return result
}

// decodeTransferEncoding decodes content based on Content-Transfer-Encoding
func decodeTransferEncoding(data []byte, encoding string) []byte {
	log.Printf("decodeTransferEncoding: encoding=%q dataLen=%d", encoding, len(data))
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			// Try with line breaks removed
			cleaned := strings.ReplaceAll(string(data), "\r\n", "")
			cleaned = strings.ReplaceAll(cleaned, "\n", "")
			decoded, err = base64.StdEncoding.DecodeString(cleaned)
			if err != nil {
				log.Printf("decodeTransferEncoding: base64 decode failed: %v", err)
				return data // Return original if decode fails
			}
		}
		log.Printf("decodeTransferEncoding: base64 decoded %d -> %d", len(data), len(decoded))
		return decoded
	case "quoted-printable":
		reader := quotedprintable.NewReader(bytes.NewReader(data))
		decoded, err := io.ReadAll(reader)
		if err != nil {
			log.Printf("decodeTransferEncoding: QP decode failed: %v", err)
			return data // Return original if decode fails
		}
		log.Printf("decodeTransferEncoding: QP decoded %d -> %d", len(data), len(decoded))
		return decoded
	default:
		log.Printf("decodeTransferEncoding: no decoding for encoding=%q", encoding)
		// 7bit, 8bit, binary, or no encoding - return as-is
		return data
	}
}

// extractBestAlternative extracts the best displayable content from a multipart message
// Returns nil if not a multipart message or no suitable content found
// Prefers text/html over text/plain for multipart/alternative
// Decodes content-transfer-encoding (quoted-printable, base64) automatically
func extractBestAlternative(data []byte) []byte {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil
	}

	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		return nil // Not multipart, use default handling
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return nil // Not multipart, use default handling
	}

	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}

	body, _ := io.ReadAll(msg.Body)
	mr := multipart.NewReader(bytes.NewReader(body), boundary)

	var textPlain, textHTML []byte

	for {
		// Use NextRawPart() instead of NextPart() to preserve Content-Transfer-Encoding header
		// NextPart() strips the Content-Transfer-Encoding header and auto-decodes, which we don't want
		// since we do our own decoding
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		partContentType := part.Header.Get("Content-Type")
		if partContentType == "" {
			partContentType = "text/plain"
		}
		partMediaType, _, _ := mime.ParseMediaType(partContentType)
		partEncoding := part.Header.Get("Content-Transfer-Encoding")
		log.Printf("extractBestAlternative: part type=%s encoding=%q headers=%v", partMediaType, partEncoding, part.Header)
		partBody, _ := io.ReadAll(part)

		// Decode the content based on transfer encoding
		decodedBody := decodeTransferEncoding(partBody, partEncoding)

		if strings.EqualFold(partMediaType, "text/plain") && textPlain == nil {
			textPlain = decodedBody
		} else if strings.EqualFold(partMediaType, "text/html") && textHTML == nil {
			textHTML = decodedBody
		} else if strings.HasPrefix(partMediaType, "multipart/") {
			// Recursively extract from nested multipart
			// Reconstruct as a message to reuse this function
			nestedMsg := append([]byte("Content-Type: "+partContentType+"\r\n\r\n"), partBody...)
			if nested := extractBestAlternative(nestedMsg); nested != nil {
				if textHTML == nil {
					textHTML = nested // Assume nested returns best (HTML)
				}
			}
		}
	}

	// Prefer HTML, fall back to plain text
	if textHTML != nil {
		return textHTML
	}
	if textPlain != nil {
		return textPlain
	}
	return nil
}

// buildBodyStructure parses the email and builds the correct BODYSTRUCTURE
func buildBodyStructure(data []byte, extended bool) imap.BodyStructure {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		// Fallback to simple text/plain
		return buildSimpleBodyStructure(data, extended)
	}

	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return buildSimpleBodyStructure(data, extended)
	}

	// Get encoding and disposition from headers
	encoding := strings.ToUpper(msg.Header.Get("Content-Transfer-Encoding"))
	if encoding == "" {
		encoding = "7BIT"
	}
	disposition := msg.Header.Get("Content-Disposition")

	// Read the body
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return buildSimpleBodyStructure(data, extended)
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		return buildMultipartBodyStructure(mediaType, params, body, extended)
	}

	return buildSinglePartBodyStructureWithHeaders(mediaType, params, body, encoding, disposition, extended)
}

func buildSimpleBodyStructure(data []byte, extended bool) imap.BodyStructure {
	// Count lines for text parts (RFC 3501 requirement)
	numLines := int64(strings.Count(string(data), "\n"))
	if len(data) > 0 && data[len(data)-1] != '\n' {
		numLines++ // Account for the last line if it doesn't end with newline
	}

	bs := &imap.BodyStructureSinglePart{
		Type:     "text",
		Subtype:  "plain",
		Params:   map[string]string{"charset": "utf-8"},
		Encoding: "7BIT",
		Size:     uint32(len(data)),
		Text:     &imap.BodyStructureText{NumLines: numLines},
	}
	if extended {
		bs.Extended = &imap.BodyStructureSinglePartExt{}
	}
	return bs
}

func buildSinglePartBodyStructure(mediaType string, params map[string]string, body []byte, extended bool) imap.BodyStructure {
	return buildSinglePartBodyStructureWithHeaders(mediaType, params, body, "7BIT", "", extended)
}

func buildSinglePartBodyStructureWithHeaders(mediaType string, params map[string]string, body []byte, encoding, disposition string, extended bool) imap.BodyStructure {
	parts := strings.SplitN(mediaType, "/", 2)
	mainType := "text"
	subType := "plain"
	if len(parts) == 2 {
		mainType = parts[0]
		subType = parts[1]
	}

	// Use the encoding passed from headers, default to 7BIT
	if encoding == "" {
		encoding = "7BIT"
	}
	encoding = strings.ToUpper(encoding)

	charset := params["charset"]
	if charset == "" && mainType == "text" {
		charset = "us-ascii"
	}

	bsParams := make(map[string]string)
	if charset != "" {
		bsParams["charset"] = charset
	}
	// Include name parameter if present (for attachments)
	if name := params["name"]; name != "" {
		bsParams["name"] = name
	}

	bs := &imap.BodyStructureSinglePart{
		Type:     mainType,
		Subtype:  subType,
		Params:   bsParams,
		Encoding: encoding,
		Size:     uint32(len(body)),
	}

	// For text/* types, we MUST include NumLines (RFC 3501 requirement)
	if strings.EqualFold(mainType, "text") {
		numLines := int64(strings.Count(string(body), "\n"))
		if len(body) > 0 && body[len(body)-1] != '\n' {
			numLines++ // Account for the last line if it doesn't end with newline
		}
		bs.Text = &imap.BodyStructureText{
			NumLines: numLines,
		}
	}

	if extended {
		ext := &imap.BodyStructureSinglePartExt{}
		// Parse disposition if present
		if disposition != "" {
			dispType, dispParams, err := mime.ParseMediaType(disposition)
			if err == nil {
				ext.Disposition = &imap.BodyStructureDisposition{
					Value:  strings.ToUpper(dispType),
					Params: dispParams,
				}
			}
		}
		bs.Extended = ext
	}
	return bs
}

func buildMultipartBodyStructure(mediaType string, params map[string]string, body []byte, extended bool) imap.BodyStructure {
	parts := strings.SplitN(mediaType, "/", 2)
	subType := "mixed"
	if len(parts) == 2 {
		subType = parts[1]
	}

	boundary := params["boundary"]
	if boundary == "" {
		log.Printf("BODYSTRUCTURE: no boundary for multipart/%s, falling back to simple", subType)
		// No boundary, return as single part
		return buildSimpleBodyStructure(body, extended)
	}

	log.Printf("BODYSTRUCTURE: parsing multipart/%s with boundary=%q bodyLen=%d", subType, boundary, len(body))

	// Parse multipart
	mr := multipart.NewReader(bytes.NewReader(body), boundary)

	var children []imap.BodyStructure
	for {
		// Use NextRawPart() to preserve Content-Transfer-Encoding header
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("BODYSTRUCTURE: error reading part: %v", err)
			break
		}

		partContentType := part.Header.Get("Content-Type")
		if partContentType == "" {
			partContentType = "text/plain"
		}

		partMediaType, partParams, _ := mime.ParseMediaType(partContentType)
		partBody, _ := io.ReadAll(part)

		log.Printf("BODYSTRUCTURE: found part %d - type=%s size=%d", len(children)+1, partMediaType, len(partBody))

		// Get encoding and disposition from part headers
		partEncoding := part.Header.Get("Content-Transfer-Encoding")
		partDisposition := part.Header.Get("Content-Disposition")

		if strings.HasPrefix(partMediaType, "multipart/") {
			children = append(children, buildMultipartBodyStructure(partMediaType, partParams, partBody, extended))
		} else {
			children = append(children, buildSinglePartBodyStructureWithHeaders(partMediaType, partParams, partBody, partEncoding, partDisposition, extended))
		}
	}

	log.Printf("BODYSTRUCTURE: multipart/%s has %d children", subType, len(children))

	if len(children) == 0 {
		log.Printf("BODYSTRUCTURE: no children found, falling back to simple")
		return buildSimpleBodyStructure(body, extended)
	}

	// Fix for Outlook: if multipart has exactly 1 child, return that child directly
	// Outlook has a known bug where it fails to display messages declared as
	// multipart/mixed or multipart/alternative with exactly one sub-part
	if len(children) == 1 {
		log.Printf("BODYSTRUCTURE: unwrapping single-child multipart/%s to avoid Outlook bug", subType)
		return children[0]
	}

	bs := &imap.BodyStructureMultiPart{
		Children: children,
		Subtype:  subType,
	}
	if extended {
		bs.Extended = &imap.BodyStructureMultiPartExt{}
	}
	return bs
}

// extractMessagePart extracts a specific part from a multipart message
// partPath is a slice like [1] for part 1, [1, 2] for part 1.2, etc.
func extractMessagePart(data []byte, partPath []int) []byte {
	if len(partPath) == 0 {
		return data
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return data
	}

	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		// Not multipart, return body directly
		body, _ := io.ReadAll(msg.Body)
		return body
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		// Not multipart, return body directly
		body, _ := io.ReadAll(msg.Body)
		return body
	}

	boundary := params["boundary"]
	if boundary == "" {
		body, _ := io.ReadAll(msg.Body)
		return body
	}

	// Read the body
	body, _ := io.ReadAll(msg.Body)

	// Parse multipart
	mr := multipart.NewReader(bytes.NewReader(body), boundary)

	partNum := partPath[0]
	currentPart := 0

	for {
		// Use NextRawPart() to preserve all headers
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		currentPart++

		if currentPart == partNum {
			partBody, _ := io.ReadAll(part)

			// If there are more levels in the path, recurse
			if len(partPath) > 1 {
				// Reconstruct message-like structure for nested multipart
				partContentType := part.Header.Get("Content-Type")
				if strings.HasPrefix(partContentType, "multipart/") {
					// Create a minimal message header to parse the nested multipart
					nestedMsg := append([]byte("Content-Type: "+partContentType+"\r\n\r\n"), partBody...)
					return extractMessagePart(nestedMsg, partPath[1:])
				}
			}

			return partBody
		}
	}

	// Part not found, return empty
	return []byte{}
}

// extractMessagePartDecoded extracts a specific part and decodes its transfer encoding
func extractMessagePartDecoded(data []byte, partPath []int) []byte {
	if len(partPath) == 0 {
		return data
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return data
	}

	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		body, _ := io.ReadAll(msg.Body)
		return body
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		body, _ := io.ReadAll(msg.Body)
		return body
	}

	boundary := params["boundary"]
	if boundary == "" {
		body, _ := io.ReadAll(msg.Body)
		return body
	}

	body, _ := io.ReadAll(msg.Body)
	mr := multipart.NewReader(bytes.NewReader(body), boundary)

	partNum := partPath[0]
	currentPart := 0

	for {
		// Use NextRawPart() to preserve Content-Transfer-Encoding header for proper decoding
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		currentPart++

		if currentPart == partNum {
			partBody, _ := io.ReadAll(part)
			partEncoding := part.Header.Get("Content-Transfer-Encoding")

			// If there are more levels in the path, recurse
			if len(partPath) > 1 {
				partContentType := part.Header.Get("Content-Type")
				if strings.HasPrefix(partContentType, "multipart/") {
					nestedMsg := append([]byte("Content-Type: "+partContentType+"\r\n\r\n"), partBody...)
					return extractMessagePartDecoded(nestedMsg, partPath[1:])
				}
			}

			// Decode the content based on transfer encoding
			return decodeTransferEncoding(partBody, partEncoding)
		}
	}

	return []byte{}
}

// extractMessagePartMIME extracts MIME headers for a specific part (BODY[n.MIME])
func extractMessagePartMIME(data []byte, partPath []int) []byte {
	if len(partPath) == 0 {
		return []byte{}
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return []byte{}
	}

	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		return []byte{}
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return []byte{}
	}

	boundary := params["boundary"]
	if boundary == "" {
		return []byte{}
	}

	// Read the body
	body, _ := io.ReadAll(msg.Body)

	// Parse multipart
	mr := multipart.NewReader(bytes.NewReader(body), boundary)

	partNum := partPath[0]
	currentPart := 0

	for {
		// Use NextRawPart() to preserve all headers including Content-Transfer-Encoding
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		currentPart++

		if currentPart == partNum {
			// If there are more levels in the path, recurse
			if len(partPath) > 1 {
				partBody, _ := io.ReadAll(part)
				partContentType := part.Header.Get("Content-Type")
				if strings.HasPrefix(partContentType, "multipart/") {
					nestedMsg := append([]byte("Content-Type: "+partContentType+"\r\n\r\n"), partBody...)
					return extractMessagePartMIME(nestedMsg, partPath[1:])
				}
				return []byte{}
			}

			// Build MIME headers for this part
			var mimeHeaders strings.Builder
			for key, values := range part.Header {
				for _, value := range values {
					mimeHeaders.WriteString(key + ": " + value + "\r\n")
				}
			}
			mimeHeaders.WriteString("\r\n")
			return []byte(mimeHeaders.String())
		}
	}

	return []byte{}
}

// extractMessagePartHeaders extracts headers from a message/rfc822 part (BODY[n.HEADER])
func extractMessagePartHeaders(data []byte, partPath []int) []byte {
	// First extract the part content
	partData := extractMessagePart(data, partPath)
	if len(partData) == 0 {
		return []byte{}
	}

	// Find the header/body separator
	idx := strings.Index(string(partData), "\r\n\r\n")
	if idx != -1 {
		return partData[:idx+4]
	}
	idx = strings.Index(string(partData), "\n\n")
	if idx != -1 {
		return partData[:idx+2]
	}
	return partData
}

// Server wraps the IMAP server
type Server struct {
	addr      string
	tlsAddr   string
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

// WithTLSAddr sets the implicit TLS port (993)
func (s *Server) WithTLSAddr(addr string) {
	s.tlsAddr = addr
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
				log.Printf("IMAP SNI: Using certificate for %s", info.ServerName)
				return &cert, nil
			}
			log.Printf("IMAP SNI: Using default certificate for %s", info.ServerName)
			return &defaultCertPair, nil
		},
		MinVersion: tls.VersionTLS12,
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
		log.Printf("Starting IMAP server at %s with STARTTLS", s.addr)
	} else {
		opts.InsecureAuth = true
		log.Printf("Starting IMAP server at %s (insecure)", s.addr)
	}

	srv := imapserver.New(opts)
	return srv.ListenAndServe(s.addr)
}

// StartTLS starts the implicit TLS IMAP server (port 993)
func (s *Server) StartTLS() error {
	if s.tlsAddr == "" || s.tlsConfig == nil {
		return nil // No TLS addr configured
	}

	opts := &imapserver.Options{
		NewSession:   s.backend.NewSession,
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}},
		TLSConfig:    s.tlsConfig,
		InsecureAuth: false,
	}

	log.Printf("Starting IMAPS server at %s (implicit TLS)", s.tlsAddr)
	srv := imapserver.New(opts)
	return srv.ListenAndServeTLS(s.tlsAddr)
}
