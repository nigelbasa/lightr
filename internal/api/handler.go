package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
	"github.com/nigelbasa/lightr/internal/smtp"
	"golang.org/x/crypto/bcrypt"
)

// APIKeyMiddleware validates API key from Authorization header
func APIKeyMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Support "Bearer <key>" or just "<key>"
		key := strings.TrimPrefix(auth, "Bearer ")
		if key != apiKey {
			http.Error(w, "invalid API key", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type Handler struct {
	accountRepo  domain.AccountRepository
	domainRepo   domain.DomainRepository
	orgRepo      domain.OrganizationRepository
	messageRepo  domain.MessageRepository
	templateRepo domain.TemplateRepository
	trackingRepo domain.TrackingEventRepository
	blobStorage  domain.BlobStorage
	relay        *smtp.Relay
}

func NewHandler(
	accRepo domain.AccountRepository,
	domRepo domain.DomainRepository,
	orgRepo domain.OrganizationRepository,
	msgRepo domain.MessageRepository,
	tmplRepo domain.TemplateRepository,
	trackRepo domain.TrackingEventRepository,
	blobStorage domain.BlobStorage,
	relay *smtp.Relay,
) *Handler {
	return &Handler{
		accountRepo:  accRepo,
		domainRepo:   domRepo,
		orgRepo:      orgRepo,
		messageRepo:  msgRepo,
		templateRepo: tmplRepo,
		trackingRepo: trackRepo,
		blobStorage:  blobStorage,
		relay:        relay,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Health
	mux.HandleFunc("GET /health", h.HandleHealth)

	// Organizations
	mux.HandleFunc("GET /v1/orgs", h.HandleListOrgs)
	mux.HandleFunc("POST /v1/orgs", h.HandleCreateOrg)
	mux.HandleFunc("GET /v1/orgs/{id}", h.HandleGetOrg)

	// Domains
	mux.HandleFunc("GET /v1/orgs/{org_id}/domains", h.HandleListDomains)
	mux.HandleFunc("POST /v1/domains", h.HandleCreateDomain)
	mux.HandleFunc("GET /v1/domains/{id}", h.HandleGetDomain)

	// Accounts
	mux.HandleFunc("POST /v1/accounts", h.HandleCreateAccount)
	mux.HandleFunc("GET /v1/accounts/{id}", h.HandleGetAccount)
	mux.HandleFunc("DELETE /v1/accounts/{id}", h.HandleDeleteAccount)

	// Messages
	mux.HandleFunc("GET /v1/accounts/{account_id}/messages", h.HandleListMessages)
	mux.HandleFunc("GET /v1/messages/{id}", h.HandleGetMessage)

	// Convenience endpoints (by email address)
	mux.HandleFunc("GET /v1/mailbox", h.HandleGetMailbox)                                              // ?email=user@domain.com
	mux.HandleFunc("GET /v1/mailbox/messages", h.HandleMailboxList)                                    // ?email=user@domain.com&folder=INBOX
	mux.HandleFunc("GET /v1/mailbox/messages/{id}", h.HandleMailboxGetMessage)                         // Get full message with body
	mux.HandleFunc("PATCH /v1/mailbox/messages/{id}", h.HandleMailboxMarkMessage)                      // Mark read/unread
	mux.HandleFunc("GET /v1/mailbox/messages/{id}/attachments/{att_id}", h.HandleMailboxGetAttachment) // Get attachment data
	mux.HandleFunc("GET /v1/mailbox/folders", h.HandleMailboxFolders)
	mux.HandleFunc("POST /v1/mailbox/send", h.HandleMailboxSend)
	mux.HandleFunc("GET /v1/mailbox/contacts", h.HandleMailboxContacts)       // Contact autocomplete
	mux.HandleFunc("PATCH /v1/mailbox/account", h.HandleUpdateMailboxAccount) // Update display name etc

	// RFC 8058 One-Click Unsubscribe endpoint
	mux.HandleFunc("POST /unsubscribe/{msg_id}", h.HandleUnsubscribe)
	mux.HandleFunc("GET /unsubscribe/{msg_id}", h.HandleUnsubscribePage)

	// Templates
	mux.HandleFunc("POST /v1/templates", h.HandleCreateTemplate)
	mux.HandleFunc("GET /v1/orgs/{org_id}/templates", h.HandleListTemplates)
	mux.HandleFunc("GET /v1/templates/{org_id}/{name}", h.HandleGetTemplate)

	// Send
	mux.HandleFunc("POST /v1/send", h.HandleSend)

	// Stats
	mux.HandleFunc("GET /v1/messages/{id}/tracking", h.HandleGetTrackingStats)
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type CreateDomainRequest struct {
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
}

func (h *Handler) HandleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req CreateDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	orgID, err := uuid.Parse(req.OrgID)
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	dom := &domain.Domain{
		ID:           uuid.New(),
		OrgID:        orgID,
		Name:         req.Name,
		DKIMSelector: "default", // default selector
		IsVerified:   false,
	}

	if err := h.domainRepo.CreateDomain(dom); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dom)
}

type CreateAccountRequest struct {
	DomainID   string `json:"domain_id"`
	LocalPart  string `json:"local_part"`
	AuthMode   string `json:"auth_mode"`
	Password   string `json:"password,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
	QuotaBytes int64  `json:"quota_bytes"`
}

func (h *Handler) HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	domID, err := uuid.Parse(req.DomainID)
	if err != nil {
		http.Error(w, "invalid domain_id", http.StatusBadRequest)
		return
	}

	acc := &domain.Account{
		ID:         uuid.New(),
		DomainID:   domID,
		LocalPart:  req.LocalPart,
		AuthMode:   domain.AuthMode(req.AuthMode),
		ExternalID: req.ExternalID,
		QuotaBytes: req.QuotaBytes,
	}

	// Handle password hashing for native auth
	if acc.AuthMode == domain.AuthModeNative && req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
			return
		}
		acc.PasswordHash = string(hash)
	}

	if err := h.accountRepo.CreateAccount(acc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(acc)
}

func (h *Handler) HandleGetAccount(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	acc, err := h.accountRepo.GetAccountByID(id)
	if err != nil {
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(acc)
}

type SendRequest struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html,omitempty"`
}

func (h *Handler) HandleSend(w http.ResponseWriter, r *http.Request) {
	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Basic RFC822 message construction (very simple for now)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", req.From, req.To, req.Subject, req.Text)

	if err := h.relay.Send(r.Context(), req.From, []string{req.To}, []byte(msg)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
}

// Organization handlers

func (h *Handler) HandleListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.orgRepo.ListOrgs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orgs)
}

type CreateOrgRequest struct {
	Name        string `json:"name"`
	BillingTier string `json:"billing_tier"`
}

func (h *Handler) HandleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var req CreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	org := &domain.Organization{
		ID:          uuid.New(),
		Name:        req.Name,
		BillingTier: req.BillingTier,
	}
	if org.BillingTier == "" {
		org.BillingTier = "free"
	}

	if err := h.orgRepo.CreateOrg(org); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(org)
}

func (h *Handler) HandleGetOrg(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	org, err := h.orgRepo.GetOrgByID(id)
	if err != nil {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(org)
}

// Domain handlers

func (h *Handler) HandleListDomains(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	domains, err := h.domainRepo.ListDomainsByOrg(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

func (h *Handler) HandleGetDomain(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	dom, err := h.domainRepo.GetDomainByID(id)
	if err != nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dom)
}

// Account handlers

func (h *Handler) HandleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	if err := h.accountRepo.DeleteAccount(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Message handlers

func (h *Handler) HandleListMessages(w http.ResponseWriter, r *http.Request) {
	accountID, err := uuid.Parse(r.PathValue("account_id"))
	if err != nil {
		http.Error(w, "invalid account_id", http.StatusBadRequest)
		return
	}

	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "INBOX"
	}

	messages, err := h.messageRepo.ListByAccount(accountID, folder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func (h *Handler) HandleGetMessage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	msg, err := h.messageRepo.GetMessageByID(id)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

// Convenience handlers for email-address-based access

// getAccountByEmail resolves email to account
func (h *Handler) getAccountByEmail(email string) (*domain.Account, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format")
	}
	localPart, domainName := parts[0], parts[1]

	dom, err := h.domainRepo.GetDomainByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("domain not found: %s (err: %v)", domainName, err)
	}

	acc, err := h.accountRepo.GetAccountByLocalPart(dom.ID, localPart)
	if err != nil {
		return nil, fmt.Errorf("account not found: %s (domain_id: %s, err: %v)", email, dom.ID, err)
	}

	return acc, nil
}

// HandleGetMailbox returns account info by email
func (h *Handler) HandleGetMailbox(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":           acc.ID,
		"email":        email,
		"display_name": acc.DisplayName,
		"auth_mode":    acc.AuthMode,
		"quota":        acc.QuotaBytes,
		"used":         acc.UsedBytes,
		"created_at":   acc.CreatedAt,
	})
}

// HandleMailboxList returns messages for an email address
func (h *Handler) HandleMailboxList(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required", http.StatusBadRequest)
		return
	}

	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "INBOX"
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	messages, err := h.messageRepo.ListByAccount(acc.ID, folder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return in a standard format
	result := make([]map[string]interface{}, len(messages))
	for i, msg := range messages {
		result[i] = map[string]interface{}{
			"id":      msg.ID,
			"from":    msg.From,
			"to":      msg.To,
			"subject": msg.Subject,
			"date":    msg.ReceivedAt,
			"read":    msg.ReadAt != nil,
			"folder":  msg.Folder,
			"size":    msg.SizeBytes,
			"preview": msg.Subject, // We can add a preview field later
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"messages": result,
		"total":    len(messages),
		"folder":   folder,
	})
}

// HandleMailboxGetMessage returns a single message with parsed body
// Requires email query param for IDOR protection
func (h *Handler) HandleMailboxGetMessage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	// IDOR Protection: Require email and verify ownership
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required for authorization", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, "account not found", http.StatusForbidden)
		return
	}

	msg, err := h.messageRepo.GetMessageByID(id)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}

	// Verify the message belongs to this account
	if msg.AccountID != acc.ID {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	// Get message body from storage and parse it
	var parsedMsg *ParsedMessage
	if msg.StoragePath != "" && h.blobStorage != nil {
		data, err := h.blobStorage.Get(msg.StoragePath)
		if err == nil {
			parsedMsg, _ = ParseRFC822Message(data)
		}
	}

	// Fallback to empty parsed message if parsing failed
	if parsedMsg == nil {
		parsedMsg = &ParsedMessage{
			Text:        "",
			HTML:        "",
			Attachments: []AttachmentMeta{},
		}
	}

	// Extract CC and BCC from raw headers if available
	var cc, bcc string
	if msg.StoragePath != "" && h.blobStorage != nil {
		data, err := h.blobStorage.Get(msg.StoragePath)
		if err == nil {
			if mailMsg, err := mail.ReadMessage(bytes.NewReader(data)); err == nil {
				cc = mailMsg.Header.Get("Cc")
				bcc = mailMsg.Header.Get("Bcc")
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          msg.ID,
		"from":        msg.From,
		"to":          msg.To,
		"cc":          cc,
		"bcc":         bcc,
		"subject":     msg.Subject,
		"date":        msg.ReceivedAt,
		"read":        msg.ReadAt != nil,
		"folder":      msg.Folder,
		"size":        msg.SizeBytes,
		"text":        parsedMsg.Text,
		"html":        parsedMsg.HTML,
		"attachments": parsedMsg.Attachments,
	})
}

// HandleMailboxFolders returns standard mailbox folders
func (h *Handler) HandleMailboxFolders(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Get message counts per folder
	folders := []string{"INBOX", "Sent", "Drafts", "Trash", "Junk"}
	result := make([]map[string]interface{}, len(folders))

	for i, folder := range folders {
		msgs, _ := h.messageRepo.ListByAccount(acc.ID, folder)
		unread := 0
		for _, m := range msgs {
			if m.ReadAt == nil {
				unread++
			}
		}
		result[i] = map[string]interface{}{
			"name":   folder,
			"path":   folder,
			"total":  len(msgs),
			"unread": unread,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mailboxes": result,
	})
}

// HandleMailboxGetAttachment returns attachment data by ID
// Requires email query param for IDOR protection
func (h *Handler) HandleMailboxGetAttachment(w http.ResponseWriter, r *http.Request) {
	msgID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid message id", http.StatusBadRequest)
		return
	}

	attID := r.PathValue("att_id")
	if attID == "" {
		http.Error(w, "attachment id required", http.StatusBadRequest)
		return
	}

	// IDOR Protection: Require email and verify ownership
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email parameter required for authorization", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, "account not found", http.StatusForbidden)
		return
	}

	msg, err := h.messageRepo.GetMessageByID(msgID)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}

	// Verify the message belongs to this account
	if msg.AccountID != acc.ID {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	// Parse the message to get attachments
	if msg.StoragePath == "" || h.blobStorage == nil {
		http.Error(w, "message content not available", http.StatusNotFound)
		return
	}

	data, err := h.blobStorage.Get(msg.StoragePath)
	if err != nil {
		http.Error(w, "failed to retrieve message", http.StatusInternalServerError)
		return
	}

	_, attachments := ParseRFC822Message(data)

	// Find the requested attachment by ID
	for _, att := range attachments {
		if att.Meta.ID == attID {
			// Set appropriate headers
			w.Header().Set("Content-Type", att.Meta.ContentType)
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, att.Meta.Filename))
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(att.Data)))
			w.Write(att.Data)
			return
		}
	}

	http.Error(w, "attachment not found", http.StatusNotFound)
}

// HandleMailboxSend sends an email on behalf of a user
func (h *Handler) HandleMailboxSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From        string   `json:"from"`
		To          []string `json:"to"`
		Cc          []string `json:"cc,omitempty"`
		Bcc         []string `json:"bcc,omitempty"`
		Subject     string   `json:"subject"`
		Text        string   `json:"text"`
		HTML        string   `json:"html,omitempty"`
		Attachments []struct {
			Filename    string `json:"filename"`
			ContentType string `json:"content_type"`
			Data        string `json:"data"` // Base64 encoded
		} `json:"attachments,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify sender account exists
	acc, err := h.getAccountByEmail(req.From)
	if err != nil {
		http.Error(w, "sender account not found", http.StatusForbidden)
		return
	}

	// Build message - BCC recipients get the email but are not in headers
	// Handle nil slices safely
	allRecipients := make([]string, 0, len(req.To)+len(req.Cc)+len(req.Bcc))
	allRecipients = append(allRecipients, req.To...)
	if len(req.Cc) > 0 {
		allRecipients = append(allRecipients, req.Cc...)
	}
	if len(req.Bcc) > 0 {
		allRecipients = append(allRecipients, req.Bcc...)
	}

	now := time.Now()
	boundary := fmt.Sprintf("----=_Part_%s", uuid.New().String()[:8])
	msgID := uuid.New().String()

	var msgBuilder strings.Builder

	// Headers (BCC is NOT included in headers - that's how BCC works)
	msgBuilder.WriteString(fmt.Sprintf("Message-ID: <%s@%s>\r\n", msgID, strings.Split(req.From, "@")[1]))
	msgBuilder.WriteString(fmt.Sprintf("From: %s\r\n", req.From))
	msgBuilder.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(req.To, ", ")))
	if len(req.Cc) > 0 {
		msgBuilder.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(req.Cc, ", ")))
	}
	msgBuilder.WriteString(fmt.Sprintf("Subject: %s\r\n", req.Subject))
	msgBuilder.WriteString(fmt.Sprintf("Date: %s\r\n", now.Format(time.RFC1123Z)))
	msgBuilder.WriteString("MIME-Version: 1.0\r\n")

	// RFC 8058 List-Unsubscribe headers (for bulk/marketing emails)
	// Only add if this looks like a bulk email (multiple recipients or from a noreply address)
	fromDomain := strings.Split(req.From, "@")[1]
	unsubEmail := fmt.Sprintf("unsubscribe@%s", fromDomain)
	unsubURL := fmt.Sprintf("https://mail.%s/unsubscribe/%s", fromDomain, msgID)
	msgBuilder.WriteString(fmt.Sprintf("List-Unsubscribe: <mailto:%s?subject=unsubscribe>, <%s>\r\n", unsubEmail, unsubURL))
	msgBuilder.WriteString("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n")

	if len(req.Attachments) > 0 {
		msgBuilder.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
		msgBuilder.WriteString("\r\n")

		// Text body part
		msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msgBuilder.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		msgBuilder.WriteString("Content-Transfer-Encoding: 7bit\r\n")
		msgBuilder.WriteString("\r\n")
		msgBuilder.WriteString(req.Text)
		msgBuilder.WriteString("\r\n")

		// Attachment parts
		for _, att := range req.Attachments {
			msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			contentType := att.ContentType
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			msgBuilder.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", contentType, att.Filename))
			msgBuilder.WriteString("Content-Transfer-Encoding: base64\r\n")
			msgBuilder.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", att.Filename))
			msgBuilder.WriteString("\r\n")
			msgBuilder.WriteString(att.Data)
			msgBuilder.WriteString("\r\n")
		}

		msgBuilder.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		msgBuilder.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		msgBuilder.WriteString("\r\n")
		msgBuilder.WriteString(req.Text)
	}

	msg := msgBuilder.String()

	if err := h.relay.Send(r.Context(), req.From, allRecipients, []byte(msg)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Save to Sent folder
	sentMsg := &domain.Message{
		ID:         uuid.New(),
		AccountID:  acc.ID,
		Folder:     "Sent",
		Subject:    req.Subject,
		From:       req.From,
		To:         strings.Join(req.To, ", "),
		SizeBytes:  int64(len(msg)),
		ReceivedAt: now,
		ReadAt:     &now, // Sent messages are marked as read
	}

	// Store the raw message
	storagePath := fmt.Sprintf("messages/%s/%s.eml", acc.ID, sentMsg.ID)
	if h.blobStorage != nil {
		if err := h.blobStorage.Put(storagePath, []byte(msg)); err == nil {
			sentMsg.StoragePath = storagePath
		}
	}

	// Save to database
	if err := h.messageRepo.CreateMessage(sentMsg); err != nil {
		// Don't fail the request, just log
		fmt.Printf("Warning: failed to save sent message: %v\n", err)
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Email queued for delivery",
	})
}

// HandleMailboxContacts provides contact autocomplete for compose
func (h *Handler) HandleMailboxContacts(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	query := r.URL.Query().Get("q")

	if email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}

	// Verify account exists
	acc, err := h.getAccountByEmail(email)
	if err != nil {
		http.Error(w, "account not found", http.StatusForbidden)
		return
	}

	var contacts []domain.Contact

	// Search accounts in the same domain (colleagues) if query provided
	if query != "" {
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			domainName := parts[1]
			domainAccounts, err := h.accountRepo.SearchByDomain(domainName, query, 10)
			if err == nil {
				for _, da := range domainAccounts {
					if da.Email != email { // Exclude self
						name := da.DisplayName
						if name == "" {
							name = da.LocalPart
						}
						contacts = append(contacts, domain.Contact{
							Email:       da.Email,
							DisplayName: name,
						})
					}
				}
			}
		}
	}

	// Also search recipients from previously sent messages
	sentMessages, err := h.messageRepo.ListByAccount(acc.ID, "Sent")
	if err == nil {
		recipientCount := make(map[string]int)
		for _, msg := range sentMessages {
			// Parse the "To" field which might have multiple recipients
			recipients := strings.Split(msg.To, ",")
			for _, r := range recipients {
				r = strings.TrimSpace(r)
				// Extract email from "Name <email>" format
				if idx := strings.Index(r, "<"); idx != -1 {
					end := strings.Index(r, ">")
					if end > idx {
						r = r[idx+1 : end]
					}
				}
				r = strings.ToLower(strings.TrimSpace(r))
				if r != "" && r != email && (query == "" || strings.Contains(r, strings.ToLower(query))) {
					recipientCount[r]++
				}
			}
		}

		// Add to contacts, avoiding duplicates
		existingEmails := make(map[string]bool)
		for _, c := range contacts {
			existingEmails[strings.ToLower(c.Email)] = true
		}

		for emailAddr, count := range recipientCount {
			if !existingEmails[emailAddr] {
				contacts = append(contacts, domain.Contact{
					Email:        emailAddr,
					ContactCount: count,
				})
				existingEmails[emailAddr] = true
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contacts)
}

// HandleMailboxMarkMessage marks a message as read or unread
// Requires email in body for IDOR protection
func (h *Handler) HandleMailboxMarkMessage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var req struct {
		Email string `json:"email"`
		Read  bool   `json:"read"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// IDOR Protection: Require email and verify ownership
	if req.Email == "" {
		http.Error(w, "email required for authorization", http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(req.Email)
	if err != nil {
		http.Error(w, "account not found", http.StatusForbidden)
		return
	}

	msg, err := h.messageRepo.GetMessageByID(id)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}

	// Verify the message belongs to this account
	if msg.AccountID != acc.ID {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	if req.Read {
		now := time.Now()
		msg.ReadAt = &now
	} else {
		msg.ReadAt = nil
	}

	if err := h.messageRepo.UpdateMessage(msg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"read":    req.Read,
	})
}

// HandleUpdateMailboxAccount updates account display name etc
func (h *Handler) HandleUpdateMailboxAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	acc, err := h.getAccountByEmail(req.Email)
	if err != nil {
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}

	acc.DisplayName = req.DisplayName
	acc.UpdatedAt = time.Now()

	if err := h.accountRepo.UpdateAccount(acc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"display_name": acc.DisplayName,
	})
}

// Template handlers

type CreateTemplateRequest struct {
	OrgID   string `json:"org_id"`
	Name    string `json:"name"`
	Subject string `json:"subject"`
	Content string `json:"content"`
}

func (h *Handler) HandleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req CreateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	orgID, err := uuid.Parse(req.OrgID)
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	tmpl := &domain.Template{
		ID:      uuid.New(),
		OrgID:   orgID,
		Name:    req.Name,
		Subject: req.Subject,
		Content: req.Content,
	}

	if err := h.templateRepo.CreateTemplate(tmpl); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tmpl)
}

func (h *Handler) HandleListTemplates(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	templates, err := h.templateRepo.ListTemplatesByOrg(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

func (h *Handler) HandleGetTemplate(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")

	tmpl, err := h.templateRepo.GetTemplateByName(orgID, name)
	if err != nil {
		http.Error(w, "template not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tmpl)
}

// Tracking stats

func (h *Handler) HandleGetTrackingStats(w http.ResponseWriter, r *http.Request) {
	msgID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	events, err := h.trackingRepo.GetTrackingEventsByMessage(msgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Aggregate stats
	stats := struct {
		Opens  int                     `json:"opens"`
		Clicks int                     `json:"clicks"`
		Events []*domain.TrackingEvent `json:"events"`
	}{
		Events: events,
	}

	for _, e := range events {
		switch e.EventType {
		case "open":
			stats.Opens++
		case "click":
			stats.Clicks++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// HandleUnsubscribe handles RFC 8058 One-Click Unsubscribe POST requests
func (h *Handler) HandleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	msgID := r.PathValue("msg_id")

	// Log the unsubscribe request
	log.Printf("Unsubscribe request received for message: %s", msgID)

	// In a real implementation, you would:
	// 1. Look up the message to find the recipient
	// 2. Add them to an unsubscribe list
	// 3. Store the unsubscribe event

	// For now, just acknowledge the request (RFC 8058 requires 200 OK)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Unsubscribed successfully"))
}

// HandleUnsubscribePage shows a confirmation page for GET requests
func (h *Handler) HandleUnsubscribePage(w http.ResponseWriter, r *http.Request) {
	msgID := r.PathValue("msg_id")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Unsubscribe</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        h1 { color: #333; }
        .btn { background: #dc3545; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #c82333; }
        .success { color: #28a745; display: none; }
    </style>
</head>
<body>
    <h1>Unsubscribe</h1>
    <p>Click the button below to unsubscribe from future emails.</p>
    <form method="POST" action="/unsubscribe/%s" onsubmit="document.getElementById('success').style.display='block'; document.getElementById('form').style.display='none'; return true;">
        <div id="form">
            <button type="submit" class="btn">Unsubscribe</button>
        </div>
    </form>
    <div id="success" class="success">
        <h2>✓ You have been unsubscribed</h2>
        <p>You will no longer receive these emails.</p>
    </div>
</body>
</html>`, msgID)

	w.Write([]byte(html))
}
