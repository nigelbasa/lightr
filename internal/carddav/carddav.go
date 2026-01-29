package carddav

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AddressBook represents a contacts address book
type AddressBook struct {
	ID          uuid.UUID `json:"id"`
	AccountID   uuid.UUID `json:"account_id"`
	OrgID       uuid.UUID `json:"org_id"`
	
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	
	// CardDAV properties
	AddressBookURL string `json:"addressbook_url"`
	CTag           string `json:"ctag"`
	SyncToken      string `json:"sync_token,omitempty"`
	
	// Settings
	IsDefault      bool   `json:"is_default"`
	IsReadOnly     bool   `json:"is_read_only"`
	IsShared       bool   `json:"is_shared"`
	
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Contact represents a contact (vCard)
type Contact struct {
	ID            uuid.UUID `json:"id"`
	AddressBookID uuid.UUID `json:"addressbook_id"`
	AccountID     uuid.UUID `json:"account_id"`
	
	// vCard UID
	UID           string    `json:"uid"`
	ETag          string    `json:"etag"`
	
	// Name
	FormattedName string    `json:"formatted_name"`  // FN
	FirstName     string    `json:"first_name"`
	MiddleName    string    `json:"middle_name,omitempty"`
	LastName      string    `json:"last_name"`
	Prefix        string    `json:"prefix,omitempty"`       // Mr., Mrs., etc.
	Suffix        string    `json:"suffix,omitempty"`       // Jr., III, etc.
	Nickname      string    `json:"nickname,omitempty"`
	
	// Company
	Organization  string    `json:"organization,omitempty"`
	Department    string    `json:"department,omitempty"`
	JobTitle      string    `json:"job_title,omitempty"`
	
	// Contact info
	Emails        []ContactEmail   `json:"emails,omitempty"`
	Phones        []ContactPhone   `json:"phones,omitempty"`
	Addresses     []ContactAddress `json:"addresses,omitempty"`
	URLs          []ContactURL     `json:"urls,omitempty"`
	
	// Social
	SocialProfiles []SocialProfile `json:"social_profiles,omitempty"`
	
	// Additional
	Birthday      *time.Time  `json:"birthday,omitempty"`
	Anniversary   *time.Time  `json:"anniversary,omitempty"`
	Notes         string      `json:"notes,omitempty"`
	Photo         string      `json:"photo,omitempty"`      // Base64 or URL
	PhotoType     string      `json:"photo_type,omitempty"` // JPEG, PNG, etc.
	
	// Categories/Groups
	Categories    []string    `json:"categories,omitempty"`
	
	// Instant Messaging
	IMHandles     []IMHandle  `json:"im_handles,omitempty"`
	
	// Custom fields
	CustomFields  map[string]string `json:"custom_fields,omitempty"`
	
	// Raw vCard data
	VCardData     string      `json:"-"`
	VCardVersion  string      `json:"vcard_version"` // 3.0 or 4.0
	
	// Metadata
	IsFavorite    bool        `json:"is_favorite"`
	LastContacted *time.Time  `json:"last_contacted,omitempty"`
	
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// ContactEmail represents an email address
type ContactEmail struct {
	Email   string   `json:"email"`
	Type    string   `json:"type,omitempty"`    // HOME, WORK, OTHER
	Label   string   `json:"label,omitempty"`   // Custom label
	Primary bool     `json:"primary,omitempty"`
}

// ContactPhone represents a phone number
type ContactPhone struct {
	Number  string   `json:"number"`
	Type    string   `json:"type,omitempty"`    // HOME, WORK, CELL, FAX, etc.
	Label   string   `json:"label,omitempty"`
	Primary bool     `json:"primary,omitempty"`
}

// ContactAddress represents a physical address
type ContactAddress struct {
	Street      string `json:"street,omitempty"`
	City        string `json:"city,omitempty"`
	State       string `json:"state,omitempty"`
	PostalCode  string `json:"postal_code,omitempty"`
	Country     string `json:"country,omitempty"`
	Type        string `json:"type,omitempty"`        // HOME, WORK, OTHER
	Label       string `json:"label,omitempty"`
	Primary     bool   `json:"primary,omitempty"`
}

// ContactURL represents a URL
type ContactURL struct {
	URL   string `json:"url"`
	Type  string `json:"type,omitempty"`
	Label string `json:"label,omitempty"`
}

// SocialProfile represents a social media profile
type SocialProfile struct {
	Service  string `json:"service"`   // Twitter, LinkedIn, etc.
	Username string `json:"username"`
	URL      string `json:"url,omitempty"`
}

// IMHandle represents an instant messaging handle
type IMHandle struct {
	Service string `json:"service"` // XMPP, Skype, etc.
	Handle  string `json:"handle"`
}

// ContactGroup represents a contact group
type ContactGroup struct {
	ID            uuid.UUID   `json:"id"`
	AddressBookID uuid.UUID   `json:"addressbook_id"`
	AccountID     uuid.UUID   `json:"account_id"`
	
	Name          string      `json:"name"`
	UID           string      `json:"uid"`
	ETag          string      `json:"etag"`
	
	// Member contact UIDs
	Members       []string    `json:"members,omitempty"`
	
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// CardDAVService handles contact operations
type CardDAVService struct {
	mu     sync.RWMutex
	repo   ContactRepository
	logger Logger
}

// ContactRepository interface
type ContactRepository interface {
	// Address Books
	SaveAddressBook(ctx context.Context, ab *AddressBook) error
	GetAddressBook(ctx context.Context, id uuid.UUID) (*AddressBook, error)
	GetAddressBooksForAccount(ctx context.Context, accountID uuid.UUID) ([]*AddressBook, error)
	DeleteAddressBook(ctx context.Context, id uuid.UUID) error
	UpdateCTag(ctx context.Context, addressBookID uuid.UUID) error
	
	// Contacts
	SaveContact(ctx context.Context, contact *Contact) error
	GetContact(ctx context.Context, id uuid.UUID) (*Contact, error)
	GetContactByUID(ctx context.Context, addressBookID uuid.UUID, uid string) (*Contact, error)
	GetContactsForAddressBook(ctx context.Context, addressBookID uuid.UUID) ([]*Contact, error)
	SearchContacts(ctx context.Context, accountID uuid.UUID, query string) ([]*Contact, error)
	DeleteContact(ctx context.Context, id uuid.UUID) error
	
	// Groups
	SaveGroup(ctx context.Context, group *ContactGroup) error
	GetGroup(ctx context.Context, id uuid.UUID) (*ContactGroup, error)
	GetGroupsForAddressBook(ctx context.Context, addressBookID uuid.UUID) ([]*ContactGroup, error)
	DeleteGroup(ctx context.Context, id uuid.UUID) error
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewCardDAVService creates a new CardDAV service
func NewCardDAVService(repo ContactRepository, logger Logger) *CardDAVService {
	return &CardDAVService{
		repo:   repo,
		logger: logger,
	}
}

// Address Book Management

// CreateAddressBook creates a new address book
func (s *CardDAVService) CreateAddressBook(ctx context.Context, ab *AddressBook) error {
	ab.ID = uuid.New()
	ab.CTag = generateCTag()
	ab.AddressBookURL = fmt.Sprintf("/addressbooks/%s/%s/", ab.AccountID.String(), ab.ID.String())
	ab.CreatedAt = time.Now()
	ab.UpdatedAt = time.Now()

	if err := s.repo.SaveAddressBook(ctx, ab); err != nil {
		return err
	}

	s.logger.Info("created address book", "id", ab.ID, "name", ab.Name)
	return nil
}

// GetAddressBook retrieves an address book by ID
func (s *CardDAVService) GetAddressBook(ctx context.Context, id uuid.UUID) (*AddressBook, error) {
	return s.repo.GetAddressBook(ctx, id)
}

// GetAddressBooks retrieves all address books for an account
func (s *CardDAVService) GetAddressBooks(ctx context.Context, accountID uuid.UUID) ([]*AddressBook, error) {
	return s.repo.GetAddressBooksForAccount(ctx, accountID)
}

// DeleteAddressBook deletes an address book
func (s *CardDAVService) DeleteAddressBook(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteAddressBook(ctx, id)
}

// Contact Management

// CreateContact creates a new contact
func (s *CardDAVService) CreateContact(ctx context.Context, contact *Contact) error {
	contact.ID = uuid.New()
	if contact.UID == "" {
		contact.UID = uuid.New().String()
	}
	contact.ETag = generateETag()
	contact.VCardVersion = "4.0"
	contact.CreatedAt = time.Now()
	contact.UpdatedAt = time.Now()

	// Generate formatted name if not set
	if contact.FormattedName == "" {
		contact.FormattedName = formatName(contact)
	}

	// Generate vCard data
	contact.VCardData = s.contactToVCard(contact)

	if err := s.repo.SaveContact(ctx, contact); err != nil {
		return err
	}

	// Update address book CTag
	s.repo.UpdateCTag(ctx, contact.AddressBookID)

	s.logger.Info("created contact", "id", contact.ID, "name", contact.FormattedName)
	return nil
}

// UpdateContact updates an existing contact
func (s *CardDAVService) UpdateContact(ctx context.Context, contact *Contact) error {
	contact.ETag = generateETag()
	contact.UpdatedAt = time.Now()

	if contact.FormattedName == "" {
		contact.FormattedName = formatName(contact)
	}

	contact.VCardData = s.contactToVCard(contact)

	if err := s.repo.SaveContact(ctx, contact); err != nil {
		return err
	}

	s.repo.UpdateCTag(ctx, contact.AddressBookID)
	s.logger.Info("updated contact", "id", contact.ID)
	return nil
}

// GetContact retrieves a contact by ID
func (s *CardDAVService) GetContact(ctx context.Context, id uuid.UUID) (*Contact, error) {
	return s.repo.GetContact(ctx, id)
}

// GetContactByUID retrieves a contact by its vCard UID
func (s *CardDAVService) GetContactByUID(ctx context.Context, addressBookID uuid.UUID, uid string) (*Contact, error) {
	return s.repo.GetContactByUID(ctx, addressBookID, uid)
}

// GetContacts retrieves all contacts for an address book
func (s *CardDAVService) GetContacts(ctx context.Context, addressBookID uuid.UUID) ([]*Contact, error) {
	return s.repo.GetContactsForAddressBook(ctx, addressBookID)
}

// SearchContacts searches for contacts matching a query
func (s *CardDAVService) SearchContacts(ctx context.Context, accountID uuid.UUID, query string) ([]*Contact, error) {
	return s.repo.SearchContacts(ctx, accountID, query)
}

// DeleteContact deletes a contact
func (s *CardDAVService) DeleteContact(ctx context.Context, id uuid.UUID) error {
	contact, err := s.repo.GetContact(ctx, id)
	if err != nil {
		return err
	}

	if err := s.repo.DeleteContact(ctx, id); err != nil {
		return err
	}

	s.repo.UpdateCTag(ctx, contact.AddressBookID)
	return nil
}

// ToggleFavorite toggles the favorite status of a contact
func (s *CardDAVService) ToggleFavorite(ctx context.Context, id uuid.UUID) error {
	contact, err := s.repo.GetContact(ctx, id)
	if err != nil {
		return err
	}

	contact.IsFavorite = !contact.IsFavorite
	return s.UpdateContact(ctx, contact)
}

// RecordContact records when a contact was last contacted
func (s *CardDAVService) RecordContact(ctx context.Context, id uuid.UUID) error {
	contact, err := s.repo.GetContact(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()
	contact.LastContacted = &now
	return s.UpdateContact(ctx, contact)
}

// Group Management

// CreateGroup creates a new contact group
func (s *CardDAVService) CreateGroup(ctx context.Context, group *ContactGroup) error {
	group.ID = uuid.New()
	if group.UID == "" {
		group.UID = uuid.New().String()
	}
	group.ETag = generateETag()
	group.CreatedAt = time.Now()
	group.UpdatedAt = time.Now()

	if err := s.repo.SaveGroup(ctx, group); err != nil {
		return err
	}

	s.repo.UpdateCTag(ctx, group.AddressBookID)
	return nil
}

// UpdateGroup updates a contact group
func (s *CardDAVService) UpdateGroup(ctx context.Context, group *ContactGroup) error {
	group.ETag = generateETag()
	group.UpdatedAt = time.Now()

	if err := s.repo.SaveGroup(ctx, group); err != nil {
		return err
	}

	s.repo.UpdateCTag(ctx, group.AddressBookID)
	return nil
}

// AddContactToGroup adds a contact to a group
func (s *CardDAVService) AddContactToGroup(ctx context.Context, groupID, contactID uuid.UUID) error {
	group, err := s.repo.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}

	contact, err := s.repo.GetContact(ctx, contactID)
	if err != nil {
		return err
	}

	// Check if already a member
	for _, uid := range group.Members {
		if uid == contact.UID {
			return nil // Already a member
		}
	}

	group.Members = append(group.Members, contact.UID)
	return s.UpdateGroup(ctx, group)
}

// RemoveContactFromGroup removes a contact from a group
func (s *CardDAVService) RemoveContactFromGroup(ctx context.Context, groupID, contactID uuid.UUID) error {
	group, err := s.repo.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}

	contact, err := s.repo.GetContact(ctx, contactID)
	if err != nil {
		return err
	}

	// Remove from members
	var newMembers []string
	for _, uid := range group.Members {
		if uid != contact.UID {
			newMembers = append(newMembers, uid)
		}
	}
	group.Members = newMembers

	return s.UpdateGroup(ctx, group)
}

// GetGroups retrieves all groups for an address book
func (s *CardDAVService) GetGroups(ctx context.Context, addressBookID uuid.UUID) ([]*ContactGroup, error) {
	return s.repo.GetGroupsForAddressBook(ctx, addressBookID)
}

// vCard Generation

func (s *CardDAVService) contactToVCard(contact *Contact) string {
	var sb strings.Builder

	sb.WriteString("BEGIN:VCARD\r\n")
	sb.WriteString("VERSION:4.0\r\n")

	sb.WriteString(fmt.Sprintf("UID:%s\r\n", contact.UID))
	sb.WriteString(fmt.Sprintf("FN:%s\r\n", escapeVCard(contact.FormattedName)))

	// Structured name: N:Last;First;Middle;Prefix;Suffix
	sb.WriteString(fmt.Sprintf("N:%s;%s;%s;%s;%s\r\n",
		escapeVCard(contact.LastName),
		escapeVCard(contact.FirstName),
		escapeVCard(contact.MiddleName),
		escapeVCard(contact.Prefix),
		escapeVCard(contact.Suffix)))

	if contact.Nickname != "" {
		sb.WriteString(fmt.Sprintf("NICKNAME:%s\r\n", escapeVCard(contact.Nickname)))
	}

	// Organization
	if contact.Organization != "" {
		if contact.Department != "" {
			sb.WriteString(fmt.Sprintf("ORG:%s;%s\r\n", 
				escapeVCard(contact.Organization), escapeVCard(contact.Department)))
		} else {
			sb.WriteString(fmt.Sprintf("ORG:%s\r\n", escapeVCard(contact.Organization)))
		}
	}

	if contact.JobTitle != "" {
		sb.WriteString(fmt.Sprintf("TITLE:%s\r\n", escapeVCard(contact.JobTitle)))
	}

	// Emails
	for _, email := range contact.Emails {
		typeStr := "HOME"
		if email.Type != "" {
			typeStr = strings.ToUpper(email.Type)
		}
		prefStr := ""
		if email.Primary {
			prefStr = ";PREF=1"
		}
		sb.WriteString(fmt.Sprintf("EMAIL;TYPE=%s%s:%s\r\n", typeStr, prefStr, email.Email))
	}

	// Phones
	for _, phone := range contact.Phones {
		typeStr := "HOME"
		if phone.Type != "" {
			typeStr = strings.ToUpper(phone.Type)
		}
		prefStr := ""
		if phone.Primary {
			prefStr = ";PREF=1"
		}
		sb.WriteString(fmt.Sprintf("TEL;TYPE=%s%s:%s\r\n", typeStr, prefStr, phone.Number))
	}

	// Addresses
	for _, addr := range contact.Addresses {
		typeStr := "HOME"
		if addr.Type != "" {
			typeStr = strings.ToUpper(addr.Type)
		}
		// ADR: POBox;Ext;Street;City;State;PostalCode;Country
		sb.WriteString(fmt.Sprintf("ADR;TYPE=%s:;;%s;%s;%s;%s;%s\r\n",
			typeStr,
			escapeVCard(addr.Street),
			escapeVCard(addr.City),
			escapeVCard(addr.State),
			escapeVCard(addr.PostalCode),
			escapeVCard(addr.Country)))
	}

	// URLs
	for _, url := range contact.URLs {
		sb.WriteString(fmt.Sprintf("URL:%s\r\n", url.URL))
	}

	// Birthday
	if contact.Birthday != nil {
		sb.WriteString(fmt.Sprintf("BDAY:%s\r\n", contact.Birthday.Format("20060102")))
	}

	// Anniversary
	if contact.Anniversary != nil {
		sb.WriteString(fmt.Sprintf("ANNIVERSARY:%s\r\n", contact.Anniversary.Format("20060102")))
	}

	// Notes
	if contact.Notes != "" {
		sb.WriteString(fmt.Sprintf("NOTE:%s\r\n", escapeVCard(contact.Notes)))
	}

	// Photo
	if contact.Photo != "" {
		if strings.HasPrefix(contact.Photo, "http") {
			sb.WriteString(fmt.Sprintf("PHOTO;VALUE=URI:%s\r\n", contact.Photo))
		} else {
			// Base64 encoded
			mediaType := "image/jpeg"
			if contact.PhotoType != "" {
				mediaType = "image/" + strings.ToLower(contact.PhotoType)
			}
			sb.WriteString(fmt.Sprintf("PHOTO;ENCODING=b;TYPE=%s:%s\r\n", mediaType, contact.Photo))
		}
	}

	// Categories
	if len(contact.Categories) > 0 {
		sb.WriteString(fmt.Sprintf("CATEGORIES:%s\r\n", strings.Join(contact.Categories, ",")))
	}

	// Social profiles
	for _, profile := range contact.SocialProfiles {
		sb.WriteString(fmt.Sprintf("X-SOCIALPROFILE;TYPE=%s:%s\r\n", 
			strings.ToLower(profile.Service), profile.Username))
	}

	// IM handles
	for _, im := range contact.IMHandles {
		sb.WriteString(fmt.Sprintf("IMPP:%s:%s\r\n", 
			strings.ToLower(im.Service), im.Handle))
	}

	// Revision timestamp
	sb.WriteString(fmt.Sprintf("REV:%s\r\n", contact.UpdatedAt.UTC().Format("20060102T150405Z")))

	sb.WriteString("END:VCARD\r\n")

	return sb.String()
}

// Helpers

func generateCTag() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func generateETag() string {
	return fmt.Sprintf("\"%s\"", uuid.New().String()[:8])
}

func formatName(contact *Contact) string {
	parts := []string{}
	if contact.Prefix != "" {
		parts = append(parts, contact.Prefix)
	}
	if contact.FirstName != "" {
		parts = append(parts, contact.FirstName)
	}
	if contact.MiddleName != "" {
		parts = append(parts, contact.MiddleName)
	}
	if contact.LastName != "" {
		parts = append(parts, contact.LastName)
	}
	if contact.Suffix != "" {
		parts = append(parts, contact.Suffix)
	}
	if len(parts) == 0 && contact.Organization != "" {
		return contact.Organization
	}
	return strings.Join(parts, " ")
}

func escapeVCard(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, ";", "\\;")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// SQLite Repository

// SQLiteContactRepository implements ContactRepository
type SQLiteContactRepository struct {
	db *sql.DB
}

// NewSQLiteContactRepository creates a new repository
func NewSQLiteContactRepository(db *sql.DB) (*SQLiteContactRepository, error) {
	repo := &SQLiteContactRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteContactRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS address_books (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			addressbook_url TEXT NOT NULL,
			ctag TEXT NOT NULL,
			sync_token TEXT,
			is_default INTEGER DEFAULT 0,
			is_read_only INTEGER DEFAULT 0,
			is_shared INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS contacts (
			id TEXT PRIMARY KEY,
			addressbook_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			uid TEXT NOT NULL,
			etag TEXT NOT NULL,
			formatted_name TEXT NOT NULL,
			first_name TEXT,
			middle_name TEXT,
			last_name TEXT,
			prefix TEXT,
			suffix TEXT,
			nickname TEXT,
			organization TEXT,
			department TEXT,
			job_title TEXT,
			emails TEXT,
			phones TEXT,
			addresses TEXT,
			urls TEXT,
			social_profiles TEXT,
			birthday DATETIME,
			anniversary DATETIME,
			notes TEXT,
			photo TEXT,
			photo_type TEXT,
			categories TEXT,
			im_handles TEXT,
			custom_fields TEXT,
			vcard_data TEXT,
			vcard_version TEXT DEFAULT '4.0',
			is_favorite INTEGER DEFAULT 0,
			last_contacted DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(addressbook_id, uid)
		)`,
		
		`CREATE TABLE IF NOT EXISTS contact_groups (
			id TEXT PRIMARY KEY,
			addressbook_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			name TEXT NOT NULL,
			uid TEXT NOT NULL,
			etag TEXT NOT NULL,
			members TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(addressbook_id, uid)
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_addressbook_account ON address_books(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_contact_addressbook ON contacts(addressbook_id)`,
		`CREATE INDEX IF NOT EXISTS idx_contact_account ON contacts(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_contact_name ON contacts(formatted_name)`,
		`CREATE INDEX IF NOT EXISTS idx_group_addressbook ON contact_groups(addressbook_id)`,
		
		// Full-text search for contacts
		`CREATE VIRTUAL TABLE IF NOT EXISTS contacts_fts USING fts5(
			contact_id,
			formatted_name,
			organization,
			emails,
			phones,
			notes,
			content='contacts',
			content_rowid='rowid'
		)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// Address Book methods

func (r *SQLiteContactRepository) SaveAddressBook(ctx context.Context, ab *AddressBook) error {
	query := `
	INSERT INTO address_books (
		id, account_id, org_id, name, description, addressbook_url,
		ctag, sync_token, is_default, is_read_only, is_shared, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		name = excluded.name,
		description = excluded.description,
		ctag = excluded.ctag,
		sync_token = excluded.sync_token,
		is_default = excluded.is_default,
		is_read_only = excluded.is_read_only,
		is_shared = excluded.is_shared,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		ab.ID.String(), ab.AccountID.String(), ab.OrgID.String(), ab.Name,
		ab.Description, ab.AddressBookURL, ab.CTag, ab.SyncToken,
		ab.IsDefault, ab.IsReadOnly, ab.IsShared, ab.CreatedAt, ab.UpdatedAt)

	return err
}

func (r *SQLiteContactRepository) GetAddressBook(ctx context.Context, id uuid.UUID) (*AddressBook, error) {
	query := `
	SELECT id, account_id, org_id, name, description, addressbook_url,
		ctag, sync_token, is_default, is_read_only, is_shared, created_at, updated_at
	FROM address_books WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())

	var ab AddressBook
	var idStr, accountIDStr, orgIDStr string

	err := row.Scan(&idStr, &accountIDStr, &orgIDStr, &ab.Name, &ab.Description,
		&ab.AddressBookURL, &ab.CTag, &ab.SyncToken, &ab.IsDefault,
		&ab.IsReadOnly, &ab.IsShared, &ab.CreatedAt, &ab.UpdatedAt)
	if err != nil {
		return nil, err
	}

	ab.ID, _ = uuid.Parse(idStr)
	ab.AccountID, _ = uuid.Parse(accountIDStr)
	ab.OrgID, _ = uuid.Parse(orgIDStr)

	return &ab, nil
}

func (r *SQLiteContactRepository) GetAddressBooksForAccount(ctx context.Context, accountID uuid.UUID) ([]*AddressBook, error) {
	query := `
	SELECT id, account_id, org_id, name, description, addressbook_url,
		ctag, sync_token, is_default, is_read_only, is_shared, created_at, updated_at
	FROM address_books WHERE account_id = ?
	`
	rows, err := r.db.QueryContext(ctx, query, accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var books []*AddressBook
	for rows.Next() {
		var ab AddressBook
		var idStr, accountIDStr, orgIDStr string

		err := rows.Scan(&idStr, &accountIDStr, &orgIDStr, &ab.Name, &ab.Description,
			&ab.AddressBookURL, &ab.CTag, &ab.SyncToken, &ab.IsDefault,
			&ab.IsReadOnly, &ab.IsShared, &ab.CreatedAt, &ab.UpdatedAt)
		if err != nil {
			return nil, err
		}

		ab.ID, _ = uuid.Parse(idStr)
		ab.AccountID, _ = uuid.Parse(accountIDStr)
		ab.OrgID, _ = uuid.Parse(orgIDStr)

		books = append(books, &ab)
	}
	return books, rows.Err()
}

func (r *SQLiteContactRepository) DeleteAddressBook(ctx context.Context, id uuid.UUID) error {
	// Delete contacts and groups first
	r.db.ExecContext(ctx, "DELETE FROM contacts WHERE addressbook_id = ?", id.String())
	r.db.ExecContext(ctx, "DELETE FROM contact_groups WHERE addressbook_id = ?", id.String())
	_, err := r.db.ExecContext(ctx, "DELETE FROM address_books WHERE id = ?", id.String())
	return err
}

func (r *SQLiteContactRepository) UpdateCTag(ctx context.Context, addressBookID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE address_books SET ctag = ?, updated_at = ? WHERE id = ?",
		generateCTag(), time.Now(), addressBookID.String())
	return err
}

// Contact methods

func (r *SQLiteContactRepository) SaveContact(ctx context.Context, contact *Contact) error {
	emailsJSON, _ := json.Marshal(contact.Emails)
	phonesJSON, _ := json.Marshal(contact.Phones)
	addressesJSON, _ := json.Marshal(contact.Addresses)
	urlsJSON, _ := json.Marshal(contact.URLs)
	socialJSON, _ := json.Marshal(contact.SocialProfiles)
	categoriesJSON, _ := json.Marshal(contact.Categories)
	imJSON, _ := json.Marshal(contact.IMHandles)
	customJSON, _ := json.Marshal(contact.CustomFields)

	query := `
	INSERT INTO contacts (
		id, addressbook_id, account_id, uid, etag, formatted_name, first_name,
		middle_name, last_name, prefix, suffix, nickname, organization, department,
		job_title, emails, phones, addresses, urls, social_profiles, birthday,
		anniversary, notes, photo, photo_type, categories, im_handles, custom_fields,
		vcard_data, vcard_version, is_favorite, last_contacted, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(addressbook_id, uid) DO UPDATE SET
		etag = excluded.etag,
		formatted_name = excluded.formatted_name,
		first_name = excluded.first_name,
		middle_name = excluded.middle_name,
		last_name = excluded.last_name,
		prefix = excluded.prefix,
		suffix = excluded.suffix,
		nickname = excluded.nickname,
		organization = excluded.organization,
		department = excluded.department,
		job_title = excluded.job_title,
		emails = excluded.emails,
		phones = excluded.phones,
		addresses = excluded.addresses,
		urls = excluded.urls,
		social_profiles = excluded.social_profiles,
		birthday = excluded.birthday,
		anniversary = excluded.anniversary,
		notes = excluded.notes,
		photo = excluded.photo,
		photo_type = excluded.photo_type,
		categories = excluded.categories,
		im_handles = excluded.im_handles,
		custom_fields = excluded.custom_fields,
		vcard_data = excluded.vcard_data,
		is_favorite = excluded.is_favorite,
		last_contacted = excluded.last_contacted,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		contact.ID.String(), contact.AddressBookID.String(), contact.AccountID.String(),
		contact.UID, contact.ETag, contact.FormattedName, contact.FirstName,
		contact.MiddleName, contact.LastName, contact.Prefix, contact.Suffix,
		contact.Nickname, contact.Organization, contact.Department, contact.JobTitle,
		string(emailsJSON), string(phonesJSON), string(addressesJSON), string(urlsJSON),
		string(socialJSON), contact.Birthday, contact.Anniversary, contact.Notes,
		contact.Photo, contact.PhotoType, string(categoriesJSON), string(imJSON),
		string(customJSON), contact.VCardData, contact.VCardVersion, contact.IsFavorite,
		contact.LastContacted, contact.CreatedAt, contact.UpdatedAt)

	return err
}

func (r *SQLiteContactRepository) GetContact(ctx context.Context, id uuid.UUID) (*Contact, error) {
	query := `
	SELECT id, addressbook_id, account_id, uid, etag, formatted_name, first_name,
		middle_name, last_name, prefix, suffix, nickname, organization, department,
		job_title, emails, phones, addresses, urls, social_profiles, birthday,
		anniversary, notes, photo, photo_type, categories, im_handles, custom_fields,
		vcard_data, vcard_version, is_favorite, last_contacted, created_at, updated_at
	FROM contacts WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanContact(row)
}

func (r *SQLiteContactRepository) GetContactByUID(ctx context.Context, addressBookID uuid.UUID, uid string) (*Contact, error) {
	query := `
	SELECT id, addressbook_id, account_id, uid, etag, formatted_name, first_name,
		middle_name, last_name, prefix, suffix, nickname, organization, department,
		job_title, emails, phones, addresses, urls, social_profiles, birthday,
		anniversary, notes, photo, photo_type, categories, im_handles, custom_fields,
		vcard_data, vcard_version, is_favorite, last_contacted, created_at, updated_at
	FROM contacts WHERE addressbook_id = ? AND uid = ?
	`
	row := r.db.QueryRowContext(ctx, query, addressBookID.String(), uid)
	return r.scanContact(row)
}

func (r *SQLiteContactRepository) GetContactsForAddressBook(ctx context.Context, addressBookID uuid.UUID) ([]*Contact, error) {
	query := `
	SELECT id, addressbook_id, account_id, uid, etag, formatted_name, first_name,
		middle_name, last_name, prefix, suffix, nickname, organization, department,
		job_title, emails, phones, addresses, urls, social_profiles, birthday,
		anniversary, notes, photo, photo_type, categories, im_handles, custom_fields,
		vcard_data, vcard_version, is_favorite, last_contacted, created_at, updated_at
	FROM contacts WHERE addressbook_id = ?
	ORDER BY formatted_name
	`
	rows, err := r.db.QueryContext(ctx, query, addressBookID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanContacts(rows)
}

func (r *SQLiteContactRepository) SearchContacts(ctx context.Context, accountID uuid.UUID, query string) ([]*Contact, error) {
	sqlQuery := `
	SELECT c.id, c.addressbook_id, c.account_id, c.uid, c.etag, c.formatted_name, c.first_name,
		c.middle_name, c.last_name, c.prefix, c.suffix, c.nickname, c.organization, c.department,
		c.job_title, c.emails, c.phones, c.addresses, c.urls, c.social_profiles, c.birthday,
		c.anniversary, c.notes, c.photo, c.photo_type, c.categories, c.im_handles, c.custom_fields,
		c.vcard_data, c.vcard_version, c.is_favorite, c.last_contacted, c.created_at, c.updated_at
	FROM contacts c
	WHERE c.account_id = ? AND (
		c.formatted_name LIKE ? OR
		c.organization LIKE ? OR
		c.emails LIKE ? OR
		c.phones LIKE ?
	)
	ORDER BY c.formatted_name
	LIMIT 100
	`
	searchTerm := "%" + query + "%"
	rows, err := r.db.QueryContext(ctx, sqlQuery, accountID.String(), 
		searchTerm, searchTerm, searchTerm, searchTerm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanContacts(rows)
}

func (r *SQLiteContactRepository) DeleteContact(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM contacts WHERE id = ?", id.String())
	return err
}

func (r *SQLiteContactRepository) scanContact(row *sql.Row) (*Contact, error) {
	var contact Contact
	var idStr, abIDStr, accountIDStr string
	var emailsJSON, phonesJSON, addressesJSON, urlsJSON string
	var socialJSON, categoriesJSON, imJSON, customJSON string

	err := row.Scan(&idStr, &abIDStr, &accountIDStr, &contact.UID, &contact.ETag,
		&contact.FormattedName, &contact.FirstName, &contact.MiddleName,
		&contact.LastName, &contact.Prefix, &contact.Suffix, &contact.Nickname,
		&contact.Organization, &contact.Department, &contact.JobTitle,
		&emailsJSON, &phonesJSON, &addressesJSON, &urlsJSON, &socialJSON,
		&contact.Birthday, &contact.Anniversary, &contact.Notes, &contact.Photo,
		&contact.PhotoType, &categoriesJSON, &imJSON, &customJSON,
		&contact.VCardData, &contact.VCardVersion, &contact.IsFavorite,
		&contact.LastContacted, &contact.CreatedAt, &contact.UpdatedAt)
	if err != nil {
		return nil, err
	}

	contact.ID, _ = uuid.Parse(idStr)
	contact.AddressBookID, _ = uuid.Parse(abIDStr)
	contact.AccountID, _ = uuid.Parse(accountIDStr)

	_ = json.Unmarshal([]byte(emailsJSON), &contact.Emails)
	_ = json.Unmarshal([]byte(phonesJSON), &contact.Phones)
	_ = json.Unmarshal([]byte(addressesJSON), &contact.Addresses)
	_ = json.Unmarshal([]byte(urlsJSON), &contact.URLs)
	_ = json.Unmarshal([]byte(socialJSON), &contact.SocialProfiles)
	_ = json.Unmarshal([]byte(categoriesJSON), &contact.Categories)
	_ = json.Unmarshal([]byte(imJSON), &contact.IMHandles)
	_ = json.Unmarshal([]byte(customJSON), &contact.CustomFields)

	return &contact, nil
}

func (r *SQLiteContactRepository) scanContacts(rows *sql.Rows) ([]*Contact, error) {
	var contacts []*Contact
	for rows.Next() {
		var contact Contact
		var idStr, abIDStr, accountIDStr string
		var emailsJSON, phonesJSON, addressesJSON, urlsJSON string
		var socialJSON, categoriesJSON, imJSON, customJSON string

		err := rows.Scan(&idStr, &abIDStr, &accountIDStr, &contact.UID, &contact.ETag,
			&contact.FormattedName, &contact.FirstName, &contact.MiddleName,
			&contact.LastName, &contact.Prefix, &contact.Suffix, &contact.Nickname,
			&contact.Organization, &contact.Department, &contact.JobTitle,
			&emailsJSON, &phonesJSON, &addressesJSON, &urlsJSON, &socialJSON,
			&contact.Birthday, &contact.Anniversary, &contact.Notes, &contact.Photo,
			&contact.PhotoType, &categoriesJSON, &imJSON, &customJSON,
			&contact.VCardData, &contact.VCardVersion, &contact.IsFavorite,
			&contact.LastContacted, &contact.CreatedAt, &contact.UpdatedAt)
		if err != nil {
			return nil, err
		}

		contact.ID, _ = uuid.Parse(idStr)
		contact.AddressBookID, _ = uuid.Parse(abIDStr)
		contact.AccountID, _ = uuid.Parse(accountIDStr)

		_ = json.Unmarshal([]byte(emailsJSON), &contact.Emails)
		_ = json.Unmarshal([]byte(phonesJSON), &contact.Phones)
		_ = json.Unmarshal([]byte(addressesJSON), &contact.Addresses)
		_ = json.Unmarshal([]byte(urlsJSON), &contact.URLs)
		_ = json.Unmarshal([]byte(socialJSON), &contact.SocialProfiles)
		_ = json.Unmarshal([]byte(categoriesJSON), &contact.Categories)
		_ = json.Unmarshal([]byte(imJSON), &contact.IMHandles)
		_ = json.Unmarshal([]byte(customJSON), &contact.CustomFields)

		contacts = append(contacts, &contact)
	}
	return contacts, rows.Err()
}

// Group methods

func (r *SQLiteContactRepository) SaveGroup(ctx context.Context, group *ContactGroup) error {
	membersJSON, _ := json.Marshal(group.Members)

	query := `
	INSERT INTO contact_groups (
		id, addressbook_id, account_id, name, uid, etag, members, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(addressbook_id, uid) DO UPDATE SET
		name = excluded.name,
		etag = excluded.etag,
		members = excluded.members,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		group.ID.String(), group.AddressBookID.String(), group.AccountID.String(),
		group.Name, group.UID, group.ETag, string(membersJSON),
		group.CreatedAt, group.UpdatedAt)

	return err
}

func (r *SQLiteContactRepository) GetGroup(ctx context.Context, id uuid.UUID) (*ContactGroup, error) {
	query := `
	SELECT id, addressbook_id, account_id, name, uid, etag, members, created_at, updated_at
	FROM contact_groups WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())

	var group ContactGroup
	var idStr, abIDStr, accountIDStr string
	var membersJSON string

	err := row.Scan(&idStr, &abIDStr, &accountIDStr, &group.Name, &group.UID,
		&group.ETag, &membersJSON, &group.CreatedAt, &group.UpdatedAt)
	if err != nil {
		return nil, err
	}

	group.ID, _ = uuid.Parse(idStr)
	group.AddressBookID, _ = uuid.Parse(abIDStr)
	group.AccountID, _ = uuid.Parse(accountIDStr)
	_ = json.Unmarshal([]byte(membersJSON), &group.Members)

	return &group, nil
}

func (r *SQLiteContactRepository) GetGroupsForAddressBook(ctx context.Context, addressBookID uuid.UUID) ([]*ContactGroup, error) {
	query := `
	SELECT id, addressbook_id, account_id, name, uid, etag, members, created_at, updated_at
	FROM contact_groups WHERE addressbook_id = ?
	ORDER BY name
	`
	rows, err := r.db.QueryContext(ctx, query, addressBookID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*ContactGroup
	for rows.Next() {
		var group ContactGroup
		var idStr, abIDStr, accountIDStr string
		var membersJSON string

		err := rows.Scan(&idStr, &abIDStr, &accountIDStr, &group.Name, &group.UID,
			&group.ETag, &membersJSON, &group.CreatedAt, &group.UpdatedAt)
		if err != nil {
			return nil, err
		}

		group.ID, _ = uuid.Parse(idStr)
		group.AddressBookID, _ = uuid.Parse(abIDStr)
		group.AccountID, _ = uuid.Parse(accountIDStr)
		_ = json.Unmarshal([]byte(membersJSON), &group.Members)

		groups = append(groups, &group)
	}
	return groups, rows.Err()
}

func (r *SQLiteContactRepository) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM contact_groups WHERE id = ?", id.String())
	return err
}
