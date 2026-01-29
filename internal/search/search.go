package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// IndexStatus represents the indexing status of a message
type IndexStatus string

const (
	StatusPending  IndexStatus = "pending"
	StatusIndexed  IndexStatus = "indexed"
	StatusFailed   IndexStatus = "failed"
	StatusDeleted  IndexStatus = "deleted"
)

// SearchField defines searchable fields
type SearchField string

const (
	FieldAll      SearchField = "all"
	FieldFrom     SearchField = "from"
	FieldTo       SearchField = "to"
	FieldSubject  SearchField = "subject"
	FieldBody     SearchField = "body"
	FieldAttachment SearchField = "attachment"
	FieldHeaders  SearchField = "headers"
)

// IndexedMessage represents an indexed email
type IndexedMessage struct {
	ID           uuid.UUID   `json:"id"`
	MessageID    uuid.UUID   `json:"message_id"`
	AccountID    uuid.UUID   `json:"account_id"`
	OrgID        uuid.UUID   `json:"org_id"`
	
	// Searchable fields
	From         string      `json:"from"`
	To           []string    `json:"to"`
	Cc           []string    `json:"cc,omitempty"`
	Subject      string      `json:"subject"`
	BodyText     string      `json:"body_text"`       // Plain text body
	BodySnippet  string      `json:"body_snippet"`    // First ~200 chars
	AttachmentNames []string `json:"attachment_names,omitempty"`
	Headers      string      `json:"headers"`         // Searchable headers
	
	// Metadata for filtering
	Folder       string      `json:"folder"`
	HasAttachment bool       `json:"has_attachment"`
	Size         int64       `json:"size"`
	ReceivedAt   time.Time   `json:"received_at"`
	IsRead       bool        `json:"is_read"`
	IsStarred    bool        `json:"is_starred"`
	Labels       []string    `json:"labels,omitempty"`
	
	// Index metadata
	Status       IndexStatus `json:"status"`
	IndexedAt    time.Time   `json:"indexed_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
}

// SearchQuery represents a search request
type SearchQuery struct {
	Query       string            `json:"query"`
	AccountID   uuid.UUID         `json:"account_id"`
	Fields      []SearchField     `json:"fields,omitempty"`      // Fields to search
	Folder      string            `json:"folder,omitempty"`
	From        string            `json:"from,omitempty"`        // Filter by sender
	To          string            `json:"to,omitempty"`          // Filter by recipient
	DateFrom    *time.Time        `json:"date_from,omitempty"`
	DateTo      *time.Time        `json:"date_to,omitempty"`
	HasAttachment *bool           `json:"has_attachment,omitempty"`
	IsRead      *bool             `json:"is_read,omitempty"`
	IsStarred   *bool             `json:"is_starred,omitempty"`
	Labels      []string          `json:"labels,omitempty"`
	SizeMin     int64             `json:"size_min,omitempty"`
	SizeMax     int64             `json:"size_max,omitempty"`
	
	// Pagination
	Limit       int               `json:"limit,omitempty"`
	Offset      int               `json:"offset,omitempty"`
	SortBy      string            `json:"sort_by,omitempty"`     // date, relevance
	SortOrder   string            `json:"sort_order,omitempty"`  // asc, desc
}

// SearchResult represents a search result
type SearchResult struct {
	MessageID    uuid.UUID `json:"message_id"`
	AccountID    uuid.UUID `json:"account_id"`
	From         string    `json:"from"`
	To           []string  `json:"to"`
	Subject      string    `json:"subject"`
	Snippet      string    `json:"snippet"`
	Folder       string    `json:"folder"`
	HasAttachment bool     `json:"has_attachment"`
	ReceivedAt   time.Time `json:"received_at"`
	IsRead       bool      `json:"is_read"`
	IsStarred    bool      `json:"is_starred"`
	Score        float64   `json:"score"`           // Relevance score
	Highlights   map[string][]string `json:"highlights,omitempty"` // Field -> highlighted snippets
}

// SearchResults contains search results with metadata
type SearchResults struct {
	Query      string          `json:"query"`
	Total      int             `json:"total"`
	Offset     int             `json:"offset"`
	Limit      int             `json:"limit"`
	Took       time.Duration   `json:"took"`
	Results    []*SearchResult `json:"results"`
}

// Engine provides full-text search capabilities
type Engine struct {
	mu       sync.RWMutex
	repo     Repository
	indexer  Indexer
	logger   Logger
	workers  int
	queue    chan *IndexJob
	stopCh   chan struct{}
	running  bool
}

// IndexJob represents an indexing task
type IndexJob struct {
	Type      string     // "index", "update", "delete"
	MessageID uuid.UUID
	Message   *MessageContent
}

// MessageContent contains content to index
type MessageContent struct {
	ID           uuid.UUID
	AccountID    uuid.UUID
	OrgID        uuid.UUID
	From         string
	To           []string
	Cc           []string
	Subject      string
	BodyText     string
	BodyHTML     string
	Attachments  []AttachmentInfo
	Headers      map[string]string
	Folder       string
	Size         int64
	ReceivedAt   time.Time
	IsRead       bool
	IsStarred    bool
	Labels       []string
}

// AttachmentInfo contains attachment metadata
type AttachmentInfo struct {
	Filename    string
	ContentType string
	Size        int64
}

// Indexer interface for indexing operations
type Indexer interface {
	Index(ctx context.Context, msg *IndexedMessage) error
	Delete(ctx context.Context, messageID uuid.UUID) error
	Search(ctx context.Context, query *SearchQuery) (*SearchResults, error)
	Suggest(ctx context.Context, prefix string, accountID uuid.UUID, limit int) ([]string, error)
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// Repository interface
type Repository interface {
	SaveIndexedMessage(ctx context.Context, msg *IndexedMessage) error
	GetIndexedMessage(ctx context.Context, messageID uuid.UUID) (*IndexedMessage, error)
	UpdateIndexStatus(ctx context.Context, messageID uuid.UUID, status IndexStatus) error
	DeleteIndexedMessage(ctx context.Context, messageID uuid.UUID) error
	GetPendingMessages(ctx context.Context, limit int) ([]*IndexedMessage, error)
}

// NewEngine creates a new search engine
func NewEngine(repo Repository, indexer Indexer, logger Logger, workers int) *Engine {
	if workers <= 0 {
		workers = 4
	}
	return &Engine{
		repo:    repo,
		indexer: indexer,
		logger:  logger,
		workers: workers,
		queue:   make(chan *IndexJob, 1000),
		stopCh:  make(chan struct{}),
	}
}

// Start starts the indexing workers
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = true
	e.mu.Unlock()

	// Start workers
	for i := 0; i < e.workers; i++ {
		go e.worker(ctx, i)
	}

	e.logger.Info("search engine started", "workers", e.workers)
	return nil
}

// Stop stops the engine
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return
	}

	close(e.stopCh)
	e.running = false
	e.logger.Info("search engine stopped")
}

func (e *Engine) worker(ctx context.Context, id int) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case job := <-e.queue:
			e.processJob(ctx, job)
		}
	}
}

func (e *Engine) processJob(ctx context.Context, job *IndexJob) {
	switch job.Type {
	case "index":
		e.indexMessage(ctx, job.Message)
	case "delete":
		e.deleteMessage(ctx, job.MessageID)
	}
}

// IndexMessage queues a message for indexing
func (e *Engine) IndexMessage(msg *MessageContent) {
	select {
	case e.queue <- &IndexJob{Type: "index", Message: msg}:
	default:
		e.logger.Error("index queue full, dropping message", "id", msg.ID)
	}
}

// DeleteMessage queues a message for deletion from index
func (e *Engine) DeleteMessage(messageID uuid.UUID) {
	select {
	case e.queue <- &IndexJob{Type: "delete", MessageID: messageID}:
	default:
		e.logger.Error("delete queue full", "id", messageID)
	}
}

func (e *Engine) indexMessage(ctx context.Context, msg *MessageContent) {
	// Extract plain text from HTML if needed
	bodyText := msg.BodyText
	if bodyText == "" && msg.BodyHTML != "" {
		bodyText = stripHTML(msg.BodyHTML)
	}

	// Create snippet
	snippet := createSnippet(bodyText, 200)

	// Extract attachment names
	var attachmentNames []string
	for _, att := range msg.Attachments {
		attachmentNames = append(attachmentNames, att.Filename)
	}

	// Prepare searchable headers
	var headerParts []string
	for k, v := range msg.Headers {
		headerParts = append(headerParts, fmt.Sprintf("%s: %s", k, v))
	}

	indexed := &IndexedMessage{
		ID:              uuid.New(),
		MessageID:       msg.ID,
		AccountID:       msg.AccountID,
		OrgID:           msg.OrgID,
		From:            msg.From,
		To:              msg.To,
		Cc:              msg.Cc,
		Subject:         msg.Subject,
		BodyText:        bodyText,
		BodySnippet:     snippet,
		AttachmentNames: attachmentNames,
		Headers:         strings.Join(headerParts, "\n"),
		Folder:          msg.Folder,
		HasAttachment:   len(msg.Attachments) > 0,
		Size:            msg.Size,
		ReceivedAt:      msg.ReceivedAt,
		IsRead:          msg.IsRead,
		IsStarred:       msg.IsStarred,
		Labels:          msg.Labels,
		Status:          StatusIndexed,
		IndexedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Index in search backend
	if err := e.indexer.Index(ctx, indexed); err != nil {
		indexed.Status = StatusFailed
		e.logger.Error("failed to index message", "id", msg.ID, "error", err)
	}

	// Save to repository
	if err := e.repo.SaveIndexedMessage(ctx, indexed); err != nil {
		e.logger.Error("failed to save indexed message", "id", msg.ID, "error", err)
	}

	e.logger.Debug("indexed message", "id", msg.ID)
}

func (e *Engine) deleteMessage(ctx context.Context, messageID uuid.UUID) {
	if err := e.indexer.Delete(ctx, messageID); err != nil {
		e.logger.Error("failed to delete from index", "id", messageID, "error", err)
	}

	if err := e.repo.DeleteIndexedMessage(ctx, messageID); err != nil {
		e.logger.Error("failed to delete indexed message", "id", messageID, "error", err)
	}

	e.logger.Debug("deleted message from index", "id", messageID)
}

// Search performs a search
func (e *Engine) Search(ctx context.Context, query *SearchQuery) (*SearchResults, error) {
	if query.Limit == 0 {
		query.Limit = 20
	}
	if query.SortBy == "" {
		query.SortBy = "date"
	}
	if query.SortOrder == "" {
		query.SortOrder = "desc"
	}

	return e.indexer.Search(ctx, query)
}

// Suggest returns search suggestions
func (e *Engine) Suggest(ctx context.Context, prefix string, accountID uuid.UUID, limit int) ([]string, error) {
	if limit == 0 {
		limit = 10
	}
	return e.indexer.Suggest(ctx, prefix, accountID, limit)
}

// Helpers

func stripHTML(html string) string {
	// Simple HTML stripping - in production use a proper HTML parser
	re := regexp.MustCompile(`<[^>]*>`)
	text := re.ReplaceAllString(html, " ")
	
	// Decode common HTML entities
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	
	// Normalize whitespace
	re = regexp.MustCompile(`\s+`)
	text = re.ReplaceAllString(text, " ")
	
	return strings.TrimSpace(text)
}

func createSnippet(text string, maxLen int) string {
	text = strings.TrimSpace(text)
	if len(text) <= maxLen {
		return text
	}
	
	// Find last space before maxLen
	end := maxLen
	for i := maxLen - 1; i > maxLen-50 && i > 0; i-- {
		if text[i] == ' ' {
			end = i
			break
		}
	}
	
	return text[:end] + "..."
}

// SQLiteIndexer implements Indexer using SQLite FTS5
type SQLiteIndexer struct {
	db *sql.DB
}

// NewSQLiteIndexer creates a new SQLite FTS5 indexer
func NewSQLiteIndexer(db *sql.DB) (*SQLiteIndexer, error) {
	indexer := &SQLiteIndexer{db: db}
	if err := indexer.migrate(); err != nil {
		return nil, err
	}
	return indexer, nil
}

func (i *SQLiteIndexer) migrate() error {
	queries := []string{
		// Main indexed messages table
		`CREATE TABLE IF NOT EXISTS search_index (
			id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL UNIQUE,
			account_id TEXT NOT NULL,
			org_id TEXT NOT NULL,
			from_addr TEXT NOT NULL,
			to_addrs TEXT NOT NULL,
			cc_addrs TEXT,
			subject TEXT NOT NULL,
			body_text TEXT NOT NULL,
			body_snippet TEXT,
			attachment_names TEXT,
			headers TEXT,
			folder TEXT NOT NULL,
			has_attachment INTEGER DEFAULT 0,
			size INTEGER DEFAULT 0,
			received_at DATETIME NOT NULL,
			is_read INTEGER DEFAULT 0,
			is_starred INTEGER DEFAULT 0,
			labels TEXT,
			status TEXT NOT NULL DEFAULT 'pending',
			indexed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		// FTS5 virtual table for full-text search
		`CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
			message_id,
			from_addr,
			to_addrs,
			subject,
			body_text,
			attachment_names,
			headers,
			content='search_index',
			content_rowid='rowid',
			tokenize='porter unicode61'
		)`,
		
		// Triggers to keep FTS in sync
		`CREATE TRIGGER IF NOT EXISTS search_index_ai AFTER INSERT ON search_index BEGIN
			INSERT INTO search_fts(rowid, message_id, from_addr, to_addrs, subject, body_text, attachment_names, headers)
			VALUES (new.rowid, new.message_id, new.from_addr, new.to_addrs, new.subject, new.body_text, new.attachment_names, new.headers);
		END`,
		
		`CREATE TRIGGER IF NOT EXISTS search_index_ad AFTER DELETE ON search_index BEGIN
			INSERT INTO search_fts(search_fts, rowid, message_id, from_addr, to_addrs, subject, body_text, attachment_names, headers)
			VALUES ('delete', old.rowid, old.message_id, old.from_addr, old.to_addrs, old.subject, old.body_text, old.attachment_names, old.headers);
		END`,
		
		`CREATE TRIGGER IF NOT EXISTS search_index_au AFTER UPDATE ON search_index BEGIN
			INSERT INTO search_fts(search_fts, rowid, message_id, from_addr, to_addrs, subject, body_text, attachment_names, headers)
			VALUES ('delete', old.rowid, old.message_id, old.from_addr, old.to_addrs, old.subject, old.body_text, old.attachment_names, old.headers);
			INSERT INTO search_fts(rowid, message_id, from_addr, to_addrs, subject, body_text, attachment_names, headers)
			VALUES (new.rowid, new.message_id, new.from_addr, new.to_addrs, new.subject, new.body_text, new.attachment_names, new.headers);
		END`,
		
		`CREATE INDEX IF NOT EXISTS idx_search_account ON search_index(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_search_folder ON search_index(account_id, folder)`,
		`CREATE INDEX IF NOT EXISTS idx_search_date ON search_index(account_id, received_at)`,
	}

	for _, q := range queries {
		if _, err := i.db.Exec(q); err != nil {
			// Ignore errors for triggers that may already exist
			if !strings.Contains(err.Error(), "already exists") {
				return err
			}
		}
	}
	return nil
}

func (i *SQLiteIndexer) Index(ctx context.Context, msg *IndexedMessage) error {
	toJSON, _ := json.Marshal(msg.To)
	ccJSON, _ := json.Marshal(msg.Cc)
	attachJSON, _ := json.Marshal(msg.AttachmentNames)
	labelsJSON, _ := json.Marshal(msg.Labels)

	query := `
	INSERT INTO search_index (
		id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, subject,
		body_text, body_snippet, attachment_names, headers, folder, has_attachment,
		size, received_at, is_read, is_starred, labels, status, indexed_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(message_id) DO UPDATE SET
		from_addr = excluded.from_addr,
		to_addrs = excluded.to_addrs,
		cc_addrs = excluded.cc_addrs,
		subject = excluded.subject,
		body_text = excluded.body_text,
		body_snippet = excluded.body_snippet,
		attachment_names = excluded.attachment_names,
		headers = excluded.headers,
		folder = excluded.folder,
		has_attachment = excluded.has_attachment,
		size = excluded.size,
		is_read = excluded.is_read,
		is_starred = excluded.is_starred,
		labels = excluded.labels,
		status = excluded.status,
		updated_at = excluded.updated_at
	`

	_, err := i.db.ExecContext(ctx, query,
		msg.ID.String(), msg.MessageID.String(), msg.AccountID.String(), msg.OrgID.String(),
		msg.From, string(toJSON), string(ccJSON), msg.Subject, msg.BodyText, msg.BodySnippet,
		string(attachJSON), msg.Headers, msg.Folder, msg.HasAttachment, msg.Size,
		msg.ReceivedAt, msg.IsRead, msg.IsStarred, string(labelsJSON), msg.Status,
		msg.IndexedAt, msg.UpdatedAt)

	return err
}

func (i *SQLiteIndexer) Delete(ctx context.Context, messageID uuid.UUID) error {
	_, err := i.db.ExecContext(ctx, "DELETE FROM search_index WHERE message_id = ?", messageID.String())
	return err
}

func (i *SQLiteIndexer) Search(ctx context.Context, query *SearchQuery) (*SearchResults, error) {
	start := time.Now()

	// Build the search query
	var conditions []string
	var args []interface{}

	// Account filter (required)
	conditions = append(conditions, "si.account_id = ?")
	args = append(args, query.AccountID.String())

	// Folder filter
	if query.Folder != "" {
		conditions = append(conditions, "si.folder = ?")
		args = append(args, query.Folder)
	}

	// Date filters
	if query.DateFrom != nil {
		conditions = append(conditions, "si.received_at >= ?")
		args = append(args, *query.DateFrom)
	}
	if query.DateTo != nil {
		conditions = append(conditions, "si.received_at <= ?")
		args = append(args, *query.DateTo)
	}

	// Boolean filters
	if query.HasAttachment != nil {
		conditions = append(conditions, "si.has_attachment = ?")
		if *query.HasAttachment {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}
	if query.IsRead != nil {
		conditions = append(conditions, "si.is_read = ?")
		if *query.IsRead {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}
	if query.IsStarred != nil {
		conditions = append(conditions, "si.is_starred = ?")
		if *query.IsStarred {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}

	// Size filters
	if query.SizeMin > 0 {
		conditions = append(conditions, "si.size >= ?")
		args = append(args, query.SizeMin)
	}
	if query.SizeMax > 0 {
		conditions = append(conditions, "si.size <= ?")
		args = append(args, query.SizeMax)
	}

	// From filter
	if query.From != "" {
		conditions = append(conditions, "si.from_addr LIKE ?")
		args = append(args, "%"+query.From+"%")
	}

	// To filter
	if query.To != "" {
		conditions = append(conditions, "si.to_addrs LIKE ?")
		args = append(args, "%"+query.To+"%")
	}

	// Full-text search
	var ftsJoin string
	if query.Query != "" {
		// Build FTS query based on fields
		ftsQuery := i.buildFTSQuery(query.Query, query.Fields)
		ftsJoin = "JOIN search_fts ON search_fts.rowid = si.rowid"
		conditions = append(conditions, "search_fts MATCH ?")
		args = append(args, ftsQuery)
	}

	// Build ORDER BY
	orderBy := "si.received_at DESC"
	if query.SortBy == "relevance" && query.Query != "" {
		orderBy = "rank, si.received_at DESC"
	} else if query.SortOrder == "asc" {
		orderBy = "si.received_at ASC"
	}

	// Count total
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM search_index si %s WHERE %s
	`, ftsJoin, strings.Join(conditions, " AND "))

	var total int
	if err := i.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, err
	}

	// Get results
	var selectQuery string
	if query.Query != "" {
		selectQuery = fmt.Sprintf(`
			SELECT si.message_id, si.account_id, si.from_addr, si.to_addrs, si.subject,
				   si.body_snippet, si.folder, si.has_attachment, si.received_at,
				   si.is_read, si.is_starred, rank
			FROM search_index si %s
			WHERE %s
			ORDER BY %s
			LIMIT ? OFFSET ?
		`, ftsJoin, strings.Join(conditions, " AND "), orderBy)
	} else {
		selectQuery = fmt.Sprintf(`
			SELECT si.message_id, si.account_id, si.from_addr, si.to_addrs, si.subject,
				   si.body_snippet, si.folder, si.has_attachment, si.received_at,
				   si.is_read, si.is_starred, 0 as rank
			FROM search_index si
			WHERE %s
			ORDER BY %s
			LIMIT ? OFFSET ?
		`, strings.Join(conditions, " AND "), orderBy)
	}

	args = append(args, query.Limit, query.Offset)

	rows, err := i.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*SearchResult
	for rows.Next() {
		var r SearchResult
		var messageIDStr, accountIDStr string
		var toJSON string
		var rank float64

		err := rows.Scan(&messageIDStr, &accountIDStr, &r.From, &toJSON, &r.Subject,
			&r.Snippet, &r.Folder, &r.HasAttachment, &r.ReceivedAt,
			&r.IsRead, &r.IsStarred, &rank)
		if err != nil {
			return nil, err
		}

		r.MessageID, _ = uuid.Parse(messageIDStr)
		r.AccountID, _ = uuid.Parse(accountIDStr)
		_ = json.Unmarshal([]byte(toJSON), &r.To)
		r.Score = -rank // FTS5 rank is negative, lower is better

		results = append(results, &r)
	}

	return &SearchResults{
		Query:   query.Query,
		Total:   total,
		Offset:  query.Offset,
		Limit:   query.Limit,
		Took:    time.Since(start),
		Results: results,
	}, nil
}

func (i *SQLiteIndexer) buildFTSQuery(query string, fields []SearchField) string {
	// If no specific fields, search all
	if len(fields) == 0 || containsField(fields, FieldAll) {
		return query
	}

	// Build column-specific query
	var parts []string
	for _, field := range fields {
		var col string
		switch field {
		case FieldFrom:
			col = "from_addr"
		case FieldTo:
			col = "to_addrs"
		case FieldSubject:
			col = "subject"
		case FieldBody:
			col = "body_text"
		case FieldAttachment:
			col = "attachment_names"
		case FieldHeaders:
			col = "headers"
		default:
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s", col, query))
	}

	if len(parts) == 0 {
		return query
	}

	return strings.Join(parts, " OR ")
}

func (i *SQLiteIndexer) Suggest(ctx context.Context, prefix string, accountID uuid.UUID, limit int) ([]string, error) {
	// Simple suggestion based on subject words
	query := `
		SELECT DISTINCT word FROM (
			SELECT DISTINCT subject as word FROM search_index 
			WHERE account_id = ? AND subject LIKE ?
			UNION
			SELECT DISTINCT from_addr as word FROM search_index
			WHERE account_id = ? AND from_addr LIKE ?
		) ORDER BY word LIMIT ?
	`

	prefixPattern := prefix + "%"
	rows, err := i.db.QueryContext(ctx, query, 
		accountID.String(), prefixPattern,
		accountID.String(), prefixPattern,
		limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var suggestions []string
	for rows.Next() {
		var word string
		if err := rows.Scan(&word); err != nil {
			return nil, err
		}
		suggestions = append(suggestions, word)
	}

	return suggestions, nil
}

func containsField(fields []SearchField, target SearchField) bool {
	for _, f := range fields {
		if f == target {
			return true
		}
	}
	return false
}

// SQLiteRepository implements Repository
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new repository
func NewSQLiteRepository(db *sql.DB) *SQLiteRepository {
	return &SQLiteRepository{db: db}
}

func (r *SQLiteRepository) SaveIndexedMessage(ctx context.Context, msg *IndexedMessage) error {
	toJSON, _ := json.Marshal(msg.To)
	ccJSON, _ := json.Marshal(msg.Cc)
	attachJSON, _ := json.Marshal(msg.AttachmentNames)
	labelsJSON, _ := json.Marshal(msg.Labels)

	query := `
	INSERT INTO search_index (
		id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, subject,
		body_text, body_snippet, attachment_names, headers, folder, has_attachment,
		size, received_at, is_read, is_starred, labels, status, indexed_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(message_id) DO UPDATE SET
		status = excluded.status,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		msg.ID.String(), msg.MessageID.String(), msg.AccountID.String(), msg.OrgID.String(),
		msg.From, string(toJSON), string(ccJSON), msg.Subject, msg.BodyText, msg.BodySnippet,
		string(attachJSON), msg.Headers, msg.Folder, msg.HasAttachment, msg.Size,
		msg.ReceivedAt, msg.IsRead, msg.IsStarred, string(labelsJSON), msg.Status,
		msg.IndexedAt, msg.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetIndexedMessage(ctx context.Context, messageID uuid.UUID) (*IndexedMessage, error) {
	query := `
	SELECT id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, subject,
		body_text, body_snippet, attachment_names, headers, folder, has_attachment,
		size, received_at, is_read, is_starred, labels, status, indexed_at, updated_at
	FROM search_index WHERE message_id = ?
	`
	row := r.db.QueryRowContext(ctx, query, messageID.String())

	var msg IndexedMessage
	var idStr, messageIDStr, accountIDStr, orgIDStr string
	var toJSON, ccJSON, attachJSON, labelsJSON string

	err := row.Scan(&idStr, &messageIDStr, &accountIDStr, &orgIDStr, &msg.From,
		&toJSON, &ccJSON, &msg.Subject, &msg.BodyText, &msg.BodySnippet,
		&attachJSON, &msg.Headers, &msg.Folder, &msg.HasAttachment, &msg.Size,
		&msg.ReceivedAt, &msg.IsRead, &msg.IsStarred, &labelsJSON, &msg.Status,
		&msg.IndexedAt, &msg.UpdatedAt)
	if err != nil {
		return nil, err
	}

	msg.ID, _ = uuid.Parse(idStr)
	msg.MessageID, _ = uuid.Parse(messageIDStr)
	msg.AccountID, _ = uuid.Parse(accountIDStr)
	msg.OrgID, _ = uuid.Parse(orgIDStr)
	_ = json.Unmarshal([]byte(toJSON), &msg.To)
	_ = json.Unmarshal([]byte(ccJSON), &msg.Cc)
	_ = json.Unmarshal([]byte(attachJSON), &msg.AttachmentNames)
	_ = json.Unmarshal([]byte(labelsJSON), &msg.Labels)

	return &msg, nil
}

func (r *SQLiteRepository) UpdateIndexStatus(ctx context.Context, messageID uuid.UUID, status IndexStatus) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE search_index SET status = ?, updated_at = ? WHERE message_id = ?",
		status, time.Now(), messageID.String())
	return err
}

func (r *SQLiteRepository) DeleteIndexedMessage(ctx context.Context, messageID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM search_index WHERE message_id = ?", messageID.String())
	return err
}

func (r *SQLiteRepository) GetPendingMessages(ctx context.Context, limit int) ([]*IndexedMessage, error) {
	query := `
	SELECT id, message_id, account_id, org_id, from_addr, to_addrs, cc_addrs, subject,
		body_text, body_snippet, attachment_names, headers, folder, has_attachment,
		size, received_at, is_read, is_starred, labels, status, indexed_at, updated_at
	FROM search_index WHERE status = 'pending' LIMIT ?
	`
	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*IndexedMessage
	for rows.Next() {
		var msg IndexedMessage
		var idStr, messageIDStr, accountIDStr, orgIDStr string
		var toJSON, ccJSON, attachJSON, labelsJSON string

		err := rows.Scan(&idStr, &messageIDStr, &accountIDStr, &orgIDStr, &msg.From,
			&toJSON, &ccJSON, &msg.Subject, &msg.BodyText, &msg.BodySnippet,
			&attachJSON, &msg.Headers, &msg.Folder, &msg.HasAttachment, &msg.Size,
			&msg.ReceivedAt, &msg.IsRead, &msg.IsStarred, &labelsJSON, &msg.Status,
			&msg.IndexedAt, &msg.UpdatedAt)
		if err != nil {
			return nil, err
		}

		msg.ID, _ = uuid.Parse(idStr)
		msg.MessageID, _ = uuid.Parse(messageIDStr)
		msg.AccountID, _ = uuid.Parse(accountIDStr)
		msg.OrgID, _ = uuid.Parse(orgIDStr)
		_ = json.Unmarshal([]byte(toJSON), &msg.To)
		_ = json.Unmarshal([]byte(ccJSON), &msg.Cc)
		_ = json.Unmarshal([]byte(attachJSON), &msg.AttachmentNames)
		_ = json.Unmarshal([]byte(labelsJSON), &msg.Labels)

		messages = append(messages, &msg)
	}

	return messages, rows.Err()
}
