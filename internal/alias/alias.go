package alias

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AliasType defines the type of alias
type AliasType string

const (
	// AliasTypeForward forwards email to one or more addresses
	AliasTypeForward AliasType = "forward"
	// AliasTypeCatchAll catches all unmatched addresses for a domain
	AliasTypeCatchAll AliasType = "catchall"
	// AliasTypeRegex matches addresses using a regex pattern
	AliasTypeRegex AliasType = "regex"
	// AliasTypeBridge mirrors mailbox traffic to an external inbox and routes replies back through lightr
	AliasTypeBridge AliasType = "bridge"
)

// Alias represents an email alias
type Alias struct {
	ID           uuid.UUID `json:"id"`
	DomainID     uuid.UUID `json:"domain_id"`
	Source       string    `json:"source"`       // e.g., "info" or "*" for catch-all
	Destinations []string  `json:"destinations"` // Target email addresses
	Type         AliasType `json:"type"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ReplyRoute struct {
	Token              string    `json:"token"`
	AliasID            uuid.UUID `json:"alias_id"`
	AccountID          uuid.UUID `json:"account_id"`
	LocalAddress       string    `json:"local_address"`
	BridgeDestinations []string  `json:"bridge_destinations"`
	OriginalFrom       string    `json:"original_from"`
	OriginalTo         string    `json:"original_to,omitempty"`
	OriginalCc         string    `json:"original_cc,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

// Repository defines alias storage operations
type Repository interface {
	Create(alias *Alias) error
	GetByID(id uuid.UUID) (*Alias, error)
	Update(alias *Alias) error
	Delete(id uuid.UUID) error
	ListByDomain(domainID uuid.UUID) ([]*Alias, error)
	FindByAddress(localPart, domain string) (*Alias, error)
}

// SQLiteRepository implements Repository using SQLite
type SQLiteRepository struct {
	db     *sql.DB
	driver string
}

// NewSQLiteRepository creates a new alias repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	return NewSQLRepository(db, "sqlite")
}

func NewPostgresRepository(db *sql.DB) (*SQLiteRepository, error) {
	return NewSQLRepository(db, "postgres")
}

func NewSQLRepository(db *sql.DB, driver string) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db, driver: driver}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) bind(query string) string {
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

func (r *SQLiteRepository) migrate() error {
	_, err := r.db.Exec(r.bind(`
		CREATE TABLE IF NOT EXISTS aliases (
			id TEXT PRIMARY KEY,
			domain_id TEXT NOT NULL,
			source TEXT NOT NULL,
			destinations TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'forward',
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(domain_id, source)
		);
		
		CREATE INDEX IF NOT EXISTS idx_aliases_domain ON aliases(domain_id);
		CREATE INDEX IF NOT EXISTS idx_aliases_source ON aliases(source);

		CREATE TABLE IF NOT EXISTS alias_reply_routes (
			token TEXT PRIMARY KEY,
			alias_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			local_address TEXT NOT NULL,
			bridge_destinations TEXT NOT NULL,
			original_from TEXT NOT NULL,
			original_to TEXT,
			original_cc TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_alias_reply_routes_alias ON alias_reply_routes(alias_id);
		CREATE INDEX IF NOT EXISTS idx_alias_reply_routes_account ON alias_reply_routes(account_id);
	`))
	return err
}

func (r *SQLiteRepository) Create(alias *Alias) error {
	destinations := strings.Join(alias.Destinations, ",")
	_, err := r.db.Exec(r.bind(`
		INSERT INTO aliases (id, domain_id, source, destinations, type, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`),
		alias.ID.String(),
		alias.DomainID.String(),
		alias.Source,
		destinations,
		string(alias.Type),
		alias.IsActive,
		alias.CreatedAt,
		alias.UpdatedAt,
	)
	return err
}

func (r *SQLiteRepository) GetByID(id uuid.UUID) (*Alias, error) {
	row := r.db.QueryRow(r.bind(`
		SELECT id, domain_id, source, destinations, type, is_active, created_at, updated_at
		FROM aliases WHERE id = ?
	`), id.String())
	return r.scanAlias(row)
}

func (r *SQLiteRepository) Update(alias *Alias) error {
	destinations := strings.Join(alias.Destinations, ",")
	alias.UpdatedAt = time.Now()
	_, err := r.db.Exec(r.bind(`
		UPDATE aliases 
		SET source = ?, destinations = ?, type = ?, is_active = ?, updated_at = ?
		WHERE id = ?
	`),
		alias.Source,
		destinations,
		string(alias.Type),
		alias.IsActive,
		alias.UpdatedAt,
		alias.ID.String(),
	)
	return err
}

func (r *SQLiteRepository) Delete(id uuid.UUID) error {
	_, err := r.db.Exec(r.bind(`DELETE FROM aliases WHERE id = ?`), id.String())
	return err
}

func (r *SQLiteRepository) ListByDomain(domainID uuid.UUID) ([]*Alias, error) {
	rows, err := r.db.Query(r.bind(`
		SELECT id, domain_id, source, destinations, type, is_active, created_at, updated_at
		FROM aliases WHERE domain_id = ? ORDER BY source
	`), domainID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var aliases []*Alias
	for rows.Next() {
		alias, err := r.scanAliasRow(rows)
		if err != nil {
			return nil, err
		}
		aliases = append(aliases, alias)
	}
	return aliases, rows.Err()
}

func (r *SQLiteRepository) FindByAddress(localPart, domainID string) (*Alias, error) {
	// First try exact match
	row := r.db.QueryRow(r.bind(`
		SELECT id, domain_id, source, destinations, type, is_active, created_at, updated_at
		FROM aliases 
		WHERE domain_id = ? AND source = ? AND is_active = TRUE
	`), domainID, localPart)

	alias, err := r.scanAlias(row)
	if err == nil {
		return alias, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	// Try regex aliases
	rows, err := r.db.Query(r.bind(`
		SELECT id, domain_id, source, destinations, type, is_active, created_at, updated_at
		FROM aliases 
		WHERE domain_id = ? AND type = 'regex' AND is_active = TRUE
	`), domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		alias, err := r.scanAliasRow(rows)
		if err != nil {
			continue
		}
		re, err := regexp.Compile(alias.Source)
		if err != nil {
			continue
		}
		if re.MatchString(localPart) {
			return alias, nil
		}
	}

	// Try catch-all
	row = r.db.QueryRow(r.bind(`
		SELECT id, domain_id, source, destinations, type, is_active, created_at, updated_at
		FROM aliases 
		WHERE domain_id = ? AND type = 'catchall' AND is_active = TRUE
	`), domainID)

	return r.scanAlias(row)
}

func (r *SQLiteRepository) scanAlias(row *sql.Row) (*Alias, error) {
	var alias Alias
	var idStr, domainIDStr, destinations, typeStr string

	err := row.Scan(
		&idStr, &domainIDStr, &alias.Source, &destinations,
		&typeStr, &alias.IsActive, &alias.CreatedAt, &alias.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	alias.ID, _ = uuid.Parse(idStr)
	alias.DomainID, _ = uuid.Parse(domainIDStr)
	alias.Destinations = strings.Split(destinations, ",")
	alias.Type = AliasType(typeStr)

	return &alias, nil
}

func (r *SQLiteRepository) scanAliasRow(rows *sql.Rows) (*Alias, error) {
	var alias Alias
	var idStr, domainIDStr, destinations, typeStr string

	err := rows.Scan(
		&idStr, &domainIDStr, &alias.Source, &destinations,
		&typeStr, &alias.IsActive, &alias.CreatedAt, &alias.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	alias.ID, _ = uuid.Parse(idStr)
	alias.DomainID, _ = uuid.Parse(domainIDStr)
	alias.Destinations = strings.Split(destinations, ",")
	alias.Type = AliasType(typeStr)

	return &alias, nil
}

func (r *SQLiteRepository) CreateReplyRoute(route *ReplyRoute) error {
	_, err := r.db.Exec(r.bind(`
		INSERT INTO alias_reply_routes (token, alias_id, account_id, local_address, bridge_destinations, original_from, original_to, original_cc, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`),
		route.Token,
		route.AliasID.String(),
		route.AccountID.String(),
		route.LocalAddress,
		strings.Join(route.BridgeDestinations, ","),
		route.OriginalFrom,
		route.OriginalTo,
		route.OriginalCc,
		route.CreatedAt,
	)
	return err
}

func (r *SQLiteRepository) GetReplyRoute(token string) (*ReplyRoute, error) {
	row := r.db.QueryRow(r.bind(`
		SELECT token, alias_id, account_id, local_address, bridge_destinations, original_from, original_to, original_cc, created_at
		FROM alias_reply_routes
		WHERE token = ?
	`), token)

	var route ReplyRoute
	var aliasID, accountID, bridgeDestinations string
	if err := row.Scan(
		&route.Token,
		&aliasID,
		&accountID,
		&route.LocalAddress,
		&bridgeDestinations,
		&route.OriginalFrom,
		&route.OriginalTo,
		&route.OriginalCc,
		&route.CreatedAt,
	); err != nil {
		return nil, err
	}

	route.AliasID, _ = uuid.Parse(aliasID)
	route.AccountID, _ = uuid.Parse(accountID)
	if strings.TrimSpace(bridgeDestinations) != "" {
		route.BridgeDestinations = strings.Split(bridgeDestinations, ",")
	}
	return &route, nil
}
