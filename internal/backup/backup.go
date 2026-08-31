package backup

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// allowedTables maps each safelisted table to its primary-key columns. The
// restore path uses these for portable ON CONFLICT clauses (works on both
// SQLite and Postgres). The safelist also prevents a crafted backup file
// from smuggling SQL via the table name.
var allowedTables = map[string][]string{
	"organizations":      {"id"},
	"domains":            {"id"},
	"accounts":           {"id"},
	"messages":           {"id"},
	"spam_feedback":      {"key_type", "key_value"},
	"aliases":            {"id"},
	"alias_reply_routes": {"token"},
	"email_queue":        {"id"},
	"bounces":            {"id"},
	"suppression_list":   {"email"},
}

// Backup creates a full backup of the lightr data
type Backup struct {
	db        *sql.DB
	dataDir   string
	outputDir string
}

// Config holds backup configuration
type Config struct {
	DB        *sql.DB
	DataDir   string // Where mail files are stored
	OutputDir string // Where to write backups
}

// New creates a backup handler
func New(cfg *Config) *Backup {
	return &Backup{
		db:        cfg.DB,
		dataDir:   cfg.DataDir,
		outputDir: cfg.OutputDir,
	}
}

// BackupMetadata contains backup information
type BackupMetadata struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Tables    []string  `json:"tables"`
	FileCount int       `json:"file_count"`
}

// Create creates a new backup
func (b *Backup) Create() (string, error) {
	// Create backup filename
	timestamp := time.Now().Format("2006-01-02T15-04-05")
	filename := filepath.Join(b.outputDir, fmt.Sprintf("lightr-backup-%s.tar.gz", timestamp))

	// Create output directory if needed
	if err := os.MkdirAll(b.outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	// Create archive file
	f, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("create backup file: %w", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	metadata := BackupMetadata{
		Version:   "1.0",
		Timestamp: time.Now().UTC(),
	}

	// Export database tables. Iterate in a stable order for reproducible
	// archives.
	tables := make([]string, 0, len(allowedTables))
	for name := range allowedTables {
		tables = append(tables, name)
	}
	sortStrings(tables)
	for _, table := range tables {
		if err := b.exportTable(tw, table); err != nil {
			// Table might not exist on older installs, skip
			continue
		}
		metadata.Tables = append(metadata.Tables, table)
	}

	// Export mail files
	fileCount, err := b.exportFiles(tw)
	if err != nil {
		return "", fmt.Errorf("export files: %w", err)
	}
	metadata.FileCount = fileCount

	// Write metadata
	metaData, _ := json.MarshalIndent(metadata, "", "  ")
	if err := b.writeToArchive(tw, "metadata.json", metaData); err != nil {
		return "", fmt.Errorf("write metadata: %w", err)
	}

	return filename, nil
}

// exportTable exports a database table to the archive
func (b *Backup) exportTable(tw *tar.Writer, table string) error {
	if _, ok := allowedTables[table]; !ok {
		return fmt.Errorf("table %q not in safelist", table)
	}
	// Query all rows. The table name is gated by allowedTables above, so the
	// interpolation here cannot smuggle SQL.
	rows, err := b.db.Query(fmt.Sprintf("SELECT * FROM %q", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return err
	}

	// Build results
	var results []map[string]interface{}
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return err
		}
		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		results = append(results, row)
	}

	// Write to archive
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	return b.writeToArchive(tw, fmt.Sprintf("db/%s.json", table), data)
}

// exportFiles exports mail files to the archive
func (b *Backup) exportFiles(tw *tar.Writer) (int, error) {
	count := 0
	
	if b.dataDir == "" {
		return 0, nil
	}

	err := filepath.Walk(b.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		// Read file
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Relative path in archive. Tar entries always use forward slashes
		// so the archive is portable across platforms.
		relPath, _ := filepath.Rel(b.dataDir, path)
		archivePath := "files/" + filepath.ToSlash(relPath)

		if err := b.writeToArchive(tw, archivePath, data); err != nil {
			return err
		}
		count++
		return nil
	})

	return count, err
}

// writeToArchive writes data to the tar archive
func (b *Backup) writeToArchive(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name:    name,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// Restore restores from a backup file
type Restore struct {
	db      *sql.DB
	driver  string
	dataDir string
}

// NewRestore creates a restore handler. driver should be "sqlite" or
// "postgres"; it controls placeholder rewriting for the destination.
func NewRestore(db *sql.DB, driver, dataDir string) *Restore {
	return &Restore{db: db, driver: driver, dataDir: dataDir}
}

// RestoreResult contains restore statistics
type RestoreResult struct {
	TablesRestored int
	FilesRestored  int
	Errors         []string
}

// FromFile restores from a backup file
func (r *Restore) FromFile(filename string) (*RestoreResult, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open backup: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	result := &RestoreResult{}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("read %s: %v", header.Name, err))
			continue
		}

		// Tar paths are POSIX. Use path/path (not filepath) so behavior is
		// stable on Windows.
		name := filepath.ToSlash(header.Name)
		switch {
		case path.Dir(name) == "db" && strings.HasSuffix(name, ".json"):
			table := strings.TrimSuffix(path.Base(name), ".json")
			if err := r.restoreTable(table, data); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("restore %s: %v", table, err))
			} else {
				result.TablesRestored++
			}
		case strings.HasPrefix(name, "files/") && len(name) > 6:
			relPath := name[6:]
			if err := r.restoreFile(relPath, data); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("restore file %s: %v", relPath, err))
			} else {
				result.FilesRestored++
			}
		}
	}

	return result, nil
}

// restoreTable restores a database table. The table name is validated against
// allowedTables, and the column set is taken from the live database schema —
// not the archive — so a crafted backup cannot inject SQL via either name.
// Uses standard ON CONFLICT upsert syntax that works on both SQLite and
// Postgres.
func (r *Restore) restoreTable(table string, data []byte) error {
	pkCols, ok := allowedTables[table]
	if !ok {
		return fmt.Errorf("table %q not in safelist", table)
	}

	var rows []map[string]interface{}
	if err := json.Unmarshal(data, &rows); err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}

	dbCols, err := r.tableColumns(table)
	if err != nil {
		return fmt.Errorf("read schema for %s: %w", table, err)
	}
	if len(dbCols) == 0 {
		return fmt.Errorf("table %s has no columns or does not exist", table)
	}

	// Only keep archive columns that exist in the live schema.
	cols := make([]string, 0, len(dbCols))
	for _, c := range dbCols {
		if _, ok := rows[0][c]; ok {
			cols = append(cols, c)
		}
	}
	if len(cols) == 0 {
		return fmt.Errorf("no overlap between archive and schema for %s", table)
	}

	pkSet := make(map[string]bool, len(pkCols))
	for _, p := range pkCols {
		pkSet[p] = true
	}

	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = fmt.Sprintf("%q", c)
	}
	quotedPK := make([]string, len(pkCols))
	for i, c := range pkCols {
		quotedPK[i] = fmt.Sprintf("%q", c)
	}

	placeholders := strings.Repeat("?,", len(cols))
	placeholders = placeholders[:len(placeholders)-1]

	// Build the ON CONFLICT (...) DO UPDATE SET ... clause, skipping the
	// primary-key columns (they can't change and Postgres rejects updates
	// to conflict-target columns).
	var updates []string
	for _, c := range cols {
		if pkSet[c] {
			continue
		}
		updates = append(updates, fmt.Sprintf("%q = EXCLUDED.%q", c, c))
	}

	var stmt string
	if len(updates) == 0 {
		// All columns are PK — fall back to DO NOTHING.
		stmt = fmt.Sprintf("INSERT INTO %q (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING",
			table, strings.Join(quoted, ","), placeholders, strings.Join(quotedPK, ","))
	} else {
		stmt = fmt.Sprintf("INSERT INTO %q (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s",
			table, strings.Join(quoted, ","), placeholders, strings.Join(quotedPK, ","),
			strings.Join(updates, ","))
	}

	stmt = bindPlaceholders(stmt, r.driver)
	prepared, err := r.db.Prepare(stmt)
	if err != nil {
		return err
	}
	defer prepared.Close()

	for _, row := range rows {
		values := make([]interface{}, len(cols))
		for i, col := range cols {
			values[i] = row[col]
		}
		if _, err := prepared.Exec(values...); err != nil {
			return err
		}
	}
	return nil
}

// bindPlaceholders rewrites `?` to `$N` for Postgres. SQLite uses `?`
// natively. The two are the only drivers lightr supports.
func bindPlaceholders(query, driver string) string {
	if driver != "postgres" {
		return query
	}
	var b strings.Builder
	arg := 1
	for _, ch := range query {
		if ch == '?' {
			fmt.Fprintf(&b, "$%d", arg)
			arg++
			continue
		}
		b.WriteRune(ch)
	}
	return b.String()
}

// tableColumns returns the column names of a table from the live schema.
// Table name is safelist-gated by the caller.
func (r *Restore) tableColumns(table string) ([]string, error) {
	rows, err := r.db.Query(fmt.Sprintf("SELECT * FROM %q LIMIT 0", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return rows.Columns()
}

// restoreFile restores a mail file under dataDir. The path must be a relative
// POSIX path that stays inside dataDir; absolute paths, drive letters, and
// "../" segments are rejected outright rather than normalized away.
func (r *Restore) restoreFile(relPath string, data []byte) error {
	rel := filepath.ToSlash(relPath)
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, ":") {
		return fmt.Errorf("rejecting unsafe path %q", relPath)
	}
	cleaned := path.Clean(rel)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return fmt.Errorf("rejecting traversal in %q", relPath)
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return fmt.Errorf("rejecting traversal in %q", relPath)
		}
	}
	fullPath := filepath.Join(r.dataDir, filepath.FromSlash(cleaned))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(fullPath, data, 0644)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

