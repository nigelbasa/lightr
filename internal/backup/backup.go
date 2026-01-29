package backup

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

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

	// Export database tables
	tables := []string{
		"accounts", "messages", "mailboxes", "aliases",
		"queue", "bounces", "suppression_list",
	}
	for _, table := range tables {
		if err := b.exportTable(tw, table); err != nil {
			// Table might not exist, skip
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
	// Query all rows
	rows, err := b.db.Query(fmt.Sprintf("SELECT * FROM %s", table))
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

		// Relative path in archive
		relPath, _ := filepath.Rel(b.dataDir, path)
		archivePath := filepath.Join("files", relPath)

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
	dataDir string
}

// NewRestore creates a restore handler
func NewRestore(db *sql.DB, dataDir string) *Restore {
	return &Restore{db: db, dataDir: dataDir}
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

		// Handle different file types
		if filepath.Dir(header.Name) == "db" {
			table := filepath.Base(header.Name)
			table = table[:len(table)-5] // Remove .json
			if err := r.restoreTable(table, data); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("restore %s: %v", table, err))
			} else {
				result.TablesRestored++
			}
		} else if len(header.Name) > 6 && header.Name[:6] == "files/" {
			relPath := header.Name[6:]
			if err := r.restoreFile(relPath, data); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("restore file %s: %v", relPath, err))
			} else {
				result.FilesRestored++
			}
		}
	}

	return result, nil
}

// restoreTable restores a database table
func (r *Restore) restoreTable(table string, data []byte) error {
	var rows []map[string]interface{}
	if err := json.Unmarshal(data, &rows); err != nil {
		return err
	}

	if len(rows) == 0 {
		return nil
	}

	// Get column names from first row
	var columns []string
	for col := range rows[0] {
		columns = append(columns, col)
	}

	// Build insert statement
	placeholders := ""
	for i := range columns {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
	}

	stmt := fmt.Sprintf("INSERT OR REPLACE INTO %s (%s) VALUES (%s)",
		table,
		joinColumns(columns),
		placeholders,
	)

	prepared, err := r.db.Prepare(stmt)
	if err != nil {
		return err
	}
	defer prepared.Close()

	// Insert rows
	for _, row := range rows {
		values := make([]interface{}, len(columns))
		for i, col := range columns {
			values[i] = row[col]
		}
		if _, err := prepared.Exec(values...); err != nil {
			return err
		}
	}

	return nil
}

// restoreFile restores a mail file
func (r *Restore) restoreFile(relPath string, data []byte) error {
	fullPath := filepath.Join(r.dataDir, relPath)
	
	// Create directory
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}

	return os.WriteFile(fullPath, data, 0644)
}

func joinColumns(cols []string) string {
	result := ""
	for i, col := range cols {
		if i > 0 {
			result += ","
		}
		result += col
	}
	return result
}
