package attachment

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Attachment represents a stored attachment
type Attachment struct {
	ID          uuid.UUID `json:"id"`
	MessageID   uuid.UUID `json:"message_id"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	StoragePath string    `json:"-"`
	ScanStatus  ScanStatus `json:"scan_status"`
	ScanResult  *ScanResult `json:"scan_result,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// ScanStatus represents virus scan status
type ScanStatus string

const (
	ScanPending   ScanStatus = "pending"
	ScanClean     ScanStatus = "clean"
	ScanInfected  ScanStatus = "infected"
	ScanError     ScanStatus = "error"
	ScanSkipped   ScanStatus = "skipped"
)

// ScanResult contains virus scan details
type ScanResult struct {
	Scanner     string    `json:"scanner"`
	Signature   string    `json:"signature,omitempty"` // Malware name if detected
	ScannedAt   time.Time `json:"scanned_at"`
	Duration    int64     `json:"duration_ms"`
	Error       string    `json:"error,omitempty"`
}

// DangerousExtensions that should be blocked or quarantined
var DangerousExtensions = map[string]string{
	".exe":  "Windows Executable",
	".bat":  "Batch Script",
	".cmd":  "Command Script",
	".com":  "DOS Executable",
	".scr":  "Screensaver (Executable)",
	".pif":  "Program Information File",
	".vbs":  "VBScript",
	".vbe":  "Encoded VBScript",
	".js":   "JavaScript",
	".jse":  "Encoded JavaScript",
	".ws":   "Windows Script",
	".wsf":  "Windows Script File",
	".wsc":  "Windows Script Component",
	".wsh":  "Windows Script Host",
	".ps1":  "PowerShell Script",
	".ps2":  "PowerShell Script",
	".psc1": "PowerShell Console File",
	".msi":  "Windows Installer",
	".msp":  "Windows Installer Patch",
	".dll":  "Dynamic Link Library",
	".jar":  "Java Archive",
	".hta":  "HTML Application",
	".cpl":  "Control Panel Extension",
	".msc":  "Microsoft Management Console",
	".inf":  "Setup Information File",
	".reg":  "Registry File",
	".lnk":  "Shortcut",
	".scf":  "Shell Command File",
	".application": "ClickOnce Application",
}

// ArchiveExtensions that may contain hidden executables
var ArchiveExtensions = map[string]bool{
	".zip": true, ".rar": true, ".7z": true, ".tar": true,
	".gz": true, ".bz2": true, ".xz": true, ".cab": true,
	".iso": true, ".img": true, ".dmg": true,
}

// Handler processes email attachments
type Handler struct {
	storageDir string
	scanner    Scanner
	repo       Repository
	maxSize    int64
}

// Config for attachment handler
type Config struct {
	StorageDir string
	Scanner    Scanner
	MaxSize    int64 // Max attachment size in bytes
}

// NewHandler creates an attachment handler
func NewHandler(cfg *Config, repo Repository) *Handler {
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 25 * 1024 * 1024 // 25MB default
	}
	return &Handler{
		storageDir: cfg.StorageDir,
		scanner:    cfg.Scanner,
		maxSize:    cfg.MaxSize,
		repo:       repo,
	}
}

// Repository defines attachment storage
type Repository interface {
	Create(att *Attachment) error
	GetByID(id uuid.UUID) (*Attachment, error)
	GetByMessageID(messageID uuid.UUID) ([]*Attachment, error)
	UpdateScanStatus(id uuid.UUID, status ScanStatus, result *ScanResult) error
	Delete(id uuid.UUID) error
}

// ProcessResult contains processing results
type ProcessResult struct {
	Attachment *Attachment
	Blocked    bool
	BlockReason string
	Warnings   []string
}

// Process handles an incoming attachment
func (h *Handler) Process(messageID uuid.UUID, filename string, contentType string, data io.Reader) (*ProcessResult, error) {
	result := &ProcessResult{}

	// Read data into buffer for analysis
	var buf bytes.Buffer
	size, err := io.Copy(&buf, data)
	if err != nil {
		return nil, fmt.Errorf("read attachment: %w", err)
	}

	// Check size limit
	if size > h.maxSize {
		result.Blocked = true
		result.BlockReason = fmt.Sprintf("attachment too large: %d bytes (max %d)", size, h.maxSize)
		return result, nil
	}

	// Calculate hash
	hash := sha256.Sum256(buf.Bytes())
	hashStr := hex.EncodeToString(hash[:])

	// Detect content type if not provided
	if contentType == "" {
		contentType = detectContentType(filename, buf.Bytes())
	}

	// Check for dangerous extensions
	ext := strings.ToLower(filepath.Ext(filename))
	if reason, dangerous := DangerousExtensions[ext]; dangerous {
		result.Blocked = true
		result.BlockReason = fmt.Sprintf("blocked extension %s (%s)", ext, reason)
		return result, nil
	}

	// Check for extension mismatch (common malware trick)
	if warning := h.checkExtensionMismatch(filename, contentType); warning != "" {
		result.Warnings = append(result.Warnings, warning)
	}

	// Check for double extensions (e.g., document.pdf.exe)
	if warning := h.checkDoubleExtension(filename); warning != "" {
		result.Warnings = append(result.Warnings, warning)
	}

	// Create attachment record
	att := &Attachment{
		ID:          uuid.New(),
		MessageID:   messageID,
		Filename:    sanitizeFilename(filename),
		ContentType: contentType,
		Size:        size,
		SHA256:      hashStr,
		ScanStatus:  ScanPending,
		CreatedAt:   time.Now(),
	}

	// Store attachment
	storagePath, err := h.store(att.ID, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("store attachment: %w", err)
	}
	att.StoragePath = storagePath

	// Scan for viruses
	if h.scanner != nil {
		scanResult := h.scanner.Scan(buf.Bytes(), filename)
		att.ScanStatus = scanResult.Status
		att.ScanResult = scanResult.Result

		if scanResult.Status == ScanInfected {
			result.Blocked = true
			result.BlockReason = fmt.Sprintf("malware detected: %s", scanResult.Result.Signature)
			// Delete the stored file
			os.Remove(storagePath)
			return result, nil
		}
	} else {
		att.ScanStatus = ScanSkipped
	}

	// Save to database
	if err := h.repo.Create(att); err != nil {
		return nil, fmt.Errorf("save attachment: %w", err)
	}

	result.Attachment = att
	return result, nil
}

// store saves attachment to disk
func (h *Handler) store(id uuid.UUID, data []byte) (string, error) {
	// Create directory structure based on ID prefix for distribution
	dir := filepath.Join(h.storageDir, id.String()[:2], id.String()[2:4])
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	path := filepath.Join(dir, id.String())
	return path, os.WriteFile(path, data, 0644)
}

// Get retrieves an attachment's data
func (h *Handler) Get(id uuid.UUID) (io.ReadCloser, *Attachment, error) {
	att, err := h.repo.GetByID(id)
	if err != nil {
		return nil, nil, err
	}
	if att == nil {
		return nil, nil, fmt.Errorf("attachment not found")
	}

	f, err := os.Open(att.StoragePath)
	if err != nil {
		return nil, nil, err
	}

	return f, att, nil
}

// Delete removes an attachment
func (h *Handler) Delete(id uuid.UUID) error {
	att, err := h.repo.GetByID(id)
	if err != nil {
		return err
	}
	if att != nil && att.StoragePath != "" {
		os.Remove(att.StoragePath)
	}
	return h.repo.Delete(id)
}

// checkExtensionMismatch detects content-type vs extension mismatches
func (h *Handler) checkExtensionMismatch(filename, contentType string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	
	// Common mismatches that indicate potential malware
	suspiciousMismatches := map[string][]string{
		".pdf": {"application/x-executable", "application/x-msdownload"},
		".doc": {"application/x-executable", "application/x-msdownload"},
		".docx": {"application/x-executable", "application/x-msdownload"},
		".jpg": {"application/x-executable", "text/html"},
		".png": {"application/x-executable", "text/html"},
	}

	if suspicious, ok := suspiciousMismatches[ext]; ok {
		for _, ct := range suspicious {
			if strings.Contains(contentType, ct) {
				return fmt.Sprintf("content-type mismatch: file claims to be %s but content is %s", ext, contentType)
			}
		}
	}

	return ""
}

// checkDoubleExtension detects double extension tricks
func (h *Handler) checkDoubleExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) < 3 {
		return ""
	}

	// Check if the real extension is dangerous
	realExt := "." + strings.ToLower(parts[len(parts)-1])
	if _, dangerous := DangerousExtensions[realExt]; dangerous {
		fakeExt := "." + strings.ToLower(parts[len(parts)-2])
		// Common document extensions used to hide executables
		if fakeExt == ".pdf" || fakeExt == ".doc" || fakeExt == ".docx" || 
		   fakeExt == ".xls" || fakeExt == ".xlsx" || fakeExt == ".txt" {
			return fmt.Sprintf("suspicious double extension: %s hides %s", fakeExt, realExt)
		}
	}

	return ""
}

func detectContentType(filename string, data []byte) string {
	// Try to detect from extension first
	ext := filepath.Ext(filename)
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}

	// Magic number detection for common types
	if len(data) >= 4 {
		switch {
		case bytes.HasPrefix(data, []byte{0x25, 0x50, 0x44, 0x46}): // %PDF
			return "application/pdf"
		case bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}): // PK.. (ZIP/DOCX/XLSX)
			return "application/zip"
		case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}): // JPEG
			return "image/jpeg"
		case bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}): // PNG
			return "image/png"
		case bytes.HasPrefix(data, []byte{0x47, 0x49, 0x46}): // GIF
			return "image/gif"
		case bytes.HasPrefix(data, []byte{0x4D, 0x5A}): // MZ (Windows executable)
			return "application/x-msdownload"
		case bytes.HasPrefix(data, []byte{0x7F, 0x45, 0x4C, 0x46}): // ELF (Linux executable)
			return "application/x-executable"
		}
	}

	return "application/octet-stream"
}

func sanitizeFilename(filename string) string {
	// Remove path components
	filename = filepath.Base(filename)
	
	// Remove null bytes and control characters
	var result strings.Builder
	for _, r := range filename {
		if r >= 32 && r != 127 {
			result.WriteRune(r)
		}
	}
	
	// Limit length
	name := result.String()
	if len(name) > 255 {
		ext := filepath.Ext(name)
		name = name[:255-len(ext)] + ext
	}
	
	return name
}

// SQLiteRepository implements Repository
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new attachment repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) migrate() error {
	_, err := r.db.Exec(`
		CREATE TABLE IF NOT EXISTS attachments (
			id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL,
			filename TEXT NOT NULL,
			content_type TEXT,
			size INTEGER,
			sha256 TEXT,
			storage_path TEXT,
			scan_status TEXT DEFAULT 'pending',
			scan_result TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);
		CREATE INDEX IF NOT EXISTS idx_attachments_sha256 ON attachments(sha256);
		CREATE INDEX IF NOT EXISTS idx_attachments_scan_status ON attachments(scan_status);
	`)
	return err
}

func (r *SQLiteRepository) Create(att *Attachment) error {
	scanResultJSON := ""
	if att.ScanResult != nil {
		// Simple JSON encoding
		scanResultJSON = fmt.Sprintf(`{"scanner":"%s","signature":"%s","scanned_at":"%s","duration_ms":%d}`,
			att.ScanResult.Scanner, att.ScanResult.Signature, att.ScanResult.ScannedAt.Format(time.RFC3339), att.ScanResult.Duration)
	}

	_, err := r.db.Exec(`
		INSERT INTO attachments (id, message_id, filename, content_type, size, sha256, storage_path, scan_status, scan_result, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, att.ID.String(), att.MessageID.String(), att.Filename, att.ContentType, att.Size, att.SHA256, att.StoragePath, att.ScanStatus, scanResultJSON, att.CreatedAt)
	return err
}

func (r *SQLiteRepository) GetByID(id uuid.UUID) (*Attachment, error) {
	row := r.db.QueryRow(`SELECT id, message_id, filename, content_type, size, sha256, storage_path, scan_status, created_at FROM attachments WHERE id = ?`, id.String())
	
	var att Attachment
	var idStr, msgIDStr string
	err := row.Scan(&idStr, &msgIDStr, &att.Filename, &att.ContentType, &att.Size, &att.SHA256, &att.StoragePath, &att.ScanStatus, &att.CreatedAt)
	if err != nil {
		return nil, err
	}
	att.ID, _ = uuid.Parse(idStr)
	att.MessageID, _ = uuid.Parse(msgIDStr)
	return &att, nil
}

func (r *SQLiteRepository) GetByMessageID(messageID uuid.UUID) ([]*Attachment, error) {
	rows, err := r.db.Query(`SELECT id, message_id, filename, content_type, size, sha256, storage_path, scan_status, created_at FROM attachments WHERE message_id = ?`, messageID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attachments []*Attachment
	for rows.Next() {
		var att Attachment
		var idStr, msgIDStr string
		if err := rows.Scan(&idStr, &msgIDStr, &att.Filename, &att.ContentType, &att.Size, &att.SHA256, &att.StoragePath, &att.ScanStatus, &att.CreatedAt); err != nil {
			return nil, err
		}
		att.ID, _ = uuid.Parse(idStr)
		att.MessageID, _ = uuid.Parse(msgIDStr)
		attachments = append(attachments, &att)
	}
	return attachments, nil
}

func (r *SQLiteRepository) UpdateScanStatus(id uuid.UUID, status ScanStatus, result *ScanResult) error {
	scanResultJSON := ""
	if result != nil {
		scanResultJSON = fmt.Sprintf(`{"scanner":"%s","signature":"%s","scanned_at":"%s","duration_ms":%d}`,
			result.Scanner, result.Signature, result.ScannedAt.Format(time.RFC3339), result.Duration)
	}
	_, err := r.db.Exec(`UPDATE attachments SET scan_status = ?, scan_result = ? WHERE id = ?`, status, scanResultJSON, id.String())
	return err
}

func (r *SQLiteRepository) Delete(id uuid.UUID) error {
	_, err := r.db.Exec(`DELETE FROM attachments WHERE id = ?`, id.String())
	return err
}
