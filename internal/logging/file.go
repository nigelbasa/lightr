package logging

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileWriter writes logs to files with rotation
type FileWriter struct {
	dir         string
	prefix      string
	maxSize     int64 // bytes
	maxAge      int   // days
	currentFile *os.File
	currentSize int64
	mu          sync.Mutex
}

// FileWriterConfig holds file writer configuration
type FileWriterConfig struct {
	Dir     string // Log directory
	Prefix  string // File prefix (e.g., "lightr")
	MaxSize int64  // Max file size in MB before rotation
	MaxAge  int    // Max days to keep old files
}

// NewFileWriter creates a rotating file writer
func NewFileWriter(cfg *FileWriterConfig) (*FileWriter, error) {
	if cfg.Dir == "" {
		cfg.Dir = "/var/log/lightr"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "lightr"
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 100 // 100MB default
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 30 // 30 days default
	}

	// Create directory if needed
	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, err
	}

	fw := &FileWriter{
		dir:     cfg.Dir,
		prefix:  cfg.Prefix,
		maxSize: cfg.MaxSize * 1024 * 1024, // Convert MB to bytes
		maxAge:  cfg.MaxAge,
	}

	if err := fw.rotate(); err != nil {
		return nil, err
	}

	return fw, nil
}

// Write implements io.Writer
func (fw *FileWriter) Write(p []byte) (n int, err error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// Check if rotation needed
	if fw.currentSize+int64(len(p)) > fw.maxSize {
		if err := fw.rotate(); err != nil {
			return 0, err
		}
	}

	n, err = fw.currentFile.Write(p)
	fw.currentSize += int64(n)
	return
}

// rotate creates a new log file
func (fw *FileWriter) rotate() error {
	// Close current file
	if fw.currentFile != nil {
		fw.currentFile.Close()
	}

	// Create new file with timestamp
	filename := filepath.Join(fw.dir, 
		fw.prefix+"-"+time.Now().Format("2006-01-02T15-04-05")+".log")
	
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	fw.currentFile = f
	fw.currentSize = 0

	// Cleanup old files in background
	go fw.cleanup()

	return nil
}

// cleanup removes old log files
func (fw *FileWriter) cleanup() {
	cutoff := time.Now().AddDate(0, 0, -fw.maxAge)

	entries, err := os.ReadDir(fw.dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(fw.dir, entry.Name()))
		}
	}
}

// Close closes the file writer
func (fw *FileWriter) Close() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.currentFile != nil {
		return fw.currentFile.Close()
	}
	return nil
}

// MultiWriter writes to multiple outputs
type MultiWriter struct {
	writers []io.Writer
}

// NewMultiWriter creates a multi-output writer
func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

func (mw *MultiWriter) Write(p []byte) (n int, err error) {
	for _, w := range mw.writers {
		n, err = w.Write(p)
		if err != nil {
			return
		}
	}
	return len(p), nil
}

// ParseLevel parses log level from string
func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}
