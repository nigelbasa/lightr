package attachment

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// Scanner interface for virus scanning
type Scanner interface {
	Scan(data []byte, filename string) *ScanResponse
	IsAvailable() bool
}

// ScanResponse contains scan results
type ScanResponse struct {
	Status ScanStatus
	Result *ScanResult
}

// ClamAVScanner implements virus scanning using ClamAV
type ClamAVScanner struct {
	address string // clamd socket or host:port
	timeout time.Duration
}

// ClamAVConfig holds ClamAV configuration
type ClamAVConfig struct {
	Address string        // Unix socket path or TCP address (host:port)
	Timeout time.Duration // Connection timeout
}

// NewClamAVScanner creates a ClamAV scanner
func NewClamAVScanner(cfg *ClamAVConfig) *ClamAVScanner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &ClamAVScanner{
		address: cfg.Address,
		timeout: cfg.Timeout,
	}
}

// Scan scans data using ClamAV
func (s *ClamAVScanner) Scan(data []byte, filename string) *ScanResponse {
	start := time.Now()
	response := &ScanResponse{
		Status: ScanError,
		Result: &ScanResult{
			Scanner:   "ClamAV",
			ScannedAt: time.Now(),
		},
	}

	conn, err := s.connect()
	if err != nil {
		response.Result.Error = fmt.Sprintf("connect: %v", err)
		return response
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(s.timeout))

	// Send INSTREAM command
	_, err = conn.Write([]byte("nINSTREAM\n"))
	if err != nil {
		response.Result.Error = fmt.Sprintf("send command: %v", err)
		return response
	}

	// Send data in chunks
	// ClamAV expects: [4-byte size big-endian][data][4-byte zero]
	chunkSize := 2048
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// Write chunk size (big-endian)
		size := uint32(len(chunk))
		sizeBytes := []byte{
			byte(size >> 24),
			byte(size >> 16),
			byte(size >> 8),
			byte(size),
		}
		if _, err := conn.Write(sizeBytes); err != nil {
			response.Result.Error = fmt.Sprintf("send size: %v", err)
			return response
		}

		// Write chunk data
		if _, err := conn.Write(chunk); err != nil {
			response.Result.Error = fmt.Sprintf("send data: %v", err)
			return response
		}
	}

	// Send terminating zero-length chunk
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		response.Result.Error = fmt.Sprintf("send terminator: %v", err)
		return response
	}

	// Read response
	var buf bytes.Buffer
	_, err = io.Copy(&buf, conn)
	if err != nil && err != io.EOF {
		response.Result.Error = fmt.Sprintf("read response: %v", err)
		return response
	}

	result := buf.String()
	response.Result.Duration = time.Since(start).Milliseconds()

	// Parse response
	// Format: "stream: OK" or "stream: <virus name> FOUND"
	if bytes.Contains(buf.Bytes(), []byte("OK")) {
		response.Status = ScanClean
	} else if bytes.Contains(buf.Bytes(), []byte("FOUND")) {
		response.Status = ScanInfected
		// Extract virus name
		parts := bytes.Split(buf.Bytes(), []byte(": "))
		if len(parts) >= 2 {
			sig := bytes.TrimSuffix(parts[1], []byte(" FOUND\n"))
			response.Result.Signature = string(sig)
		}
	} else if bytes.Contains(buf.Bytes(), []byte("ERROR")) {
		response.Status = ScanError
		response.Result.Error = result
	}

	return response
}

// IsAvailable checks if ClamAV is reachable
func (s *ClamAVScanner) IsAvailable() bool {
	conn, err := s.connect()
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("nPING\n"))

	buf := make([]byte, 10)
	n, _ := conn.Read(buf)
	return bytes.Contains(buf[:n], []byte("PONG"))
}

func (s *ClamAVScanner) connect() (net.Conn, error) {
	// Determine connection type
	if s.address[0] == '/' {
		// Unix socket
		return net.DialTimeout("unix", s.address, s.timeout)
	}
	// TCP
	return net.DialTimeout("tcp", s.address, s.timeout)
}

// VirusTotalScanner uses VirusTotal API for scanning
type VirusTotalScanner struct {
	apiKey  string
	timeout time.Duration
}

// VirusTotalConfig holds VirusTotal configuration
type VirusTotalConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewVirusTotalScanner creates a VirusTotal scanner
func NewVirusTotalScanner(cfg *VirusTotalConfig) *VirusTotalScanner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &VirusTotalScanner{
		apiKey:  cfg.APIKey,
		timeout: cfg.Timeout,
	}
}

// Scan scans data using VirusTotal API
func (s *VirusTotalScanner) Scan(data []byte, filename string) *ScanResponse {
	response := &ScanResponse{
		Status: ScanError,
		Result: &ScanResult{
			Scanner:   "VirusTotal",
			ScannedAt: time.Now(),
		},
	}

	// First check hash to avoid re-uploading known files
	hash := fmt.Sprintf("%x", data) // simplified - would use sha256
	
	// Check if file is already known
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	_ = ctx // Would use for HTTP requests

	// VirusTotal API integration would go here
	// For now, return a placeholder
	response.Status = ScanSkipped
	response.Result.Error = "VirusTotal integration requires API implementation"
	_ = hash

	return response
}

// IsAvailable checks if VirusTotal API is accessible
func (s *VirusTotalScanner) IsAvailable() bool {
	return s.apiKey != ""
}

// CompositeScanner combines multiple scanners
type CompositeScanner struct {
	scanners []Scanner
}

// NewCompositeScanner creates a scanner that uses multiple backends
func NewCompositeScanner(scanners ...Scanner) *CompositeScanner {
	return &CompositeScanner{scanners: scanners}
}

// Scan runs all available scanners
func (s *CompositeScanner) Scan(data []byte, filename string) *ScanResponse {
	for _, scanner := range s.scanners {
		if !scanner.IsAvailable() {
			continue
		}

		result := scanner.Scan(data, filename)
		
		// If any scanner finds a virus, return immediately
		if result.Status == ScanInfected {
			return result
		}
		
		// If scan was successful (clean), continue to next scanner
		if result.Status == ScanClean {
			return result
		}
	}

	// All scanners failed or unavailable
	return &ScanResponse{
		Status: ScanSkipped,
		Result: &ScanResult{
			Scanner:   "Composite",
			ScannedAt: time.Now(),
			Error:     "no scanners available",
		},
	}
}

// IsAvailable checks if any scanner is available
func (s *CompositeScanner) IsAvailable() bool {
	for _, scanner := range s.scanners {
		if scanner.IsAvailable() {
			return true
		}
	}
	return false
}

// NoOpScanner is a scanner that always returns clean (for testing)
type NoOpScanner struct{}

// Scan always returns clean
func (s *NoOpScanner) Scan(data []byte, filename string) *ScanResponse {
	return &ScanResponse{
		Status: ScanClean,
		Result: &ScanResult{
			Scanner:   "NoOp",
			ScannedAt: time.Now(),
		},
	}
}

// IsAvailable always returns true
func (s *NoOpScanner) IsAvailable() bool {
	return true
}
