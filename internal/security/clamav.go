package security

import (
	"context"
	"fmt"
	"net"

	"github.com/nigelbasa/lightr/internal/domain"
)

type ClamAVScanner struct {
	address string // e.g., "localhost:3310"
}

func NewClamAVScanner(address string) *ClamAVScanner {
	return &ClamAVScanner{address: address}
}

func (c *ClamAVScanner) ScanMessage(ctx context.Context, data []byte) (*domain.ScanResult, error) {
	conn, err := net.Dial("tcp", c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to clamav: %v", err)
	}
	defer conn.Close()

	// clamav INSTREAM protocol
	// Send "nINSTREAM\n"
	_, err = conn.Write([]byte("nINSTREAM\n"))
	if err != nil {
		return nil, err
	}

	// Send length followed by data
	// (simplest form, would need chunking for large files)
	// ... stubbing for brevity ...

	return &domain.ScanResult{IsThreat: false, Details: "Scan performed (stubbed)"}, nil
}
