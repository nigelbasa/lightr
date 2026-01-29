package domain

import (
	"context"
)

type ScanResult struct {
	IsThreat bool    `json:"is_threat"`
	Score    float64 `json:"score"`
	Details  string  `json:"details"`
}

type MalwareScanner interface {
	ScanMessage(ctx context.Context, data []byte) (*ScanResult, error)
}

type SpamScanner interface {
	CheckSpam(ctx context.Context, data []byte) (*ScanResult, error)
}
