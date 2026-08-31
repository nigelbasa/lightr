package spam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type RspamdScanner struct {
	url      string
	password string
	client   *http.Client
}

func NewRspamdScanner(url, password string, timeout time.Duration) *RspamdScanner {
	if strings.TrimSpace(url) == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &RspamdScanner{
		url:      strings.TrimRight(url, "/"),
		password: password,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (r *RspamdScanner) Check(ctx context.Context, req *CheckRequest) (*ExternalCheckResult, error) {
	if r == nil || req == nil {
		return nil, nil
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url+"/checkv2", bytes.NewReader(req.Raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "message/rfc822")
	httpReq.Header.Set("User-Agent", "lightr-spam/1.0")
	if req.RemoteIP != "" {
		httpReq.Header.Set("IP", req.RemoteIP)
	}
	if req.Helo != "" {
		httpReq.Header.Set("Helo", req.Helo)
	}
	if req.EnvelopeFrom != "" {
		httpReq.Header.Set("From", req.EnvelopeFrom)
	}
	if req.HeaderFrom != "" {
		httpReq.Header.Set("MTA-Tag", req.HeaderFrom)
	}
	if r.password != "" {
		httpReq.Header.Set("Password", r.password)
	}

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rspamd returned %d", resp.StatusCode)
	}

	var payload struct {
		Score   float64 `json:"score"`
		Action  string  `json:"action"`
		Symbols map[string]struct {
			Name        string  `json:"name"`
			Description string  `json:"description"`
			Score       float64 `json:"score"`
		} `json:"symbols"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	result := &ExternalCheckResult{
		Source:  "rspamd",
		Score:   payload.Score,
		Verdict: payload.Action,
	}
	for key, symbol := range payload.Symbols {
		if symbol.Score <= 0 {
			continue
		}
		desc := strings.TrimSpace(symbol.Description)
		if desc == "" {
			desc = key
		}
		result.Reasons = append(result.Reasons, "rspamd: "+desc)
		if len(result.Reasons) >= 5 {
			break
		}
	}
	return result, nil
}
