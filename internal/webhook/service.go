package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type EventType string

const (
	EventEmailReceived EventType = "email.received"
	EventEmailBounce   EventType = "email.bounce"
	EventEmailSpam     EventType = "email.spam"
)

type Event struct {
	ID        uuid.UUID   `json:"id"`
	Type      EventType   `json:"type"`
	Payload   interface{} `json:"payload"`
	Timestamp time.Time   `json:"timestamp"`
}

type Service struct {
	client *http.Client
}

func NewService() *Service {
	return &Service{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *Service) Trigger(ctx context.Context, hookURL string, eventType EventType, payload interface{}) {
	event := Event{
		ID:        uuid.New(),
		Type:      eventType,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("failed to marshal webhook event: %v", err)
		return
	}

	// For now, we fire and forget with a simple goroutine.
	// A production system would use a persistent queue.
	go func() {
		req, err := http.NewRequest("POST", hookURL, bytes.NewBuffer(data))
		if err != nil {
			log.Printf("failed to create webhook request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			log.Printf("webhook delivery failed: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Printf("webhook returned non-200 status: %d", resp.StatusCode)
		}
	}()
}
