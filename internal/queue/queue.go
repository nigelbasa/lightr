package queue

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Status represents the delivery status of a queued message
type Status string

const (
	StatusPending   Status = "pending"
	StatusSending   Status = "sending"
	StatusDelivered Status = "delivered"
	StatusFailed    Status = "failed"
	StatusRetrying  Status = "retrying"
)

// QueuedMessage represents an email message in the queue
type QueuedMessage struct {
	ID           uuid.UUID       `json:"id"`
	OrgID        uuid.UUID       `json:"org_id"`
	DomainID     uuid.UUID       `json:"domain_id"`
	From         string          `json:"from"`
	To           []string        `json:"to"`
	Subject      string          `json:"subject"`
	Body         string          `json:"body"`
	HTMLBody     string          `json:"html_body,omitempty"`
	Headers      json.RawMessage `json:"headers,omitempty"`
	Status       Status          `json:"status"`
	Attempts     int             `json:"attempts"`
	MaxAttempts  int             `json:"max_attempts"`
	LastError    string          `json:"last_error,omitempty"`
	NextRetry    time.Time       `json:"next_retry"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	DeliveredAt  *time.Time      `json:"delivered_at,omitempty"`
}

// Repository defines storage operations for the queue
type Repository interface {
	// Create adds a new message to the queue
	Create(msg *QueuedMessage) error
	
	// GetPending returns messages ready for sending (status=pending or retrying with next_retry <= now)
	GetPending(ctx context.Context, limit int) ([]*QueuedMessage, error)
	
	// UpdateStatus updates the message status and metadata
	UpdateStatus(id uuid.UUID, status Status, lastError string, nextRetry *time.Time) error
	
	// MarkDelivered marks a message as successfully delivered
	MarkDelivered(id uuid.UUID) error
	
	// GetByID retrieves a queued message by ID
	GetByID(id uuid.UUID) (*QueuedMessage, error)
	
	// ListByOrg lists queued messages for an organization
	ListByOrg(orgID uuid.UUID, status *Status, limit int) ([]*QueuedMessage, error)
	
	// DeleteOld removes delivered/failed messages older than the given duration
	DeleteOld(olderThan time.Duration) (int64, error)
}

// Sender is the interface for actually sending emails
type Sender interface {
	Send(ctx context.Context, msg *QueuedMessage) error
}

// Config holds queue worker configuration
type Config struct {
	// MaxAttempts is the maximum number of delivery attempts
	MaxAttempts int
	// WorkerCount is the number of concurrent workers
	WorkerCount int
	// PollInterval is how often to check for pending messages
	PollInterval time.Duration
	// RetryBackoff calculates the delay for the next retry attempt
	RetryBackoff func(attempt int) time.Duration
}

// DefaultConfig returns sensible default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxAttempts:  5,
		WorkerCount:  3,
		PollInterval: 10 * time.Second,
		RetryBackoff: ExponentialBackoff,
	}
}

// ExponentialBackoff returns exponential delays: 1m, 5m, 15m, 1h, 4h
func ExponentialBackoff(attempt int) time.Duration {
	delays := []time.Duration{
		1 * time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		1 * time.Hour,
		4 * time.Hour,
	}
	if attempt >= len(delays) {
		return delays[len(delays)-1]
	}
	return delays[attempt]
}

// Worker processes the email queue
type Worker struct {
	repo     Repository
	sender   Sender
	config   *Config
	stopCh   chan struct{}
	wg       sync.WaitGroup
	running  bool
	mu       sync.Mutex
}

// NewWorker creates a new queue worker
func NewWorker(repo Repository, sender Sender, config *Config) *Worker {
	if config == nil {
		config = DefaultConfig()
	}
	return &Worker{
		repo:   repo,
		sender: sender,
		config: config,
		stopCh: make(chan struct{}),
	}
}

// Start begins processing the queue
func (w *Worker) Start(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.mu.Unlock()

	log.Printf("Starting email queue worker with %d workers", w.config.WorkerCount)

	// Start worker goroutines
	for i := 0; i < w.config.WorkerCount; i++ {
		w.wg.Add(1)
		go w.worker(ctx, i)
	}
}

// Stop gracefully stops the worker
func (w *Worker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	w.mu.Unlock()

	close(w.stopCh)
	w.wg.Wait()
	log.Println("Email queue worker stopped")
}

func (w *Worker) worker(ctx context.Context, id int) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.processMessages(ctx)
		}
	}
}

func (w *Worker) processMessages(ctx context.Context) {
	messages, err := w.repo.GetPending(ctx, 10)
	if err != nil {
		log.Printf("Queue worker: failed to get pending messages: %v", err)
		return
	}

	for _, msg := range messages {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		default:
			w.processMessage(ctx, msg)
		}
	}
}

func (w *Worker) processMessage(ctx context.Context, msg *QueuedMessage) {
	// Mark as sending
	if err := w.repo.UpdateStatus(msg.ID, StatusSending, "", nil); err != nil {
		log.Printf("Queue worker: failed to update status to sending: %v", err)
		return
	}

	// Attempt to send
	err := w.sender.Send(ctx, msg)
	if err == nil {
		// Success!
		if err := w.repo.MarkDelivered(msg.ID); err != nil {
			log.Printf("Queue worker: failed to mark as delivered: %v", err)
		}
		log.Printf("Queue worker: delivered message %s to %v", msg.ID, msg.To)
		return
	}

	// Failed - check if we should retry
	attempt := msg.Attempts + 1
	if attempt >= w.config.MaxAttempts {
		// Max attempts reached - mark as failed
		if err := w.repo.UpdateStatus(msg.ID, StatusFailed, err.Error(), nil); err != nil {
			log.Printf("Queue worker: failed to mark as failed: %v", err)
		}
		log.Printf("Queue worker: message %s failed permanently after %d attempts: %v", msg.ID, attempt, err)
		return
	}

	// Schedule retry
	nextRetry := time.Now().Add(w.config.RetryBackoff(attempt))
	if err := w.repo.UpdateStatus(msg.ID, StatusRetrying, err.Error(), &nextRetry); err != nil {
		log.Printf("Queue worker: failed to schedule retry: %v", err)
	}
	log.Printf("Queue worker: message %s attempt %d failed, retry at %v: %v", msg.ID, attempt, nextRetry.Format(time.RFC3339), err)
}

// Enqueue adds a message to the queue
func (w *Worker) Enqueue(msg *QueuedMessage) error {
	msg.ID = uuid.New()
	msg.Status = StatusPending
	msg.Attempts = 0
	msg.MaxAttempts = w.config.MaxAttempts
	msg.CreatedAt = time.Now()
	msg.UpdatedAt = time.Now()
	msg.NextRetry = time.Now() // Ready to send immediately

	return w.repo.Create(msg)
}
