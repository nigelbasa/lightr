package tracking

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

type Service struct {
	trackingRepo domain.TrackingEventRepository
}

func NewService(trackingRepo domain.TrackingEventRepository) *Service {
	return &Service{trackingRepo: trackingRepo}
}

func (s *Service) HandleOpen(w http.ResponseWriter, r *http.Request) {
	msgIDStr := r.PathValue("msg_id")
	msgID, err := uuid.Parse(msgIDStr)
	if err != nil {
		http.Error(w, "invalid msg_id", http.StatusBadRequest)
		return
	}

	// Record the event
	event := &domain.TrackingEvent{
		ID:        uuid.New(),
		MessageID: msgID,
		EventType: "open",
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
		CreatedAt: time.Now(),
	}
	if err := s.trackingRepo.CreateTrackingEvent(event); err != nil {
		fmt.Printf("Error storing tracking event: %v\n", err)
	}

	// Return 1x1 transparent gif
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write([]byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
		0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
		0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
	})
}

func (s *Service) HandleClick(w http.ResponseWriter, r *http.Request) {
	msgIDStr := r.PathValue("msg_id")
	targetURL := r.URL.Query().Get("url")

	if msgIDStr == "" || targetURL == "" {
		http.Error(w, "missing parameters", http.StatusBadRequest)
		return
	}

	msgID, err := uuid.Parse(msgIDStr)
	if err != nil {
		http.Error(w, "invalid msg_id", http.StatusBadRequest)
		return
	}

	// Record the event
	event := &domain.TrackingEvent{
		ID:        uuid.New(),
		MessageID: msgID,
		EventType: "click",
		LinkURL:   targetURL,
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
		CreatedAt: time.Now(),
	}
	if err := s.trackingRepo.CreateTrackingEvent(event); err != nil {
		fmt.Printf("Error storing tracking event: %v\n", err)
	}

	// Redirect to target
	http.Redirect(w, r, targetURL, http.StatusFound)
}
