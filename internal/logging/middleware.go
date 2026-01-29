package logging

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// HTTPMiddleware provides request logging
func HTTPMiddleware(logger *Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Generate or extract request ID
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
			}

			// Add request ID to response
			w.Header().Set("X-Request-ID", requestID)

			// Create request-scoped logger
			reqLogger := logger.WithRequestID(requestID).With(map[string]interface{}{
				"method":     r.Method,
				"path":       r.URL.Path,
				"remote_ip":  getClientIP(r),
				"user_agent": r.UserAgent(),
			})

			// Add logger to context
			ctx := WithContext(r.Context(), reqLogger)
			r = r.WithContext(ctx)

			// Wrap response writer to capture status
			wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			// Process request
			next.ServeHTTP(wrapped, r)

			// Log completion
			duration := time.Since(start)
			reqLogger.Info("request completed", map[string]interface{}{
				"status":      wrapped.status,
				"bytes":       wrapped.bytes,
				"duration_ms": duration.Milliseconds(),
			})
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *responseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func getClientIP(r *http.Request) string {
	// Check forwarded headers
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

// SMTPLogger provides SMTP-specific logging
type SMTPLogger struct {
	*Logger
}

// NewSMTPLogger creates an SMTP logger
func NewSMTPLogger(base *Logger) *SMTPLogger {
	return &SMTPLogger{Logger: base.WithComponent("smtp")}
}

// Connection logs a new SMTP connection
func (l *SMTPLogger) Connection(sessionID, remoteAddr string) *Logger {
	return l.With(map[string]interface{}{
		"session_id":  sessionID,
		"remote_addr": remoteAddr,
	})
}

// Message logs message details
func (l *SMTPLogger) Message(sessionID, messageID, from string, to []string) {
	l.Info("message received", map[string]interface{}{
		"session_id": sessionID,
		"message_id": messageID,
		"from":       from,
		"to":         to,
		"recipients": len(to),
	})
}

// Delivered logs successful delivery
func (l *SMTPLogger) Delivered(messageID, recipient string, durationMS int64) {
	l.Info("message delivered", map[string]interface{}{
		"message_id":  messageID,
		"recipient":   recipient,
		"duration_ms": durationMS,
	})
}

// DeliveryFailed logs failed delivery
func (l *SMTPLogger) DeliveryFailed(messageID, recipient string, err error, attempt int) {
	l.Error("delivery failed", map[string]interface{}{
		"message_id": messageID,
		"recipient":  recipient,
		"error":      err.Error(),
		"attempt":    attempt,
	})
}

// Bounced logs bounce event
func (l *SMTPLogger) Bounced(messageID, recipient, bounceType string) {
	l.Warn("message bounced", map[string]interface{}{
		"message_id":  messageID,
		"recipient":   recipient,
		"bounce_type": bounceType,
	})
}

// IMAPLogger provides IMAP-specific logging
type IMAPLogger struct {
	*Logger
}

// NewIMAPLogger creates an IMAP logger
func NewIMAPLogger(base *Logger) *IMAPLogger {
	return &IMAPLogger{Logger: base.WithComponent("imap")}
}

// Login logs authentication attempts
func (l *IMAPLogger) Login(sessionID, username string, success bool) {
	if success {
		l.Info("login successful", map[string]interface{}{
			"session_id": sessionID,
			"username":   username,
		})
	} else {
		l.Warn("login failed", map[string]interface{}{
			"session_id": sessionID,
			"username":   username,
		})
	}
}

// Command logs IMAP commands
func (l *IMAPLogger) Command(sessionID, command, mailbox string) {
	l.Debug("imap command", map[string]interface{}{
		"session_id": sessionID,
		"command":    command,
		"mailbox":    mailbox,
	})
}
