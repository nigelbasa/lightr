package metrics

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Metrics provides Prometheus-compatible metrics
type Metrics struct {
	mu sync.RWMutex

	// Counters
	emailsSent      map[string]int64 // by domain
	emailsReceived  map[string]int64 // by domain
	emailsBounced   map[string]int64 // by type (hard, soft)
	emailsFailed    map[string]int64 // by reason
	smtpConnections int64
	imapConnections int64
	apiRequests     map[string]int64 // by endpoint
	apiErrors       map[string]int64 // by status code

	// Gauges
	queueDepth      int64
	activeSmtpConns int64
	activeImapConns int64

	// Histograms (simplified as counters per bucket)
	sendLatencyBuckets  map[string]int64 // "0.1", "0.5", "1", "5", "10", "+Inf"
	apiLatencyBuckets   map[string]int64

	// Summaries
	sendLatencySum   float64
	sendLatencyCount int64
	apiLatencySum    float64
	apiLatencyCount  int64
}

// NewMetrics creates a new metrics collector
func NewMetrics() *Metrics {
	return &Metrics{
		emailsSent:         make(map[string]int64),
		emailsReceived:     make(map[string]int64),
		emailsBounced:      make(map[string]int64),
		emailsFailed:       make(map[string]int64),
		apiRequests:        make(map[string]int64),
		apiErrors:          make(map[string]int64),
		sendLatencyBuckets: make(map[string]int64),
		apiLatencyBuckets:  make(map[string]int64),
	}
}

// IncEmailSent increments sent email counter
func (m *Metrics) IncEmailSent(domain string) {
	m.mu.Lock()
	m.emailsSent[domain]++
	m.mu.Unlock()
}

// IncEmailReceived increments received email counter
func (m *Metrics) IncEmailReceived(domain string) {
	m.mu.Lock()
	m.emailsReceived[domain]++
	m.mu.Unlock()
}

// IncEmailBounced increments bounce counter
func (m *Metrics) IncEmailBounced(bounceType string) {
	m.mu.Lock()
	m.emailsBounced[bounceType]++
	m.mu.Unlock()
}

// IncEmailFailed increments failure counter
func (m *Metrics) IncEmailFailed(reason string) {
	m.mu.Lock()
	m.emailsFailed[reason]++
	m.mu.Unlock()
}

// IncSMTPConnection increments SMTP connection counter
func (m *Metrics) IncSMTPConnection() {
	m.mu.Lock()
	m.smtpConnections++
	m.activeSmtpConns++
	m.mu.Unlock()
}

// DecSMTPConnection decrements active SMTP connections
func (m *Metrics) DecSMTPConnection() {
	m.mu.Lock()
	m.activeSmtpConns--
	m.mu.Unlock()
}

// IncIMAPConnection increments IMAP connection counter
func (m *Metrics) IncIMAPConnection() {
	m.mu.Lock()
	m.imapConnections++
	m.activeImapConns++
	m.mu.Unlock()
}

// DecIMAPConnection decrements active IMAP connections
func (m *Metrics) DecIMAPConnection() {
	m.mu.Lock()
	m.activeImapConns--
	m.mu.Unlock()
}

// IncAPIRequest increments API request counter
func (m *Metrics) IncAPIRequest(endpoint string) {
	m.mu.Lock()
	m.apiRequests[endpoint]++
	m.mu.Unlock()
}

// IncAPIError increments API error counter
func (m *Metrics) IncAPIError(statusCode int) {
	m.mu.Lock()
	m.apiErrors[strconv.Itoa(statusCode)]++
	m.mu.Unlock()
}

// SetQueueDepth sets the current queue depth
func (m *Metrics) SetQueueDepth(depth int64) {
	m.mu.Lock()
	m.queueDepth = depth
	m.mu.Unlock()
}

// ObserveSendLatency records send latency
func (m *Metrics) ObserveSendLatency(seconds float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sendLatencySum += seconds
	m.sendLatencyCount++

	// Update histogram buckets
	buckets := []float64{0.1, 0.5, 1, 5, 10}
	for _, b := range buckets {
		if seconds <= b {
			m.sendLatencyBuckets[formatBucket(b)]++
		}
	}
	m.sendLatencyBuckets["+Inf"]++
}

// ObserveAPILatency records API latency
func (m *Metrics) ObserveAPILatency(seconds float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.apiLatencySum += seconds
	m.apiLatencyCount++

	buckets := []float64{0.01, 0.05, 0.1, 0.5, 1}
	for _, b := range buckets {
		if seconds <= b {
			m.apiLatencyBuckets[formatBucket(b)]++
		}
	}
	m.apiLatencyBuckets["+Inf"]++
}

func formatBucket(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// Handler returns an HTTP handler for the /metrics endpoint
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		defer m.mu.RUnlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		// Email counters
		writeHelp(w, "lightr_emails_sent_total", "Total emails sent")
		writeType(w, "lightr_emails_sent_total", "counter")
		for domain, count := range m.emailsSent {
			writeMetric(w, "lightr_emails_sent_total", count, "domain", domain)
		}

		writeHelp(w, "lightr_emails_received_total", "Total emails received")
		writeType(w, "lightr_emails_received_total", "counter")
		for domain, count := range m.emailsReceived {
			writeMetric(w, "lightr_emails_received_total", count, "domain", domain)
		}

		writeHelp(w, "lightr_emails_bounced_total", "Total bounced emails")
		writeType(w, "lightr_emails_bounced_total", "counter")
		for bounceType, count := range m.emailsBounced {
			writeMetric(w, "lightr_emails_bounced_total", count, "type", bounceType)
		}

		writeHelp(w, "lightr_emails_failed_total", "Total failed emails")
		writeType(w, "lightr_emails_failed_total", "counter")
		for reason, count := range m.emailsFailed {
			writeMetric(w, "lightr_emails_failed_total", count, "reason", reason)
		}

		// Connection counters
		writeHelp(w, "lightr_smtp_connections_total", "Total SMTP connections")
		writeType(w, "lightr_smtp_connections_total", "counter")
		writeMetricSimple(w, "lightr_smtp_connections_total", m.smtpConnections)

		writeHelp(w, "lightr_imap_connections_total", "Total IMAP connections")
		writeType(w, "lightr_imap_connections_total", "counter")
		writeMetricSimple(w, "lightr_imap_connections_total", m.imapConnections)

		// API counters
		writeHelp(w, "lightr_api_requests_total", "Total API requests")
		writeType(w, "lightr_api_requests_total", "counter")
		for endpoint, count := range m.apiRequests {
			writeMetric(w, "lightr_api_requests_total", count, "endpoint", endpoint)
		}

		writeHelp(w, "lightr_api_errors_total", "Total API errors")
		writeType(w, "lightr_api_errors_total", "counter")
		for code, count := range m.apiErrors {
			writeMetric(w, "lightr_api_errors_total", count, "status", code)
		}

		// Gauges
		writeHelp(w, "lightr_queue_depth", "Current email queue depth")
		writeType(w, "lightr_queue_depth", "gauge")
		writeMetricSimple(w, "lightr_queue_depth", m.queueDepth)

		writeHelp(w, "lightr_smtp_connections_active", "Active SMTP connections")
		writeType(w, "lightr_smtp_connections_active", "gauge")
		writeMetricSimple(w, "lightr_smtp_connections_active", m.activeSmtpConns)

		writeHelp(w, "lightr_imap_connections_active", "Active IMAP connections")
		writeType(w, "lightr_imap_connections_active", "gauge")
		writeMetricSimple(w, "lightr_imap_connections_active", m.activeImapConns)

		// Histograms
		writeHelp(w, "lightr_send_latency_seconds", "Email send latency in seconds")
		writeType(w, "lightr_send_latency_seconds", "histogram")
		for bucket, count := range m.sendLatencyBuckets {
			writeMetric(w, "lightr_send_latency_seconds_bucket", count, "le", bucket)
		}
		writeMetricFloat(w, "lightr_send_latency_seconds_sum", m.sendLatencySum)
		writeMetricSimple(w, "lightr_send_latency_seconds_count", m.sendLatencyCount)

		writeHelp(w, "lightr_api_latency_seconds", "API request latency in seconds")
		writeType(w, "lightr_api_latency_seconds", "histogram")
		for bucket, count := range m.apiLatencyBuckets {
			writeMetric(w, "lightr_api_latency_seconds_bucket", count, "le", bucket)
		}
		writeMetricFloat(w, "lightr_api_latency_seconds_sum", m.apiLatencySum)
		writeMetricSimple(w, "lightr_api_latency_seconds_count", m.apiLatencyCount)
	}
}

func writeHelp(w http.ResponseWriter, name, help string) {
	w.Write([]byte("# HELP " + name + " " + help + "\n"))
}

func writeType(w http.ResponseWriter, name, metricType string) {
	w.Write([]byte("# TYPE " + name + " " + metricType + "\n"))
}

func writeMetric(w http.ResponseWriter, name string, value int64, labels ...string) {
	line := name + "{"
	for i := 0; i < len(labels); i += 2 {
		if i > 0 {
			line += ","
		}
		line += labels[i] + "=\"" + labels[i+1] + "\""
	}
	line += "} " + strconv.FormatInt(value, 10) + "\n"
	w.Write([]byte(line))
}

func writeMetricSimple(w http.ResponseWriter, name string, value int64) {
	w.Write([]byte(name + " " + strconv.FormatInt(value, 10) + "\n"))
}

func writeMetricFloat(w http.ResponseWriter, name string, value float64) {
	w.Write([]byte(name + " " + strconv.FormatFloat(value, 'f', 6, 64) + "\n"))
}

// Middleware creates an HTTP middleware that records metrics
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w, status: 200}
		
		next.ServeHTTP(wrapped, r)

		// Record metrics
		m.IncAPIRequest(r.URL.Path)
		if wrapped.status >= 400 {
			m.IncAPIError(wrapped.status)
		}
		m.ObserveAPILatency(time.Since(start).Seconds())
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
