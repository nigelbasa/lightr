package ratelimit

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Limit defines rate limit configuration
type Limit struct {
	// Requests is the maximum number of requests allowed in the window
	Requests int
	// Window is the time window for the limit
	Window time.Duration
}

// DefaultLimits provides sensible defaults
var DefaultLimits = map[string]Limit{
	"send_per_account":    {Requests: 100, Window: time.Hour},
	"send_per_domain":     {Requests: 1000, Window: time.Hour},
	"send_per_org":        {Requests: 10000, Window: time.Hour},
	"api_per_key":         {Requests: 1000, Window: time.Minute},
	"smtp_per_ip":         {Requests: 100, Window: time.Minute},
	"smtp_rcpt_per_msg":   {Requests: 50, Window: 0}, // Per message, not time-based
	"imap_login_per_ip":   {Requests: 10, Window: time.Minute},
}

// Limiter provides rate limiting functionality
type Limiter struct {
	limits  map[string]Limit
	buckets map[string]*bucket
	mu      sync.RWMutex
}

type bucket struct {
	count     int
	resetAt   time.Time
	mu        sync.Mutex
}

// NewLimiter creates a new rate limiter
func NewLimiter(limits map[string]Limit) *Limiter {
	if limits == nil {
		limits = DefaultLimits
	}
	return &Limiter{
		limits:  limits,
		buckets: make(map[string]*bucket),
	}
}

// Allow checks if a request is allowed and consumes one token if so
func (l *Limiter) Allow(limitType string, key string) bool {
	limit, ok := l.limits[limitType]
	if !ok {
		return true // Unknown limit type, allow
	}

	bucketKey := limitType + ":" + key
	
	l.mu.Lock()
	b, ok := l.buckets[bucketKey]
	if !ok {
		b = &bucket{
			count:   0,
			resetAt: time.Now().Add(limit.Window),
		}
		l.buckets[bucketKey] = b
	}
	l.mu.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()

	// Reset if window has passed
	if time.Now().After(b.resetAt) {
		b.count = 0
		b.resetAt = time.Now().Add(limit.Window)
	}

	// Check limit
	if b.count >= limit.Requests {
		return false
	}

	b.count++
	return true
}

// AllowN checks if N requests are allowed and consumes them if so
func (l *Limiter) AllowN(limitType string, key string, n int) bool {
	limit, ok := l.limits[limitType]
	if !ok {
		return true
	}

	bucketKey := limitType + ":" + key
	
	l.mu.Lock()
	b, ok := l.buckets[bucketKey]
	if !ok {
		b = &bucket{
			count:   0,
			resetAt: time.Now().Add(limit.Window),
		}
		l.buckets[bucketKey] = b
	}
	l.mu.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()

	if time.Now().After(b.resetAt) {
		b.count = 0
		b.resetAt = time.Now().Add(limit.Window)
	}

	if b.count+n > limit.Requests {
		return false
	}

	b.count += n
	return true
}

// Remaining returns the number of requests remaining in the current window
func (l *Limiter) Remaining(limitType string, key string) int {
	limit, ok := l.limits[limitType]
	if !ok {
		return -1
	}

	bucketKey := limitType + ":" + key
	
	l.mu.RLock()
	b, ok := l.buckets[bucketKey]
	l.mu.RUnlock()

	if !ok {
		return limit.Requests
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if time.Now().After(b.resetAt) {
		return limit.Requests
	}

	remaining := limit.Requests - b.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Reset clears the limit for a specific key
func (l *Limiter) Reset(limitType string, key string) {
	bucketKey := limitType + ":" + key
	
	l.mu.Lock()
	delete(l.buckets, bucketKey)
	l.mu.Unlock()
}

// Cleanup removes expired buckets (call periodically)
func (l *Limiter) Cleanup() {
	now := time.Now()
	
	l.mu.Lock()
	defer l.mu.Unlock()

	for key, b := range l.buckets {
		b.mu.Lock()
		if now.After(b.resetAt) {
			delete(l.buckets, key)
		}
		b.mu.Unlock()
	}
}

// StartCleanup starts a background goroutine to clean up expired buckets
func (l *Limiter) StartCleanup(interval time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				l.Cleanup()
			case <-stop:
				return
			}
		}
	}()
}

// Helper types for common rate limit checks

// AccountLimiter wraps Limiter for account-specific limits
type AccountLimiter struct {
	limiter *Limiter
}

// NewAccountLimiter creates a limiter for account operations
func NewAccountLimiter(limiter *Limiter) *AccountLimiter {
	return &AccountLimiter{limiter: limiter}
}

// AllowSend checks if an account can send
func (a *AccountLimiter) AllowSend(accountID uuid.UUID) bool {
	return a.limiter.Allow("send_per_account", accountID.String())
}

// DomainLimiter wraps Limiter for domain-specific limits
type DomainLimiter struct {
	limiter *Limiter
}

// NewDomainLimiter creates a limiter for domain operations
func NewDomainLimiter(limiter *Limiter) *DomainLimiter {
	return &DomainLimiter{limiter: limiter}
}

// AllowSend checks if a domain can send
func (d *DomainLimiter) AllowSend(domainID uuid.UUID) bool {
	return d.limiter.Allow("send_per_domain", domainID.String())
}

// IPLimiter wraps Limiter for IP-based limits
type IPLimiter struct {
	limiter *Limiter
}

// NewIPLimiter creates a limiter for IP operations
func NewIPLimiter(limiter *Limiter) *IPLimiter {
	return &IPLimiter{limiter: limiter}
}

// AllowSMTP checks if an IP can make SMTP connections
func (i *IPLimiter) AllowSMTP(ip string) bool {
	return i.limiter.Allow("smtp_per_ip", ip)
}

// AllowIMAPLogin checks if an IP can attempt IMAP login
func (i *IPLimiter) AllowIMAPLogin(ip string) bool {
	return i.limiter.Allow("imap_login_per_ip", ip)
}
