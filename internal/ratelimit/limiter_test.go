package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter_Allow(t *testing.T) {
	limits := map[string]Limit{
		"account": {Requests: 10, Window: time.Minute},
		"domain":  {Requests: 100, Window: time.Minute},
		"api":     {Requests: 50, Window: time.Minute},
	}
	limiter := NewLimiter(limits)

	// Test account rate limiting
	t.Run("account limit", func(t *testing.T) {
		key := "test@example.com"
		
		// Should allow up to limit
		for i := 0; i < 10; i++ {
			if !limiter.Allow("account", key) {
				t.Errorf("Allow() = false at request %d, expected true", i+1)
			}
		}

		// Should deny after limit
		if limiter.Allow("account", key) {
			t.Error("Allow() = true after limit, expected false")
		}
	})

	t.Run("domain limit", func(t *testing.T) {
		limiter2 := NewLimiter(limits)
		key := "example.com"

		// Should allow up to domain limit
		for i := 0; i < 100; i++ {
			if !limiter2.Allow("domain", key) {
				t.Errorf("Allow() = false at request %d, expected true", i+1)
			}
		}

		// Should deny after limit
		if limiter2.Allow("domain", key) {
			t.Error("Allow() = true after limit, expected false")
		}
	})

	t.Run("api limit", func(t *testing.T) {
		limiter3 := NewLimiter(limits)
		key := "192.168.1.1"

		// Should allow up to API limit
		for i := 0; i < 50; i++ {
			if !limiter3.Allow("api", key) {
				t.Errorf("Allow() = false at request %d, expected true", i+1)
			}
		}

		// Should deny after limit
		if limiter3.Allow("api", key) {
			t.Error("Allow() = true after limit, expected false")
		}
	})

	t.Run("unknown limit type allows", func(t *testing.T) {
		if !limiter.Allow("unknown_type", "anykey") {
			t.Error("Allow() for unknown limit type should return true")
		}
	})
}

func TestLimiter_DefaultLimits(t *testing.T) {
	limiter := NewLimiter(nil) // Use defaults

	// Test send_per_account limit exists
	if !limiter.Allow("send_per_account", "test@example.com") {
		t.Error("First request should be allowed with default limits")
	}
}

func TestLimiter_ConcurrentAccess(t *testing.T) {
	limits := map[string]Limit{
		"concurrent": {Requests: 1000, Window: time.Minute},
	}
	limiter := NewLimiter(limits)
	key := "concurrent@example.com"

	// Run concurrent requests
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			limiter.Allow("concurrent", key)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
	// Test passes if no panic occurred
}
