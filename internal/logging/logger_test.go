package logging

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestLogger_Levels(t *testing.T) {
	tests := []struct {
		name      string
		level     Level
		logLevel  Level
		shouldLog bool
	}{
		{"debug at debug", LevelDebug, LevelDebug, true},
		{"info at debug", LevelDebug, LevelInfo, true},
		{"debug at info", LevelInfo, LevelDebug, false},
		{"info at info", LevelInfo, LevelInfo, true},
		{"warn at info", LevelInfo, LevelWarn, true},
		{"error at warn", LevelWarn, LevelError, true},
		{"warn at error", LevelError, LevelWarn, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := New(&Config{
				Output:   buf,
				Level:    tt.level,
				JSONMode: true,
			})

			switch tt.logLevel {
			case LevelDebug:
				logger.Debug("test message")
			case LevelInfo:
				logger.Info("test message")
			case LevelWarn:
				logger.Warn("test message")
			case LevelError:
				logger.Error("test message")
			}

			hasOutput := buf.Len() > 0
			if hasOutput != tt.shouldLog {
				t.Errorf("logged = %v, want %v", hasOutput, tt.shouldLog)
			}
		})
	}
}

func TestLogger_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Output:   buf,
		Level:    LevelInfo,
		JSONMode: true,
	})

	logger.Info("test message", map[string]interface{}{
		"key": "value",
		"num": 42,
	})

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Check required fields
	if entry["msg"] != "test message" {
		t.Errorf("msg = %v, want 'test message'", entry["msg"])
	}
	if entry["level"] != "info" {
		t.Errorf("level = %v, want 'info'", entry["level"])
	}
	if entry["key"] != "value" {
		t.Errorf("key = %v, want 'value'", entry["key"])
	}
	if entry["num"] != float64(42) {
		t.Errorf("num = %v, want 42", entry["num"])
	}
	if _, ok := entry["time"]; !ok {
		t.Error("missing time field")
	}
}

func TestLogger_With(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Output:   buf,
		Level:    LevelInfo,
		JSONMode: true,
	})

	// Create child logger with fields
	child := logger.With(map[string]interface{}{
		"component": "test",
		"version":   "1.0",
	})

	child.Info("child message")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if entry["component"] != "test" {
		t.Errorf("component = %v, want 'test'", entry["component"])
	}
	if entry["version"] != "1.0" {
		t.Errorf("version = %v, want '1.0'", entry["version"])
	}
}

func TestLogger_WithRequestID(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Output:   buf,
		Level:    LevelInfo,
		JSONMode: true,
	})

	child := logger.WithRequestID("req-123")
	child.Info("request message")

	var entry map[string]interface{}
	json.Unmarshal(buf.Bytes(), &entry)

	if entry["request_id"] != "req-123" {
		t.Errorf("request_id = %v, want 'req-123'", entry["request_id"])
	}
}

func TestLogger_ErrorErr(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Output:   buf,
		Level:    LevelInfo,
		JSONMode: true,
	})

	logger.ErrorErr("operation failed", &testError{msg: "connection refused"})

	var entry map[string]interface{}
	json.Unmarshal(buf.Bytes(), &entry)

	if entry["error"] != "connection refused" {
		t.Errorf("error = %v, want 'connection refused'", entry["error"])
	}
	if entry["level"] != "error" {
		t.Errorf("level = %v, want 'error'", entry["level"])
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  Level
	}{
		{"debug", LevelDebug},
		{"info", LevelInfo},
		{"warn", LevelWarn},
		{"warning", LevelWarn},
		{"error", LevelError},
		{"invalid", LevelInfo}, // default
		{"", LevelInfo},        // default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseLevel(tt.input)
			if got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{LevelDebug, "debug"},
		{LevelInfo, "info"},
		{LevelWarn, "warn"},
		{LevelError, "error"},
		{Level(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("Level(%d).String() = %v, want %v", tt.level, got, tt.want)
		}
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
