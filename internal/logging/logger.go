package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// Level represents log severity
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// Logger provides structured logging
type Logger struct {
	output    io.Writer
	level     Level
	fields    map[string]interface{}
	mu        sync.Mutex
	jsonMode  bool
}

// Config holds logger configuration
type Config struct {
	Output   io.Writer
	Level    Level
	JSONMode bool
}

// New creates a new logger
func New(cfg *Config) *Logger {
	if cfg == nil {
		cfg = &Config{
			Output:   os.Stdout,
			Level:    LevelInfo,
			JSONMode: true,
		}
	}
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}
	return &Logger{
		output:   cfg.Output,
		level:    cfg.Level,
		fields:   make(map[string]interface{}),
		jsonMode: cfg.JSONMode,
	}
}

// With creates a child logger with additional fields
func (l *Logger) With(fields map[string]interface{}) *Logger {
	newFields := make(map[string]interface{}, len(l.fields)+len(fields))
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}
	return &Logger{
		output:   l.output,
		level:    l.level,
		fields:   newFields,
		jsonMode: l.jsonMode,
	}
}

// WithRequestID creates a child logger with request ID
func (l *Logger) WithRequestID(requestID string) *Logger {
	return l.With(map[string]interface{}{"request_id": requestID})
}

// WithComponent creates a child logger with component name
func (l *Logger) WithComponent(component string) *Logger {
	return l.With(map[string]interface{}{"component": component})
}

// Debug logs at debug level
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	l.log(LevelDebug, msg, fields...)
}

// Info logs at info level
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	l.log(LevelInfo, msg, fields...)
}

// Warn logs at warn level
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	l.log(LevelWarn, msg, fields...)
}

// Error logs at error level
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	l.log(LevelError, msg, fields...)
}

// ErrorErr logs an error with the error value
func (l *Logger) ErrorErr(msg string, err error, fields ...map[string]interface{}) {
	combined := make(map[string]interface{})
	if len(fields) > 0 {
		for k, v := range fields[0] {
			combined[k] = v
		}
	}
	combined["error"] = err.Error()
	l.log(LevelError, msg, combined)
}

func (l *Logger) log(level Level, msg string, fields ...map[string]interface{}) {
	if level < l.level {
		return
	}

	entry := make(map[string]interface{}, len(l.fields)+len(fields)+4)
	
	// Base fields
	entry["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	entry["level"] = level.String()
	entry["msg"] = msg

	// Logger fields
	for k, v := range l.fields {
		entry[k] = v
	}

	// Call fields
	if len(fields) > 0 {
		for k, v := range fields[0] {
			entry[k] = v
		}
	}

	// Add caller info for errors
	if level >= LevelError {
		if _, file, line, ok := runtime.Caller(2); ok {
			entry["caller"] = fmt.Sprintf("%s:%d", file, line)
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.jsonMode {
		data, _ := json.Marshal(entry)
		l.output.Write(append(data, '\n'))
	} else {
		// Text format
		fmt.Fprintf(l.output, "%s [%s] %s", 
			entry["time"], 
			entry["level"],
			msg,
		)
		delete(entry, "time")
		delete(entry, "level")
		delete(entry, "msg")
		if len(entry) > 0 {
			for k, v := range entry {
				fmt.Fprintf(l.output, " %s=%v", k, v)
			}
		}
		fmt.Fprintln(l.output)
	}
}

// Context key for logger
type contextKey struct{}

// FromContext retrieves logger from context
func FromContext(ctx context.Context) *Logger {
	if l, ok := ctx.Value(contextKey{}).(*Logger); ok {
		return l
	}
	return New(nil) // Return default logger
}

// WithContext adds logger to context
func WithContext(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, l)
}

// Global default logger
var defaultLogger = New(nil)

// SetDefault sets the default logger
func SetDefault(l *Logger) {
	defaultLogger = l
}

// Default returns the default logger
func Default() *Logger {
	return defaultLogger
}

// Package-level convenience functions
func Debug(msg string, fields ...map[string]interface{}) { defaultLogger.Debug(msg, fields...) }
func Info(msg string, fields ...map[string]interface{})  { defaultLogger.Info(msg, fields...) }
func Warn(msg string, fields ...map[string]interface{})  { defaultLogger.Warn(msg, fields...) }
func Error(msg string, fields ...map[string]interface{}) { defaultLogger.Error(msg, fields...) }
