package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// LogLevel represents logging levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// Logger handles structured logging
type Logger struct {
	format string // "json" or "text"
	level  LogLevel
	output io.Writer
}

// NewLogger creates a new logger
func NewLogger(format, level string, output io.Writer) *Logger {
	return &Logger{
		format: format,
		level:  parseLevel(level),
		output: output,
	}
}

// parseLevel converts string to LogLevel
func parseLevel(level string) LogLevel {
	switch level {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn":
		return WARN
	case "error":
		return ERROR
	default:
		return INFO
	}
}

// levelString converts LogLevel to string
func levelString(level LogLevel) string {
	switch level {
	case DEBUG:
		return "debug"
	case INFO:
		return "info"
	case WARN:
		return "warn"
	case ERROR:
		return "error"
	default:
		return "info"
	}
}

// shouldLog checks if message should be logged at current level
func (l *Logger) shouldLog(level LogLevel) bool {
	return level >= l.level
}

// log writes a log entry
func (l *Logger) log(level LogLevel, component, event string, fields map[string]interface{}) {
	if !l.shouldLog(level) {
		return
	}

	if l.format == "json" {
		l.logJSON(level, component, event, fields)
	} else {
		l.logText(level, component, event, fields)
	}
}

// logJSON writes a JSON log entry
func (l *Logger) logJSON(level LogLevel, component, event string, fields map[string]interface{}) {
	entry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339Nano),
		"level":     levelString(level),
		"component": component,
		"event":     event,
	}

	// Add custom fields
	for k, v := range fields {
		entry[k] = v
	}

	data, _ := json.Marshal(entry)
	fmt.Fprintf(l.output, "%s\n", string(data))
}

// logText writes a text log entry
func (l *Logger) logText(level LogLevel, component, event string, fields map[string]interface{}) {
	timestamp := time.Now().Format(time.RFC3339Nano)
	levelStr := fmt.Sprintf("[%s]", levelString(level))

	msg := fmt.Sprintf("%s %-7s %s: %s", timestamp, levelStr, component, event)

	// Add fields
	if len(fields) > 0 {
		for k, v := range fields {
			msg += fmt.Sprintf(" %s=%v", k, v)
		}
	}

	fmt.Fprintf(l.output, "%s\n", msg)
}

// Debug logs at debug level
func (l *Logger) Debug(component, event string, fields map[string]interface{}) {
	l.log(DEBUG, component, event, fields)
}

// Info logs at info level
func (l *Logger) Info(component, event string, fields map[string]interface{}) {
	l.log(INFO, component, event, fields)
}

// Warn logs at warn level
func (l *Logger) Warn(component, event string, fields map[string]interface{}) {
	l.log(WARN, component, event, fields)
}

// Error logs at error level
func (l *Logger) Error(component, event string, fields map[string]interface{}) {
	l.log(ERROR, component, event, fields)
}
