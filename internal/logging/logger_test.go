package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger("json", "info", &buf)

	logger.Info("auth", "test_event", map[string]interface{}{
		"username":  "testuser",
		"client_ip": "192.168.1.100",
	})

	output := buf.String()

	// Verify it's valid JSON
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Verify required fields
	if logEntry["level"] != "info" {
		t.Errorf("Expected level info, got %v", logEntry["level"])
	}

	if logEntry["component"] != "auth" {
		t.Errorf("Expected component auth, got %v", logEntry["component"])
	}

	if logEntry["event"] != "test_event" {
		t.Errorf("Expected event test_event, got %v", logEntry["event"])
	}
}

func TestTextLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger("text", "info", &buf)

	logger.Info("server", "startup", map[string]interface{}{
		"port": 9090,
	})

	output := buf.String()
	t.Logf("Text output: %q", output)

	if !strings.Contains(output, "[info]") {
		t.Error("Expected output to contain [info]")
	}

	if !strings.Contains(output, "server") {
		t.Error("Expected output to contain component")
	}

	if !strings.Contains(output, "startup") {
		t.Error("Expected output to contain event")
	}
}

func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger("text", "warn", &buf)

	// Info should not be logged
	logger.Info("test", "info_event", nil)
	if buf.Len() > 0 {
		t.Error("Info message should not be logged at warn level")
	}

	// Warn should be logged
	logger.Warn("test", "warn_event", nil)
	if buf.Len() == 0 {
		t.Error("Warn message should be logged at warn level")
	}
}
