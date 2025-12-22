package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  listen_address: "0.0.0.0:9090"

mode: "spoke"

auth:
  enabled: true
  localhost_bypass: true
  passwords:
    - name: "default"
      password_hash: "$2a$10$test"
      allowed_clients:
        - "gasp-cli"
      allowed_sources:
        - ip: "192.168.1.0/24"
      token_ttl: "168h"
  jwt:
    secret_file: "/tmp/jwt-secret"

security:
  alerts:
    enabled: false

logging:
  level: "info"
  format: "json"
  output: "stdout"

rate_limiting:
  failed_login:
    max_attempts: 5
    lockout_duration: "15m"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Server.ListenAddress != "0.0.0.0:9090" {
		t.Errorf("Expected listen_address 0.0.0.0:9090, got %s", cfg.Server.ListenAddress)
	}

	if !cfg.Auth.Enabled {
		t.Error("Expected auth to be enabled")
	}

	if !cfg.Auth.LocalhostBypass {
		t.Error("Expected localhost_bypass to be true")
	}

	if len(cfg.Auth.Passwords) != 1 {
		t.Fatalf("Expected 1 password config, got %d", len(cfg.Auth.Passwords))
	}
}

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"tilde expansion", "~/.config/gasp", ".config/gasp"},
		{"absolute path", "/etc/gasp", "/etc/gasp"},
		{"relative path", "config.yaml", "config.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandPath(tt.input)
			if result != tt.input && tt.input[0] != '~' {
				t.Errorf("Non-tilde path changed: %s -> %s", tt.input, result)
			}
		})
	}
}
