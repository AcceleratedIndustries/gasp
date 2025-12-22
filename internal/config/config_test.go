package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	// Test duration parsing
	expectedTTL := 168 * time.Hour
	if cfg.Auth.Passwords[0].TokenTTLParsed != expectedTTL {
		t.Errorf("Expected TokenTTLParsed %v, got %v", expectedTTL, cfg.Auth.Passwords[0].TokenTTLParsed)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid config with auth enabled",
			config: Config{
				Auth: AuthConfig{
					Enabled: true,
					Passwords: []PasswordConfig{
						{
							Name:         "test",
							PasswordHash: "$2a$10$test",
						},
					},
					JWT: JWTConfig{
						SecretFile: "/tmp/jwt-secret",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "invalid: auth enabled but no passwords",
			config: Config{
				Auth: AuthConfig{
					Enabled:   true,
					Passwords: []PasswordConfig{},
					JWT: JWTConfig{
						SecretFile: "/tmp/jwt-secret",
					},
				},
			},
			expectErr: true,
			errMsg:    "auth enabled but no passwords configured",
		},
		{
			name: "invalid: auth enabled but no JWT secret file",
			config: Config{
				Auth: AuthConfig{
					Enabled: true,
					Passwords: []PasswordConfig{
						{
							Name:         "test",
							PasswordHash: "$2a$10$test",
						},
					},
					JWT: JWTConfig{
						SecretFile: "",
					},
				},
			},
			expectErr: true,
			errMsg:    "jwt.secret_file is required when auth is enabled",
		},
		{
			name: "valid: auth disabled (should pass even without passwords/JWT)",
			config: Config{
				Auth: AuthConfig{
					Enabled:   false,
					Passwords: []PasswordConfig{},
					JWT: JWTConfig{
						SecretFile: "",
					},
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

func TestLoadConfig_InvalidDuration(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  listen_address: "0.0.0.0:9090"

mode: "spoke"

auth:
  enabled: true
  passwords:
    - name: "default"
      password_hash: "$2a$10$test"
      token_ttl: "invalid"
  jwt:
    secret_file: "/tmp/jwt-secret"

logging:
  level: "info"
  format: "json"
  output: "stdout"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("Expected error for invalid duration string, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "invalid token_ttl") {
		t.Errorf("Expected error about invalid token_ttl, got: %v", err)
	}
}

func TestLoadConfig_DefaultTTL(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  listen_address: "0.0.0.0:9090"

mode: "spoke"

auth:
  enabled: true
  passwords:
    - name: "default"
      password_hash: "$2a$10$test"
  jwt:
    secret_file: "/tmp/jwt-secret"

logging:
  level: "info"
  format: "json"
  output: "stdout"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	expectedTTL := 7 * 24 * time.Hour // Default 7 days
	if cfg.Auth.Passwords[0].TokenTTLParsed != expectedTTL {
		t.Errorf("Expected default TokenTTLParsed %v, got %v", expectedTTL, cfg.Auth.Passwords[0].TokenTTLParsed)
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
