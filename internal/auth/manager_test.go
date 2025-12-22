package auth

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/accelerated-industries/gasp/internal/config"
)

func TestAuthManager_Login(t *testing.T) {
	tmpDir := t.TempDir()

	// Create JWT secret
	secretFile := filepath.Join(tmpDir, "jwt-secret")
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	if err := os.WriteFile(secretFile, secret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	// Create config
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled: true,
			JWT: config.JWTConfig{
				SecretFile: secretFile,
			},
		},
	}

	sessionsFile := filepath.Join(tmpDir, "sessions.json")
	securityFile := filepath.Join(tmpDir, "security.json")

	manager, err := NewAuthManager(cfg, sessionsFile, securityFile)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Note: We can't test actual login without pwauth
	// Just verify manager is created successfully
	if manager == nil {
		t.Error("Expected non-nil auth manager")
	}
}

func TestAuthManager_ValidateToken(t *testing.T) {
	tmpDir := t.TempDir()

	secretFile := filepath.Join(tmpDir, "jwt-secret")
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	if err := os.WriteFile(secretFile, secret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled:         true,
			LocalhostBypass: false,
			JWT: config.JWTConfig{
				SecretFile: secretFile,
			},
		},
	}

	sessionsFile := filepath.Join(tmpDir, "sessions.json")
	securityFile := filepath.Join(tmpDir, "security.json")

	manager, err := NewAuthManager(cfg, sessionsFile, securityFile)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Create a session directly
	session := NewSession("testuser", "192.168.1.100", "gasp-cli", 24*time.Hour)
	manager.sessions.Create(session)

	// Generate token
	token, err := manager.tokenManager.GenerateToken(session)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Validate token
	validSession, err := manager.ValidateToken(token, "192.168.1.100")
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if validSession.Username != "testuser" {
		t.Errorf("Expected username testuser, got %s", validSession.Username)
	}
}

func TestAuthManager_IPBindingViolation(t *testing.T) {
	tmpDir := t.TempDir()

	secretFile := filepath.Join(tmpDir, "jwt-secret")
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	if err := os.WriteFile(secretFile, secret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled: true,
			JWT: config.JWTConfig{
				SecretFile: secretFile,
			},
		},
	}

	sessionsFile := filepath.Join(tmpDir, "sessions.json")
	securityFile := filepath.Join(tmpDir, "security.json")

	manager, err := NewAuthManager(cfg, sessionsFile, securityFile)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Create session for one IP
	session := NewSession("testuser", "192.168.1.100", "gasp-cli", 24*time.Hour)
	manager.sessions.Create(session)

	token, err := manager.tokenManager.GenerateToken(session)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Try to validate from different IP
	_, err = manager.ValidateToken(token, "192.168.1.200")
	if err == nil {
		t.Error("Expected IP binding violation error")
	}

	// Verify IP is blocked
	if !manager.IsIPBlocked("192.168.1.200") {
		t.Error("Expected IP to be blocked after violation")
	}
}

func TestAuthManager_FullLoginFlow(t *testing.T) {
	// This test requires pwauth, skip if not available
	if _, err := exec.LookPath("/usr/bin/pwauth"); err != nil {
		t.Skip("pwauth not available, skipping integration test")
	}

	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "jwt-secret")
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	if err := os.WriteFile(secretFile, secret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled: true,
			JWT: config.JWTConfig{
				SecretFile: secretFile,
			},
		},
		RateLimiting: config.RateLimitingConfig{
			FailedLogin: config.FailedLoginConfig{
				MaxAttempts:     5,
				LockoutDuration: "15m",
			},
		},
	}

	sessionsFile := filepath.Join(tmpDir, "sessions.json")
	securityFile := filepath.Join(tmpDir, "security.json")

	manager, err := NewAuthManager(cfg, sessionsFile, securityFile)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Note: Cannot test actual login without valid credentials
	// Test the flow with invalid credentials
	_, _, err = manager.Login("nonexistentuser", "wrongpassword", "192.168.1.100", "test-client", 24*time.Hour)
	if err == nil {
		t.Error("Expected login to fail with invalid credentials")
	}
}

func TestAuthManager_SecurityStatePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "jwt-secret")
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	if err := os.WriteFile(secretFile, secret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled: true,
			JWT: config.JWTConfig{
				SecretFile: secretFile,
			},
		},
		RateLimiting: config.RateLimitingConfig{
			FailedLogin: config.FailedLoginConfig{
				MaxAttempts:     5,
				LockoutDuration: "15m",
			},
		},
	}

	sessionsFile := filepath.Join(tmpDir, "sessions.json")
	securityFile := filepath.Join(tmpDir, "security.json")

	// Create manager and block an IP
	manager1, err := NewAuthManager(cfg, sessionsFile, securityFile)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Block an IP
	manager1.BlockIP("192.168.1.200", "test_block", "testuser", 12345)

	// Record failed logins to create lockout
	for i := 0; i < 5; i++ {
		manager1.RecordFailedLogin("testuser", "192.168.1.100")
	}

	// Save security state
	if err := manager1.saveSecurityState(); err != nil {
		t.Fatalf("Failed to save security state: %v", err)
	}

	// Create new manager (simulates restart)
	manager2, err := NewAuthManager(cfg, sessionsFile, securityFile)
	if err != nil {
		t.Fatalf("Failed to create second auth manager: %v", err)
	}

	// Verify blocked IP persisted
	if !manager2.IsIPBlocked("192.168.1.200") {
		t.Error("Blocked IP should persist across restarts")
	}

	// Verify lockout persisted
	locked, _ := manager2.CheckUserLockout("testuser")
	if !locked {
		t.Error("User lockout should persist across restarts")
	}
}
