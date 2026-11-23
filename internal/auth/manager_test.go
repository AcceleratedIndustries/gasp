package auth

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

	t.Cleanup(manager.waitForBackgroundSaves)

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
	t.Cleanup(manager1.waitForBackgroundSaves)

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

func TestAuthManager_ConcurrentSecurityStateSaves(t *testing.T) {
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
				MaxAttempts:     1,
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
	t.Cleanup(manager.waitForBackgroundSaves)

	// Every BlockIP and every locking RecordFailedLogin starts a background
	// save, and direct saves run alongside them. None may fail.
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			manager.BlockIP(fmt.Sprintf("10.0.0.%d", i), "test_block", "testuser", uint64(i))
		}(i)
		go func(i int) {
			defer wg.Done()
			manager.RecordFailedLogin(fmt.Sprintf("user%d", i), "10.0.1.1")
		}(i)
		go func() {
			defer wg.Done()
			errs <- manager.saveSecurityState()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Concurrent save failed: %v", err)
		}
	}

	manager.waitForBackgroundSaves()

	// The file on disk must hold the final state.
	reloaded, err := NewAuthManager(cfg, sessionsFile, securityFile)
	if err != nil {
		t.Fatalf("Failed to reload auth manager: %v", err)
	}
	for i := 0; i < n; i++ {
		if !reloaded.IsIPBlocked(fmt.Sprintf("10.0.0.%d", i)) {
			t.Errorf("Blocked IP 10.0.0.%d was not persisted", i)
		}
		if locked, _ := reloaded.CheckUserLockout(fmt.Sprintf("user%d", i)); !locked {
			t.Errorf("Lockout for user%d was not persisted", i)
		}
	}

	// No temp files may be left behind.
	leftovers, err := filepath.Glob(filepath.Join(tmpDir, "*.tmp"))
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	if len(leftovers) > 0 {
		t.Errorf("Temp files left behind: %v", leftovers)
	}
}

// writeFakePwauth writes a pwauth stand-in that records its stdin to
// stdinFile and always rejects the credentials.
func writeFakePwauth(t *testing.T, dir, stdinFile string) string {
	t.Helper()
	script := filepath.Join(dir, "fake-pwauth")
	body := "#!/bin/sh\ncat >> '" + stdinFile + "'\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatalf("Failed to write fake pwauth: %v", err)
	}
	return script
}

func TestAuthManager_LoginRejectsControlCharacters(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available for fake pwauth")
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

	manager, err := NewAuthManager(cfg, filepath.Join(tmpDir, "sessions.json"), filepath.Join(tmpDir, "security.json"))
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}
	t.Cleanup(manager.waitForBackgroundSaves)

	stdinFile := filepath.Join(tmpDir, "pwauth-stdin")
	manager.pamAuth.pwauthPath = writeFakePwauth(t, tmpDir, stdinFile)

	// Each of these would make pwauth check root's password while lockout
	// was tracked under a fresh key, allowing unlimited guesses.
	bad := []struct{ username, password string }{
		{"root\nGUESS1", "x"},
		{"root\rGUESS2", "x"},
		{"root\x00", "x"},
		{"root", "GUESS3\nextra"},
	}
	for _, c := range bad {
		if _, _, err := manager.Login(c.username, c.password, "192.168.1.100", "gasp-cli", time.Hour); err == nil {
			t.Errorf("Login(%q, %q) succeeded, expected rejection", c.username, c.password)
		}
	}

	if _, err := os.Stat(stdinFile); !os.IsNotExist(err) {
		data, _ := os.ReadFile(stdinFile)
		t.Fatalf("pwauth must not run for malformed credentials, got stdin %q", data)
	}

	manager.mu.RLock()
	lockouts := len(manager.userLockouts)
	manager.mu.RUnlock()
	if lockouts != 0 {
		t.Errorf("Malformed credentials must not create lockout entries, got %d", lockouts)
	}

	// A normal failed login does reach pwauth with exactly two lines, and
	// counts against the real username.
	if _, _, err := manager.Login("root", "wrong", "192.168.1.100", "gasp-cli", time.Hour); err == nil {
		t.Fatal("Expected login with wrong password to fail")
	}
	data, err := os.ReadFile(stdinFile)
	if err != nil {
		t.Fatalf("Expected fake pwauth to run for valid input: %v", err)
	}
	if got := string(data); got != "root\nwrong\n" {
		t.Errorf("pwauth stdin = %q, want %q", got, "root\nwrong\n")
	}
	if strings.Count(string(data), "\n") != 2 {
		t.Errorf("pwauth stdin should have exactly two lines, got %q", data)
	}

	manager.mu.RLock()
	_, counted := manager.userLockouts["root"]
	manager.mu.RUnlock()
	if !counted {
		t.Error("Failed login should be counted against user root")
	}
}
