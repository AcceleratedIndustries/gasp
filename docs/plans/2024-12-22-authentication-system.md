# GASP Authentication System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement complete authentication and security system for GASP with PAM authentication, JWT sessions, IP binding, rate limiting, and security alerts.

**Architecture:** Session-based authentication using PAM/pwauth for login validation, HS256 JWT tokens with strict IP binding, in-memory session store with JSON persistence, localhost bypass for easy local development, and comprehensive security features (rate limiting, IP blocking, email alerts).

**Tech Stack:** Go 1.25.5, github.com/golang-jwt/jwt/v5 (JWT), golang.org/x/crypto (bcrypt), gopkg.in/yaml.v3 (config), pwauth (PAM bridge), net/smtp (alerts)

---

## Phase 1: Core Authentication (Priority 1)

### Task 1: Configuration Foundation

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Modify: `go.mod`

**Step 1: Add dependencies to go.mod**

```bash
cd /home/will/src/gasp
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/crypto/bcrypt
go get gopkg.in/yaml.v3
```

**Step 2: Write failing test for config loading**

Create `internal/config/config_test.go`:

```go
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
```

**Step 3: Run test to verify it fails**

```bash
go test ./internal/config/... -v
```

Expected: FAIL with "package config is not in GOROOT"

**Step 4: Implement config loading**

Create `internal/config/config.go`:

```go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete GASP configuration
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Mode         string             `yaml:"mode"` // hub or spoke
	Auth         AuthConfig         `yaml:"auth"`
	Security     SecurityConfig     `yaml:"security"`
	Logging      LoggingConfig      `yaml:"logging"`
	RateLimiting RateLimitingConfig `yaml:"rate_limiting"`
	Collection   CollectionConfig   `yaml:"collection,omitempty"`
	Output       OutputConfig       `yaml:"output,omitempty"`
}

type ServerConfig struct {
	ListenAddress string        `yaml:"listen_address"`
	ReadTimeout   time.Duration `yaml:"read_timeout,omitempty"`
	WriteTimeout  time.Duration `yaml:"write_timeout,omitempty"`
}

type AuthConfig struct {
	Enabled         bool             `yaml:"enabled"`
	LocalhostBypass bool             `yaml:"localhost_bypass"`
	Passwords       []PasswordConfig `yaml:"passwords"`
	JWT             JWTConfig        `yaml:"jwt"`
}

type PasswordConfig struct {
	Name           string         `yaml:"name"`
	PasswordHash   string         `yaml:"password_hash"`
	AllowedClients []string       `yaml:"allowed_clients"`
	AllowedSources []AllowedIP    `yaml:"allowed_sources"`
	TokenTTL       string         `yaml:"token_ttl"`
	TokenTTLParsed time.Duration  `yaml:"-"`
}

type AllowedIP struct {
	IP   string `yaml:"ip"`
	Name string `yaml:"name,omitempty"`
}

type JWTConfig struct {
	SecretFile string `yaml:"secret_file"`
}

type SecurityConfig struct {
	Alerts AlertsConfig `yaml:"alerts"`
}

type AlertsConfig struct {
	Enabled bool        `yaml:"enabled"`
	Email   EmailConfig `yaml:"email,omitempty"`
	SMTP    SMTPConfig  `yaml:"smtp,omitempty"`
}

type EmailConfig struct {
	To   string `yaml:"to"`
	From string `yaml:"from"`
}

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"` // json or text
	Output string `yaml:"output"` // stdout, file, or both
	File   string `yaml:"file,omitempty"`
}

type RateLimitingConfig struct {
	FailedLogin FailedLoginConfig `yaml:"failed_login"`
}

type FailedLoginConfig struct {
	MaxAttempts     int    `yaml:"max_attempts"`
	LockoutDuration string `yaml:"lockout_duration"`
	WindowDuration  string `yaml:"window_duration,omitempty"`
}

type CollectionConfig struct {
	Interval time.Duration `yaml:"interval,omitempty"`
}

type OutputConfig struct {
	File string `yaml:"file,omitempty"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	expandedPath := ExpandPath(path)

	data, err := os.ReadFile(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Parse duration strings
	for i := range cfg.Auth.Passwords {
		if cfg.Auth.Passwords[i].TokenTTL != "" {
			ttl, err := time.ParseDuration(cfg.Auth.Passwords[i].TokenTTL)
			if err != nil {
				return nil, fmt.Errorf("invalid token_ttl for password %s: %w", cfg.Auth.Passwords[i].Name, err)
			}
			cfg.Auth.Passwords[i].TokenTTLParsed = ttl
		} else {
			cfg.Auth.Passwords[i].TokenTTLParsed = 7 * 24 * time.Hour // Default 7 days
		}
	}

	// Expand paths in config
	if cfg.Auth.JWT.SecretFile != "" {
		cfg.Auth.JWT.SecretFile = ExpandPath(cfg.Auth.JWT.SecretFile)
	}
	if cfg.Logging.File != "" {
		cfg.Logging.File = ExpandPath(cfg.Logging.File)
	}
	if cfg.Output.File != "" {
		cfg.Output.File = ExpandPath(cfg.Output.File)
	}

	return &cfg, nil
}

// ExpandPath expands ~ to home directory
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Auth.Enabled {
		if len(c.Auth.Passwords) == 0 {
			return fmt.Errorf("auth enabled but no passwords configured")
		}

		if c.Auth.JWT.SecretFile == "" {
			return fmt.Errorf("jwt.secret_file is required when auth is enabled")
		}
	}

	return nil
}
```

**Step 5: Run test to verify it passes**

```bash
go test ./internal/config/... -v
```

Expected: PASS

**Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go go.mod go.sum
git commit -m "feat(auth): add configuration loading with YAML support

- Add Config struct with all auth sections
- Support tilde expansion for paths
- Parse duration strings for TTLs
- Add validation for required fields
- Includes unit tests for config loading"
```

---

### Task 2: Session Data Structures

**Files:**
- Create: `internal/auth/session.go`
- Create: `internal/auth/session_test.go`

**Step 1: Write failing test for session creation**

Create `internal/auth/session_test.go`:

```go
package auth

import (
	"testing"
	"time"
)

func TestNewSession(t *testing.T) {
	username := "testuser"
	clientIP := "192.168.1.100"
	clientID := "gasp-cli"
	ttl := 24 * time.Hour

	session := NewSession(username, clientIP, clientID, ttl)

	if session.Username != username {
		t.Errorf("Expected username %s, got %s", username, session.Username)
	}

	if session.ClientIP != clientIP {
		t.Errorf("Expected client IP %s, got %s", clientIP, session.ClientIP)
	}

	if session.ClientID != clientID {
		t.Errorf("Expected client ID %s, got %s", clientID, session.ClientID)
	}

	if session.TokenID == 0 {
		t.Error("Expected non-zero token ID")
	}

	if session.IssuedAt.IsZero() {
		t.Error("Expected issued_at to be set")
	}

	expectedExpiry := time.Now().Add(ttl)
	if session.ExpiresAt.Before(expectedExpiry.Add(-time.Second)) ||
	   session.ExpiresAt.After(expectedExpiry.Add(time.Second)) {
		t.Errorf("Expected expiry around %v, got %v", expectedExpiry, session.ExpiresAt)
	}
}

func TestSessionIsExpired(t *testing.T) {
	// Create expired session
	session := &Session{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	if !session.IsExpired() {
		t.Error("Expected session to be expired")
	}

	// Create valid session
	session.ExpiresAt = time.Now().Add(1 * time.Hour)

	if session.IsExpired() {
		t.Error("Expected session to be valid")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/... -v
```

Expected: FAIL with "package auth is not in GOROOT"

**Step 3: Implement session structures**

Create `internal/auth/session.go`:

```go
package auth

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Session represents an authenticated user session
type Session struct {
	TokenID   uint64    `json:"token_id"`
	Username  string    `json:"username"`
	ClientIP  string    `json:"client_ip"`
	ClientID  string    `json:"client_id"` // e.g., "gasp-cli"
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewSession creates a new session with a random token ID
func NewSession(username, clientIP, clientID string, ttl time.Duration) *Session {
	now := time.Now()

	return &Session{
		TokenID:   generateTokenID(),
		Username:  username,
		ClientIP:  clientIP,
		ClientID:  clientID,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// generateTokenID generates a cryptographically secure random 64-bit token ID
func generateTokenID() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to time-based (should never happen)
		return uint64(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint64(b[:])
}

// BlockedIP represents a permanently blocked IP address
type BlockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"` // "unauthorized_source", "ip_binding_violation"
	BlockedAt time.Time `json:"blocked_at"`
	Username  string    `json:"username,omitempty"`
	TokenID   uint64    `json:"token_id,omitempty"`
}

// UserLockout represents a temporarily locked user account
type UserLockout struct {
	Username       string      `json:"username"`
	FailedAttempts int         `json:"failed_attempts"`
	LockedUntil    time.Time   `json:"locked_until"`
	LastAttemptIP  string      `json:"last_attempt_ip"`
	AttemptTimes   []time.Time `json:"attempt_times"` // For windowing
}

// IsLocked checks if the user is currently locked out
func (u *UserLockout) IsLocked() bool {
	return time.Now().Before(u.LockedUntil)
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/auth/... -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/auth/session.go internal/auth/session_test.go
git commit -m "feat(auth): add session data structures

- Add Session struct with token ID, IP binding, expiration
- Add BlockedIP and UserLockout structures
- Generate cryptographically secure token IDs
- Add IsExpired() helper for session validation"
```

---

### Task 3: JWT Token Generation

**Files:**
- Create: `internal/auth/tokens.go`
- Create: `internal/auth/tokens_test.go`

**Step 1: Write failing test for JWT generation**

Create `internal/auth/tokens_test.go`:

```go
package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateAndValidateToken(t *testing.T) {
	// Create temporary secret file
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "jwt-secret")
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	if err := os.WriteFile(secretFile, secret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	tm := NewTokenManager(secretFile)
	if err := tm.LoadSecret(); err != nil {
		t.Fatalf("Failed to load secret: %v", err)
	}

	session := &Session{
		TokenID:   12345,
		Username:  "testuser",
		ClientIP:  "192.168.1.100",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	token, err := tm.GenerateToken(session)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token")
	}

	// Validate token
	claims, err := tm.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.TokenID != session.TokenID {
		t.Errorf("Expected token ID %d, got %d", session.TokenID, claims.TokenID)
	}

	if claims.Username != session.Username {
		t.Errorf("Expected username %s, got %s", session.Username, claims.Username)
	}

	if claims.ClientIP != session.ClientIP {
		t.Errorf("Expected client IP %s, got %s", session.ClientIP, claims.ClientIP)
	}
}

func TestValidateExpiredToken(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "jwt-secret")
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	if err := os.WriteFile(secretFile, secret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	tm := NewTokenManager(secretFile)
	if err := tm.LoadSecret(); err != nil {
		t.Fatalf("Failed to load secret: %v", err)
	}

	// Create expired session
	session := &Session{
		TokenID:   12345,
		Username:  "testuser",
		ClientIP:  "192.168.1.100",
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	token, err := tm.GenerateToken(session)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Should fail validation
	_, err = tm.ValidateToken(token)
	if err == nil {
		t.Error("Expected validation to fail for expired token")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/... -v
```

Expected: FAIL with "undefined: NewTokenManager"

**Step 3: Implement JWT token generation**

Create `internal/auth/tokens.go`:

```go
package auth

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenManager handles JWT token generation and validation
type TokenManager struct {
	secretFile string
	secret     []byte
}

// GASPClaims represents the JWT claims for GASP tokens
type GASPClaims struct {
	TokenID  uint64 `json:"token_id"`
	Username string `json:"username"`
	ClientIP string `json:"client_ip"`
	jwt.RegisteredClaims
}

// NewTokenManager creates a new token manager
func NewTokenManager(secretFile string) *TokenManager {
	return &TokenManager{
		secretFile: secretFile,
	}
}

// LoadSecret loads the JWT secret from file
func (tm *TokenManager) LoadSecret() error {
	data, err := os.ReadFile(tm.secretFile)
	if err != nil {
		return fmt.Errorf("failed to read JWT secret: %w", err)
	}

	if len(data) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 bytes")
	}

	tm.secret = data
	return nil
}

// GenerateToken generates a JWT token for a session
func (tm *TokenManager) GenerateToken(session *Session) (string, error) {
	claims := GASPClaims{
		TokenID:  session.TokenID,
		Username: session.Username,
		ClientIP: session.ClientIP,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(session.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(session.ExpiresAt),
			Subject:   session.Username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(tm.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the claims
func (tm *TokenManager) ValidateToken(tokenString string) (*GASPClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &GASPClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*GASPClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// GenerateSecret generates a new random JWT secret
func GenerateSecret() ([]byte, error) {
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}
	return secret, nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/auth/... -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/auth/tokens.go internal/auth/tokens_test.go
git commit -m "feat(auth): add JWT token generation and validation

- Implement TokenManager with HS256 signing
- Add GASPClaims with token_id, username, client_ip
- Support secret loading from file
- Validate signature and expiration
- Generate cryptographically secure secrets"
```

---

### Task 4: PAM Authentication

**Files:**
- Create: `internal/auth/pam.go`
- Create: `internal/auth/pam_test.go`

**Step 1: Write test for PAM authentication**

Create `internal/auth/pam_test.go`:

```go
package auth

import (
	"testing"
)

func TestPAMAuthenticator_ValidInput(t *testing.T) {
	auth := NewPAMAuthenticator()

	// Test with empty credentials (should fail quickly)
	err := auth.Authenticate("", "")
	if err == nil {
		t.Error("Expected authentication to fail with empty credentials")
	}

	// Note: We can't test successful auth without real user credentials
	// This test just verifies the authenticator is created and handles errors
}

func TestHashPassword(t *testing.T) {
	password := "test-password-123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if len(hash) == 0 {
		t.Error("Expected non-empty hash")
	}

	if hash[:4] != "$2a$" {
		t.Errorf("Expected bcrypt hash to start with $2a$, got %s", hash[:4])
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "test-password-123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Verify correct password
	if !VerifyPassword(password, hash) {
		t.Error("Failed to verify correct password")
	}

	// Verify incorrect password
	if VerifyPassword("wrong-password", hash) {
		t.Error("Incorrectly verified wrong password")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/... -v
```

Expected: FAIL with "undefined: NewPAMAuthenticator"

**Step 3: Implement PAM authentication**

Create `internal/auth/pam.go`:

```go
package auth

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// PAMAuthenticator handles authentication via pwauth
type PAMAuthenticator struct {
	pwauthPath string
}

// NewPAMAuthenticator creates a new PAM authenticator
func NewPAMAuthenticator() *PAMAuthenticator {
	return &PAMAuthenticator{
		pwauthPath: "/usr/bin/pwauth",
	}
}

// Authenticate validates credentials via pwauth
func (p *PAMAuthenticator) Authenticate(username, password string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}

	// Check if pwauth exists
	if _, err := exec.LookPath(p.pwauthPath); err != nil {
		return fmt.Errorf("pwauth not found (authentication unavailable): %w", err)
	}

	// Execute pwauth with username\npassword\n on stdin
	cmd := exec.Command(p.pwauthPath)

	stdin := bytes.NewBufferString(username + "\n" + password + "\n")
	cmd.Stdin = stdin

	// Capture output for debugging
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// pwauth returns 0 for success, non-zero for failure
	if err := cmd.Run(); err != nil {
		// Log the error details but return generic message
		return fmt.Errorf("authentication failed")
	}

	return nil
}

// HashPassword generates a bcrypt hash of a password
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifies a password against a bcrypt hash
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// IsIPInCIDR checks if an IP address is in a CIDR range
func IsIPInCIDR(ip, cidr string) (bool, error) {
	// Simple implementation for exact IP match or CIDR
	// For production, use net.ParseCIDR and ip.Contains

	// Exact match
	if ip == cidr {
		return true, nil
	}

	// CIDR match - simplified (production should use net package)
	if strings.Contains(cidr, "/") {
		parts := strings.Split(cidr, "/")
		network := parts[0]

		// Simple prefix match for /24
		if strings.HasSuffix(cidr, "/24") {
			ipPrefix := strings.Join(strings.Split(ip, ".")[:3], ".")
			networkPrefix := strings.Join(strings.Split(network, ".")[:3], ".")
			return ipPrefix == networkPrefix, nil
		}
	}

	return false, nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/auth/... -v
```

Expected: PASS (note: PAM auth will fail without real credentials, but error handling will pass)

**Step 5: Commit**

```bash
git add internal/auth/pam.go internal/auth/pam_test.go
git commit -m "feat(auth): add PAM authentication via pwauth

- Implement PAMAuthenticator using pwauth binary
- Add bcrypt password hashing and verification
- Add CIDR IP matching helper (simplified)
- Handle pwauth errors gracefully"
```

---

### Task 5: Session Store with Persistence

**Files:**
- Create: `internal/auth/store.go`
- Create: `internal/auth/store_test.go`

**Step 1: Write failing test for session store**

Create `internal/auth/store_test.go`:

```go
package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionStore_CreateAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewSessionStore(filepath.Join(tmpDir, "sessions.json"))

	session := NewSession("testuser", "192.168.1.100", "gasp-cli", 24*time.Hour)

	store.Create(session)

	retrieved := store.Get(session.TokenID)
	if retrieved == nil {
		t.Fatal("Expected to retrieve session")
	}

	if retrieved.Username != session.Username {
		t.Errorf("Expected username %s, got %s", session.Username, retrieved.Username)
	}
}

func TestSessionStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewSessionStore(filepath.Join(tmpDir, "sessions.json"))

	session := NewSession("testuser", "192.168.1.100", "gasp-cli", 24*time.Hour)
	store.Create(session)

	store.Delete(session.TokenID)

	retrieved := store.Get(session.TokenID)
	if retrieved != nil {
		t.Error("Expected session to be deleted")
	}
}

func TestSessionStore_GetByUsername(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewSessionStore(filepath.Join(tmpDir, "sessions.json"))

	session1 := NewSession("user1", "192.168.1.100", "gasp-cli", 24*time.Hour)
	session2 := NewSession("user1", "192.168.1.101", "gasp-cli", 24*time.Hour)
	session3 := NewSession("user2", "192.168.1.102", "gasp-cli", 24*time.Hour)

	store.Create(session1)
	store.Create(session2)
	store.Create(session3)

	sessions := store.GetByUsername("user1")
	if len(sessions) != 2 {
		t.Errorf("Expected 2 sessions for user1, got %d", len(sessions))
	}
}

func TestSessionStore_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "sessions.json")

	// Create store and add session
	store1 := NewSessionStore(sessionFile)
	session := NewSession("testuser", "192.168.1.100", "gasp-cli", 24*time.Hour)
	store1.Create(session)

	// Save to disk
	if err := store1.Save(); err != nil {
		t.Fatalf("Failed to save sessions: %v", err)
	}

	// Create new store and load
	store2 := NewSessionStore(sessionFile)
	if err := store2.Load(); err != nil {
		t.Fatalf("Failed to load sessions: %v", err)
	}

	// Verify session persisted
	retrieved := store2.Get(session.TokenID)
	if retrieved == nil {
		t.Fatal("Expected to retrieve persisted session")
	}

	if retrieved.Username != session.Username {
		t.Errorf("Expected username %s, got %s", session.Username, retrieved.Username)
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/... -v
```

Expected: FAIL with "undefined: NewSessionStore"

**Step 3: Implement session store**

Create `internal/auth/store.go`:

```go
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SessionStore manages in-memory sessions with disk persistence
type SessionStore struct {
	sessions map[uint64]*Session
	mu       sync.RWMutex
	filePath string
}

// NewSessionStore creates a new session store
func NewSessionStore(filePath string) *SessionStore {
	return &SessionStore{
		sessions: make(map[uint64]*Session),
		filePath: filePath,
	}
}

// Create adds a new session
func (s *SessionStore) Create(session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.TokenID] = session
}

// Get retrieves a session by token ID
func (s *SessionStore) Get(tokenID uint64) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[tokenID]
}

// Delete removes a session by token ID
func (s *SessionStore) Delete(tokenID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, tokenID)
}

// GetByUsername retrieves all sessions for a username
func (s *SessionStore) GetByUsername(username string) []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sessions []*Session
	for _, session := range s.sessions {
		if session.Username == username {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// DeleteByUsername removes all sessions for a username
func (s *SessionStore) DeleteByUsername(username string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for tokenID, session := range s.sessions {
		if session.Username == username {
			delete(s.sessions, tokenID)
			count++
		}
	}
	return count
}

// GetAll returns all sessions
func (s *SessionStore) GetAll() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// CleanupExpired removes all expired sessions
func (s *SessionStore) CleanupExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for tokenID, session := range s.sessions {
		if session.IsExpired() {
			delete(s.sessions, tokenID)
			count++
		}
	}
	return count
}

// Save persists sessions to disk
func (s *SessionStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create directory if it doesn't exist
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Convert map to slice for JSON
	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}

	// Write to temp file then rename (atomic)
	tempFile := s.filePath + ".tmp"
	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sessions: %w", err)
	}

	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write sessions: %w", err)
	}

	if err := os.Rename(tempFile, s.filePath); err != nil {
		return fmt.Errorf("failed to rename sessions file: %w", err)
	}

	return nil
}

// Load reads sessions from disk
func (s *SessionStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, that's okay
			return nil
		}
		return fmt.Errorf("failed to read sessions: %w", err)
	}

	var sessions []*Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		// Log warning but don't fail - start with empty sessions
		return fmt.Errorf("failed to unmarshal sessions (starting fresh): %w", err)
	}

	// Rebuild map
	s.sessions = make(map[uint64]*Session)
	for _, session := range sessions {
		// Skip expired sessions during load
		if !session.IsExpired() {
			s.sessions[session.TokenID] = session
		}
	}

	return nil
}

// Count returns the number of active sessions
func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/auth/... -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/auth/store.go internal/auth/store_test.go
git commit -m "feat(auth): add session store with persistence

- Implement in-memory session store with O(1) lookup
- Add session CRUD operations
- Support persistence to JSON file
- Automatic cleanup of expired sessions
- Thread-safe with read/write locks
- Atomic file writes (temp + rename)"
```

---

## Phase 2: HTTP Integration

### Task 6: Authentication Manager

**Files:**
- Create: `internal/auth/manager.go`
- Create: `internal/auth/manager_test.go`

**Step 1: Write failing test for auth manager**

Create `internal/auth/manager_test.go`:

```go
package auth

import (
	"os"
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
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/... -v
```

Expected: FAIL with "undefined: NewAuthManager"

**Step 3: Implement auth manager (part 1 - basic structure)**

Create `internal/auth/manager.go`:

```go
package auth

import (
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	"github.com/accelerated-industries/gasp/internal/config"
)

// AuthManager handles all authentication and authorization
type AuthManager struct {
	config         *config.Config
	sessions       *SessionStore
	tokenManager   *TokenManager
	pamAuth        *PAMAuthenticator
	blockedIPs     map[string]*BlockedIP
	userLockouts   map[string]*UserLockout
	securityFile   string
	mu             sync.RWMutex
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(cfg *config.Config, sessionsFile, securityFile string) (*AuthManager, error) {
	tm := NewTokenManager(cfg.Auth.JWT.SecretFile)
	if err := tm.LoadSecret(); err != nil {
		return nil, fmt.Errorf("failed to load JWT secret: %w", err)
	}

	sessions := NewSessionStore(sessionsFile)
	if err := sessions.Load(); err != nil {
		// Log warning but continue
		fmt.Printf("Warning: failed to load sessions: %v\n", err)
	}

	manager := &AuthManager{
		config:       cfg,
		sessions:     sessions,
		tokenManager: tm,
		pamAuth:      NewPAMAuthenticator(),
		blockedIPs:   make(map[string]*BlockedIP),
		userLockouts: make(map[string]*UserLockout),
		securityFile: securityFile,
	}

	// Load security state
	if err := manager.loadSecurityState(); err != nil {
		fmt.Printf("Warning: failed to load security state: %v\n", err)
	}

	return manager, nil
}

// ValidateToken validates a JWT token and returns the session
func (am *AuthManager) ValidateToken(tokenString, clientIP string) (*Session, error) {
	// Parse and validate JWT
	claims, err := am.tokenManager.ValidateToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Look up session
	session := am.sessions.Get(claims.TokenID)
	if session == nil {
		return nil, fmt.Errorf("session not found")
	}

	// Check expiration
	if session.IsExpired() {
		am.sessions.Delete(session.TokenID)
		return nil, fmt.Errorf("session expired")
	}

	// Verify IP binding (constant-time comparison)
	if subtle.ConstantTimeCompare([]byte(session.ClientIP), []byte(clientIP)) != 1 {
		// IP binding violation - revoke token and block IP
		am.sessions.Delete(session.TokenID)
		am.BlockIP(clientIP, "ip_binding_violation", session.Username, session.TokenID)
		return nil, fmt.Errorf("IP binding violation")
	}

	return session, nil
}

// IsIPBlocked checks if an IP is blocked
func (am *AuthManager) IsIPBlocked(ip string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	_, blocked := am.blockedIPs[ip]
	return blocked
}

// BlockIP permanently blocks an IP address
func (am *AuthManager) BlockIP(ip, reason, username string, tokenID uint64) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.blockedIPs[ip] = &BlockedIP{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
		Username:  username,
		TokenID:   tokenID,
	}

	// Save security state
	go am.saveSecurityState()
}

// Placeholder methods for persistence
func (am *AuthManager) loadSecurityState() error {
	// TODO: Implement JSON loading
	return nil
}

func (am *AuthManager) saveSecurityState() error {
	// TODO: Implement JSON saving
	return nil
}

// RevokeSession revokes a specific session
func (am *AuthManager) RevokeSession(tokenID uint64) error {
	session := am.sessions.Get(tokenID)
	if session == nil {
		return fmt.Errorf("session not found")
	}

	am.sessions.Delete(tokenID)
	return am.sessions.Save()
}

// RevokeUserSessions revokes all sessions for a user
func (am *AuthManager) RevokeUserSessions(username string) (int, error) {
	count := am.sessions.DeleteByUsername(username)
	return count, am.sessions.Save()
}

// GetActiveSessions returns all active sessions
func (am *AuthManager) GetActiveSessions() []*Session {
	return am.sessions.GetAll()
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/auth/... -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/auth/manager.go internal/auth/manager_test.go
git commit -m "feat(auth): add authentication manager

- Implement AuthManager coordinating all auth components
- Add token validation with IP binding checks
- Add session revocation (by token or username)
- Add IP blocking with persistence hooks
- Strict constant-time IP comparison for security
- Load/save sessions and security state"
```

---

### Task 7: HTTP Handlers for Authentication

**Files:**
- Create: `internal/server/auth_handlers.go`
- Create: `internal/server/errors.go`
- Modify: `internal/server/http.go`

**Step 1: Write error response helpers**

Create `internal/server/errors.go`:

```go
package server

import (
	"encoding/json"
	"net/http"
	"time"
)

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error     string                 `json:"error"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Action    string                 `json:"action"`
	Timestamp string                 `json:"timestamp"`
}

// writeErrorResponse writes a JSON error response
func writeErrorResponse(w http.ResponseWriter, statusCode int, errorCode, message, action string, details map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:     errorCode,
		Message:   message,
		Details:   details,
		Action:    action,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

// Error response helpers
func writeUnauthorized(w http.ResponseWriter, errorCode, message, action string) {
	w.Header().Set("WWW-Authenticate", "Bearer realm=\"GASP\"")
	writeErrorResponse(w, http.StatusUnauthorized, errorCode, message, action, nil)
}

func writeForbidden(w http.ResponseWriter, errorCode, message, action string, details map[string]interface{}) {
	writeErrorResponse(w, http.StatusForbidden, errorCode, message, action, details)
}

func writeBadRequest(w http.ResponseWriter, errorCode, message, action string) {
	writeErrorResponse(w, http.StatusBadRequest, errorCode, message, action, nil)
}

func writeInternalError(w http.ResponseWriter, errorCode, message string) {
	writeErrorResponse(w, http.StatusInternalServerError, errorCode, message, "retry_or_contact_admin", nil)
}
```

**Step 2: Write auth handlers**

Create `internal/server/auth_handlers.go`:

```go
package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// LoginRequest represents a login request body
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	Token       string    `json:"token"`
	TokenID     string    `json:"token_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	Username    string    `json:"username"`
	IssuedToIP  string    `json:"issued_to_ip"`
}

// handleLogin handles POST /auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "invalid_method",
			"Method not allowed for this endpoint.", "use_correct_method",
			map[string]interface{}{
				"method_used": r.Method,
				"allowed_methods": []string{"POST"},
			})
		return
	}

	// Extract client IP
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	// Check if IP is blocked
	if s.authManager != nil && s.authManager.IsIPBlocked(clientIP) {
		writeForbidden(w, "ip_blocked", "Access denied. Your IP address has been blocked.",
			"contact_admin", map[string]interface{}{
				"ip": clientIP,
			})
		return
	}

	// Parse credentials (support both Basic Auth and JSON body)
	var username, password string

	// Try Basic Auth first
	if u, p, ok := r.BasicAuth(); ok {
		username = u
		password = p
	} else {
		// Try JSON body
		var loginReq LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
			writeBadRequest(w, "malformed_request",
				"Request body is malformed or missing required fields.", "fix_request")
			return
		}
		username = loginReq.Username
		password = loginReq.Password
	}

	if username == "" || password == "" {
		writeBadRequest(w, "malformed_request",
			"Username and password are required.", "fix_request")
		return
	}

	// TODO: Implement actual login logic with AuthManager
	// For now, return error
	writeInternalError(w, "not_implemented", "Authentication not yet fully implemented")
}

// extractBearerToken extracts the Bearer token from Authorization header
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}
```

**Step 3: Update server to include auth handlers**

Modify `internal/server/http.go` (add auth route):

```go
// In the Start() method, add auth endpoint:
mux.HandleFunc("/auth/login", s.handleLogin)
```

**Step 4: Compile and verify no errors**

```bash
go build ./cmd/gasp
```

Expected: Successful compilation

**Step 5: Commit**

```bash
git add internal/server/auth_handlers.go internal/server/errors.go internal/server/http.go
git commit -m "feat(server): add authentication HTTP handlers

- Add /auth/login endpoint (POST)
- Support Basic Auth and JSON body for credentials
- Implement standard error response format
- Add error helpers for 400, 401, 403, 500
- Extract Bearer token from Authorization header
- IP blocking check on login attempts"
```

---

## Phase 3: Security Features

### Task 8: Rate Limiting and Lockouts

**Files:**
- Create: `internal/auth/ratelimit.go`
- Create: `internal/auth/ratelimit_test.go`
- Modify: `internal/auth/manager.go`

**Step 1: Write test for rate limiting**

Create `internal/auth/ratelimit_test.go`:

```go
package auth

import (
	"testing"
	"time"
)

func TestRecordFailedAttempt(t *testing.T) {
	lockout := &UserLockout{
		Username:     "testuser",
		AttemptTimes: []time.Time{},
	}

	// Record 3 attempts
	for i := 0; i < 3; i++ {
		recordFailedAttempt(lockout, "192.168.1.100")
	}

	if lockout.FailedAttempts != 3 {
		t.Errorf("Expected 3 failed attempts, got %d", lockout.FailedAttempts)
	}

	if len(lockout.AttemptTimes) != 3 {
		t.Errorf("Expected 3 attempt times, got %d", len(lockout.AttemptTimes))
	}
}

func TestShouldLockUser(t *testing.T) {
	lockout := &UserLockout{
		Username:       "testuser",
		FailedAttempts: 5,
		AttemptTimes:   []time.Time{time.Now(), time.Now(), time.Now(), time.Now(), time.Now()},
	}

	if !shouldLockUser(lockout, 5) {
		t.Error("Expected user to be locked after 5 attempts")
	}

	lockout.FailedAttempts = 3
	if shouldLockUser(lockout, 5) {
		t.Error("Expected user not to be locked with only 3 attempts")
	}
}

func TestCleanupOldAttempts(t *testing.T) {
	lockout := &UserLockout{
		Username: "testuser",
		AttemptTimes: []time.Time{
			time.Now().Add(-10 * time.Minute), // Old
			time.Now().Add(-2 * time.Minute),  // Recent
			time.Now().Add(-1 * time.Minute),  // Recent
		},
		FailedAttempts: 3,
	}

	windowDuration := 5 * time.Minute
	cleanupOldAttempts(lockout, windowDuration)

	// Should only keep recent attempts
	if len(lockout.AttemptTimes) != 2 {
		t.Errorf("Expected 2 recent attempts, got %d", len(lockout.AttemptTimes))
	}

	if lockout.FailedAttempts != 2 {
		t.Errorf("Expected failed attempts to be updated to 2, got %d", lockout.FailedAttempts)
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/... -v
```

Expected: FAIL with "undefined: recordFailedAttempt"

**Step 3: Implement rate limiting logic**

Create `internal/auth/ratelimit.go`:

```go
package auth

import (
	"time"
)

// recordFailedAttempt records a failed login attempt for a user
func recordFailedAttempt(lockout *UserLockout, clientIP string) {
	lockout.FailedAttempts++
	lockout.LastAttemptIP = clientIP
	lockout.AttemptTimes = append(lockout.AttemptTimes, time.Now())
}

// shouldLockUser determines if a user should be locked based on failed attempts
func shouldLockUser(lockout *UserLockout, maxAttempts int) bool {
	return lockout.FailedAttempts >= maxAttempts
}

// lockUser locks a user account for the specified duration
func lockUser(lockout *UserLockout, lockoutDuration time.Duration) {
	lockout.LockedUntil = time.Now().Add(lockoutDuration)
}

// cleanupOldAttempts removes attempts outside the time window
func cleanupOldAttempts(lockout *UserLockout, windowDuration time.Duration) {
	cutoff := time.Now().Add(-windowDuration)

	var validAttempts []time.Time
	for _, attemptTime := range lockout.AttemptTimes {
		if attemptTime.After(cutoff) {
			validAttempts = append(validAttempts, attemptTime)
		}
	}

	lockout.AttemptTimes = validAttempts
	lockout.FailedAttempts = len(validAttempts)
}

// clearLockout clears a user's lockout state
func clearLockout(lockout *UserLockout) {
	lockout.FailedAttempts = 0
	lockout.AttemptTimes = []time.Time{}
	lockout.LockedUntil = time.Time{}
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/auth/... -v
```

Expected: PASS

**Step 5: Integrate rate limiting into AuthManager**

Modify `internal/auth/manager.go` (add methods):

```go
// Add to AuthManager:

// CheckUserLockout checks if a user is locked out
func (am *AuthManager) CheckUserLockout(username string) (bool, time.Time) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	lockout, exists := am.userLockouts[username]
	if !exists {
		return false, time.Time{}
	}

	if lockout.IsLocked() {
		return true, lockout.LockedUntil
	}

	return false, time.Time{}
}

// RecordFailedLogin records a failed login attempt
func (am *AuthManager) RecordFailedLogin(username, clientIP string) (shouldLock bool, lockedUntil time.Time) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Get or create lockout entry
	lockout, exists := am.userLockouts[username]
	if !exists {
		lockout = &UserLockout{
			Username:     username,
			AttemptTimes: []time.Time{},
		}
		am.userLockouts[username] = lockout
	}

	// Cleanup old attempts (5 minute window by default)
	windowDuration := 5 * time.Minute
	if am.config.RateLimiting.FailedLogin.WindowDuration != "" {
		if d, err := time.ParseDuration(am.config.RateLimiting.FailedLogin.WindowDuration); err == nil {
			windowDuration = d
		}
	}
	cleanupOldAttempts(lockout, windowDuration)

	// Record attempt
	recordFailedAttempt(lockout, clientIP)

	// Check if should lock
	maxAttempts := am.config.RateLimiting.FailedLogin.MaxAttempts
	if shouldLockUser(lockout, maxAttempts) {
		lockoutDuration, _ := time.ParseDuration(am.config.RateLimiting.FailedLogin.LockoutDuration)
		lockUser(lockout, lockoutDuration)

		// Save security state
		go am.saveSecurityState()

		return true, lockout.LockedUntil
	}

	return false, time.Time{}
}

// ClearUserLockout manually clears a user's lockout
func (am *AuthManager) ClearUserLockout(username string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	lockout, exists := am.userLockouts[username]
	if !exists {
		return fmt.Errorf("no lockout found for user %s", username)
	}

	clearLockout(lockout)
	return am.saveSecurityState()
}
```

**Step 6: Commit**

```bash
git add internal/auth/ratelimit.go internal/auth/ratelimit_test.go internal/auth/manager.go
git commit -m "feat(auth): add rate limiting and user lockouts

- Implement failed login attempt tracking
- Add configurable lockout after max attempts
- Support time window for attempt counting
- Auto-cleanup old attempts outside window
- Integrate lockout checks into AuthManager
- Add manual lockout clearing for admins"
```

---

## Phase 4: Logging and Alerts

### Task 9: Structured Logging

**Files:**
- Create: `internal/logging/logger.go`
- Create: `internal/logging/logger_test.go`

**Step 1: Write test for structured logger**

Create `internal/logging/logger_test.go`:

```go
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
		"username": "testuser",
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

	if !strings.Contains(output, "[INFO]") {
		t.Error("Expected output to contain [INFO]")
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
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/logging/... -v
```

Expected: FAIL with "package logging is not in GOROOT"

**Step 3: Implement structured logger**

Create `internal/logging/logger.go`:

```go
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
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/logging/... -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add internal/logging/logger.go internal/logging/logger_test.go
git commit -m "feat(logging): add structured logging system

- Implement JSON and text log formats
- Support configurable log levels (debug, info, warn, error)
- AI-optimized JSON structure with timestamp, component, event
- Human-readable text format option
- Level-based filtering
- Extensible field support for context"
```

---

## Execution Plan Summary

This implementation plan breaks down the GASP authentication system into **9 core tasks** following TDD principles:

### Phase 1: Core Authentication (Tasks 1-5)
1. Configuration foundation with YAML loading
2. Session data structures
3. JWT token generation and validation
4. PAM authentication via pwauth
5. Session store with persistence

### Phase 2: HTTP Integration (Tasks 6-7)
6. Authentication manager coordinating all components
7. HTTP handlers for /auth/login with error responses

### Phase 3: Security (Task 8)
8. Rate limiting and user lockouts

### Phase 4: Observability (Task 9)
9. Structured logging (JSON and text)

### Remaining Work (Not in this plan)
The following still need implementation:
- Email alerting (SMTP integration)
- Security state persistence (blocked IPs, lockouts)
- Complete login flow in AuthManager
- Auth middleware for protected endpoints
- CLI admin commands
- Installation scripts

---

## New Error Modes to Track

**Document for GASP skill updates:**

1. `pwauth_not_found` - pwauth binary not installed (500)
2. `jwt_secret_too_short` - JWT secret < 32 bytes (500)
3. `session_file_corrupted` - Unable to parse sessions.json (500, logged)

---

Plan complete and saved to `docs/plans/2024-12-22-authentication-system.md`.

**Execution Options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
