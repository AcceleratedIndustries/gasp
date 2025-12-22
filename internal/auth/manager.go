package auth

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// Login authenticates a user and creates a session
func (am *AuthManager) Login(username, password, clientIP, clientID string, ttl time.Duration) (*Session, string, error) {
	// Check if user is locked out
	if locked, lockedUntil := am.CheckUserLockout(username); locked {
		return nil, "", fmt.Errorf("user locked out until %v", lockedUntil)
	}

	// Authenticate via PAM
	if err := am.pamAuth.Authenticate(username, password); err != nil {
		// Record failed attempt
		shouldLock, lockedUntil := am.RecordFailedLogin(username, clientIP)
		if shouldLock {
			return nil, "", fmt.Errorf("user locked out until %v after too many failed attempts", lockedUntil)
		}
		return nil, "", fmt.Errorf("authentication failed")
	}

	// Create session
	session := NewSession(username, clientIP, clientID, ttl)
	am.sessions.Create(session)

	// Generate JWT token
	token, err := am.tokenManager.GenerateToken(session)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Save sessions
	if err := am.sessions.Save(); err != nil {
		// Log but don't fail
		fmt.Printf("Warning: failed to save sessions: %v\n", err)
	}

	return session, token, nil
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

// SecurityState holds all security-related state for persistence
type SecurityState struct {
	BlockedIPs   map[string]*BlockedIP   `json:"blocked_ips"`
	UserLockouts map[string]*UserLockout `json:"user_lockouts"`
}

func (am *AuthManager) loadSecurityState() error {
	data, err := os.ReadFile(am.securityFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet, that's okay
		}
		return fmt.Errorf("failed to read security state: %w", err)
	}

	var state SecurityState
	if err := json.Unmarshal(data, &state); err != nil {
		// Log warning but don't fail - start fresh
		fmt.Printf("Warning: failed to unmarshal security state (starting fresh): %v\n", err)
		return nil
	}

	// Restore state
	if state.BlockedIPs != nil {
		am.blockedIPs = state.BlockedIPs
	}
	if state.UserLockouts != nil {
		am.userLockouts = state.UserLockouts
	}

	return nil
}

func (am *AuthManager) saveSecurityState() error {
	am.mu.RLock()
	defer am.mu.RUnlock()

	state := SecurityState{
		BlockedIPs:   am.blockedIPs,
		UserLockouts: am.userLockouts,
	}

	// Create directory if needed
	dir := filepath.Dir(am.securityFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Atomic write (temp + rename)
	tempFile := am.securityFile + ".tmp"
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal security state: %w", err)
	}

	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write security state: %w", err)
	}

	if err := os.Rename(tempFile, am.securityFile); err != nil {
		return fmt.Errorf("failed to rename security state file: %w", err)
	}

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
