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
