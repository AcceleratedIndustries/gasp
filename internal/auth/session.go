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
//
// The function uses crypto/rand to generate a cryptographically secure random
// 64-bit token ID. If crypto/rand fails (which should never happen on properly
// configured Linux systems), it falls back to time.Now().UnixNano().
//
// Note: The fallback path is not tested because:
// 1. crypto/rand.Read() cannot fail on properly configured Linux systems
// 2. Forcing crypto/rand to fail would require monkey-patching or OS-level manipulation
// 3. The fallback exists only as a safety measure for catastrophic system failures
// 4. Testing the fallback would require invasive mocking that reduces test value
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
