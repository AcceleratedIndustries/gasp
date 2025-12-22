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

func TestUserLockoutIsLocked(t *testing.T) {
	// Test locked user (LockedUntil in the future)
	lockedUser := &UserLockout{
		Username:    "locked",
		LockedUntil: time.Now().Add(1 * time.Hour),
	}

	if !lockedUser.IsLocked() {
		t.Error("Expected user to be locked (LockedUntil in future)")
	}

	// Test unlocked user (LockedUntil in the past)
	unlockedUser := &UserLockout{
		Username:    "unlocked",
		LockedUntil: time.Now().Add(-1 * time.Hour),
	}

	if unlockedUser.IsLocked() {
		t.Error("Expected user to be unlocked (LockedUntil in past)")
	}

	// Test user with zero LockedUntil
	neverLockedUser := &UserLockout{
		Username:    "neverlocked",
		LockedUntil: time.Time{},
	}

	if neverLockedUser.IsLocked() {
		t.Error("Expected user to be unlocked (zero LockedUntil)")
	}
}

func TestTokenIDUniqueness(t *testing.T) {
	const iterations = 1000
	seenIDs := make(map[uint64]bool, iterations)

	for i := 0; i < iterations; i++ {
		session := NewSession("testuser", "192.168.1.100", "gasp-cli", 24*time.Hour)

		if seenIDs[session.TokenID] {
			t.Errorf("Token ID collision detected: %d appeared more than once", session.TokenID)
		}

		seenIDs[session.TokenID] = true
	}

	if len(seenIDs) != iterations {
		t.Errorf("Expected %d unique token IDs, got %d", iterations, len(seenIDs))
	}
}
