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
