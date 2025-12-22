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
