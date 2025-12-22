package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadSecretTooShort(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "jwt-secret")
	shortSecret := []byte("too-short")
	if err := os.WriteFile(secretFile, shortSecret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	tm := NewTokenManager(secretFile)
	err := tm.LoadSecret()
	if err == nil {
		t.Error("Expected error for secret < 32 bytes")
	}
	if !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Errorf("Expected error message about minimum length, got: %v", err)
	}
}

func TestGenerateSecret(t *testing.T) {
	secret1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	if len(secret1) != 64 {
		t.Errorf("Expected 64-byte secret, got %d bytes", len(secret1))
	}

	// Verify randomness - two calls should produce different secrets
	secret2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate second secret: %v", err)
	}

	if bytes.Equal(secret1, secret2) {
		t.Error("Two generated secrets should not be identical")
	}

	// Verify secret is not all zeros
	allZeros := true
	for _, b := range secret1 {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Generated secret should not be all zeros")
	}
}

func TestValidateInvalidTokenFormat(t *testing.T) {
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

	testCases := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"random string", "not-a-valid-jwt-token"},
		{"malformed JWT", "header.payload"},
		{"invalid base64", "abc.def.ghi"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tm.ValidateToken(tc.token)
			if err == nil {
				t.Errorf("Expected validation to fail for %s", tc.name)
			}
		})
	}
}
