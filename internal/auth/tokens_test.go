package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func writeSecret(t *testing.T, secret []byte, mode os.FileMode) string {
	t.Helper()
	secretFile := filepath.Join(t.TempDir(), "jwt-secret")
	if err := os.WriteFile(secretFile, secret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}
	if err := os.Chmod(secretFile, mode); err != nil {
		t.Fatalf("Failed to chmod secret: %v", err)
	}
	return secretFile
}

func TestLoadSecret_FilePermissions(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	tests := []struct {
		mode      os.FileMode
		expectErr bool
	}{
		{0600, false},
		{0400, false},
		{0640, true},
		{0644, true},
		{0604, true},
		{0660, true},
	}
	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			tm := NewTokenManager(writeSecret(t, secret, tt.mode))
			err := tm.LoadSecret()
			if (err != nil) != tt.expectErr {
				t.Fatalf("LoadSecret() error = %v, expectErr %v", err, tt.expectErr)
			}
			if err != nil && !strings.Contains(err.Error(), "chmod 600") {
				t.Errorf("Expected the error to say how to fix it, got: %v", err)
			}
		})
	}
}

func TestLoadSecret_WhitespaceDoesNotCount(t *testing.T) {
	short := []byte(strings.Repeat("a", 31) + "\n")
	if err := NewTokenManager(writeSecret(t, short, 0600)).LoadSecret(); err == nil {
		t.Error("31 bytes plus a newline should be rejected")
	}

	// A valid secret with a trailing newline still loads, and the newline
	// stays part of the key, so tokens signed by older builds still verify.
	withNewline := []byte(strings.Repeat("a", 32) + "\n")
	tm := NewTokenManager(writeSecret(t, withNewline, 0600))
	if err := tm.LoadSecret(); err != nil {
		t.Fatalf("LoadSecret() = %v", err)
	}
	if string(tm.secret) != string(withNewline) {
		t.Errorf("Secret bytes changed: got %q", tm.secret)
	}
}

func TestValidateToken_RejectsForgedTokens(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	tm := NewTokenManager(writeSecret(t, secret, 0600))
	if err := tm.LoadSecret(); err != nil {
		t.Fatalf("LoadSecret() = %v", err)
	}

	now := time.Now()
	validClaims := func() GASPClaims {
		return GASPClaims{
			TokenID:  1,
			Username: "alice",
			ClientIP: "192.0.2.10",
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				Subject:   "alice",
				Issuer:    tokenIssuer,
				Audience:  jwt.ClaimStrings{tokenAudience},
			},
		}
	}
	sign := func(t *testing.T, method jwt.SigningMethod, claims GASPClaims, key interface{}) string {
		t.Helper()
		s, err := jwt.NewWithClaims(method, claims).SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}

	// Sanity check: a correctly built token is accepted
	if _, err := tm.ValidateToken(sign(t, jwt.SigningMethodHS256, validClaims(), secret)); err != nil {
		t.Fatalf("Valid token rejected: %v", err)
	}

	noIssuer := validClaims()
	noIssuer.Issuer = ""
	otherAudience := validClaims()
	otherAudience.Audience = jwt.ClaimStrings{"other-service"}
	noExpiry := validClaims()
	noExpiry.ExpiresAt = nil

	tests := []struct {
		name  string
		token string
	}{
		{"wrong key", sign(t, jwt.SigningMethodHS256, validClaims(), []byte("another-secret-key-that-is-32-bytes-long"))},
		{"HS512 with the same key", sign(t, jwt.SigningMethodHS512, validClaims(), secret)},
		{"alg none", sign(t, jwt.SigningMethodNone, validClaims(), jwt.UnsafeAllowNoneSignatureType)},
		{"missing issuer", sign(t, jwt.SigningMethodHS256, noIssuer, secret)},
		{"wrong audience", sign(t, jwt.SigningMethodHS256, otherAudience, secret)},
		{"no expiry", sign(t, jwt.SigningMethodHS256, noExpiry, secret)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tm.ValidateToken(tt.token); err == nil {
				t.Errorf("Expected %s to be rejected", tt.name)
			}
		})
	}
}

func TestGenerateToken_SetsIssuerAndAudience(t *testing.T) {
	tm := NewTokenManager(writeSecret(t, []byte("test-secret-key-at-least-32-chars-long-12345"), 0600))
	if err := tm.LoadSecret(); err != nil {
		t.Fatalf("LoadSecret() = %v", err)
	}
	session := &Session{TokenID: 7, Username: "alice", ClientIP: "192.0.2.10",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	token, err := tm.GenerateToken(session)
	if err != nil {
		t.Fatalf("GenerateToken() = %v", err)
	}
	claims, err := tm.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() = %v", err)
	}
	if claims.Issuer != tokenIssuer || len(claims.Audience) != 1 || claims.Audience[0] != tokenAudience {
		t.Errorf("Expected iss and aud %q, got iss=%q aud=%v", tokenIssuer, claims.Issuer, claims.Audience)
	}
}
