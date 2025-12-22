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
