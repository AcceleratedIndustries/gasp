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

func TestValidateCredentials(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{"valid", "alice", "correct horse", false},
		{"tab in password allowed", "alice", "pass\tword", false},
		{"empty username", "", "secret", true},
		{"empty password", "alice", "", true},
		{"newline in username", "root\nGUESS", "x", true},
		{"carriage return in username", "root\rGUESS", "x", true},
		{"NUL in username", "root\x00", "x", true},
		{"tab in username", "root\t", "x", true},
		{"DEL in username", "root\x7f", "x", true},
		{"newline in password", "alice", "secret\nextra", true},
		{"carriage return in password", "alice", "secret\r", true},
		{"NUL in password", "alice", "sec\x00ret", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCredentials(tt.username, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCredentials(%q, %q) error = %v, wantErr %v", tt.username, tt.password, err, tt.wantErr)
			}
		})
	}
}
