package auth

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// PAMAuthenticator handles authentication via pwauth
type PAMAuthenticator struct {
	pwauthPath string
}

// NewPAMAuthenticator creates a new PAM authenticator
func NewPAMAuthenticator() *PAMAuthenticator {
	return &PAMAuthenticator{
		pwauthPath: "/usr/bin/pwauth",
	}
}

// ValidateCredentials rejects credentials that are empty or could change
// what pwauth reads. pwauth takes "username\npassword\n" on stdin, so a
// username like "root\nGUESS" would check root's password while lockout
// was tracked under a different key. Usernames may not contain any control
// character; passwords may not contain CR, LF or NUL.
func ValidateCredentials(username, password string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}
	for _, r := range username {
		if unicode.IsControl(r) {
			return fmt.Errorf("username contains invalid characters")
		}
	}
	if strings.ContainsAny(password, "\r\n\x00") {
		return fmt.Errorf("password contains invalid characters")
	}
	return nil
}

// Authenticate validates credentials via pwauth
func (p *PAMAuthenticator) Authenticate(username, password string) error {
	if err := ValidateCredentials(username, password); err != nil {
		return err
	}

	// Check if pwauth exists
	if _, err := exec.LookPath(p.pwauthPath); err != nil {
		return fmt.Errorf("pwauth not found (authentication unavailable): %w", err)
	}

	// Execute pwauth with username\npassword\n on stdin
	cmd := exec.Command(p.pwauthPath)

	stdin := bytes.NewBufferString(username + "\n" + password + "\n")
	cmd.Stdin = stdin

	// Capture output for debugging
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// pwauth returns 0 for success, non-zero for failure
	if err := cmd.Run(); err != nil {
		// Log the error details but return generic message
		return fmt.Errorf("authentication failed")
	}

	return nil
}

// HashPassword generates a bcrypt hash of a password
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifies a password against a bcrypt hash
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// IsIPInCIDR checks if an IP address is in a CIDR range
func IsIPInCIDR(ip, cidr string) (bool, error) {
	// Simple implementation for exact IP match or CIDR
	// For production, use net.ParseCIDR and ip.Contains

	// Exact match
	if ip == cidr {
		return true, nil
	}

	// CIDR match - simplified (production should use net package)
	if strings.Contains(cidr, "/") {
		parts := strings.Split(cidr, "/")
		network := parts[0]

		// Simple prefix match for /24
		if strings.HasSuffix(cidr, "/24") {
			ipPrefix := strings.Join(strings.Split(ip, ".")[:3], ".")
			networkPrefix := strings.Join(strings.Split(network, ".")[:3], ".")
			return ipPrefix == networkPrefix, nil
		}
	}

	return false, nil
}
