package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/accelerated-industries/gasp/internal/auth"
	"github.com/accelerated-industries/gasp/internal/config"
)

// newTestServerWithBlockedIPs builds a Server with a real AuthManager whose
// saved security state already blocks the given IPs.
func newTestServerWithBlockedIPs(t *testing.T, blocked ...string) *Server {
	t.Helper()
	tmpDir := t.TempDir()

	secretFile := filepath.Join(tmpDir, "jwt-secret")
	secret := []byte("test-secret-key-at-least-32-chars-long-12345")
	if err := os.WriteFile(secretFile, secret, 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	state := auth.SecurityState{BlockedIPs: map[string]*auth.BlockedIP{}}
	for _, ip := range blocked {
		state.BlockedIPs[ip] = &auth.BlockedIP{IP: ip, Reason: "test_block", BlockedAt: time.Now()}
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Failed to marshal security state: %v", err)
	}
	securityFile := filepath.Join(tmpDir, "security.json")
	if err := os.WriteFile(securityFile, data, 0600); err != nil {
		t.Fatalf("Failed to write security state: %v", err)
	}

	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled: true,
			JWT: config.JWTConfig{
				SecretFile: secretFile,
			},
		},
	}

	am, err := auth.NewAuthManager(cfg, filepath.Join(tmpDir, "sessions.json"), securityFile)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	return &Server{config: cfg, authManager: am}
}

func TestHandleLogin_BlockedIPIsRecognized(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		blockedIP  string
	}{
		{"IPv4", "192.168.1.200:51234", "192.168.1.200"},
		{"IPv6", "[2001:db8::5]:51234", "2001:db8::5"},
		{"IPv6 loopback", "[::1]:51234", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServerWithBlockedIPs(t, tt.blockedIP)

			req := httptest.NewRequest(http.MethodPost, "/auth/login",
				strings.NewReader(`{"username":"alice","password":"secret"}`))
			req.RemoteAddr = tt.remoteAddr
			w := httptest.NewRecorder()

			srv.handleLogin(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("Expected 403 for blocked IP %s, got %d: %s", tt.blockedIP, w.Code, w.Body.String())
			}

			var resp ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}
			if resp.Error != "ip_blocked" {
				t.Errorf("Expected error ip_blocked, got %q", resp.Error)
			}
			if got := resp.Details["ip"]; got != tt.blockedIP {
				t.Errorf("Expected ip %q in details, got %v", tt.blockedIP, got)
			}
		})
	}
}

// The IP that login binds to a session must be the IP the middleware sees
// on later requests, or the first request with the new token is treated as
// an IP binding violation.
func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		want       string
	}{
		{"192.168.1.100:12345", "192.168.1.100"},
		{"127.0.0.1:8080", "127.0.0.1"},
		{"[::1]:12345", "::1"},
		{"[2001:db8::5]:51234", "2001:db8::5"},
		{"[fe80::1%eth0]:51234", "fe80::1%eth0"},
	}

	for _, tt := range tests {
		if got := extractClientIP(tt.remoteAddr); got != tt.want {
			t.Errorf("extractClientIP(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
		}
	}
}
