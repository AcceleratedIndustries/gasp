package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/accelerated-industries/gasp/internal/auth"
	"github.com/accelerated-industries/gasp/internal/config"
)

// fakePwauthScript accepts only alice/correct, like pwauth: one line of
// username and one of password on stdin, exit 0 on success.
const fakePwauthScript = `#!/bin/sh
read -r user
read -r pass
[ "$user" = "alice" ] && [ "$pass" = "correct" ]
`

// newE2EServer builds a Server with a real AuthManager that checks
// passwords with a fake pwauth script.
func newE2EServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available for fake pwauth")
	}

	pwauth := filepath.Join(t.TempDir(), "fake-pwauth")
	if err := os.WriteFile(pwauth, []byte(fakePwauthScript), 0700); err != nil {
		t.Fatalf("Failed to write fake pwauth: %v", err)
	}
	return newE2EServerWithPwauth(t, pwauth)
}

// newE2EServerWithPwauth is newE2EServer with a chosen pwauth path.
func newE2EServerWithPwauth(t *testing.T, pwauth string) (*Server, http.Handler) {
	t.Helper()
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "jwt-secret")
	if err := os.WriteFile(secretFile, []byte("test-secret-key-at-least-32-chars-long-12345"), 0600); err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}

	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled:         true,
			LocalhostBypass: true,
			Passwords: []config.PasswordConfig{
				{Name: "default", TokenTTL: "1h", TokenTTLParsed: time.Hour},
			},
			JWT:        config.JWTConfig{SecretFile: secretFile},
			PwauthPath: pwauth,
		},
		RateLimiting: config.RateLimitingConfig{
			FailedLogin: config.FailedLoginConfig{
				MaxAttempts:     3,
				LockoutDuration: "15m",
			},
		},
	}

	am, err := auth.NewAuthManager(cfg, filepath.Join(tmpDir, "sessions.json"), filepath.Join(tmpDir, "security.json"))
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}
	t.Cleanup(am.Flush)

	srv := &Server{config: cfg, authManager: am, version: "test"}
	return srv, srv.Handler()
}

type e2eResult struct {
	code int
	body map[string]interface{}
	hdr  http.Header
}

func doRequest(t *testing.T, h http.Handler, method, path, remoteAddr, body string, setup func(*http.Request)) e2eResult {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	if setup != nil {
		setup(req)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	res := e2eResult{code: w.Code, hdr: w.Header()}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &res.body); err != nil {
			t.Fatalf("%s %s: response is not JSON: %q", method, path, w.Body.String())
		}
	}
	return res
}

func login(t *testing.T, h http.Handler, remoteAddr, username, password string) e2eResult {
	t.Helper()
	body, _ := json.Marshal(LoginRequest{Username: username, Password: password})
	return doRequest(t, h, http.MethodPost, "/auth/login", remoteAddr, string(body), nil)
}

func withBearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func TestLoginFlow_EndToEnd(t *testing.T) {
	clients := []struct {
		name, loginAddr, laterAddr, ip string
	}{
		{"IPv4", "192.168.1.50:40000", "192.168.1.50:40001", "192.168.1.50"},
		{"IPv6", "[2001:db8::50]:40000", "[2001:db8::50]:40001", "2001:db8::50"},
	}

	for _, c := range clients {
		t.Run(c.name, func(t *testing.T) {
			_, h := newE2EServer(t)

			before := time.Now()
			res := login(t, h, c.loginAddr, "alice", "correct")
			if res.code != http.StatusOK {
				t.Fatalf("Login: expected 200, got %d: %v", res.code, res.body)
			}
			token, _ := res.body["token"].(string)
			if token == "" {
				t.Fatal("Login: expected a token")
			}
			if got := res.body["issued_to_ip"]; got != c.ip {
				t.Errorf("issued_to_ip = %v, want %s", got, c.ip)
			}
			if _, ok := res.body["token_id"].(string); !ok {
				t.Errorf("token_id should be a string, got %T", res.body["token_id"])
			}
			expiresAt, err := time.Parse(time.RFC3339Nano, res.body["expires_at"].(string))
			if err != nil {
				t.Fatalf("Bad expires_at: %v", err)
			}
			if d := expiresAt.Sub(before); d < time.Hour-time.Minute || d > time.Hour+time.Minute {
				t.Errorf("Token should expire in about 1h (config), expires in %v", d)
			}

			// The token works from the same client on a new connection.
			res = doRequest(t, h, http.MethodGet, "/health", c.laterAddr, "", withBearer(token))
			if res.code != http.StatusOK {
				t.Fatalf("Protected request: expected 200, got %d: %v", res.code, res.body)
			}
		})
	}
}

func TestLoginFlow_BasicAuth(t *testing.T) {
	_, h := newE2EServer(t)

	res := doRequest(t, h, http.MethodPost, "/auth/login", "192.168.1.50:40000", "", func(r *http.Request) {
		r.SetBasicAuth("alice", "correct")
	})
	if res.code != http.StatusOK {
		t.Fatalf("Basic Auth login: expected 200, got %d: %v", res.code, res.body)
	}
}

func TestLoginFlow_BadCredentials(t *testing.T) {
	_, h := newE2EServer(t)

	wrongPassword := login(t, h, "192.168.1.50:40000", "alice", "wrong")
	unknownUser := login(t, h, "192.168.1.50:40000", "mallory", "wrong")

	for name, res := range map[string]e2eResult{"wrong password": wrongPassword, "unknown user": unknownUser} {
		if res.code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", name, res.code)
		}
		if res.body["error"] != "invalid_credentials" {
			t.Errorf("%s: expected invalid_credentials, got %v", name, res.body["error"])
		}
		if res.hdr.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: expected WWW-Authenticate header", name)
		}
	}
	if wrongPassword.body["message"] != unknownUser.body["message"] {
		t.Error("Wrong password and unknown user must look the same")
	}
}

func TestLoginFlow_Lockout(t *testing.T) {
	_, h := newE2EServer(t)

	for i := 0; i < 2; i++ {
		if res := login(t, h, "192.168.1.50:40000", "alice", "wrong"); res.body["error"] != "invalid_credentials" {
			t.Fatalf("Attempt %d: expected invalid_credentials, got %v", i+1, res.body["error"])
		}
	}
	if res := login(t, h, "192.168.1.50:40000", "alice", "wrong"); res.body["error"] != "user_locked_out" {
		t.Fatalf("3rd failure: expected user_locked_out, got %v", res.body["error"])
	}

	// Locked out even with the right password.
	res := login(t, h, "192.168.1.50:40000", "alice", "correct")
	if res.code != http.StatusUnauthorized || res.body["error"] != "user_locked_out" {
		t.Fatalf("Correct password while locked: expected 401 user_locked_out, got %d %v", res.code, res.body["error"])
	}
}

func TestLoginFlow_IPBindingViolation(t *testing.T) {
	_, h := newE2EServer(t)

	res := login(t, h, "192.168.1.50:40000", "alice", "correct")
	if res.code != http.StatusOK {
		t.Fatalf("Login: expected 200, got %d: %v", res.code, res.body)
	}
	token := res.body["token"].(string)

	// Stolen token used from another host.
	res = doRequest(t, h, http.MethodGet, "/health", "192.168.1.66:40000", "", withBearer(token))
	if res.code != http.StatusForbidden || res.body["error"] != "ip_binding_violation" {
		t.Fatalf("Expected 403 ip_binding_violation, got %d %v", res.code, res.body["error"])
	}
	if strings.Contains(strings.Join(mapValues(res.body), " "), token) {
		t.Error("Error response must not echo the token")
	}

	// The token is revoked for its owner too.
	res = doRequest(t, h, http.MethodGet, "/health", "192.168.1.50:40001", "", withBearer(token))
	if res.code != http.StatusUnauthorized || res.body["error"] != "token_revoked" {
		t.Fatalf("Expected 401 token_revoked, got %d %v", res.code, res.body["error"])
	}

	// The offending host is blocked from logging in.
	res = login(t, h, "192.168.1.66:40000", "alice", "correct")
	if res.code != http.StatusForbidden || res.body["error"] != "ip_blocked" {
		t.Fatalf("Expected 403 ip_blocked, got %d %v", res.code, res.body["error"])
	}
}

func TestLoginFlow_ProtectedRouteResponses(t *testing.T) {
	_, h := newE2EServer(t)

	res := doRequest(t, h, http.MethodGet, "/health", "192.168.1.50:40000", "", nil)
	if res.code != http.StatusUnauthorized || res.body["error"] != "missing_credentials" {
		t.Errorf("No token: expected 401 missing_credentials, got %d %v", res.code, res.body["error"])
	}

	res = doRequest(t, h, http.MethodGet, "/health", "192.168.1.50:40000", "", withBearer("not-a-jwt"))
	if res.code != http.StatusUnauthorized || res.body["error"] != "token_invalid" {
		t.Errorf("Garbage token: expected 401 token_invalid, got %d %v", res.code, res.body["error"])
	}

	res = doRequest(t, h, http.MethodGet, "/auth/login", "192.168.1.50:40000", "", nil)
	if res.code != http.StatusMethodNotAllowed || res.body["error"] != "invalid_method" {
		t.Errorf("GET login: expected 405 invalid_method, got %d %v", res.code, res.body["error"])
	}

	res = doRequest(t, h, http.MethodPost, "/auth/login", "192.168.1.50:40000", "{not json", nil)
	if res.code != http.StatusBadRequest || res.body["error"] != "malformed_request" {
		t.Errorf("Malformed body: expected 400 malformed_request, got %d %v", res.code, res.body["error"])
	}
}

func mapValues(m map[string]interface{}) []string {
	var out []string
	for _, v := range m {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestLoginFlow_PwauthNotFound(t *testing.T) {
	_, h := newE2EServerWithPwauth(t, filepath.Join(t.TempDir(), "no-such-pwauth"))

	for i := 0; i < 4; i++ {
		res := login(t, h, "192.168.1.50:40000", "alice", "correct")
		if res.code != http.StatusServiceUnavailable || res.body["error"] != "pwauth_not_found" {
			t.Fatalf("Attempt %d: expected 503 pwauth_not_found, got %d %v", i+1, res.code, res.body["error"])
		}
	}
}

func TestLoginFlow_AllowedSources(t *testing.T) {
	srv, h := newE2EServer(t)
	srv.config.Auth.Passwords[0].AllowedSources = []config.AllowedIP{
		{IP: "192.168.1.0/24", Name: "home"},
		{IP: "2001:db8::/32", Name: "home v6"},
	}

	// Outside the list: refused before the password is checked, not blocked.
	res := login(t, h, "203.0.113.9:40000", "alice", "correct")
	if res.code != http.StatusForbidden || res.body["error"] != "unauthorized_source_ip" {
		t.Fatalf("Outside source: expected 403 unauthorized_source_ip, got %d %v", res.code, res.body["error"])
	}
	if srv.authManager.IsIPBlocked("203.0.113.9") {
		t.Error("A source outside the list should be refused, not permanently blocked")
	}

	// Inside the list, IPv4 and IPv6.
	for _, addr := range []string{"192.168.1.50:40000", "[2001:db8::50]:40000"} {
		if res := login(t, h, addr, "alice", "correct"); res.code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d %v", addr, res.code, res.body)
		}
	}

	// Tightening the list cuts off existing tokens too.
	res = login(t, h, "192.168.1.50:40000", "alice", "correct")
	token := res.body["token"].(string)
	srv.config.Auth.Passwords[0].AllowedSources = []config.AllowedIP{{IP: "10.0.0.0/8"}}
	res = doRequest(t, h, http.MethodGet, "/health", "192.168.1.50:40001", "", withBearer(token))
	if res.code != http.StatusForbidden || res.body["error"] != "unauthorized_source_ip" {
		t.Errorf("Token from removed source: expected 403 unauthorized_source_ip, got %d %v", res.code, res.body["error"])
	}
}
