package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/accelerated-industries/gasp/internal/config"
)

func TestLocalhostBypass(t *testing.T) {
	// Create config with localhost bypass enabled
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled:         true,
			LocalhostBypass: true,
		},
	}

	srv := &Server{
		config: cfg,
	}

	// Create a test handler that should be protected
	called := false
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Wrap with auth middleware
	handler := srv.RequireAuth(protectedHandler)

	// Test request from localhost (127.0.0.1)
	req := httptest.NewRequest("GET", "http://localhost:8080/metrics", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Expected handler to be called for localhost request")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestLocalhostBypassIPv6(t *testing.T) {
	// Create config with localhost bypass enabled
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled:         true,
			LocalhostBypass: true,
		},
	}

	srv := &Server{
		config: cfg,
	}

	// Create a test handler
	called := false
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := srv.RequireAuth(protectedHandler)

	// Test request from IPv6 localhost (::1)
	req := httptest.NewRequest("GET", "http://localhost:8080/metrics", nil)
	req.RemoteAddr = "[::1]:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Expected handler to be called for IPv6 localhost request")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestNonLocalhostRequiresAuth(t *testing.T) {
	// Create config with localhost bypass enabled
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled:         true,
			LocalhostBypass: true,
		},
	}

	srv := &Server{
		config: cfg,
	}

	// Create a test handler
	called := false
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := srv.RequireAuth(protectedHandler)

	// Test request from non-localhost IP without auth
	req := httptest.NewRequest("GET", "http://localhost:8080/metrics", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if called {
		t.Error("Expected handler NOT to be called for non-localhost without auth")
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestLocalhostBypassDisabled(t *testing.T) {
	// Create config with localhost bypass DISABLED
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled:         true,
			LocalhostBypass: false,
		},
	}

	srv := &Server{
		config: cfg,
	}

	// Create a test handler
	called := false
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := srv.RequireAuth(protectedHandler)

	// Test request from localhost but bypass disabled - should require auth
	req := httptest.NewRequest("GET", "http://localhost:8080/metrics", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if called {
		t.Error("Expected handler NOT to be called when bypass disabled")
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAuthDisabled(t *testing.T) {
	// Create config with auth disabled
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled: false,
		},
	}

	srv := &Server{
		config: cfg,
	}

	// Create a test handler
	called := false
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := srv.RequireAuth(protectedHandler)

	// When auth disabled, all requests should pass through
	req := httptest.NewRequest("GET", "http://localhost:8080/metrics", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Expected handler to be called when auth is disabled")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestLocalhostBypass_BrowserRequests(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled:         true,
			LocalhostBypass: true,
		},
	}
	srv := &Server{config: cfg}
	handler := srv.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		remoteAddr string
		host       string
		origin     string
		wantCode   int
	}{
		{"localhost name", "127.0.0.1:12345", "localhost:8080", "", http.StatusOK},
		{"loopback IPv4", "127.0.0.1:12345", "127.0.0.1:8080", "", http.StatusOK},
		{"loopback IPv6", "[::1]:12345", "[::1]:8080", "", http.StatusOK},
		{"no port", "127.0.0.1:12345", "localhost", "", http.StatusOK},
		{"DNS rebinding", "127.0.0.1:12345", "evil.example:8080", "", http.StatusUnauthorized},
		{"LAN hostname", "127.0.0.1:12345", "anvil.local:8080", "", http.StatusUnauthorized},
		{"cross-origin page", "127.0.0.1:12345", "localhost:8080", "https://evil.example", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/metrics", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("Expected %d, got %d", tt.wantCode, w.Code)
			}
		})
	}
}

func TestNoCrossOriginAccess(t *testing.T) {
	srv := &Server{config: &config.Config{}, version: "test"}
	h := srv.Handler()

	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		req := httptest.NewRequest(method, "http://localhost:8080/version", nil)
		req.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s: Access-Control-Allow-Origin = %q, want none", method, got)
		}
	}
}

func TestLocalhostBypass_ProxiedAndNonLoopback(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled:         true,
			LocalhostBypass: true,
		},
	}
	srv := &Server{config: cfg}
	handler := srv.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		remoteAddr string
		header     string
		value      string
		wantCode   int
	}{
		{"proxy X-Forwarded-For", "127.0.0.1:12345", "X-Forwarded-For", "203.0.113.9", http.StatusUnauthorized},
		{"proxy X-Real-IP", "127.0.0.1:12345", "X-Real-IP", "203.0.113.9", http.StatusUnauthorized},
		{"proxy Forwarded", "127.0.0.1:12345", "Forwarded", "for=203.0.113.9", http.StatusUnauthorized},
		{"proxy X-Forwarded-Host", "127.0.0.1:12345", "X-Forwarded-Host", "gasp.example", http.StatusUnauthorized},
		// A remote client can't claim to be local with a header.
		{"spoofed X-Forwarded-For", "192.168.1.100:12345", "X-Forwarded-For", "127.0.0.1", http.StatusUnauthorized},
		// Only 127.0.0.1 and ::1 are local; pin that.
		{"127.0.0.2", "127.0.0.2:12345", "", "", http.StatusUnauthorized},
		{"IPv4-mapped loopback", "[::ffff:127.0.0.1]:12345", "", "", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost:8080/metrics", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.header != "" {
				req.Header.Set(tt.header, tt.value)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("Expected %d, got %d", tt.wantCode, w.Code)
			}
		})
	}
}
