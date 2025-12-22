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
	req := httptest.NewRequest("GET", "/metrics", nil)
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
	req := httptest.NewRequest("GET", "/metrics", nil)
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
	req := httptest.NewRequest("GET", "/metrics", nil)
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
	req := httptest.NewRequest("GET", "/metrics", nil)
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
	req := httptest.NewRequest("GET", "/metrics", nil)
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
