package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/accelerated-industries/gasp/internal/auth"
	"github.com/accelerated-industries/gasp/internal/collectors"
	"github.com/accelerated-industries/gasp/internal/config"
)

// Server represents the HTTP server
type Server struct {
	manager     *collectors.Manager
	authManager *auth.AuthManager
	config      *config.Config
	version     string
	port        int
}

// Config holds server configuration
type Config struct {
	Port    int
	Version string
}

// NewServer creates a new HTTP server
func NewServer(manager *collectors.Manager, config Config) *Server {
	return &Server{
		manager:     manager,
		authManager: nil, // Set separately via SetAuthManager
		version:     config.Version,
		port:        config.Port,
	}
}

// SetAuthManager sets the authentication manager
func (s *Server) SetAuthManager(authManager *auth.AuthManager) {
	s.authManager = authManager
}

// SetConfig sets the configuration
func (s *Server) SetConfig(cfg *config.Config) {
	s.config = cfg
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Register public endpoints (no auth required)
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/version", s.handleVersion)

	// Register protected endpoints (auth required unless localhost bypass)
	mux.Handle("/health", s.RequireAuth(http.HandlerFunc(s.handleHealth)))
	mux.Handle("/metrics", s.RequireAuth(http.HandlerFunc(s.handleMetrics)))

	// Add CORS middleware
	handler := corsMiddleware(mux)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Starting GASP server on %s", addr)
	log.Printf("Endpoints:")
	log.Printf("  http://localhost%s/health  - Health check", addr)
	log.Printf("  http://localhost%s/metrics - System metrics", addr)
	log.Printf("  http://localhost%s/version - Version info", addr)

	return http.ListenAndServe(addr, handler)
}

// handleHealth returns a simple health check response
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "gasp",
	}

	json.NewEncoder(w).Encode(response)
}

// handleMetrics returns the full system snapshot
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Collect all metrics
	snapshot, err := s.manager.CollectAll()
	if err != nil {
		log.Printf("Error collecting metrics: %v", err)
		// Still return the snapshot even if there were partial errors
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ") // Pretty print for readability
	if err := encoder.Encode(snapshot); err != nil {
		log.Printf("Error encoding metrics: %v", err)
	}
}

// handleVersion returns version information
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"service": "gasp",
		"version": s.version,
		"build":   "development",
	}

	json.NewEncoder(w).Encode(response)
}

// corsMiddleware adds CORS headers to responses
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
