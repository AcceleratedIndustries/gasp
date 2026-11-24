package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
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
	address     string

	readTimeout  time.Duration
	writeTimeout time.Duration
}

// Config holds server configuration
type Config struct {
	Port    int
	Version string
	// Address is the host:port to listen on. If empty, the server listens
	// on all interfaces at Port.
	Address string
	// ReadTimeout and WriteTimeout bound how long a client may take to send
	// a request and to receive the response. Zero means the default.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Default HTTP timeouts, used when the config leaves them unset. They stop
// slow clients from holding connections open indefinitely.
const (
	defaultReadHeaderTimeout = 10 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 60 * time.Second
	defaultIdleTimeout       = 120 * time.Second
)

// NewServer creates a new HTTP server
func NewServer(manager *collectors.Manager, config Config) *Server {
	return &Server{
		manager:     manager,
		authManager: nil, // Set separately via SetAuthManager
		version:     config.Version,
		port:        config.Port,
		address:     config.Address,

		readTimeout:  config.ReadTimeout,
		writeTimeout: config.WriteTimeout,
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

// Handler returns the server's HTTP handler with all routes registered
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Register public endpoints (no auth required)
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/version", s.handleVersion)

	// Register protected endpoints (auth required unless localhost bypass)
	mux.Handle("/health", s.RequireAuth(http.HandlerFunc(s.handleHealth)))
	mux.Handle("/metrics", s.RequireAuth(http.HandlerFunc(s.handleMetrics)))

	// Add CORS middleware
	return corsMiddleware(mux)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	handler := s.Handler()

	addr := s.address
	if addr == "" {
		addr = fmt.Sprintf(":%d", s.port)
	}
	base := displayURL(addr)
	log.Printf("Starting GASP server on %s", addr)
	log.Printf("Endpoints:")
	log.Printf("  %s/health  - Health check", base)
	log.Printf("  %s/metrics - System metrics", base)
	log.Printf("  %s/version - Version info", base)

	return s.httpServer(addr, handler).ListenAndServe()
}

// httpServer builds the *http.Server with timeouts applied
func (s *Server) httpServer(addr string, handler http.Handler) *http.Server {
	readTimeout := s.readTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	writeTimeout := s.writeTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultWriteTimeout
	}
	readHeaderTimeout := defaultReadHeaderTimeout
	if readHeaderTimeout > readTimeout {
		readHeaderTimeout = readTimeout
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       defaultIdleTimeout,
		MaxHeaderBytes:    1 << 20,
	}
}

// displayURL turns a listen address into a URL for log messages
func displayURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
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

// corsMiddleware answers preflight requests. It deliberately grants no
// cross-origin access: GASP serves CLI and AI clients, not browser pages,
// and "Access-Control-Allow-Origin: *" let any web page open on this
// machine read /metrics through the localhost bypass.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
