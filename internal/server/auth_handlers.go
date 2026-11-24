package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/accelerated-industries/gasp/internal/auth"
)

// maxLoginBodyBytes caps the login request body. A username and password
// fit in far less; the cap stops a client from making the server read an
// arbitrarily large body.
const maxLoginBodyBytes = 64 << 10

// LoginRequest represents a login request body
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	Token      string    `json:"token"`
	TokenID    string    `json:"token_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	Username   string    `json:"username"`
	IssuedToIP string    `json:"issued_to_ip"`
}

// handleLogin handles POST /auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "invalid_method",
			"Method not allowed for this endpoint.", "use_correct_method",
			map[string]interface{}{
				"method_used":     r.Method,
				"allowed_methods": []string{"POST"},
			})
		return
	}

	// Without auth there is nothing to log in to, and without an auth
	// manager the login below would dereference nil
	if s.config == nil || !s.config.Auth.Enabled {
		writeErrorResponse(w, http.StatusNotFound, "authentication_disabled",
			"Authentication is disabled on this server. No login is needed.",
			"no_auth_required", nil)
		return
	}
	if s.authManager == nil {
		writeErrorResponse(w, http.StatusServiceUnavailable,
			"authentication_service_unavailable",
			"Authentication service is not available.",
			"retry_later",
			nil)
		return
	}

	// Extract client IP the same way RequireAuth does, so the IP bound to
	// the session matches the IP seen on later requests (IPv6 included)
	clientIP := extractClientIP(r.RemoteAddr)

	// Check if IP is blocked (direct requests from localhost are exempt)
	if s.isBlocked(r, clientIP) {
		writeForbidden(w, "ip_blocked", "Access denied. Your IP address has been blocked.",
			"contact_admin", map[string]interface{}{
				"ip": clientIP,
			})
		return
	}

	// Only sources listed in allowed_sources may log in (any, if none are
	// listed). The spec also blocks such IPs permanently; that is left out
	// on purpose, since a typo in the list would lock out a real client.
	if !s.authManager.IsSourceAllowed(clientIP) {
		writeForbidden(w, "unauthorized_source_ip", "Access denied. Your IP address is not authorized.",
			"contact_admin", map[string]interface{}{
				"source_ip": clientIP,
			})
		return
	}

	// Parse credentials (support both Basic Auth and JSON body)
	var username, password string

	// Try Basic Auth first
	if u, p, ok := r.BasicAuth(); ok {
		username = u
		password = p
	} else {
		// Try JSON body
		var loginReq LoginRequest
		r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeErrorResponse(w, http.StatusRequestEntityTooLarge, "request_too_large",
					"Request body is too large.", "fix_request", nil)
				return
			}
			writeBadRequest(w, "malformed_request",
				"Request body is malformed or missing required fields.", "fix_request")
			return
		}
		username = loginReq.Username
		password = loginReq.Password
	}

	if username == "" || password == "" {
		writeBadRequest(w, "malformed_request",
			"Username and password are required.", "fix_request")
		return
	}

	if err := auth.ValidateCredentials(username, password); err != nil {
		writeBadRequest(w, "malformed_request",
			"Username and password must not contain control characters.", "fix_request")
		return
	}

	// Get TTL from config (default 7 days)
	ttl := 7 * 24 * time.Hour
	if s.config != nil && len(s.config.Auth.Passwords) > 0 {
		ttl = s.config.Auth.Passwords[0].TokenTTLParsed
	}

	// Authenticate and create session
	session, token, err := s.authManager.Login(username, password, clientIP, "gasp-cli", ttl)
	if err != nil {
		if errors.Is(err, auth.ErrPwauthNotFound) {
			writeErrorResponse(w, http.StatusServiceUnavailable, "pwauth_not_found",
				"PAM authentication service not available. pwauth binary not found.",
				"install_pwauth", nil)
		} else if errors.Is(err, auth.ErrPwauthTimeout) {
			writeErrorResponse(w, http.StatusServiceUnavailable, "authentication_timeout",
				"Authentication service did not respond in time.",
				"retry_later", nil)
		} else if strings.Contains(err.Error(), "locked out") {
			writeUnauthorized(w, "user_locked_out", err.Error(), "wait_or_contact_admin")
		} else {
			writeUnauthorized(w, "invalid_credentials", "Authentication failed. Invalid username or password.", "verify_credentials")
		}
		return
	}

	// Return successful login response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := LoginResponse{
		Token:      token,
		TokenID:    fmt.Sprintf("%d", session.TokenID),
		ExpiresAt:  session.ExpiresAt,
		Username:   session.Username,
		IssuedToIP: session.ClientIP,
	}

	json.NewEncoder(w).Encode(response)
}

// extractBearerToken extracts the Bearer token from Authorization header
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}
