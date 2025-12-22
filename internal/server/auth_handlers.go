package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

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

	// Extract client IP
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	// Check if IP is blocked
	if s.authManager != nil && s.authManager.IsIPBlocked(clientIP) {
		writeForbidden(w, "ip_blocked", "Access denied. Your IP address has been blocked.",
			"contact_admin", map[string]interface{}{
				"ip": clientIP,
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
		if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
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

	// TODO: Implement actual login logic with AuthManager
	// For now, return error
	writeInternalError(w, "not_implemented", "Authentication not yet fully implemented")
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
