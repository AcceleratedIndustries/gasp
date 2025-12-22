package server

import (
	"net/http"
	"strings"
)

// RequireAuth is middleware that enforces authentication
func (s *Server) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If auth is disabled, allow all requests
		if s.config == nil || !s.config.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Extract client IP from RemoteAddr
		clientIP := extractClientIP(r.RemoteAddr)

		// Check localhost bypass
		if s.config.Auth.LocalhostBypass && isLocalhost(clientIP) {
			// Allow localhost requests without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Require authentication for non-localhost or when bypass disabled
		tokenString := extractBearerToken(r)
		if tokenString == "" {
			writeUnauthorized(w, "missing_credentials",
				"Authentication required. Please provide credentials.",
				"authenticate")
			return
		}

		// Validate token if auth manager is available
		if s.authManager == nil {
			writeErrorResponse(w, http.StatusServiceUnavailable,
				"authentication_service_unavailable",
				"Authentication service is not available.",
				"retry_later",
				nil)
			return
		}

		// Validate token and check IP binding
		session, err := s.authManager.ValidateToken(tokenString, clientIP)
		if err != nil {
			if strings.Contains(err.Error(), "expired") {
				writeUnauthorized(w, "token_expired",
					"Your session has expired. Please login again.",
					"authenticate")
			} else if strings.Contains(err.Error(), "IP binding violation") {
				writeForbidden(w, "ip_binding_violation",
					"Token cannot be used from this IP address.",
					"obtain_new_token",
					map[string]interface{}{
						"client_ip": clientIP,
					})
			} else if strings.Contains(err.Error(), "session not found") {
				writeUnauthorized(w, "token_revoked",
					"Session has been revoked or does not exist.",
					"authenticate")
			} else {
				writeUnauthorized(w, "token_invalid",
					"Invalid authentication token.",
					"authenticate")
			}
			return
		}

		// Store session info in request context for handlers to use
		// (Future: use context.WithValue to pass session to handlers)
		_ = session

		// Authentication successful, call next handler
		next.ServeHTTP(w, r)
	})
}

// extractClientIP extracts the client IP address from RemoteAddr
func extractClientIP(remoteAddr string) string {
	// Handle IPv6 addresses in brackets [::1]:port
	if strings.HasPrefix(remoteAddr, "[") {
		// Find the closing bracket
		closeBracket := strings.Index(remoteAddr, "]")
		if closeBracket > 0 {
			return remoteAddr[1:closeBracket]
		}
	}

	// Handle IPv4 addresses ip:port
	colonIdx := strings.LastIndex(remoteAddr, ":")
	if colonIdx > 0 {
		return remoteAddr[:colonIdx]
	}

	return remoteAddr
}

// isLocalhost checks if an IP address is localhost
func isLocalhost(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}
