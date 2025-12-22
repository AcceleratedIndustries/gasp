package server

import (
	"encoding/json"
	"net/http"
	"time"
)

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error     string                 `json:"error"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Action    string                 `json:"action"`
	Timestamp string                 `json:"timestamp"`
}

// writeErrorResponse writes a JSON error response
func writeErrorResponse(w http.ResponseWriter, statusCode int, errorCode, message, action string, details map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:     errorCode,
		Message:   message,
		Details:   details,
		Action:    action,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

// Error response helpers
func writeUnauthorized(w http.ResponseWriter, errorCode, message, action string) {
	w.Header().Set("WWW-Authenticate", "Bearer realm=\"GASP\"")
	writeErrorResponse(w, http.StatusUnauthorized, errorCode, message, action, nil)
}

func writeForbidden(w http.ResponseWriter, errorCode, message, action string, details map[string]interface{}) {
	writeErrorResponse(w, http.StatusForbidden, errorCode, message, action, details)
}

func writeBadRequest(w http.ResponseWriter, errorCode, message, action string) {
	writeErrorResponse(w, http.StatusBadRequest, errorCode, message, action, nil)
}

func writeInternalError(w http.ResponseWriter, errorCode, message string) {
	writeErrorResponse(w, http.StatusInternalServerError, errorCode, message, "retry_or_contact_admin", nil)
}
