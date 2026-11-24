package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SessionStore manages in-memory sessions with disk persistence
type SessionStore struct {
	sessions map[uint64]*Session
	mu       sync.RWMutex
	filePath string
	saveMu   sync.Mutex // serializes Save so writes can't collide or reorder
}

// NewSessionStore creates a new session store
func NewSessionStore(filePath string) *SessionStore {
	return &SessionStore{
		sessions: make(map[uint64]*Session),
		filePath: filePath,
	}
}

// Create adds a new session
func (s *SessionStore) Create(session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.TokenID] = session
}

// Get retrieves a session by token ID
func (s *SessionStore) Get(tokenID uint64) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[tokenID]
}

// Delete removes a session by token ID
func (s *SessionStore) Delete(tokenID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, tokenID)
}

// GetByUsername retrieves all sessions for a username
func (s *SessionStore) GetByUsername(username string) []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sessions []*Session
	for _, session := range s.sessions {
		if session.Username == username {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// DeleteByUsername removes all sessions for a username
func (s *SessionStore) DeleteByUsername(username string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for tokenID, session := range s.sessions {
		if session.Username == username {
			delete(s.sessions, tokenID)
			count++
		}
	}
	return count
}

// GetAll returns all sessions
func (s *SessionStore) GetAll() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// CleanupExpired removes all expired sessions
func (s *SessionStore) CleanupExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for tokenID, session := range s.sessions {
		if session.IsExpired() {
			delete(s.sessions, tokenID)
			count++
		}
	}
	return count
}

// Save persists sessions to disk
func (s *SessionStore) Save() error {
	// Hold saveMu across snapshot and write, so concurrent saves can't
	// collide and a later save always carries the newer state
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	// Convert map to slice for JSON
	s.mu.RLock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	data, err := json.MarshalIndent(sessions, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to marshal sessions: %w", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to a unique temp file then rename (atomic)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.filePath)+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp sessions file: %w", err)
	}
	tempFile := tmp.Name()
	defer os.Remove(tempFile) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write sessions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync sessions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close sessions file: %w", err)
	}

	if err := os.Rename(tempFile, s.filePath); err != nil {
		return fmt.Errorf("failed to rename sessions file: %w", err)
	}

	return nil
}

// Load reads sessions from disk
func (s *SessionStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, that's okay
			return nil
		}
		return fmt.Errorf("failed to read sessions: %w", err)
	}

	var sessions []*Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		// Log warning but don't fail - start with empty sessions
		return fmt.Errorf("failed to unmarshal sessions (starting fresh): %w", err)
	}

	// Rebuild map
	s.sessions = make(map[uint64]*Session)
	for _, session := range sessions {
		// Skip expired sessions during load
		if !session.IsExpired() {
			s.sessions[session.TokenID] = session
		}
	}

	return nil
}

// Count returns the number of active sessions
func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
