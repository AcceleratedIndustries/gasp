package auth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionStore_CreateAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewSessionStore(filepath.Join(tmpDir, "sessions.json"))

	session := NewSession("testuser", "192.168.1.100", "gasp-cli", 24*time.Hour)

	store.Create(session)

	retrieved := store.Get(session.TokenID)
	if retrieved == nil {
		t.Fatal("Expected to retrieve session")
	}

	if retrieved.Username != session.Username {
		t.Errorf("Expected username %s, got %s", session.Username, retrieved.Username)
	}
}

func TestSessionStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewSessionStore(filepath.Join(tmpDir, "sessions.json"))

	session := NewSession("testuser", "192.168.1.100", "gasp-cli", 24*time.Hour)
	store.Create(session)

	store.Delete(session.TokenID)

	retrieved := store.Get(session.TokenID)
	if retrieved != nil {
		t.Error("Expected session to be deleted")
	}
}

func TestSessionStore_GetByUsername(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewSessionStore(filepath.Join(tmpDir, "sessions.json"))

	session1 := NewSession("user1", "192.168.1.100", "gasp-cli", 24*time.Hour)
	session2 := NewSession("user1", "192.168.1.101", "gasp-cli", 24*time.Hour)
	session3 := NewSession("user2", "192.168.1.102", "gasp-cli", 24*time.Hour)

	store.Create(session1)
	store.Create(session2)
	store.Create(session3)

	sessions := store.GetByUsername("user1")
	if len(sessions) != 2 {
		t.Errorf("Expected 2 sessions for user1, got %d", len(sessions))
	}
}

func TestSessionStore_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "sessions.json")

	// Create store and add session
	store1 := NewSessionStore(sessionFile)
	session := NewSession("testuser", "192.168.1.100", "gasp-cli", 24*time.Hour)
	store1.Create(session)

	// Save to disk
	if err := store1.Save(); err != nil {
		t.Fatalf("Failed to save sessions: %v", err)
	}

	// Create new store and load
	store2 := NewSessionStore(sessionFile)
	if err := store2.Load(); err != nil {
		t.Fatalf("Failed to load sessions: %v", err)
	}

	// Verify session persisted
	retrieved := store2.Get(session.TokenID)
	if retrieved == nil {
		t.Fatal("Expected to retrieve persisted session")
	}

	if retrieved.Username != session.Username {
		t.Errorf("Expected username %s, got %s", session.Username, retrieved.Username)
	}
}
