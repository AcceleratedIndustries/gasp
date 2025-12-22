package auth

import (
	"testing"
	"time"
)

func TestRecordFailedAttempt(t *testing.T) {
	lockout := &UserLockout{
		Username:     "testuser",
		AttemptTimes: []time.Time{},
	}

	// Record 3 attempts
	for i := 0; i < 3; i++ {
		recordFailedAttempt(lockout, "192.168.1.100")
	}

	if lockout.FailedAttempts != 3 {
		t.Errorf("Expected 3 failed attempts, got %d", lockout.FailedAttempts)
	}

	if len(lockout.AttemptTimes) != 3 {
		t.Errorf("Expected 3 attempt times, got %d", len(lockout.AttemptTimes))
	}
}

func TestShouldLockUser(t *testing.T) {
	lockout := &UserLockout{
		Username:       "testuser",
		FailedAttempts: 5,
		AttemptTimes:   []time.Time{time.Now(), time.Now(), time.Now(), time.Now(), time.Now()},
	}

	if !shouldLockUser(lockout, 5) {
		t.Error("Expected user to be locked after 5 attempts")
	}

	lockout.FailedAttempts = 3
	if shouldLockUser(lockout, 5) {
		t.Error("Expected user not to be locked with only 3 attempts")
	}
}

func TestCleanupOldAttempts(t *testing.T) {
	lockout := &UserLockout{
		Username: "testuser",
		AttemptTimes: []time.Time{
			time.Now().Add(-10 * time.Minute), // Old
			time.Now().Add(-2 * time.Minute),  // Recent
			time.Now().Add(-1 * time.Minute),  // Recent
		},
		FailedAttempts: 3,
	}

	windowDuration := 5 * time.Minute
	cleanupOldAttempts(lockout, windowDuration)

	// Should only keep recent attempts
	if len(lockout.AttemptTimes) != 2 {
		t.Errorf("Expected 2 recent attempts, got %d", len(lockout.AttemptTimes))
	}

	if lockout.FailedAttempts != 2 {
		t.Errorf("Expected failed attempts to be updated to 2, got %d", lockout.FailedAttempts)
	}
}
