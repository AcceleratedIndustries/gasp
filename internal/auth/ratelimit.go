package auth

import (
	"time"
)

// recordFailedAttempt records a failed login attempt for a user
func recordFailedAttempt(lockout *UserLockout, clientIP string) {
	lockout.FailedAttempts++
	lockout.LastAttemptIP = clientIP
	lockout.AttemptTimes = append(lockout.AttemptTimes, time.Now())
}

// shouldLockUser determines if a user should be locked based on failed attempts
func shouldLockUser(lockout *UserLockout, maxAttempts int) bool {
	return lockout.FailedAttempts >= maxAttempts
}

// lockUser locks a user account for the specified duration
func lockUser(lockout *UserLockout, lockoutDuration time.Duration) {
	lockout.LockedUntil = time.Now().Add(lockoutDuration)
}

// cleanupOldAttempts removes attempts outside the time window
func cleanupOldAttempts(lockout *UserLockout, windowDuration time.Duration) {
	cutoff := time.Now().Add(-windowDuration)

	var validAttempts []time.Time
	for _, attemptTime := range lockout.AttemptTimes {
		if attemptTime.After(cutoff) {
			validAttempts = append(validAttempts, attemptTime)
		}
	}

	lockout.AttemptTimes = validAttempts
	lockout.FailedAttempts = len(validAttempts)
}

// clearLockout clears a user's lockout state
func clearLockout(lockout *UserLockout) {
	lockout.FailedAttempts = 0
	lockout.AttemptTimes = []time.Time{}
	lockout.LockedUntil = time.Time{}
}
