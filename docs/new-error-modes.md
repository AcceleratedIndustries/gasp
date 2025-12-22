# GASP Authentication - New Error Modes

This document tracks error modes discovered during implementation that are not defined in `GASP-Authentication-Specification.md`. These should be added to the GASP skill for proper error handling.

---

## New Error Modes Discovered

### 1. `pwauth_not_found`
**HTTP Status:** 503 Service Unavailable
**Trigger:** PAM authentication attempted but `/usr/bin/pwauth` binary not installed
**Location:** `internal/auth/pam.go:68-70`

**Error Response:**
```json
{
  "error": "pwauth_not_found",
  "message": "PAM authentication service not available. pwauth binary not found.",
  "details": {
    "path": "/usr/bin/pwauth"
  },
  "action": "install_pwauth",
  "timestamp": "2024-12-22T15:30:00Z"
}
```

**Client Action:** Contact system administrator to install pwauth package
**Server Action:** Log warning, refuse login attempts

**Installation Fix:**
- Arch Linux: `sudo pacman -S pwauth`
- Debian/Ubuntu: `sudo apt install pwauth`

---

### 2. `jwt_secret_too_short`
**HTTP Status:** 500 Internal Server Error
**Trigger:** JWT secret file contains less than 32 bytes
**Location:** `internal/auth/tokens.go:39-41`

**Error Response:**
```json
{
  "error": "jwt_secret_too_short",
  "message": "JWT secret must be at least 32 bytes for security.",
  "details": {
    "secret_file": "/home/user/.config/gasp/jwt-secret",
    "actual_length": 16,
    "required_length": 32
  },
  "action": "regenerate_secret",
  "timestamp": "2024-12-22T15:30:00Z"
}
```

**Client Action:** Cannot proceed - server misconfiguration
**Server Action:** Refuse to start, log fatal error

**Admin Fix:**
```bash
gasp config generate-secret > ~/.config/gasp/jwt-secret
```

---

### 3. `session_file_corrupted`
**HTTP Status:** 500 Internal Server Error (logged only, not returned)
**Trigger:** `sessions.json` file exists but cannot be parsed as valid JSON
**Location:** `internal/auth/store.go:226-227`

**Behavior:**
- Logs warning: `"failed to unmarshal sessions (starting fresh)"`
- Starts with empty session store
- Does NOT prevent server startup
- Corrupted file is not deleted (manual cleanup required)

**Admin Fix:**
```bash
# Backup corrupted file
mv ~/.local/state/gasp/sessions.json ~/.local/state/gasp/sessions.json.corrupted

# Restart server (will create new empty sessions file)
systemctl --user restart gasp
```

---

### 4. `security_state_corrupted`
**HTTP Status:** 500 Internal Server Error (logged only, not returned)
**Trigger:** `security-state.json` file exists but cannot be parsed
**Location:** `internal/auth/manager.go:49` (placeholder - not yet implemented)

**Expected Behavior (when implemented):**
- Log warning
- Start with empty security state (no blocked IPs, no lockouts)
- Server continues to function
- **SECURITY RISK:** Blocked IPs and lockouts are lost

**Admin Fix:** Same as `session_file_corrupted`

---

### 5. `config_yaml_parse_error`
**HTTP Status:** 500 Internal Server Error
**Trigger:** Config file is not valid YAML syntax
**Location:** `internal/config/config.go:29-31`

**Error Response:**
```json
{
  "error": "config_yaml_parse_error",
  "message": "Failed to parse configuration file.",
  "details": {
    "config_file": "/home/user/.config/gasp/config.yaml",
    "parse_error": "yaml: line 12: mapping values are not allowed in this context"
  },
  "action": "fix_config_syntax",
  "timestamp": "2024-12-22T15:30:00Z"
}
```

**Client Action:** Cannot connect - server misconfiguration
**Server Action:** Refuse to start, log fatal error

**Admin Fix:** Validate YAML syntax with `gasp config validate`

---

### 6. `invalid_token_ttl_duration`
**HTTP Status:** 500 Internal Server Error
**Trigger:** `token_ttl` field in config contains invalid duration string
**Location:** `internal/config/config.go:35-38`

**Error Response:**
```json
{
  "error": "invalid_token_ttl_duration",
  "message": "Invalid token_ttl duration in configuration.",
  "details": {
    "password_name": "default",
    "token_ttl": "invalid",
    "expected_format": "168h, 7d, 1w"
  },
  "action": "fix_config",
  "timestamp": "2024-12-22T15:30:00Z"
}
```

**Client Action:** Cannot connect - server misconfiguration
**Server Action:** Refuse to start, log fatal error

**Admin Fix:** Use valid Go duration format (e.g., "168h" for 7 days)

---

### 7. `session_creation_failed`
**HTTP Status:** 500 Internal Server Error
**Trigger:** Failed to generate cryptographically secure token ID
**Location:** `internal/auth/session.go:34-37` (fallback exists, extremely rare)

**Error Response:**
```json
{
  "error": "session_creation_failed",
  "message": "Failed to create session. Please try again.",
  "action": "retry",
  "timestamp": "2024-12-22T15:30:00Z"
}
```

**Client Action:** Retry login
**Server Action:** Log error, use time-based fallback token ID

**Note:** This error is nearly impossible on properly functioning systems (crypto/rand failure).

---

### 8. `session_persistence_failed`
**HTTP Status:** 500 Internal Server Error (logged only)
**Trigger:** Failed to write sessions.json to disk
**Location:** `internal/auth/store.go:143-146`

**Behavior:**
- Login succeeds
- Session works in memory
- Warning logged: `"failed to write sessions"`
- Session will be lost on restart
- Server continues to function

**Possible Causes:**
- Disk full
- Permission denied on `~/.local/state/gasp/`
- Filesystem readonly

**Admin Fix:** Check disk space and permissions

---

### 9. `concurrent_login_limit_exceeded`
**HTTP Status:** 429 Too Many Requests
**Trigger:** User has too many active sessions (future feature)
**Location:** Not yet implemented

**Expected Error Response:**
```json
{
  "error": "concurrent_login_limit_exceeded",
  "message": "Maximum concurrent sessions exceeded for this user.",
  "details": {
    "active_sessions": 5,
    "max_allowed": 5
  },
  "action": "logout_other_sessions",
  "timestamp": "2024-12-22T15:30:00Z"
}
```

**Client Action:** Revoke old sessions or wait for expiration

---

### 10. `authentication_service_unavailable`
**HTTP Status:** 503 Service Unavailable
**Trigger:** AuthManager not initialized when endpoint called
**Location:** `internal/server/auth_handlers.go:42`

**Error Response:**
```json
{
  "error": "authentication_service_unavailable",
  "message": "Authentication service is not available.",
  "action": "retry_later",
  "timestamp": "2024-12-22T15:30:00Z"
}
```

**Client Action:** Retry after brief wait
**Server Action:** Log error, check AuthManager initialization

---

## Error Modes from Spec (Already Defined)

These are already in `GASP-Authentication-Specification.md` and are correctly implemented:

- ✅ `invalid_credentials` (401)
- ✅ `user_locked_out` (401)
- ✅ `missing_credentials` (401)
- ✅ `token_expired` (401)
- ✅ `token_invalid` (401)
- ✅ `token_revoked` (401)
- ✅ `ip_binding_violation` (403)
- ✅ `unauthorized_source_ip` (403)
- ✅ `ip_blocked` (403)
- ✅ `unauthorized_user` (403)
- ✅ `rate_limit_exceeded` (429)
- ✅ `too_many_failed_attempts` (429)
- ✅ `malformed_request` (400)
- ✅ `invalid_method` (405)
- ✅ `endpoint_not_found` (404)
- ✅ `request_timeout` (408)
- ✅ `internal_error` (500)

---

## Implementation Status

| Error Mode | Implemented | Tested | Documented |
|-----------|-------------|--------|------------|
| pwauth_not_found | ✅ Yes | ⚠️ Partial | ✅ Yes |
| jwt_secret_too_short | ✅ Yes | ✅ Yes | ✅ Yes |
| session_file_corrupted | ✅ Yes | ⚠️ No | ✅ Yes |
| security_state_corrupted | ❌ Placeholder | ❌ No | ✅ Yes |
| config_yaml_parse_error | ✅ Yes | ✅ Yes | ✅ Yes |
| invalid_token_ttl_duration | ✅ Yes | ✅ Yes | ✅ Yes |
| session_creation_failed | ✅ Yes (fallback) | ⚠️ Untestable | ✅ Yes |
| session_persistence_failed | ✅ Yes | ❌ No | ✅ Yes |
| concurrent_login_limit_exceeded | ❌ Future | ❌ No | ✅ Yes |
| authentication_service_unavailable | ✅ Yes | ❌ No | ✅ Yes |

---

## Recommendations for GASP Skill Update

### Priority 1: Add to Error Catalog

Add all 10 new error modes to `GASP-Authentication-Specification.md` Section 16 (Error Response Catalog) with:
- HTTP status code
- Trigger conditions
- Example JSON response
- Client action guidance
- Server-side behavior

### Priority 2: Update GASP Skill

Update the `gasp-diagnostics` Claude Code skill to recognize and diagnose these errors:
- Parse error responses from GASP instances
- Provide specific remediation steps
- Check for common misconfigurations (missing pwauth, short secrets, etc.)

### Priority 3: Testing

Add integration tests for error handling:
- Start server without pwauth installed
- Use corrupted sessions.json file
- Use invalid config.yaml syntax
- Use JWT secret < 32 bytes

---

## Common Error Patterns

### Server Startup Failures (Fatal)
- `config_yaml_parse_error`
- `invalid_token_ttl_duration`
- `jwt_secret_too_short`

**Detection:** Server won't start, systemd shows failed status

**Fix:** Validate configuration with `gasp config validate`

### Authentication Failures (Runtime)
- `pwauth_not_found`
- `authentication_service_unavailable`

**Detection:** Login attempts fail with 503 errors

**Fix:** Install pwauth or check server initialization

### Data Corruption (Non-Fatal)
- `session_file_corrupted`
- `security_state_corrupted`

**Detection:** Warning in logs, server continues

**Fix:** Delete corrupted files, server will regenerate

---

## Security Implications

### High Risk
- **security_state_corrupted**: Blocked IPs and lockouts lost → attackers can retry
- **session_persistence_failed**: Active sessions not saved → tokens become invalid on restart

### Medium Risk
- **pwauth_not_found**: No authentication possible → DoS condition
- **jwt_secret_too_short**: Weak tokens → brute force attacks feasible

### Low Risk
- **session_file_corrupted**: Old sessions lost, new sessions work fine
- **config_yaml_parse_error**: Server won't start → fail-safe

---

## Monitoring Recommendations

Alert on these error modes in production:
1. **pwauth_not_found** - Critical service dependency missing
2. **jwt_secret_too_short** - Security configuration error
3. **security_state_corrupted** - Potential security breach
4. **session_persistence_failed** - Storage subsystem failure

Log and investigate:
1. session_file_corrupted
2. config_yaml_parse_error
3. authentication_service_unavailable

---

**Document Version:** 1.0
**Date:** 2024-12-22
**Status:** Ready for integration into GASP skill
