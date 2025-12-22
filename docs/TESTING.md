# GASP Authentication System - Manual Test Plan

**Version:** 1.0
**Date:** 2024-12-22
**Purpose:** Guide for manual testing of GASP authentication features

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Test Environment Setup](#test-environment-setup)
3. [Test Scenarios](#test-scenarios)
4. [Troubleshooting](#troubleshooting)
5. [Expected Behaviors Reference](#expected-behaviors-reference)

---

## Prerequisites

### Required Software

- ✅ Go 1.21+ (check: `go version`)
- ✅ `curl` for HTTP testing
- ✅ `jq` for JSON parsing (optional but helpful)
- ✅ `openssl` for generating secrets
- ✅ `pwauth` for PAM authentication (install: `sudo pacman -S pwauth` on Arch)

### Build GASP

```bash
cd ~/src/gasp
go build -o gasp ./cmd/gasp
```

### Verify Build

```bash
./gasp --version
# Expected: GASP (General AI Specialized Process monitor) v0.1.0-dev
```

---

## Test Environment Setup

### 1. Create Configuration Directory

```bash
mkdir -p ~/.config/gasp
mkdir -p ~/.local/state/gasp
```

### 2. Generate JWT Secret

```bash
# Generate a 48-byte (256-bit) secret
openssl rand -base64 48 > ~/.config/gasp/jwt-secret

# Verify it was created and is >= 32 bytes
wc -c ~/.config/gasp/jwt-secret
# Expected: Should show at least 32 bytes
```

### 3. Create Test Configuration

Create `~/.config/gasp/config.yaml`:

```yaml
server:
  listen_address: "127.0.0.1:9090"

mode: "spoke"

auth:
  enabled: true
  localhost_bypass: true

  passwords:
    - name: "default"
      password_hash: ""  # Leave empty, we'll use PAM
      allowed_clients:
        - "gasp-cli"
        - "test-client"
      allowed_sources:
        - ip: "127.0.0.1"
          name: "localhost"
        - ip: "192.168.1.0/24"
          name: "home_network"
      token_ttl: "1h"

  jwt:
    secret_file: "~/.config/gasp/jwt-secret"

security:
  alerts:
    enabled: false

logging:
  level: "info"
  format: "json"
  output: "stdout"

rate_limiting:
  failed_login:
    max_attempts: 5
    lockout_duration: "15m"
    window_duration: "5m"
```

**Note:** The `password_hash` field is empty because we're using PAM authentication with your Linux user credentials.

---

## Test Scenarios

### Scenario 1: Server Startup with Configuration

**Objective:** Verify server starts successfully and loads configuration.

**Steps:**

1. Start the server:
   ```bash
   cd ~/src/gasp
   ./gasp --config ~/.config/gasp/config.yaml
   ```

2. **Expected Output:**
   ```
   2024/12/22 16:00:00 Starting GASP v0.1.0-dev
   2024/12/22 16:00:00 Loaded configuration from: /home/will/.config/gasp/config.yaml
   2024/12/22 16:00:00 Registering collectors...
   2024/12/22 16:00:00 Registered CPU and Memory collectors
   2024/12/22 16:00:00 Authentication enabled
   2024/12/22 16:00:00 Starting GASP server on :8080
   2024/12/22 16:00:00 Endpoints:
   2024/12/22 16:00:00   http://localhost:8080/health  - Health check
   2024/12/22 16:00:00   http://localhost:8080/metrics - System metrics
   2024/12/22 16:00:00   http://localhost:8080/version - Version info
   ```

3. **Verify:**
   - ✅ "Loaded configuration from" message appears
   - ✅ "Authentication enabled" message appears
   - ✅ No error messages
   - ✅ Server doesn't exit

**Pass Criteria:** Server starts without errors and displays all expected messages.

**Fail If:**
- "Failed to load config" error
- "Failed to load JWT secret" error
- Server exits immediately

---

### Scenario 2: Localhost Bypass - Unauthenticated Access

**Objective:** Verify localhost can access protected endpoints without authentication.

**Prerequisites:** Server running from Scenario 1.

**Steps:**

1. Test `/health` endpoint:
   ```bash
   curl -s http://127.0.0.1:8080/health | jq .
   ```

2. **Expected Output:**
   ```json
   {
     "service": "gasp",
     "status": "healthy",
     "timestamp": "2024-12-22T16:00:00-06:00"
   }
   ```

3. Test `/metrics` endpoint:
   ```bash
   curl -s http://127.0.0.1:8080/metrics | jq '.timestamp'
   ```

4. **Expected Output:**
   ```
   "2024-12-22T16:00:00.123456789-06:00"
   ```

5. **Verify:**
   - ✅ HTTP 200 OK status
   - ✅ Valid JSON response
   - ✅ No "authentication required" error

**Pass Criteria:** Both endpoints return data without requiring credentials.

**Fail If:**
- 401 Unauthorized response
- "missing_credentials" error
- Connection refused

---

### Scenario 3: Public Endpoints (No Auth Required)

**Objective:** Verify public endpoints work for all clients.

**Steps:**

1. Test `/version` endpoint:
   ```bash
   curl -s http://127.0.0.1:8080/version | jq .
   ```

2. **Expected Output:**
   ```json
   {
     "service": "gasp",
     "version": "0.1.0-dev",
     "build": "development"
   }
   ```

3. **Verify:**
   - ✅ HTTP 200 OK
   - ✅ Version information displayed
   - ✅ No authentication required

**Pass Criteria:** Version endpoint accessible without credentials.

---

### Scenario 4: PAM Authentication - Valid Login

**Objective:** Verify login with valid Linux user credentials.

**Prerequisites:**
- Server running
- `pwauth` installed (`sudo pacman -S pwauth`)
- You know your Linux user password

**Steps:**

1. Login with your Linux credentials:
   ```bash
   curl -s -X POST http://127.0.0.1:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"will","password":"YOUR_PASSWORD"}'
   ```

2. **Expected Output (Success):**
   ```json
   {
     "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "token_id": "1234567890",
     "expires_at": "2024-12-22T17:00:00-06:00",
     "username": "will",
     "issued_to_ip": "127.0.0.1"
   }
   ```

3. Save the token for next tests:
   ```bash
   TOKEN=$(curl -s -X POST http://127.0.0.1:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"will","password":"YOUR_PASSWORD"}' | jq -r '.token')

   echo "Token: $TOKEN"
   ```

4. **Verify:**
   - ✅ HTTP 200 OK
   - ✅ Received JWT token
   - ✅ `expires_at` is ~1 hour in future
   - ✅ `issued_to_ip` is "127.0.0.1"

**Pass Criteria:** Login succeeds and returns valid token.

**Fail If:**
- 401 "invalid_credentials" (wrong password)
- 503 "pwauth_not_found" (pwauth not installed)
- 500 "internal_error"

---

### Scenario 5: PAM Authentication - Invalid Credentials

**Objective:** Verify login fails with wrong password.

**Steps:**

1. Attempt login with wrong password:
   ```bash
   curl -s -X POST http://127.0.0.1:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"will","password":"wrongpassword"}'
   ```

2. **Expected Output:**
   ```json
   {
     "error": "invalid_credentials",
     "message": "Authentication failed. Invalid username or password.",
     "action": "verify_credentials",
     "timestamp": "2024-12-22T16:00:00-06:00"
   }
   ```

3. **Verify:**
   - ✅ HTTP 401 Unauthorized
   - ✅ Error code: "invalid_credentials"
   - ✅ No token returned

**Pass Criteria:** Login fails with clear error message.

---

### Scenario 6: Rate Limiting - Failed Login Lockout

**Objective:** Verify user gets locked out after 5 failed attempts.

**Steps:**

1. Attempt 5 failed logins:
   ```bash
   for i in {1..5}; do
     echo "Attempt $i:"
     curl -s -X POST http://127.0.0.1:8080/auth/login \
       -H "Content-Type: application/json" \
       -d '{"username":"will","password":"wrong"}' | jq -r '.error'
     sleep 1
   done
   ```

2. **Expected:** First 4 attempts show "invalid_credentials"

3. Attempt 6th login:
   ```bash
   curl -s -X POST http://127.0.0.1:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"will","password":"wrong"}' | jq .
   ```

4. **Expected Output:**
   ```json
   {
     "error": "user_locked_out",
     "message": "user locked out until 2024-12-22T16:15:00-06:00 after too many failed attempts",
     "action": "wait_or_contact_admin",
     "timestamp": "2024-12-22T16:00:00-06:00"
   }
   ```

5. **Verify:**
   - ✅ HTTP 401 Unauthorized
   - ✅ Error: "user_locked_out"
   - ✅ Message includes lockout expiration time
   - ✅ Lockout duration is ~15 minutes

6. Wait for lockout to expire or restart server to clear lockouts.

**Pass Criteria:** User locked out after 5 failed attempts.

---

### Scenario 7: Token-Based Access (Simulating Remote Client)

**Objective:** Verify token works for authenticated requests.

**Prerequisites:**
- Have valid token from Scenario 4
- Server running

**Note:** Since we're testing from localhost, we can't truly test "remote" access, but we can verify the token validation logic works.

**Steps:**

1. Create test config with localhost_bypass disabled:
   ```bash
   cp ~/.config/gasp/config.yaml ~/.config/gasp/config-no-bypass.yaml
   ```

2. Edit `~/.config/gasp/config-no-bypass.yaml` and set:
   ```yaml
   auth:
     enabled: true
     localhost_bypass: false  # Changed from true
   ```

3. Stop current server (Ctrl+C) and restart with new config:
   ```bash
   ./gasp --config ~/.config/gasp/config-no-bypass.yaml
   ```

4. Try accessing /metrics without token:
   ```bash
   curl -s http://127.0.0.1:8080/metrics | jq .
   ```

5. **Expected Output:**
   ```json
   {
     "error": "missing_credentials",
     "message": "Authentication required. Please provide credentials.",
     "details": {
       "login_endpoint": "/auth/login"
     },
     "action": "authenticate",
     "timestamp": "2024-12-22T16:00:00-06:00"
   }
   ```

6. Login to get token:
   ```bash
   TOKEN=$(curl -s -X POST http://127.0.0.1:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"will","password":"YOUR_PASSWORD"}' | jq -r '.token')
   ```

7. Access /metrics WITH token:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/metrics | jq '.timestamp'
   ```

8. **Expected:** Valid metrics response with timestamp.

9. **Verify:**
   - ✅ Without token: 401 error
   - ✅ With valid token: 200 OK with data
   - ✅ Token works for multiple requests

**Pass Criteria:** Token-based authentication works when localhost_bypass disabled.

---

### Scenario 8: Session Persistence Across Restarts

**Objective:** Verify sessions are saved to disk and restored.

**Prerequisites:** Have valid token from previous scenario.

**Steps:**

1. With server running and valid token, check sessions file:
   ```bash
   cat ~/.local/state/gasp/sessions.json | jq .
   ```

2. **Expected:** JSON file with your active session:
   ```json
   [
     {
       "TokenID": 1234567890,
       "Username": "will",
       "ClientIP": "127.0.0.1",
       "ClientID": "gasp-cli",
       "IssuedAt": "2024-12-22T16:00:00-06:00",
       "ExpiresAt": "2024-12-22T17:00:00-06:00"
     }
   ]
   ```

3. Stop server (Ctrl+C).

4. Restart server:
   ```bash
   ./gasp --config ~/.config/gasp/config-no-bypass.yaml
   ```

5. Use same token from before restart:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/metrics | jq '.timestamp'
   ```

6. **Verify:**
   - ✅ Sessions file exists and contains session data
   - ✅ Server loads sessions on startup (no error in logs)
   - ✅ Old token still works after restart
   - ✅ Can continue using session without re-login

**Pass Criteria:** Sessions persist across server restarts.

---

### Scenario 9: Configuration Validation Errors

**Objective:** Verify server fails gracefully with invalid configuration.

**Test 9A: Missing JWT Secret File**

1. Create bad config:
   ```bash
   cat > /tmp/bad-config-1.yaml <<EOF
   auth:
     enabled: true
     jwt:
       secret_file: "/nonexistent/secret"
   EOF
   ```

2. Try to start server:
   ```bash
   ./gasp --config /tmp/bad-config-1.yaml
   ```

3. **Expected Output:**
   ```
   2024/12/22 16:00:00 Failed to create auth manager: failed to load JWT secret: ...
   ```

4. **Verify:**
   - ✅ Server refuses to start
   - ✅ Clear error message about missing secret
   - ✅ Exit code non-zero

**Test 9B: Invalid Duration Format**

1. Create bad config:
   ```bash
   cat > /tmp/bad-config-2.yaml <<EOF
   auth:
     enabled: true
     passwords:
       - name: "test"
         token_ttl: "invalid"
     jwt:
       secret_file: "~/.config/gasp/jwt-secret"
   EOF
   ```

2. Try to start server:
   ```bash
   ./gasp --config /tmp/bad-config-2.yaml
   ```

3. **Expected Output:**
   ```
   2024/12/22 16:00:00 Failed to load config: invalid token_ttl for password test: ...
   ```

4. **Verify:**
   - ✅ Server refuses to start
   - ✅ Error mentions "invalid token_ttl"
   - ✅ Identifies which password config is broken

**Test 9C: Auth Enabled Without Passwords**

1. Create bad config:
   ```bash
   cat > /tmp/bad-config-3.yaml <<EOF
   auth:
     enabled: true
     passwords: []
     jwt:
       secret_file: "~/.config/gasp/jwt-secret"
   EOF
   ```

2. Try to start server:
   ```bash
   ./gasp --config /tmp/bad-config-3.yaml
   ```

3. **Expected Output:**
   ```
   2024/12/22 16:00:00 Invalid configuration: auth enabled but no passwords configured
   ```

**Pass Criteria:** All invalid configs are rejected with clear error messages.

---

### Scenario 10: Missing pwauth Binary

**Objective:** Verify graceful handling when pwauth is not installed.

**Steps:**

1. Uninstall pwauth (or rename it temporarily):
   ```bash
   sudo pacman -Rs pwauth
   # OR
   sudo mv /usr/bin/pwauth /usr/bin/pwauth.backup
   ```

2. Attempt login:
   ```bash
   curl -s -X POST http://127.0.0.1:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"will","password":"password"}' | jq .
   ```

3. **Expected Output:**
   ```json
   {
     "error": "invalid_credentials",
     "message": "Authentication failed. Invalid username or password.",
     "action": "verify_credentials",
     "timestamp": "2024-12-22T16:00:00-06:00"
   }
   ```

4. **Verify:**
   - ✅ Login fails (doesn't crash server)
   - ✅ Generic error message (doesn't expose system details)
   - ✅ Server continues running

5. Reinstall pwauth:
   ```bash
   sudo pacman -S pwauth
   # OR
   sudo mv /usr/bin/pwauth.backup /usr/bin/pwauth
   ```

**Pass Criteria:** Server handles missing pwauth gracefully without crashing.

---

## Troubleshooting

### Problem: "Failed to load config"

**Possible Causes:**
- Config file doesn't exist at specified path
- Invalid YAML syntax
- Permission denied

**Solutions:**
1. Verify file exists: `ls -la ~/.config/gasp/config.yaml`
2. Check YAML syntax online or with: `python -c "import yaml; yaml.safe_load(open('~/.config/gasp/config.yaml'))"`
3. Check permissions: `chmod 600 ~/.config/gasp/config.yaml`

---

### Problem: "JWT secret too short"

**Cause:** Secret file has less than 32 bytes.

**Solution:**
```bash
openssl rand -base64 48 > ~/.config/gasp/jwt-secret
wc -c ~/.config/gasp/jwt-secret  # Should be >= 32
```

---

### Problem: "pwauth not found"

**Cause:** PAM authentication binary not installed.

**Solution:**
```bash
# Arch Linux
sudo pacman -S pwauth

# Debian/Ubuntu
sudo apt install pwauth

# Verify installation
which pwauth
ls -l /usr/bin/pwauth  # Should show setuid bit: -rws--x--x
```

---

### Problem: Localhost bypass not working

**Symptoms:** Getting 401 errors even from localhost.

**Checks:**
1. Verify config has `localhost_bypass: true`
2. Check you're actually connecting to 127.0.0.1 (not hostname)
3. Restart server after config changes

---

### Problem: Token doesn't work after restart

**Possible Causes:**
- Sessions file corrupted
- JWT secret changed
- IP binding violation (testing from different IP)

**Solutions:**
1. Check sessions file: `cat ~/.local/state/gasp/sessions.json`
2. Verify JWT secret hasn't changed
3. Get new token with fresh login

---

### Problem: Can't connect to server

**Checks:**
1. Is server running? `ps aux | grep gasp`
2. Correct port? Check config or use default 8080
3. Firewall blocking? `sudo iptables -L`
4. Listening on correct interface? Check `listen_address` in config

---

## Expected Behaviors Reference

### HTTP Status Codes

| Code | Meaning | When You'll See It |
|------|---------|-------------------|
| 200 | Success | Valid requests with proper auth |
| 401 | Unauthorized | Missing/invalid/expired token, wrong password |
| 403 | Forbidden | IP blocked, IP binding violation |
| 404 | Not Found | Invalid endpoint |
| 405 | Method Not Allowed | Wrong HTTP method (GET vs POST) |
| 429 | Too Many Requests | Rate limited, user locked out |
| 500 | Internal Server Error | Server bug, config issue |
| 503 | Service Unavailable | Auth service not ready |

### Error Codes Quick Reference

| Error Code | HTTP | Meaning | Action |
|-----------|------|---------|--------|
| `missing_credentials` | 401 | No token provided | Login first |
| `invalid_credentials` | 401 | Wrong username/password | Check credentials |
| `token_expired` | 401 | Session timed out | Login again |
| `token_invalid` | 401 | Malformed/tampered token | Get new token |
| `token_revoked` | 401 | Session deleted | Login again |
| `user_locked_out` | 401 | Too many failed logins | Wait 15 minutes |
| `ip_binding_violation` | 403 | Token used from wrong IP | Get new token |
| `ip_blocked` | 403 | IP address blocked | Contact admin |
| `pwauth_not_found` | 503 | PAM not available | Install pwauth |

### File Locations Reference

| File | Purpose | Location |
|------|---------|----------|
| Config file | Server configuration | `~/.config/gasp/config.yaml` |
| JWT secret | Token signing key | `~/.config/gasp/jwt-secret` |
| Sessions | Active sessions | `~/.local/state/gasp/sessions.json` |
| Security state | Blocked IPs, lockouts | `~/.local/state/gasp/security-state.json` |
| Server binary | Executable | `~/src/gasp/gasp` |

---

## Test Completion Checklist

Before considering testing complete, verify:

- [ ] Server starts with valid config
- [ ] Server rejects invalid configs with clear errors
- [ ] Localhost bypass works (127.0.0.1 and ::1)
- [ ] Public endpoints accessible without auth
- [ ] PAM authentication works with valid credentials
- [ ] Login fails appropriately with invalid credentials
- [ ] Rate limiting locks users out after 5 failures
- [ ] Tokens work for authenticated access
- [ ] Sessions persist across restarts
- [ ] Missing pwauth handled gracefully
- [ ] JWT secret validation works (rejects < 32 bytes)
- [ ] State directories created automatically

---

## Reporting Issues

When reporting issues, include:

1. **What you were testing:** Scenario number and step
2. **What you expected:** From the test plan
3. **What actually happened:** Full error message or unexpected behavior
4. **Logs:** Relevant server output
5. **Config:** Your config.yaml (redact secrets)
6. **Environment:** OS, Go version, pwauth installed?

Example:
```
Scenario 4, Step 1 - PAM Authentication
Expected: Login success with token
Actual: 503 error "pwauth_not_found"
Environment: Arch Linux, Go 1.21.5, pwauth NOT installed
Solution: Installed pwauth, retested successfully
```

---

**End of Test Plan**
