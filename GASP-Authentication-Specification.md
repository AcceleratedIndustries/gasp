# GASP Authentication & Security Specification
## Complete Requirements and Error Response Catalog

**Project:** GASP (General AI Specialized Process monitor)  
**Organization:** Accelerated Industries  
**Version:** 1.0.0  
**Date:** December 2024  
**Author:** Will (with Claude)

---

## Document Structure

**Part 1:** Requirements (Sections 1-15)  
**Part 2:** Error Response Catalog (Sections 16-26)

---

# PART 1: REQUIREMENTS

## Consolidated Requirements - December 2024

---

## 1. Project Overview

**Name:** GASP (General AI Specialized Process monitor)  
**Purpose:** AI-optimized Linux system monitoring tool  
**Organization:** Accelerated Industries  
**Primary Use Case:** Enable AI agents (Claude) to diagnose system issues via HTTP queries

**Key Principles:**
- AI-first design (context-rich JSON output)
- Single source of truth for system state
- Low overhead (suitable for workstations and servers)
- Easy distribution (single static binary)
- Network accessible via HTTP

---

## 2. Technology Stack

**Language:** Go
- Single static binary distribution
- Excellent standard library for system metrics
- Native concurrency for parallel collection
- Fast execution and low overhead
- Superior JSON handling

**Deployment:** User-level installation
- No root privileges required
- Runs in user's home directory
- Uses systemd --user services
- High ports (>1024)

---

## 3. Authentication & Authorization

### 3.1 Authentication Method

**Initial Login:**
- Username/password authentication via PAM
- Uses `pwauth` utility (setuid helper)
- Validates against Linux user accounts
- No custom password storage

**Session Management:**
- Internal sessions table (in-memory + disk persistence)
- 64-bit token IDs for fast lookup
- Tokens bound to client IP address
- Configurable TTL (default 7 days)
- Force re-authentication (no token refresh)

**Localhost Bypass:**
- Connections from 127.0.0.1 skip authentication entirely
- Enables easy local queries

### 3.2 Authorization Model

**User-Based Access:**
- Uses existing Linux user accounts
- No need to create dedicated service users
- Admin runs GASP as their own user (e.g., "will")

**IP Binding:**
- Each password configuration specifies allowed source IPs/networks
- Strict IP binding: tokens only work from issued IP
- CIDR notation supported (e.g., 192.168.1.0/24)

**Per-Request Validation:**
- Fast O(1) token lookup in sessions table
- No PAM call per request (only on login)
- Checks: token validity, expiration, IP binding

### 3.3 Security Features

**Rate Limiting:**
- Username-based failed login tracking
- 5 failed attempts → 15 minute lockout
- Tracks attempts within 5-minute window
- Lockouts persist across restarts

**IP Blocking:**
- Immediate permanent block for unauthorized source IPs
- First login attempt from non-allowed IP → permanent block
- IP violations (token used from wrong IP) → revoke token + block IP
- Blocked IPs persist across restarts
- Admin must manually unblock

**Revocation:**
- Manual revocation commands:
  - `gasp auth revoke --user <username>` (all sessions)
  - `gasp auth revoke --token <tokenID>` (specific session)
  - `gasp auth revoke --all` (emergency: all sessions)
- Required after password changes (manual two-step process)
- Revoked sessions removed from sessions table

**Persistent Storage:**
- Sessions: `~/.local/state/gasp/sessions.json`
- Security state (blocked IPs, lockouts): `~/.local/state/gasp/security-state.json`
- Periodic saves (default: every 5 minutes)
- Loaded on startup

### 3.4 JWT Configuration

**Per-Host Secrets:**
- Each GASP instance has unique JWT secret
- Generated during installation
- Stored in `~/.config/gasp/jwt-secret` (mode 600)
- No federation between hosts

**Token Structure:**
- 64-bit token ID (for internal lookup)
- Username
- Client IP (binding)
- Issued timestamp
- Expiration timestamp
- Signed with HS256

---

## 4. Security Alerts

**Email Notifications:**
- Alerts sent to configured email address
- Default: will@accelerated.industries
- Desktop notification via hyprmail integration

**Alert Triggers:**
- IP binding violations
- Unauthorized source IP attempts
- User account lockouts
- Token revocations (admin-initiated)
- NOT individual failed logins (too noisy)

**Alert Rate Limiting:**
- Maximum 10 alerts per hour
- Prevents spam during sustained attacks

**Email Content:**
- Event type and timestamp
- Affected username and IPs
- Actions taken automatically
- Admin guidance for response
- Plain text format

**SMTP Configuration:**
- Default: localhost:25
- Optional authenticated SMTP
- Configurable from address (gasp@hostname)

---

## 5. Logging

### 5.1 Log Levels

**Global Level:** info (default), debug, warn, error

**Component-Specific Levels:**
- `auth`: info (always logged - login, logout, revoke)
- `security`: info (always logged - violations, blocks, alerts)
- `requests`: warn (configurable - successful requests at warn+)
- `metrics`: debug (one level up from most verbose)
- `server`: info (lifecycle events)

### 5.2 Log Format

**JSON Format (AI-Optimized):**
```json
{
  "timestamp": "2024-12-17T10:30:45.123Z",
  "level": "info",
  "component": "auth",
  "event": "login_success",
  "username": "will",
  "client_ip": "192.168.1.100",
  "token_id": "67890",
  "expires_at": "2024-12-24T10:30:45Z"
}
```

**Text Format (Human-Readable):**
```
2024-12-17T10:30:45.123Z [INFO] auth: login_success username=will client_ip=192.168.1.100
```

**Benefits of JSON:**
- Structured and parseable
- No regex needed for AI consumption
- Easy to aggregate and analyze
- Still human-readable

### 5.3 Log Outputs

**Destinations:**
- stdout (default)
- File: `~/.local/state/gasp/gasp.log`
- Both stdout and file (configurable)

**File Rotation:**
- Max size: 100MB
- Max backups: 5
- Max age: 30 days
- Compression: enabled

---

## 6. Installation & Deployment

### 6.1 Directory Structure

**XDG Base Directory Compliance:**
```
~/.local/bin/gasp                       # Binary
~/.config/gasp/
  ├── config.yaml                       # Main config
  ├── jwt-secret                        # Encryption key
  └── spokes.yaml                       # Spoke registry (hub only)
~/.local/state/gasp/
  ├── sessions.json                     # Active sessions
  ├── security-state.json               # Blocked IPs, lockouts
  └── gasp.log                          # Log file (optional)
~/.config/systemd/user/
  └── gasp.service                      # User systemd unit
```

### 6.2 Hub vs Spoke Configuration

**Hub Mode:**
- Aggregator/admin workstation
- Can query spoke instances
- Maintains spoke registry
- Full auth and alerting enabled

**Spoke Mode:**
- Monitored host
- Serves own metrics only
- No spoke registry
- May disable alerts (hub handles alerting)

### 6.3 Installation Scripts

**Hub Installation (`install-gasp.sh`):**
- Runs on local machine
- Interactive prompts:
  - Port selection (default: 9090)
  - Admin email for alerts
- Creates directory structure
- Generates JWT secret
- Creates default config
- Sets up systemd user service
- Enables lingering (`loginctl enable-linger`)
- No root required (except for lingering)

**Spoke Installation (`gaspinstall <hostname>`):**
- Installs GASP on remote host via SSH
- Requires SSH access to target host
- Interactive prompts (on remote):
  - Port selection
- Copies binary to remote `~/.local/bin`
- Generates spoke config remotely
- Sets up systemd user service
- Enables lingering
- Registers spoke in hub's `spokes.yaml`

### 6.4 Port Configuration

**Default Port:** 9090
- Avoids common conflicts (80, 8080)
- User-selectable during installation
- Port availability check during install
- Warning if port in use

**Requirements:**
- Must be high port (>1024)
- No root privileges needed
- Same port can be used across spokes

### 6.5 Spoke Registry

**File:** `~/.config/gasp/spokes.yaml`

**Structure:**
```yaml
spokes:
  - hostname: "hyperion.accelerated.local"
    ip: "192.168.1.10"
    port: 9090
    installed_at: "2024-12-17T10:30:00Z"
    installed_by: "will"
```

**Maintained by:**
- `gaspinstall` command (auto-appends)
- Manual editing allowed

### 6.6 Systemd User Service

**Service File:**
```ini
[Unit]
Description=GASP System Monitor
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/gasp
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
```

**Lingering:**
- Enabled during installation
- Service persists when user logs out
- Command: `loginctl enable-linger $USER`

---

## 7. CLI Tools

### 7.1 Main Binary: `gasp`

**Server Mode (default):**
```bash
gasp                  # Start server with default config
gasp --config /path   # Use alternate config
gasp --port 8080      # Override port
```

**Admin Commands:**
```bash
# Authentication management
gasp auth setpass --name default          # Set password hash
gasp auth hashpass                        # Generate bcrypt hash
gasp auth revoke --user <username>        # Revoke all user sessions
gasp auth revoke --token <tokenID>        # Revoke specific token
gasp auth revoke --all                    # Revoke all tokens
gasp auth list                            # List active sessions

# IP blocking management
gasp auth list-blocked                    # Show blocked IPs
gasp auth unblock --ip <ip>               # Unblock IP
gasp auth list-lockouts                   # Show locked users
gasp auth unlock --user <username>        # Clear lockout early

# Configuration
gasp config validate                      # Validate config file
gasp config show                          # Show effective config
gasp config test-smtp                     # Send test email
gasp config test-auth                     # Test PAM auth
```

### 7.2 Query CLI: `gasp` (client mode)

**Usage:**
```bash
gasp [OPTIONS] [HOSTNAME] <ENDPOINT>

Options:
  -a, --all          Query all registered spokes
  -u, --user USER    Username for authentication
  -p, --port PORT    Override default port
  -h, --help         Show help

Examples:
  gasp hyperion /metrics              # Query specific host
  gasp -a /metrics                    # Query all spokes
  gasp --all /cpu                     # CPU from all hosts
  gasp proxmox1 /health               # Health check
```

**Behavior:**
- Reads spoke registry to validate hosts
- Prevents querying non-registered hosts
- With `--all`: ignores hostname argument
- Caches tokens per session (in memory)
- Prompts for password if not in env

### 7.3 Installation CLI

**gaspinstall:**
```bash
gaspinstall <hostname>                # Install on remote host
gaspinstall --help                    # Show usage
```

---

## 8. HTTP API Endpoints

### 8.1 Authentication Endpoints

**POST /auth/login**
- Purpose: Authenticate and receive token
- Methods: Basic Auth or JSON body
- Returns: Token + expiration

**POST /auth/logout** (optional)
- Purpose: Explicitly invalidate token
- Requires: Valid token
- Returns: Success confirmation

### 8.2 Metrics Endpoints

**GET /metrics**
- Purpose: Full system snapshot (primary endpoint)
- Returns: Complete JSON with all metrics
- Requires: Valid token (unless localhost)

**GET /health**
- Purpose: Service health check
- Returns: Simple health status
- May not require auth (configurable)

**GET /version**
- Purpose: Version and build information
- Returns: Version, commit, build date
- May not require auth (configurable)

**GET /cpu** (optional)
- Purpose: CPU metrics only
- Returns: Subset of /metrics

**GET /memory** (optional)
- Purpose: Memory metrics only
- Returns: Subset of /metrics

### 8.3 Request/Response Flow

**Authentication Required:**
1. Client sends request with `Authorization: Bearer <token>` header
2. Server validates token:
   - Lookup in sessions table
   - Check expiration
   - Check IP binding
3. If valid: process request
4. If invalid: return error (see error catalog)

**Localhost Bypass:**
1. Server checks if client IP is 127.0.0.1
2. If yes: skip all auth checks
3. Process request directly

---

## 9. Configuration File

**Location:** `~/.config/gasp/config.yaml`

**Major Sections:**
- server: Listen address, ports, timeouts
- mode: hub or spoke
- auth: Passwords, JWT, sessions
- rate_limiting: Failed login limits
- security: IP blocking, alerts, SMTP
- logging: Levels, format, output
- collection: Intervals, collectors
- output: Optional file output
- hub: Spoke registry (hub mode only)
- advanced: Performance tuning

**See complete schema in approved config.yaml above**

---

## 10. Data Structures

### 10.1 Session

```go
type Session struct {
    TokenID    uint64    // 64-bit unique ID
    Username   string    // Linux username
    ClientIP   string    // IP token bound to
    ClientID   string    // Client identifier
    IssuedAt   time.Time
    ExpiresAt  time.Time
}
```

### 10.2 Blocked IP

```go
type BlockedIP struct {
    IP         string
    Reason     string    // "unauthorized_source", "ip_binding_violation"
    BlockedAt  time.Time
    Username   string    // Associated user (if applicable)
    TokenID    uint64    // Associated token (if applicable)
}
```

### 10.3 User Lockout

```go
type UserLockout struct {
    Username       string
    FailedAttempts int
    LockedUntil    time.Time
    LastAttemptIP  string
    AttemptTimes   []time.Time  // For windowing
}
```

---

## 11. Performance Targets

**Resource Usage:**
- Binary size: < 15MB
- Memory footprint: < 50MB
- CPU overhead: < 1% idle, < 5% during collection
- Disk I/O: Minimal (periodic state saves only)

**Response Times:**
- HTTP /metrics endpoint: < 100ms
- Collection cycle: < 2 seconds
- Token validation: < 1ms (in-memory lookup)

**Authentication:**
- Login (PAM call): < 500ms
- Per-request validation: < 1ms (no PAM)

---

## 12. Error Handling

**(To be defined in Error Response Catalog)**

---

## 13. Security Model

**Threat Model:**
- Trusted network (home lab, internal infrastructure)
- Primary threats: credential theft, token misuse
- Secondary: unauthorized access attempts

**Defense in Depth:**
1. PAM authentication (Linux user management)
2. IP binding (token tied to source IP)
3. Rate limiting (brute force protection)
4. Immediate blocking (unauthorized IPs)
5. Session revocation (compromised tokens)
6. Email alerts (detection and response)
7. Audit logging (forensics)

**Assumptions:**
- Network is not hostile (no TLS required initially)
- Admins can SSH to hosts
- Email delivery is functional

---

## 14. Future Enhancements (Not in Initial Spec)

**Phase 2 Possibilities:**
- TLS/HTTPS support
- mTLS for high-security environments
- Container awareness (Docker, LXC)
- Proxmox integration
- Central aggregation service
- Predictive monitoring
- Interactive querying
- Configuration management tracking

---

## 15. Open Questions / Decisions for Specification

None - all requirements confirmed.

---

**Document Status:** Complete, ready for Error Response Catalog  
**Next Step:** Define Error Response Catalog  
**Final Step:** Merge into specification.md

---
---

# PART 2: ERROR RESPONSE CATALOG

---

# GASP Error Response Catalog
## Comprehensive Error Definitions for Client Handling

---

## Error Response Format

All errors follow a consistent JSON structure:

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {
    // Optional: additional context
  },
  "action": "suggested_action",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**HTTP Status Codes Used:**
- `400` - Bad Request (client error)
- `401` - Unauthorized (authentication required/failed)
- `403` - Forbidden (authenticated but not authorized)
- `404` - Not Found (endpoint doesn't exist)
- `429` - Too Many Requests (rate limited)
- `500` - Internal Server Error (server problem)
- `503` - Service Unavailable (server not ready)

---

## 1. Authentication Errors (401 Unauthorized)

### 1.1 Invalid Credentials

**Error Code:** `invalid_credentials`  
**HTTP Status:** 401  
**Trigger:** Username/password authentication failed via PAM

```json
{
  "error": "invalid_credentials",
  "message": "Authentication failed. Invalid username or password.",
  "action": "verify_credentials",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Prompt user to re-enter credentials or check credentials configuration.

---

### 1.2 User Locked Out

**Error Code:** `user_locked_out`  
**HTTP Status:** 401  
**Trigger:** User exceeded max failed login attempts

```json
{
  "error": "user_locked_out",
  "message": "Account temporarily locked due to too many failed login attempts.",
  "details": {
    "locked_until": "2024-12-17T10:45:00Z",
    "remaining_seconds": 900
  },
  "action": "wait_or_contact_admin",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Wait until lockout expires or contact admin for manual unlock.

---

### 1.3 Missing Credentials

**Error Code:** `missing_credentials`  
**HTTP Status:** 401  
**Trigger:** No authentication provided when required

```json
{
  "error": "missing_credentials",
  "message": "Authentication required. Please provide credentials.",
  "details": {
    "login_endpoint": "/auth/login"
  },
  "action": "authenticate",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Send credentials to /auth/login endpoint.

---

### 1.4 Token Expired

**Error Code:** `token_expired`  
**HTTP Status:** 401  
**Trigger:** Token TTL exceeded

```json
{
  "error": "token_expired",
  "message": "Authentication token has expired. Please re-authenticate.",
  "details": {
    "expired_at": "2024-12-17T10:00:00Z",
    "login_endpoint": "/auth/login"
  },
  "action": "login",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Re-authenticate at /auth/login to get new token.

---

### 1.5 Token Invalid

**Error Code:** `token_invalid`  
**HTTP Status:** 401  
**Trigger:** Malformed token, invalid signature, or not found in sessions

```json
{
  "error": "token_invalid",
  "message": "Authentication token is invalid. Please re-authenticate.",
  "details": {
    "login_endpoint": "/auth/login"
  },
  "action": "login",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Re-authenticate to get valid token.

---

### 1.6 Token Revoked

**Error Code:** `token_revoked`  
**HTTP Status:** 401  
**Trigger:** Token was explicitly revoked by admin

```json
{
  "error": "token_revoked",
  "message": "Authentication token has been revoked. Please re-authenticate.",
  "details": {
    "revoked_at": "2024-12-17T10:00:00Z",
    "reason": "admin_revoke",
    "login_endpoint": "/auth/login"
  },
  "action": "login",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Re-authenticate. If repeatedly revoked, contact admin.

---

## 2. Authorization Errors (403 Forbidden)

### 2.1 IP Binding Violation

**Error Code:** `ip_binding_violation`  
**HTTP Status:** 403  
**Trigger:** Token used from different IP than it was issued to

```json
{
  "error": "ip_binding_violation",
  "message": "Token was issued to a different IP address. Access denied.",
  "details": {
    "issued_ip": "192.168.1.100",
    "request_ip": "192.168.1.200",
    "login_endpoint": "/auth/login"
  },
  "action": "login_from_correct_host",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Re-authenticate from the correct host. Token has been revoked.  
**Server Action:** Token revoked, requesting IP blocked, alert sent.

---

### 2.2 Unauthorized Source IP

**Error Code:** `unauthorized_source_ip`  
**HTTP Status:** 403  
**Trigger:** Login attempt from IP not in allowed_sources

```json
{
  "error": "unauthorized_source_ip",
  "message": "Access denied. Your IP address is not authorized.",
  "details": {
    "source_ip": "192.168.1.200"
  },
  "action": "contact_admin",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Contact admin to add IP to allowed sources.  
**Server Action:** IP permanently blocked, alert sent.

---

### 2.3 IP Blocked

**Error Code:** `ip_blocked`  
**HTTP Status:** 403  
**Trigger:** Request from permanently blocked IP

```json
{
  "error": "ip_blocked",
  "message": "Access denied. Your IP address has been blocked.",
  "details": {
    "ip": "192.168.1.200",
    "blocked_at": "2024-12-17T09:00:00Z",
    "reason": "ip_binding_violation"
  },
  "action": "contact_admin",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Contact admin for unblock.

---

### 2.4 Unauthorized User

**Error Code:** `unauthorized_user`  
**HTTP Status:** 403  
**Trigger:** User authenticated but not in allowed_clients list

```json
{
  "error": "unauthorized_user",
  "message": "User is not authorized to access this service.",
  "details": {
    "username": "someuser"
  },
  "action": "contact_admin",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Contact admin to be added to allowed users.

---

## 3. Rate Limiting Errors (429 Too Many Requests)

### 3.1 Rate Limit Exceeded

**Error Code:** `rate_limit_exceeded`  
**HTTP Status:** 429  
**Trigger:** Too many requests in time window

```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Please slow down.",
  "details": {
    "retry_after_seconds": 60,
    "limit": "100 requests per minute"
  },
  "action": "wait_and_retry",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Wait specified time before retrying.

---

### 3.2 Too Many Failed Login Attempts

**Error Code:** `too_many_failed_attempts`  
**HTTP Status:** 429  
**Trigger:** Multiple failed login attempts in short time (before lockout)

```json
{
  "error": "too_many_failed_attempts",
  "message": "Too many failed login attempts. Please wait before trying again.",
  "details": {
    "attempts_remaining": 2,
    "lockout_threshold": 5,
    "window_reset_seconds": 300
  },
  "action": "wait_and_verify_credentials",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Wait and verify credentials before next attempt.

---

## 4. Request Errors (400 Bad Request)

### 4.1 Malformed Request

**Error Code:** `malformed_request`  
**HTTP Status:** 400  
**Trigger:** Invalid JSON, missing required fields

```json
{
  "error": "malformed_request",
  "message": "Request body is malformed or missing required fields.",
  "details": {
    "required_fields": ["username", "password"],
    "error_detail": "invalid JSON syntax at line 2"
  },
  "action": "fix_request",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Fix request format and retry.

---

### 4.2 Invalid Request Method

**Error Code:** `invalid_method`  
**HTTP Status:** 405  
**Trigger:** Wrong HTTP method for endpoint

```json
{
  "error": "invalid_method",
  "message": "Method not allowed for this endpoint.",
  "details": {
    "method_used": "GET",
    "allowed_methods": ["POST"]
  },
  "action": "use_correct_method",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Use correct HTTP method.

---

### 4.3 Endpoint Not Found

**Error Code:** `endpoint_not_found`  
**HTTP Status:** 404  
**Trigger:** Requested endpoint doesn't exist

```json
{
  "error": "endpoint_not_found",
  "message": "The requested endpoint does not exist.",
  "details": {
    "path": "/invalid/endpoint",
    "available_endpoints": ["/metrics", "/health", "/version", "/auth/login"]
  },
  "action": "check_endpoint",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Check endpoint path and retry with correct endpoint.

---

### 4.4 Request Timeout

**Error Code:** `request_timeout`  
**HTTP Status:** 408  
**Trigger:** Request took too long to complete

```json
{
  "error": "request_timeout",
  "message": "Request timed out.",
  "details": {
    "timeout_seconds": 30
  },
  "action": "retry",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Retry request.

---

## 5. Server Errors (500 Internal Server Error)

### 5.1 Internal Server Error

**Error Code:** `internal_error`  
**HTTP Status:** 500  
**Trigger:** Unexpected server-side error

```json
{
  "error": "internal_error",
  "message": "An internal server error occurred. Please try again later.",
  "details": {
    "error_id": "550e8400-e29b-41d4-a716-446655440000"
  },
  "action": "retry_or_contact_admin",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Retry. If persistent, contact admin with error_id.

---

### 5.2 Auth Helper Unavailable

**Error Code:** `auth_service_unavailable`  
**HTTP Status:** 503  
**Trigger:** Cannot communicate with pwauth or PAM

```json
{
  "error": "auth_service_unavailable",
  "message": "Authentication service is temporarily unavailable.",
  "details": {
    "service": "pwauth"
  },
  "action": "retry_later",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Retry after brief wait.

---

### 5.3 Service Starting

**Error Code:** `service_starting`  
**HTTP Status:** 503  
**Trigger:** Server still initializing

```json
{
  "error": "service_starting",
  "message": "Service is still starting up. Please wait.",
  "details": {
    "estimated_ready_seconds": 5
  },
  "action": "wait_and_retry",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Wait a few seconds and retry.

---

### 5.4 Metrics Collection Failed

**Error Code:** `metrics_collection_failed`  
**HTTP Status:** 500  
**Trigger:** Error collecting metrics from system

```json
{
  "error": "metrics_collection_failed",
  "message": "Failed to collect system metrics.",
  "details": {
    "failed_collectors": ["disk", "network"],
    "partial_data": true
  },
  "action": "retry",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Retry. Partial data may be available in response.

---

## 6. Configuration Errors (500 Internal Server Error)

### 6.1 Configuration Invalid

**Error Code:** `config_invalid`  
**HTTP Status:** 500  
**Trigger:** Server configuration is invalid (caught during runtime)

```json
{
  "error": "config_invalid",
  "message": "Server configuration is invalid.",
  "details": {
    "config_section": "auth.passwords",
    "error_detail": "no passwords configured"
  },
  "action": "contact_admin",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Contact admin to fix configuration.

---

## 7. Special Responses

### 7.1 Localhost Bypass Notice

**Note:** When localhost bypass is enabled, requests from 127.0.0.1 skip all authentication. They will never receive auth-related errors.

If localhost client tries to authenticate:

**Error Code:** `localhost_bypass_enabled`  
**HTTP Status:** 400  
**Trigger:** Localhost trying to use /auth/login when bypass is enabled

```json
{
  "error": "localhost_bypass_enabled",
  "message": "Authentication not required for localhost connections.",
  "details": {
    "bypass_enabled": true
  },
  "action": "use_endpoint_directly",
  "timestamp": "2024-12-17T10:30:45Z"
}
```

**Client Action:** Skip authentication and query endpoints directly.

---

### 7.2 Successful Login Response

**Not an error, but included for completeness:**

**HTTP Status:** 200  
**Response:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_id": "67890",
  "expires_at": "2024-12-24T10:30:45Z",
  "username": "will",
  "issued_to_ip": "192.168.1.100"
}
```

---

## 8. Error Handling Best Practices for Clients

### 8.1 Retry Strategy

**Transient Errors (Retry):**
- `auth_service_unavailable`
- `service_starting`
- `request_timeout`
- `metrics_collection_failed`
- `internal_error`

**Retry with Exponential Backoff:**
```
Attempt 1: Wait 1 second
Attempt 2: Wait 2 seconds
Attempt 3: Wait 4 seconds
Max attempts: 3-5
```

**Permanent Errors (Don't Retry):**
- `ip_blocked`
- `unauthorized_user`
- `unauthorized_source_ip`
- `config_invalid`

**Re-authenticate Errors:**
- `token_expired`
- `token_invalid`
- `token_revoked`
- `invalid_credentials` (after fixing credentials)

### 8.2 Client State Machine

```
UNAUTHENTICATED
  ↓ (send credentials)
AUTHENTICATING
  ↓ (receive token)
AUTHENTICATED
  ↓ (make request)
  → Success → Continue
  → token_expired → Re-authenticate
  → ip_binding_violation → Alert user, re-auth from correct host
  → rate_limit_exceeded → Wait and retry
  → internal_error → Retry with backoff
```

### 8.3 User Notifications

**Silent Retry:**
- `service_starting`
- `request_timeout`
- `metrics_collection_failed`

**Warn User:**
- `rate_limit_exceeded`
- `too_many_failed_attempts`
- `token_expired` (after auto-retry fails)

**Alert User (Action Required):**
- `ip_binding_violation`
- `ip_blocked`
- `user_locked_out`
- `unauthorized_user`
- `invalid_credentials` (after multiple attempts)

---

## 9. HTTP Response Headers

All error responses include standard headers:

```
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-GASP-Version: 1.0.0
```

For rate limiting errors:
```
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1702819845
```

For authentication errors:
```
WWW-Authenticate: Bearer realm="GASP"
```

---

## 10. Error Logging

All errors are logged server-side in structured format:

```json
{
  "timestamp": "2024-12-17T10:30:45.123Z",
  "level": "error",
  "component": "auth",
  "event": "ip_binding_violation",
  "error_code": "ip_binding_violation",
  "username": "will",
  "token_id": "67890",
  "issued_ip": "192.168.1.100",
  "request_ip": "192.168.1.200",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "actions_taken": ["token_revoked", "ip_blocked", "alert_sent"]
}
```

---

## 11. Error Code Summary Table

| Error Code | HTTP Status | Retry? | Re-auth? | User Action |
|-----------|-------------|--------|----------|-------------|
| `invalid_credentials` | 401 | No | Yes | Fix credentials |
| `user_locked_out` | 401 | After wait | Yes | Wait or contact admin |
| `missing_credentials` | 401 | No | Yes | Authenticate |
| `token_expired` | 401 | No | Yes | Re-authenticate |
| `token_invalid` | 401 | No | Yes | Re-authenticate |
| `token_revoked` | 401 | No | Yes | Re-authenticate |
| `ip_binding_violation` | 403 | No | Yes (correct host) | Auth from correct host |
| `unauthorized_source_ip` | 403 | No | No | Contact admin |
| `ip_blocked` | 403 | No | No | Contact admin |
| `unauthorized_user` | 403 | No | No | Contact admin |
| `rate_limit_exceeded` | 429 | After wait | No | Wait |
| `too_many_failed_attempts` | 429 | After wait | Yes | Wait + verify creds |
| `malformed_request` | 400 | No | No | Fix request |
| `invalid_method` | 405 | No | No | Use correct method |
| `endpoint_not_found` | 404 | No | No | Check endpoint |
| `request_timeout` | 408 | Yes | No | Retry |
| `internal_error` | 500 | Yes | No | Retry or contact admin |
| `auth_service_unavailable` | 503 | Yes | No | Wait and retry |
| `service_starting` | 503 | Yes | No | Wait and retry |
| `metrics_collection_failed` | 500 | Yes | No | Retry |
| `config_invalid` | 500 | No | No | Contact admin |
| `localhost_bypass_enabled` | 400 | No | No | Skip auth |

---

**Document Status:** Complete  
**Next Step:** Merge with requirements document into specification.md

---
